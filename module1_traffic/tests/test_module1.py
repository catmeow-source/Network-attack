"""
Smoke tests for Module 1. Run with:

    python -m unittest module1_traffic.tests.test_module1 -v

These exist to catch regressions of the two real bugs found while
building this module (see baseline.py and traffic_generator.py
docstrings/comments for the full explanation of each):

  1. EWMA variance bootstraps from 0, so without a warm-up exemption
     the freeze mechanism latches permanently within the first few
     windows of pure NORMAL traffic.
  2. BASELINE_WARMUP_WINDOWS (30) exceeds the demo arc's original
     length (20 windows) -- without a quiet lead-in, baseline_ready
     never flips true during the scripted demo.
"""

import unittest

from shared import config

from module1_traffic.baseline import AdaptiveBaseline
from module1_traffic.feature_extractor import extract_window_features, process_traffic
from module1_traffic.traffic_generator import generate_demo_traffic


def _synthetic_normal_record(i):
    return {
        "src_ip": f"192.168.1.{i % 40}",
        "dst_ip": "10.0.1.1",
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flag": "SYN" if i % 2 == 0 else "ACK",
        "packet_size": 500,
        "connection_failed": False,
    }


class ExtractWindowFeaturesTests(unittest.TestCase):
    def test_empty_window_returns_zeros_not_a_crash(self):
        features = extract_window_features([])
        self.assertEqual(features["packets_per_second"], 0.0)
        self.assertEqual(features["syn_rate"], 0.0)
        self.assertEqual(features["unique_source_ips"], 0)

    def test_contract_has_all_nine_features(self):
        records = [_synthetic_normal_record(i) for i in range(100)]
        features = extract_window_features(records)
        expected_keys = {
            "packets_per_second", "bytes_per_second", "avg_packet_size",
            "unique_source_ips", "unique_destination_ips", "syn_rate",
            "failed_connections", "connection_rate", "port_entropy",
        }
        self.assertEqual(set(features.keys()), expected_keys)

    def test_syn_rate_is_a_ratio_not_a_throughput(self):
        # All records SYN -> ratio must be 1.0, not a packets/sec count.
        records = [dict(_synthetic_normal_record(i), tcp_flag="SYN") for i in range(50)]
        features = extract_window_features(records)
        self.assertEqual(features["syn_rate"], 1.0)

    def test_port_entropy_zero_for_single_port(self):
        records = [_synthetic_normal_record(i) for i in range(20)]
        features = extract_window_features(records)
        self.assertEqual(features["port_entropy"], 0.0)  # all records use port 80


class ProcessTrafficContractTests(unittest.TestCase):
    def test_output_matches_integration_contract_shape(self):
        baseline = AdaptiveBaseline()
        records = [_synthetic_normal_record(i) for i in range(50)]
        window = process_traffic(records, baseline=baseline, timestamp="2026-08-26T19:05:00")
        self.assertEqual(
            set(window.keys()), {"timestamp", "baseline_ready", "features", "anomalies"}
        )
        self.assertEqual(
            set(window["anomalies"].keys()), {"traffic", "syn", "source", "connection"}
        )
        self.assertNotIn("temporal_acceleration", window)  # owned by Module 2, not us

    def test_anomalies_are_always_bounded_zero_one(self):
        baseline = AdaptiveBaseline()
        # Feed something wildly outside any plausible baseline and confirm
        # the [0,1] clamp actually holds -- this is the contract Module 2
        # depends on for its own weighted-sum clamp to be meaningful.
        for _ in range(5):
            process_traffic([_synthetic_normal_record(i) for i in range(50)], baseline=baseline)
        extreme = [
            dict(_synthetic_normal_record(i), src_ip=f"9.9.9.{i}", packet_size=1)
            for i in range(5000)
        ]
        window = process_traffic(extreme, baseline=baseline)
        for value in window["anomalies"].values():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)


class BaselineWarmupAndFreezeTests(unittest.TestCase):
    def test_baseline_ready_false_during_warmup_true_after(self):
        baseline = AdaptiveBaseline()
        records = [_synthetic_normal_record(i) for i in range(50)]
        last_ready = None
        for i in range(config.BASELINE_WARMUP_WINDOWS + 1):
            _, last_ready = baseline.update(
                packets_per_second=50 / 60, bytes_per_second=25000 / 60,
                syn_rate=0.5, unique_source_ips=40, failed_connections=1,
            )
            if i < config.BASELINE_WARMUP_WINDOWS - 1:
                self.assertFalse(last_ready, f"window {i} should not be ready yet")
        self.assertTrue(last_ready, "baseline should be ready once warmup completes")

    def test_never_freezes_during_warmup_even_with_a_spike(self):
        # A single noisy window mid-warmup must not latch a permanent
        # freeze -- this is the exact bug that made every NORMAL window
        # saturate to anomaly=1.0 before the fix.
        baseline = AdaptiveBaseline()
        for _ in range(5):
            baseline.update(packets_per_second=10, bytes_per_second=5000,
                             syn_rate=0.5, unique_source_ips=40, failed_connections=1)
        baseline.update(packets_per_second=500, bytes_per_second=500000,
                         syn_rate=0.99, unique_source_ips=200, failed_connections=100)
        self.assertFalse(baseline.is_frozen, "must not freeze before warmup completes")

    def test_freezes_after_warmup_when_indicator_crosses_threshold(self):
        baseline = AdaptiveBaseline()
        for _ in range(config.BASELINE_WARMUP_WINDOWS):
            baseline.update(packets_per_second=10, bytes_per_second=5000,
                             syn_rate=0.5, unique_source_ips=40, failed_connections=1)
        self.assertFalse(baseline.is_frozen)
        baseline.update(packets_per_second=500, bytes_per_second=500000,
                         syn_rate=0.99, unique_source_ips=200, failed_connections=100)
        self.assertTrue(baseline.is_frozen, "should freeze once mature baseline sees a real spike")


class DemoGeneratorTests(unittest.TestCase):
    def test_generator_is_deterministic(self):
        run_a = generate_demo_traffic(seed=7)
        run_b = generate_demo_traffic(seed=7)
        self.assertEqual([len(r) for _, r in run_a], [len(r) for _, r in run_b])

    def test_full_arc_escalates_end_to_end(self):
        """Feed the real generator through the real pipeline and confirm
        the aggregate anomaly signal is materially higher at the DDoS
        end of the arc than at the NORMAL start -- the property the
        whole demo narrative depends on."""
        baseline = AdaptiveBaseline()
        results = []
        for stage_label, records in generate_demo_traffic():
            window = process_traffic(records, baseline=baseline)
            avg_anomaly = sum(window["anomalies"].values()) / len(window["anomalies"])
            results.append((stage_label, avg_anomaly, window["baseline_ready"]))

        normal_avg = sum(a for label, a, ready in results if label == "NORMAL (warmup)") / \
            sum(1 for label, _, _ in results if label == "NORMAL (warmup)")
        ddos_avg = sum(a for label, a, _ in results if label == "DDoS") / \
            sum(1 for label, _, _ in results if label == "DDoS")

        self.assertLess(normal_avg, 0.3, "NORMAL traffic should not read as anomalous")
        self.assertGreater(ddos_avg, 0.8, "DDoS traffic should read as strongly anomalous")

        ready_at_ddos = all(ready for label, _, ready in results if label == "DDoS")
        self.assertTrue(ready_at_ddos, "baseline must be out of warmup before the DDoS scenes")


if __name__ == "__main__":
    unittest.main()
