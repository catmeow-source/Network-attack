"""
Smoke tests for Module 1. Run with:

    python -m unittest module1_traffic.tests.test_module1 -v

Each test's docstring/comment explains the specific bug or coverage
gap it guards against. See module1_traffic/README.md ("Design
decisions worth knowing about") for the full, numbered list -- kept
there rather than duplicated here so there's one place to update, not
two that drift out of sync with each other.
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

    def test_avg_packet_size_matches_bytes_over_packets_invariant(self):
        # Design doc §5.1 calls this out explicitly as "worth asserting
        # in code" -- it hadn't been, until this test. Tolerance is one
        # rounding step (1e-4), not exact equality: avg_packet_size is
        # itself rounded after being derived from the rounded pps/bps
        # below, so it can differ from their raw ratio by up to half a
        # rounding increment.
        records = [dict(_synthetic_normal_record(i), packet_size=100 + i) for i in range(37)]
        features = extract_window_features(records)
        derived = features["bytes_per_second"] / features["packets_per_second"]
        self.assertAlmostEqual(derived, features["avg_packet_size"], delta=1e-4)


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

    def _warmed_up_baseline(self):
        baseline = AdaptiveBaseline()
        for _ in range(config.BASELINE_WARMUP_WINDOWS):
            baseline.update(packets_per_second=10, bytes_per_second=5000,
                             syn_rate=0.5, unique_source_ips=40, failed_connections=1)
        return baseline

    def _quiet_update(self, baseline):
        return baseline.update(packets_per_second=10, bytes_per_second=5000,
                                syn_rate=0.5, unique_source_ips=40, failed_connections=1)

    def _spike_update(self, baseline):
        return baseline.update(packets_per_second=500, bytes_per_second=500000,
                                syn_rate=0.99, unique_source_ips=200, failed_connections=100)

    def test_unfreezes_after_five_consecutive_quiet_windows(self):
        # This branch (baseline.py's `elif self._frozen: quiet_streak += 1
        # ...`) was previously exercised by NOTHING: the scripted demo
        # only ever escalates, so it froze once and stayed frozen for
        # the rest of the arc. A bug here -- e.g. an off-by-one on the
        # 5-window threshold -- would have shipped undetected.
        baseline = self._warmed_up_baseline()
        self._spike_update(baseline)
        self.assertTrue(baseline.is_frozen)

        for i in range(4):
            self._quiet_update(baseline)
            self.assertTrue(baseline.is_frozen, f"should still be frozen after {i + 1} quiet windows")

        self._quiet_update(baseline)  # 5th consecutive quiet window
        self.assertFalse(baseline.is_frozen, "should unfreeze after 5 consecutive quiet windows")

    def test_quiet_streak_resets_on_renewed_spike(self):
        baseline = self._warmed_up_baseline()
        self._spike_update(baseline)
        self._quiet_update(baseline)
        self._quiet_update(baseline)  # streak = 2, still frozen

        self._spike_update(baseline)  # renewed spike must reset the streak
        self.assertTrue(baseline.is_frozen)

        for i in range(4):
            self._quiet_update(baseline)
            self.assertTrue(
                baseline.is_frozen,
                f"streak should have been reset by the renewed spike (only {i + 1} quiet windows since)",
            )
        self._quiet_update(baseline)  # 5th quiet window since the reset
        self.assertFalse(baseline.is_frozen)


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

    def test_destination_diversity_collapses_toward_victim_during_ddos(self):
        # module1_traffic/README.md documents unique_destination_ips as
        # corroborating evidence because "collapsing to one host
        # corroborates a targeted flood" -- an earlier version of the
        # generator never actually produced that: legit background
        # traffic kept spanning the full 8-host pool throughout, so the
        # feature sat flat at 8 for the entire arc regardless of attack
        # severity, contradicting the module's own documentation.
        normal_dests, ddos_dests = [], []
        for stage_label, records in generate_demo_traffic():
            dests = extract_window_features(records)["unique_destination_ips"]
            if stage_label == "NORMAL (warmup)":
                normal_dests.append(dests)
            elif stage_label == "DDoS":
                ddos_dests.append(dests)

        self.assertEqual(max(normal_dests), 8, "NORMAL traffic should span the full destination pool")
        self.assertLessEqual(
            max(ddos_dests), 3,
            "destination diversity should have collapsed well below 8 by the DDoS stage",
        )


if __name__ == "__main__":
    unittest.main()
