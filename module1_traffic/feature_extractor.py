"""
Module 1 -- Traffic Intelligence.

Converts raw flow records into the normalized feature + anomaly
contract defined in SIH26153_Predictive_Cyber_Defense_Design_Document.md
§5.1 / §7.1.

Raw flow record format (one dict per packet/flow observed in a window):

    {
        "src_ip": str,
        "dst_ip": str,
        "dst_port": int,
        "protocol": "TCP" | "UDP",
        "tcp_flag": "SYN" | "SYN-ACK" | "ACK" | "RST" | "FIN" | None,
        "packet_size": int,           # bytes
        "connection_failed": bool,    # RST/timeout on a tracked connection
    }

This shape isn't mandated by the design doc (which deliberately leaves
"PCAP-derived flow data / NetFlow-like CSV / synthetic" open); it's
the concrete shape this prototype's generator, and any real ingester
swapped in later, must produce.
"""

import math
from collections import Counter
from datetime import datetime, timezone

from shared import config

from .baseline import AdaptiveBaseline

# Module-level singleton so `process_traffic(records)` -- the exact
# single-argument signature required by the design doc -- still
# accumulates history across calls by default. Pass an explicit
# `baseline=` for tests or multi-tenant use.
_default_baseline = AdaptiveBaseline()


def _shannon_entropy_bits(counts):
    total = sum(counts)
    if total == 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def extract_window_features(records, window_seconds=config.WINDOW_SECONDS):
    """Aggregate one window's worth of flow records into the `features`
    block of the Module 1 output contract. Pure function, no state."""
    n = len(records)
    if n == 0:
        return {
            "packets_per_second": 0.0,
            "bytes_per_second": 0.0,
            "avg_packet_size": 0.0,
            "unique_source_ips": 0,
            "unique_destination_ips": 0,
            "syn_rate": 0.0,
            "failed_connections": 0,
            "connection_rate": 0.0,
            "port_entropy": 0.0,
        }

    total_bytes = sum(r["packet_size"] for r in records)
    src_ips = {r["src_ip"] for r in records}
    dst_ips = {r["dst_ip"] for r in records}
    tcp_records = [r for r in records if r["protocol"] == "TCP"]
    syn_records = [r for r in tcp_records if r["tcp_flag"] == "SYN"]
    failed = sum(1 for r in records if r.get("connection_failed"))
    port_counts = Counter(r["dst_port"] for r in records)

    # syn_rate is a RATIO (SYN packets / TCP packets), not a throughput --
    # see design doc §5.1's note on avoiding "SYN rate" as a label.
    syn_rate = (len(syn_records) / len(tcp_records)) if tcp_records else 0.0

    return {
        "packets_per_second": n / window_seconds,
        "bytes_per_second": total_bytes / window_seconds,
        "avg_packet_size": total_bytes / n,
        "unique_source_ips": len(src_ips),
        "unique_destination_ips": len(dst_ips),
        "syn_rate": round(syn_rate, 4),
        "failed_connections": failed,
        "connection_rate": len(syn_records) / window_seconds,
        "port_entropy": round(_shannon_entropy_bits(port_counts.values()), 4),
    }


def process_traffic(records, baseline=None, timestamp=None):
    """
    Required Module 1 entry point (design doc §5.1):

        window = process_traffic(raw_data)

    records:   list of flow-record dicts covering exactly one
               config.WINDOW_SECONDS window (see module docstring for
               the record shape).
    baseline:  optional AdaptiveBaseline instance. Defaults to a
               module-level singleton so repeated calls accumulate
               history automatically -- pass your own instance to run
               multiple independent streams (e.g. in tests) in the
               same process.
    timestamp: ISO-8601 string for this window; defaults to "now" (UTC).

    Returns the full §7.1 handoff contract:
        {"timestamp", "baseline_ready", "features", "anomalies"}
    """
    baseline = baseline if baseline is not None else _default_baseline
    features = extract_window_features(records)

    anomalies, baseline_ready = baseline.update(
        packets_per_second=features["packets_per_second"],
        bytes_per_second=features["bytes_per_second"],
        syn_rate=features["syn_rate"],
        unique_source_ips=features["unique_source_ips"],
        failed_connections=features["failed_connections"],
    )

    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    return {
        "timestamp": ts,
        "baseline_ready": baseline_ready,
        "features": features,
        "anomalies": anomalies,
    }
