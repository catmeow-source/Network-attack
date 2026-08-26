"""
Standalone demo runner for Module 1.

    python -m module1_traffic.run_demo

Generates the scripted NORMAL -> DDoS traffic arc (traffic_generator),
runs it through process_traffic() with a single shared AdaptiveBaseline
(so history actually accumulates), prints each window's anomaly scores
next to the generator's intended stage, and writes the full arc to
module1_traffic/data/demo_windows.json.

That JSON file is real Module 1 output -- Module 2 can develop against
it immediately instead of hand-written sample data (design doc §9.3).
"""

import json
import os
from datetime import datetime, timedelta, timezone

from shared import config

from .baseline import AdaptiveBaseline
from .feature_extractor import process_traffic
from .traffic_generator import generate_demo_traffic


def main():
    baseline = AdaptiveBaseline()
    start = datetime.now(timezone.utc)
    output = []

    for i, (stage_label, records) in enumerate(generate_demo_traffic()):
        ts = (start + timedelta(seconds=i * config.WINDOW_SECONDS)).strftime("%Y-%m-%dT%H:%M:%S")
        window = process_traffic(records, baseline=baseline, timestamp=ts)
        # Generator's intended stage, for eyeballing only -- NOT part of
        # the §7.1 contract. Module 2/3/4 must never read this key.
        window["_demo_stage"] = stage_label
        output.append(window)

        a, f_ = window["anomalies"], window["features"]
        print(
            f"[{i:2d}] {stage_label:16s} ready={str(window['baseline_ready']):5s} "
            f"syn={a['syn']:.2f} traffic={a['traffic']:.2f} "
            f"source={a['source']:.2f} conn={a['connection']:.2f} "
            f"| frozen={baseline.is_frozen} "
            f"| dst_ips={f_['unique_destination_ips']:2d} avg_pkt={f_['avg_packet_size']:6.1f}"
        )

    out_path = os.path.join(os.path.dirname(__file__), "data", "demo_windows.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\nWrote {len(output)} windows to {out_path}")


if __name__ == "__main__":
    main()
