# Module 1 --- Traffic Intelligence

Owner: Member 1 (Network/Data Engineer). Converts raw flow records into
the normalized feature + anomaly contract that Module 2 consumes. See
[`SIH26153_Predictive_Cyber_Defense_Design_Document.md`](../SIH26153_Predictive_Cyber_Defense_Design_Document.md)
§5.1 and §7.1 for the full spec this implements.

## Run it

```bash
# From the repository root, so `shared` and `module1_traffic` resolve
# as siblings on the import path.
python -m module1_traffic.run_demo
```

This generates the scripted NORMAL → DDoS traffic arc, runs it through
`process_traffic()` with one shared `AdaptiveBaseline`, prints each
window's anomaly scores, and writes the full run to
[`data/demo_windows.json`](data/demo_windows.json) — real Module 1
output Module 2 can develop against immediately.

```bash
python -m unittest module1_traffic.tests.test_module1 -v
```

## Files

| File | Purpose |
|---|---|
| `feature_extractor.py` | `process_traffic(records)` — the required entry point. Aggregates one window of flow records into the 9-feature contract, then scores it against the baseline. |
| `baseline.py` | `AdaptiveBaseline` — stateful EWMA baseline per channel, with warm-up and freeze logic. |
| `traffic_generator.py` | `generate_demo_traffic()` — deterministic synthetic NORMAL→DDoS arc (design doc §12: synthetic only, never touches a real network). |
| `run_demo.py` | Wires the above together; the fastest way to see the module actually work. |
| `tests/test_module1.py` | Regression tests for the two real bugs found while building this (see below). |

## Raw input format

`process_traffic()` expects a list of flow-record dicts, one per
packet/flow, all falling within a single `WINDOW_SECONDS` (60s) window:

```python
{
    "src_ip": "192.168.1.4",
    "dst_ip": "10.0.42.5",
    "dst_port": 80,
    "protocol": "TCP",              # or "UDP"
    "tcp_flag": "SYN",              # SYN | SYN-ACK | ACK | RST | FIN | None
    "packet_size": 64,               # bytes
    "connection_failed": False,      # RST/timeout on a tracked connection
}
```

This shape isn't mandated by the design doc — it's what this
prototype's generator (and any real PCAP/NetFlow ingester swapped in
later) must produce.

## Design decisions worth knowing about

**The baseline-freeze rule doesn't depend on Module 2.** The design
doc's freeze rule is keyed on `threat_score`, which is Module 2's
output — but Module 1 has to run standalone. `AdaptiveBaseline`
freezes against a local composite indicator computed from its own four
anomaly channels (same weights Module 2 uses, renormalized since we
have no `temporal_acceleration` term). It's an internal approximation,
never published on the output contract.

**`temporal_acceleration` is not computed here.** It's history-derived
and owned by Module 2. Module 1's output has exactly four anomaly
channels: `traffic`, `syn`, `source`, `connection`.

**Two bugs found by actually running this, not by reading the design
doc:**

1. EWMA variance bootstraps from 0, so early on the learned std-dev is
   too small relative to real traffic jitter — ordinary noise reads as
   many standard deviations out, and without a warm-up exemption the
   freeze mechanism latches permanently within the first few windows
   of pure *NORMAL* traffic. Fixed: freeze never engages during the
   first `BASELINE_WARMUP_WINDOWS`, regardless of indicator value.
2. `BASELINE_WARMUP_WINDOWS` (30) is longer than the original 20-window
   demo arc, so `baseline_ready` would never flip `true` on-screen.
   Fixed: the generator prepends 30 quiet lead-in windows (meant to be
   replayed fast / skipped visually) ahead of the scripted arc.

A third, non-bug finding: the first version of the escalation ramp was
too front-loaded — every anomaly channel saturated to 1.0 within 2-3
windows of the attack starting and then sat flat for the rest of the
arc, which would make the dashboard look frozen rather than
escalating. The `_STAGE_PLAN` parameters in `traffic_generator.py` are
tuned so `attacker_src` and `syn_ratio` climb roughly evenly across
all four attack stages instead.

## What's deliberately out of scope here

`avg_packet_size`, `unique_destination_ips`, and `port_entropy` are
computed and included in `features`, but do **not** feed any anomaly
channel — they're corroborating evidence (small packets support a SYN
flood read; collapsing destination IPs support a targeted flood; port
entropy would be the primary signal for a port-scan model, which isn't
built in this prototype). See design doc §5.1, "Which features feed
the score."
