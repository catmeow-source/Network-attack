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
| `tests/test_module1.py` | Regression tests for the real bugs found while building this (see below) — 15 tests, all passing. |

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

**Real bugs found by actually running this and re-reading it
adversarially, not by reading the design doc once and trusting it:**

1. **Freeze latched permanently during pure NORMAL traffic.** EWMA
   variance bootstraps from 0, so early on the learned std-dev is too
   small relative to real traffic jitter — ordinary noise read as many
   standard deviations out, latching the freeze within the first few
   windows and never releasing. Fixed: freeze never engages during the
   first `BASELINE_WARMUP_WINDOWS`, regardless of indicator value.
2. **`baseline_ready` could never flip `true` during the scripted
   demo.** `BASELINE_WARMUP_WINDOWS` (30) is longer than the original
   20-window demo arc. Fixed: the generator prepends 30 quiet lead-in
   windows (meant to be replayed fast / skipped visually) ahead of the
   scripted arc.
3. **The escalation ramp was too front-loaded.** Every anomaly channel
   saturated to 1.0 within 2-3 windows of the attack starting and then
   sat flat for the rest of the arc — the dashboard would look frozen,
   not escalating. Fixed by re-pacing `_STAGE_PLAN` so `attacker_src`
   and `syn_ratio` climb roughly evenly across all four attack stages.
4. **`z_score()` divided by an exact-zero variance** for a channel
   with a perfectly flat history, silently returning 0 (never
   anomalous) instead of detecting the spike — a plausible real case
   (a quiet segment, or the first few windows before jitter
   accumulates), not just a test artifact. Fixed with a variance floor.
5. **Two early-binding-of-default-arguments bugs**, the same Python
   footgun caught twice: `extract_window_features`'s and (until this
   pass) `generate_demo_traffic`'s parameter defaults referenced
   `config.*` values at *import* time, so changing the config after
   the module loaded would be silently ignored. Fixed by resolving
   both against `config` inside the function body at call time.
6. **`generate_demo_traffic(window_seconds=...)` was a dead
   parameter** — accepted but never read. `_STAGE_PLAN`'s record
   counts are calibrated for a `WINDOW_SECONDS`-long window; passing a
   different value produced identical output while implying it had an
   effect, which would have silently corrupted `packets_per_second`
   for anyone who used it together with `process_traffic(window_seconds=...)`.
   Removed rather than wired up — see the docstring for why supporting
   it properly isn't worth it here.
7. **The module-level default `AdaptiveBaseline` had no reset hook.**
   It's deliberate process-lifetime global state (needed so
   `process_traffic(records)` works with the single-argument signature
   the design doc requires), but nothing guarded test isolation
   against it. No test here hits it — every call site passes its own
   `baseline=` — but the first one that doesn't would silently inherit
   history from earlier calls in the same run. Added
   `reset_default_baseline()`.
8. **Independent field-level rounding broke an exact invariant.**
   Rounding `packets_per_second`, `bytes_per_second`, and
   `avg_packet_size` separately (for readable JSON output) meant
   `avg_packet_size` no longer exactly equalled
   `bytes_per_second / packets_per_second` — up to ~0.5% off in
   testing, breaking the invariant design doc §5.1 explicitly asks to
   be asserted in code. Fixed by deriving `avg_packet_size` from the
   already-rounded `pps`/`bps` instead of independently from raw
   totals, so the relationship holds by construction, not coincidence.
9. **This README's own claim about `unique_destination_ips` was
   false.** It said destination-IP diversity "collapses toward one
   host, corroborating a targeted flood" — but the generator's legit
   background traffic kept spanning the full 8-host destination pool
   throughout, so the feature sat flat at 8 for the entire arc
   regardless of attack severity, contradicting the module's own
   documentation. Fixed by shrinking the pool of *reachable* legit
   destinations as attack severity rises (`legit_dest_count` in
   `_STAGE_PLAN`); it now runs 8 -> 1 across the arc.
10. **The 5-consecutive-quiet-window unfreeze branch had zero test
    coverage.** The scripted demo only ever escalates, so that code
    path had never actually executed under test — a bug there (e.g.
    an off-by-one on the threshold) could have shipped silently.
    Added `test_unfreezes_after_five_consecutive_quiet_windows` and
    `test_quiet_streak_resets_on_renewed_spike`.

## What's deliberately out of scope here

`avg_packet_size`, `unique_destination_ips`, and `port_entropy` are
computed and included in `features`, but do **not** feed any anomaly
channel — they're corroborating evidence (small packets support a SYN
flood read; collapsing destination IPs support a targeted flood; port
entropy would be the primary signal for a port-scan model, which isn't
built in this prototype). See design doc §5.1, "Which features feed
the score."
