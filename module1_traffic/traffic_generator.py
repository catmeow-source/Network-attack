"""
Synthetic traffic generator for Module 1 -- the demo dataset described
in the design doc as `traffic_generator.py`, on the critical path for
all four members (§9.2, due 00:50).

Produces a scripted NORMAL -> ANOMALY -> SCANNING -> ATTACK IMMINENT ->
DDoS arc (canonical stages, §3.2) as a sequence of raw flow records,
one list per WINDOW_SECONDS window -- ready to hand straight to
feature_extractor.process_traffic().

Synthetic data only (design doc §12): no real network is touched.
Deterministic for a given seed, so the demo replays identically every
run -- important once Module 4 scripts a fixed timeline around it.
"""

import random

from shared import config

VICTIM_IP = "10.0.42.5"
_LEGIT_DEST_POOL = [f"10.0.1.{i}" for i in range(1, 8)] + [VICTIM_IP]
_LEGIT_PORTS = [80, 443, 22, 53, 25, 3306, 8080, 21]
_ATTACK_PORT = 80

# One entry per canonical stage: (label, window_count, params at the
# END of that stage). Parameters ramp linearly from the previous
# stage's end value across a stage's windows, so the arc is gradual
# rather than a step function -- 20 windows total, matching the
# "15-20 windows for a full arc" figure in design doc §9.4.
#
# Deliberately paced so attacker_src and syn_ratio climb roughly evenly
# across all four attack stages rather than front-loading the jump in
# ANOMALY. An earlier, steeper version reached z > Z_CAP against the
# NORMAL-phase baseline by the last window of ANOMALY, saturating every
# channel at 1.0 for the remaining 60% of the arc -- visually flat,
# and contrary to the gradual-climb narrative in design doc §3.1.
#
# legit_dest_count: how many entries of _LEGIT_DEST_POOL (8 total,
# VICTIM_IP last) are reachable/observed in a window. Taking the pool's
# *last* N entries means VICTIM_IP is always included and the OTHER
# legit destinations drop off first as this shrinks -- modelling
# services other than the target becoming unreachable/unobserved under
# escalating load, so unique_destination_ips actually narrows toward
# the victim during the attack instead of staying flat at 8 throughout
# (an earlier version made no such claim true -- see module1_traffic/
# README.md and tests/test_module1.py for the discrepancy this fixes).
_STAGE_PLAN = [
    ("NORMAL",          5, dict(records=600,  legit_src=40, attacker_src=0,
                                 syn_ratio=0.50, fail_rate=0.004, avg_size=500,
                                 legit_dest_count=8)),
    ("ANOMALY",         4, dict(records=750,  legit_src=41, attacker_src=4,
                                 syn_ratio=0.56, fail_rate=0.010, avg_size=450,
                                 legit_dest_count=7)),
    ("SCANNING",        4, dict(records=950,  legit_src=42, attacker_src=10,
                                 syn_ratio=0.63, fail_rate=0.020, avg_size=380,
                                 legit_dest_count=5)),
    ("ATTACK IMMINENT", 4, dict(records=1400, legit_src=43, attacker_src=22,
                                 syn_ratio=0.74, fail_rate=0.045, avg_size=250,
                                 legit_dest_count=3)),
    ("DDoS",            3, dict(records=2800, legit_src=44, attacker_src=55,
                                 syn_ratio=0.92, fail_rate=0.15,  avg_size=64,
                                 legit_dest_count=1)),
]

_BASE_PARAMS = dict(records=550, legit_src=38, attacker_src=0,
                     syn_ratio=0.48, fail_rate=0.003, avg_size=520,
                     legit_dest_count=8)


def _lerp(a, b, t):
    return a + (b - a) * t


def _lerp_params(p0, p1, t):
    return {k: _lerp(p0[k], p1[k], t) for k in p0}


def _noisy_round(rng, target, rel_noise=0.12, floor=0):
    """Gaussian jitter around `target`, not just the ~8% multiplicative
    jitter applied to warm-up windows upstream. Without per-window
    noise here, record counts and source-IP pool sizes come out nearly
    deterministic, the baseline's learned std-dev stays tiny, and any
    real deviation reads as many standard deviations out -- every
    anomaly channel saturates to 1.0 within 2-3 windows of an attack
    starting instead of climbing gradually across the scripted arc."""
    if target <= 0:
        return floor
    value = rng.gauss(target, max(target * rel_noise, 1e-6))
    return max(floor, int(round(value)))


def _synthesize_window(rng, params):
    n = max(1, _noisy_round(rng, params["records"], rel_noise=0.15, floor=1))
    n_legit_src = max(1, _noisy_round(rng, params["legit_src"], rel_noise=0.10, floor=1))
    n_attacker_src = _noisy_round(rng, params["attacker_src"], rel_noise=0.15, floor=0)

    legit_srcs = [f"192.168.{rng.randint(0, 15)}.{i}" for i in range(n_legit_src)]
    attacker_srcs = [f"203.0.{rng.randint(0, 255)}.{i}" for i in range(n_attacker_src)]

    n_active_dests = max(1, min(len(_LEGIT_DEST_POOL), int(round(params["legit_dest_count"]))))
    active_legit_dests = _LEGIT_DEST_POOL[-n_active_dests:]  # keeps VICTIM_IP, drops others first

    denom = n_legit_src + n_attacker_src
    attacker_share = (n_attacker_src / denom) if denom else 0.0

    records = []
    for _ in range(n):
        is_attack_record = bool(attacker_srcs) and rng.random() < min(0.95, attacker_share + 0.25)

        if is_attack_record:
            src_ip = rng.choice(attacker_srcs)
            dst_ip = VICTIM_IP
            dst_port = _ATTACK_PORT
        else:
            src_ip = rng.choice(legit_srcs)
            dst_ip = rng.choice(active_legit_dests)
            dst_port = rng.choice(_LEGIT_PORTS)

        is_syn = rng.random() < params["syn_ratio"]
        tcp_flag = "SYN" if is_syn else rng.choice(["ACK", "SYN-ACK", "FIN"])
        connection_failed = rng.random() < params["fail_rate"]
        packet_size = max(40, int(rng.gauss(params["avg_size"], params["avg_size"] * 0.15)))

        records.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "tcp_flag": tcp_flag,
            "packet_size": packet_size,
            "connection_failed": connection_failed,
        })
    return records


def generate_demo_traffic(seed=42, warmup_windows=None):
    """Return [(stage_label, records), ...] for a full scripted
    NORMAL -> DDoS arc. Deterministic for a given seed.

    Note there is no `window_seconds` parameter: every _STAGE_PLAN
    "records" target is calibrated assuming a WINDOW_SECONDS-long
    window (e.g. 600 records implies ~10 pkt/s at 60s). An earlier
    version accepted window_seconds but silently ignored it -- ANY
    value produced the same record counts, so calling it with a
    different window length would have fed mismatched data straight
    into process_traffic(window_seconds=...), corrupting
    packets_per_second silently. Properly supporting a variable window
    would mean scaling every stage's targets proportionally, which
    isn't worth it for a synthetic demo generator; if that's ever
    needed, do it explicitly rather than resurrecting a dead parameter.

    Prepends `warmup_windows` quiet windows of plain background traffic
    ahead of the scripted arc (defaults to config.BASELINE_WARMUP_WINDOWS,
    resolved at call time -- not baked in as a parameter default, which
    would silently ignore a config change made after this module loads).
    Without this lead-in, AdaptiveBaseline's `baseline_ready` (design
    doc §5.1) would never flip true during a 20-window demo, since
    BASELINE_WARMUP_WINDOWS defaults to 30 -- the dashboard would sit
    on "BASELINE WARMING" for the entire demo. These lead-in windows
    are meant to be replayed fast / skipped visually (§9.4
    REPLAY_SPEED), not shown scene by scene.

    `stage_label` is the generator's *intended* stage -- useful for
    validating that Module 2's derived trajectory tracks it -- and is
    not part of any module's real output contract.
    """
    if warmup_windows is None:
        warmup_windows = config.BASELINE_WARMUP_WINDOWS

    rng = random.Random(seed)
    windows = []

    for _ in range(warmup_windows):
        # Same baseline traffic used to open the NORMAL stage, so
        # there's no discontinuity at the seam -- _synthesize_window's
        # own per-window noise (_noisy_round) is what gives this a
        # realistic spread, not an extra jitter layer here.
        windows.append(("NORMAL (warmup)", _synthesize_window(rng, _BASE_PARAMS)))

    prev_params = _BASE_PARAMS
    for stage_label, window_count, end_params in _STAGE_PLAN:
        for i in range(window_count):
            t = (i + 1) / window_count
            params = _lerp_params(prev_params, end_params, t)
            records = _synthesize_window(rng, params)
            windows.append((stage_label, records))
        prev_params = end_params
    return windows


if __name__ == "__main__":
    # python -m module1_traffic.traffic_generator
    for stage, records in generate_demo_traffic():
        print(f"{stage:16s}  records={len(records):5d}")
