"""
Canonical constants for the Predictive Cyber Defense prototype.

Every module MUST import these rather than hardcoding values — see
SIH26153_Predictive_Cyber_Defense_Design_Document.md §2.3.

Ownership note (design doc §9.2): this file is nominally Member 2's
00:20 deliverable. It's created here, ahead of that, purely so Module 1
has something real to import and run against instead of a stub. Member
2 should treat this as the starting point to extend, not overwrite —
in particular, do not change WINDOW_SECONDS or the four anomaly
weights below without re-deriving §2.4 of the design doc and updating
module1_traffic/baseline.py's freeze-indicator renormalization.
"""

# --- Windowing --------------------------------------------------------
WINDOW_SECONDS = 60

# --- Thresholds ---------------------------------------------------------
ESCALATION_THRESHOLD = 0.95
FORECAST_HORIZON_MINUTES = 5
BASELINE_WARMUP_WINDOWS = 30
BASELINE_FREEZE_THRESHOLD = 0.50

# --- Demo replay ---------------------------------------------------------
REPLAY_SPEED = 30  # data-minutes rendered per wall-minute during the demo

# --- Threat score weights (must sum to 1.0) -------------------------------
WEIGHT_SYN = 0.30
WEIGHT_TRAFFIC = 0.20
WEIGHT_SOURCE = 0.20
WEIGHT_CONNECTION = 0.20
WEIGHT_ACCELERATION = 0.10

THREAT_SCORE_WEIGHTS = {
    "syn": WEIGHT_SYN,
    "traffic": WEIGHT_TRAFFIC,
    "source": WEIGHT_SOURCE,
    "connection": WEIGHT_CONNECTION,
    "acceleration": WEIGHT_ACCELERATION,
}
_weight_total = sum(THREAT_SCORE_WEIGHTS.values())
if abs(_weight_total - 1.0) >= 1e-9:
    # A bare `assert` here would be silently stripped under `python -O`,
    # turning a guaranteed invariant into an unenforced one -- this
    # check needs to survive that.
    raise ValueError(
        f"threat score weights must sum to 1.0 (design doc §2.3), got {_weight_total}"
    )

# --- Mitigation parameters (§2.3) -----------------------------------------
MITIGATION = {
    "NO_ACTION":      {"immediate_reduction": 0.00, "momentum_damping": 0.00},
    "BLOCK_SOURCES":  {"immediate_reduction": 0.60, "momentum_damping": 0.90},
    "ISOLATE_SERVER": {"immediate_reduction": 0.70, "momentum_damping": 1.00},
}

# --- Canonical attack trajectory (§3.2) ------------------------------------
# The only permitted stage vocabulary anywhere in the system.
TRAJECTORY_STAGES = ["NORMAL", "ANOMALY", "SCANNING", "ATTACK IMMINENT", "DDoS"]
