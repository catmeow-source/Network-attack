---
organization: NTRO
problem_statement: AI based Network Attack Forecasting from Network
  Traffic Data
prototype_window: 5 hours
status: Prototype / SIH 2026
team_size: 4
title: SIH26153 --- Predictive Cyber Defense Prototype Design Document
version: 2.0
---

# 1. Executive Summary

## 1.1 Problem

**SIH26153 --- AI based Network Attack Forecasting from Network Traffic
Data** asks for an AI-driven approach to forecasting network attacks
from network traffic data.

The prototype deliberately goes beyond conventional intrusion detection.

### Core proposition

> **Observe → Detect trajectory → Forecast attack → Simulate futures → Recommend intervention → Re-forecast**

The system should not merely say:

> "An attack is happening."

It should answer:

> "The network is moving toward a likely attack, this is the expected
> attack stage, this is the estimated time to escalation, these traffic
> changes explain the forecast, and these defensive actions are
> predicted to reduce future risk."

## 1.2 How to read this document

Every numeric example in this document is **derived, not asserted**.
The canonical constants live in §2.3 and the worked end-to-end example
in §2.4. If you change a constant, recompute §2.4 and propagate — do
not hand-edit numbers in the demo script.

------------------------------------------------------------------------

# 2. Prototype Goals, Scope and Canonical Constants

## 2.1 Primary goals

1.  Process network-flow/time-series data.
2.  Establish an adaptive baseline for normal network behavior.
3.  Calculate anomaly and threat scores.
4.  Forecast attack stage progression, and rank attack families by
    likelihood (see the scope caveat in §2.2).
5.  Estimate threat momentum and time-to-escalation.
6.  Simulate alternative future outcomes.
7.  Recommend the intervention with the highest projected risk
    reduction.
8.  Present the result through an investigator/SOC-style dashboard.

## 2.2 Prototype scope

For the 5-hour build, the prototype models **one attack family end to
end: DDoS/SYN-flood-style escalation**.

Goal 4 above is deliberately worded as "rank attack families" rather
than "forecast attack type": only DDoS has a real model behind it in
the prototype window. The other families are emitted as placeholder
likelihoods so the schema and dashboard are already shaped for them
(§5.2, §6.4). **Do not claim four modelled attack types in the
demo** — claim one modelled family plus an extensible slot for more.

## 2.3 Canonical constants

These are the single source of truth. `shared/config.py` must contain
exactly these values and every module must import them rather than
hardcoding.

| Constant | Value | Meaning |
|---|---|---|
| `WINDOW_SECONDS` | `60` | Feature window size (fixed 1 minute) |
| `ESCALATION_THRESHOLD` | `0.95` | Threat score defining "escalated" |
| `FORECAST_HORIZON_MINUTES` | `5` | Counterfactual projection horizon |
| `BASELINE_WARMUP_WINDOWS` | `30` | Windows before scores are trusted |
| `BASELINE_FREEZE_THRESHOLD` | `0.50` | Threat score above which the baseline stops adapting (§5.1) |
| `REPLAY_SPEED` | `30` | Data-minutes per wall-minute during demo (§9.4) |

### Threat score weights

Must sum to `1.0`:

| Weight | Component | Value |
|---|---|---|
| `w_syn` | SYN anomaly | `0.30` |
| `w_traffic` | Traffic-volume anomaly | `0.20` |
| `w_source` | Source-diversity anomaly | `0.20` |
| `w_connection` | Connection-failure anomaly | `0.20` |
| `w_accel` | Temporal acceleration | `0.10` |

### Mitigation parameters

Each action has an **immediate risk reduction** (exposure removed now)
and a **momentum damping** (escalation rate slowed). Both are required:
damping alone can never lower risk below its current value, because the
projection in §7.2 is monotonically increasing in `t`.

| Action | Immediate reduction `r` | Momentum damping `d` |
|---|---|---|
| `NO_ACTION` | `0.00` | `0.00` |
| `BLOCK_SOURCES` | `0.60` | `0.90` |
| `ISOLATE_SERVER` | `0.70` | `1.00` |

These are **assumed effectiveness values, not measured ones.** See §13.

## 2.4 Worked end-to-end example

This is the demo's peak window. Every number elsewhere in this document
traces back to here.

``` text
Module 1 anomalies:
  syn 0.94   traffic 0.86   source 0.80   connection 0.88
Module 2 derives:
  temporal_acceleration 0.80

Threat score
  = 0.30(0.94) + 0.20(0.86) + 0.20(0.80) + 0.20(0.88) + 0.10(0.80)
  = 0.282 + 0.172 + 0.160 + 0.176 + 0.080
  = 0.870                                            → 0.87

Threat momentum (delta vs previous 1-min window)
  = 0.87 - 0.69 = 0.18                               → +18 pts/min

Time to escalation (threshold 0.95)
  t = -ln((1-0.95)/(1-0.87)) / 0.18
    = -ln(0.3846) / 0.18  =  0.9555 / 0.18
    = 5.31 min                                       → ~5 min

Counterfactual projections at t = 5 min
  NO_ACTION      R0'=0.87  m'=0.180 → 1-(0.13)e^-0.900 = 0.947  → 0.95
  BLOCK_SOURCES  R0'=0.348 m'=0.018 → 1-(0.652)e^-0.090 = 0.404 → 0.40
  ISOLATE_SERVER R0'=0.261 m'=0.000 →                     0.261 → 0.26

Risk reduction (best action vs NO_ACTION at same horizon)
  = (0.947 - 0.261) / 0.947
  = 0.724                                            → 72%
```

Note the internal consistency check: no-action risk at the 5-minute
horizon (`0.947`) sits just below `ESCALATION_THRESHOLD` (`0.95`),
which agrees with the independently computed time-to-escalation of
5.31 minutes. If you change a constant and these two stop agreeing,
you have a bug.

------------------------------------------------------------------------

# 3. Novelty

The prototype's novelty should be positioned as a **predictive
cyber-defense workflow**, not as a claim that AI-based intrusion
detection itself is new.

## 3.1 Threat Momentum

Measure not only the current threat score, but the **rate at which the
threat is increasing**.

The threat score is stored internally as a normalized float in
`[0.0, 1.0]` and displayed as a percentage (`0.87 → "87%"`). Momentum
is the score delta between two consecutive windows; because
`WINDOW_SECONDS = 60`, the delta *is* the per-minute rate with no
division step.

Example (dashboard-scale values, i.e. ×100 — deltas 12, 15, 18):

``` text
Threat score:
42 → 54 → 69 → 87

Threat momentum:
+18 points/minute
```

## 3.2 Attack Trajectory

Represent the network as progressing through states. This is the
**canonical 5-state list** — it is the only permitted vocabulary for
stages anywhere in the system (Module 2 output, dashboard, demo
script, header status).

``` text
NORMAL
  ↓
ANOMALY
  ↓
SCANNING
  ↓
ATTACK IMMINENT
  ↓
DDoS
```

The system predicts the likely next state rather than only classifying
the current state. Transitions are single-step: `next_stage` is always
the immediate successor of `current_stage`.

## 3.3 Time-to-Escalation

Estimate how soon the network may cross `ESCALATION_THRESHOLD`.

Inverting the projection in §7.2:

``` text
t_escalation = -ln( (1 - THRESHOLD) / (1 - current_score) ) / momentum
```

Reported with an uncertainty band derived from momentum spread over the
last 3 windows (§5.2), not as a bare point estimate:

``` text
Threat score: 87%
Estimated escalation: ~5 min  (band 4-6 min)
```

If `momentum <= 0`, escalation time is undefined — emit `null` and have
the dashboard render "not escalating", never a negative or infinite
number.

## 3.4 Counterfactual Future Simulation

Compare possible futures at the 5-minute horizon:

``` text
                    CURRENT STATE
                         │
          ┌──────────────┼──────────────┐
          │              │              │
       No action    Block sources   Isolate server
          │              │              │
       Risk 95%        Risk 40%        Risk 26%
```

The system recommends the action with the greatest projected risk
reduction.

## 3.5 Explainable Forecasting

Every forecast carries an evidence panel. Crucially, it separates two
different things that are easy to conflate:

-   **Observed change** — how far a feature moved from its baseline.
-   **Contribution** — how much that feature actually drove the score,
    i.e. `weight × anomaly` as a share of the total.

A feature can move a lot and contribute little (low weight), or move
modestly and dominate (high weight). Showing only the first while
captioning it "why the forecast changed" would be misleading.

``` text
Feature              Observed change   Contribution
SYN ratio                    +68%          32.4%
Failed connections           +72%          20.2%
Traffic volume               +61%          19.8%
Unique source IPs            +54%          18.4%
Traffic acceleration         +49%           9.2%
```

Contributions are computed from §2.4 and sum to 100%.

------------------------------------------------------------------------

# 4. System Architecture

``` text
                    NETWORK TRAFFIC
                          │
                          ▼
              ┌────────────────────────┐
              │ MODULE 1               │
              │ Traffic Intelligence   │
              │ + Feature Engineering  │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ MODULE 2               │
              │ Threat Forecasting     │
              │ + Attack Trajectory    │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ MODULE 3               │
              │ Future Simulator       │
              │ + Counterfactual AI    │
              └────────────┬───────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ MODULE 4               │
              │ SOC Dashboard          │
              │ + Explainability       │
              └────────────────────────┘
```

`run_pipeline.py` at the repository root wires these four together and
is the only entry point the demo uses (§8, owned per §9.2).

------------------------------------------------------------------------

# 5. Four-Team-Member Module Plan

Each module is an equal-weight subsection owned by one member. Every
module must run standalone against `shared/sample_data.json` without
any other module being finished (see §7).

## 5.1 Module 1 --- Traffic Intelligence

### Owner

**Member 1 --- Network/Data Engineer**

### Responsibility

Convert raw/replayed traffic into normalized time-window features and
anomaly indicators, **and produce the demo dataset**.

### Input

-   PCAP-derived flow data
-   NetFlow-like CSV
-   Synthetic/replayed traffic

### Core features

All eight features below appear in the output contract. `timestamp` is
top-level, not inside `features`.

| Feature | Units | Range |
|---|---|---|
| `packets_per_second` | packets/s | ≥ 0 |
| `bytes_per_second` | bytes/s | ≥ 0 |
| `avg_packet_size` | bytes | ≥ 0 |
| `unique_source_ips` | count/window | ≥ 0 |
| `unique_destination_ips` | count/window | ≥ 0 |
| `syn_rate` | **ratio** SYN ÷ total TCP packets | `[0,1]` |
| `failed_connections` | count/window | ≥ 0 |
| `connection_rate` | connections/s | ≥ 0 |
| `port_entropy` | Shannon bits over destination ports | ≥ 0 |

`syn_rate` is a **ratio, not a per-second count** — this was ambiguous
in earlier drafts. The dashboard must label it "SYN ratio", not
"SYN rate", to avoid implying a throughput.

Invariant worth asserting in code:
`avg_packet_size ≈ bytes_per_second / packets_per_second`.

### Which features feed the score

Only four anomaly channels feed the threat score (§2.3). The remaining
features are deliberately **corroborating evidence**, displayed but
unweighted:

-   `avg_packet_size` — small packets corroborate SYN flood
-   `unique_destination_ips` — collapsing to one host corroborates a
    targeted flood
-   `port_entropy` — the primary signal for *port scan*, a family not
    modelled in v1 (§2.2)

If a judge asks why they are computed, that is the answer. Do not
silently drop them, and do not pretend they are scored.

### Processing

Window size is fixed at `WINDOW_SECONDS = 60`. Changing it changes the
units of momentum everywhere it is displayed.

``` text
Raw Traffic
    ↓
Flow Extraction
    ↓
Time Windows (fixed 60 s)
    ↓
Feature Extraction
    ↓
Adaptive Baseline  ──  warmup + freeze rules below
    ↓
Anomaly Scores
```

### Adaptive baseline: warm-up and freeze

A naively adaptive baseline **defeats the entire premise of this
project**: during a slow ramp it learns the attack as normal, anomaly
scores stay flat, and nothing is forecast. Two rules prevent this.

1.  **Warm-up.** For the first `BASELINE_WARMUP_WINDOWS` (30) windows,
    emit anomaly scores but flag `baseline_ready: false`. The dashboard
    shows a `BASELINE WARMING` state and suppresses forecasts.
2.  **Freeze.** Once the threat score exceeds
    `BASELINE_FREEZE_THRESHOLD` (0.50), stop updating the baseline.
    Resume adapting only after it falls back below for 5 consecutive
    windows. The baseline must never learn from a window it considers
    anomalous.

Use an EWMA (`alpha ≈ 0.05`) over frozen-eligible windows; anomaly
score per channel is a clamped z-score against that baseline.

### Output contract

``` json
{
  "timestamp": "2026-08-26T19:05:00",
  "baseline_ready": true,
  "features": {
    "packets_per_second": 1840,
    "bytes_per_second": 283360,
    "avg_packet_size": 154,
    "unique_source_ips": 73,
    "unique_destination_ips": 8,
    "syn_rate": 0.82,
    "failed_connections": 143,
    "connection_rate": 912,
    "port_entropy": 4.72
  },
  "anomalies": {
    "traffic": 0.86,
    "syn": 0.94,
    "source": 0.80,
    "connection": 0.88
  }
}
```

Module 1 emits **exactly these four anomaly channels**. It does *not*
emit `temporal_acceleration` — that is history-derived and owned by
Module 2 (§5.2). This ownership split was previously undefined and is
the most likely source of a "we each thought the other was doing it"
integration failure.

### Deliverables

``` text
module1_traffic/
├── __init__.py
├── feature_extractor.py
├── baseline.py
├── traffic_generator.py     # demo dataset - build FIRST
├── data/
└── README.md
```

`traffic_generator.py` is on the critical path for all four members: it
produces the scripted NORMAL → DDoS replay every demo scene depends on.
Ship a crude version by 00:50, refine later.

### Required function

``` python
window = process_traffic(raw_data)   # -> full contract dict above
```

## 5.2 Module 2 --- Threat Forecasting

### Owner

**Member 2 --- ML/Forecasting Engineer**

### Responsibility

Turn the time-series of Module 1 windows into threat forecasts and
attack trajectories. Owns **all history-derived quantities**: momentum,
temporal acceleration, and the momentum band.

### Input

Module 1 output, plus its own retained history.

### Why this module is stateful

Momentum is `current_score − previous_score`, so a stateless
`predict(features)` **cannot compute it**. The required interface is a
stateful predictor, not a pure function:

``` python
predictor = ThreatPredictor()          # retains window history
forecast  = predictor.update(window)   # -> forecast dict
```

`temporal_acceleration` is the normalized second derivative — the
change in momentum across the last three windows, clamped to `[0,1]`.
The momentum band used for the time-to-escalation range in §3.3 is the
min/max momentum over those same three windows.

### Outputs

-   threat score, threat momentum
-   per-family attack likelihoods
-   current and next attack stage
-   time-to-escalation, with band

### Example output

`attack_probabilities` are **independent per-family likelihoods, not a
probability distribution** — they are not expected to sum to 1 (these
sum to 1.64). Do not "fix" this by normalizing. Only `DDoS` is
model-backed in the prototype; the rest are placeholders (§2.2).

`current_stage`/`next_stage` are adjacent values from the canonical
list in §3.2 — `SCANNING`'s successor is `ATTACK IMMINENT`, never
`DDoS`.

``` json
{
  "timestamp": "2026-08-26T19:05:00",
  "threat_score": 0.87,
  "threat_momentum": 0.18,
  "momentum_band": [0.15, 0.22],
  "temporal_acceleration": 0.80,
  "predicted_attack": "DDoS",
  "attack_probability": 0.87,
  "attack_probabilities": {
    "DDoS": 0.87,
    "CREDENTIAL_ATTACK": 0.42,
    "PORT_SCAN": 0.23,
    "EXFILTRATION": 0.12
  },
  "current_stage": "SCANNING",
  "next_stage": "ATTACK IMMINENT",
  "time_to_escalation_minutes": 5,
  "time_to_escalation_band": [4, 6],
  "contributions": {
    "syn": 0.324,
    "connection": 0.202,
    "traffic": 0.198,
    "source": 0.184,
    "acceleration": 0.092
  }
}
```

`contributions` is what makes §3.5's explainability panel honest — it
is computed here, not reverse-engineered in the dashboard.

### Recommended prototype approach

Use a hybrid approach rather than spending the window training a deep
model.

**Baseline:** rolling-window features, anomaly scores, temporal
acceleration, threshold/state transitions.

**Optional ML:** XGBoost, Random Forest, LightGBM; LSTM/GRU only if an
already-trained model exists.

### Core calculations

#### Threat score

Weights are fixed in §2.3 and sum to 1. Anomaly channels are already
clamped to `[0,1]`, so a weighted mean is automatically in range — the
clamp below is a defensive assertion, not load-bearing.

``` text
Threat Score = clamp(
    0.30 * syn_anomaly
  + 0.20 * traffic_anomaly
  + 0.20 * source_anomaly
  + 0.20 * connection_anomaly
  + 0.10 * temporal_acceleration
, 0, 1)
```

Worked instance in §2.4 → `0.870`.

#### Threat momentum

``` text
Threat Momentum = current threat score - previous threat score
```

Between consecutive 60-second windows, so directly readable as
points/minute.

#### Trajectory

Stage is assigned by threat-score band, with hysteresis (a stage must
hold for 2 windows before promoting) to stop the dashboard flickering
between states during the demo:

| Stage | Threat score |
|---|---|
| `NORMAL` | `< 0.20` |
| `ANOMALY` | `0.20 – 0.45` |
| `SCANNING` | `0.45 – 0.70` |
| `ATTACK IMMINENT` | `0.70 – 0.95` |
| `DDoS` | `≥ 0.95` |

At `0.87` the demo sits in `ATTACK IMMINENT` by score band. The
worked example reports `SCANNING` because hysteresis has not yet
promoted it — **keep this consistent in `sample_data.json`**, and if
you prefer the simpler story, drop hysteresis and let stage follow the
band directly.

### Deliverables

``` text
module2_forecast/
├── __init__.py
├── model.py
├── trajectory.py
├── predictor.py
└── README.md
```

### Required interface

``` python
predictor = ThreatPredictor()
forecast  = predictor.update(window)
```

## 5.3 Module 3 --- Counterfactual Future Simulator

### Owner

**Member 3 --- Simulation/Decision Intelligence Engineer**

### Responsibility

Project future threat states under each candidate defensive action.

### Input

Module 2 forecast.

### Output

Future risk per action, projected reduction, recommended intervention.

### Example

``` json
{
  "timestamp": "2026-08-26T19:05:00",
  "current_risk": 0.87,
  "horizon_minutes": 5,
  "scenarios": [
    { "action": "NO_ACTION",      "risk_at_horizon": 0.95 },
    { "action": "BLOCK_SOURCES",  "risk_at_horizon": 0.40 },
    { "action": "ISOLATE_SERVER", "risk_at_horizon": 0.26 }
  ],
  "recommended_action": "ISOLATE_SERVER",
  "risk_reduction": 0.72,
  "risk_reduction_basis": "vs NO_ACTION at same horizon"
}
```

`risk_reduction_basis` is mandatory. Reduction measured against
*current risk* and against the *no-action baseline* give different
numbers (72.4% vs 70.0% here), and earlier drafts quoted a figure that
matched neither. Fix one basis and label it.

### Prototype implementation

Do not build a network simulator. Use a **saturating risk projection**:

``` text
future_risk(t) = 1 - (1 - R0') * exp(-m' * t)

  R0' = current_risk * (1 - immediate_reduction)
  m'  = momentum     * (1 - momentum_damping)
```

Why saturating rather than linear: linear extrapolation
(`R0 + m·t`) of a bounded probability blows past 1.0 almost
immediately — at the demo's own values it reaches `0.87 + 0.18×5 =
1.77`. Clamping hides that but leaves every projection pinned at 100%,
destroying the comparison between actions. The exponential form
approaches 1.0 asymptotically and **never requires a clamp**.

Why mitigation needs both terms: the projection is monotonically
increasing in `t`, so damping momentum alone can never produce a risk
*below* `current_risk`. Blocking sources must also remove present
exposure. Parameters are in §2.3; worked results in §2.4.

``` python
def project(current_risk, momentum, t, immediate_reduction, damping):
    r0 = current_risk * (1.0 - immediate_reduction)
    m  = momentum * (1.0 - damping)
    return 1.0 - (1.0 - r0) * math.exp(-m * t)
```

This is a **prototype counterfactual model with assumed mitigation
effectiveness**, not a production causal simulator, and not a validated
one — see §13.

### Deliverables

``` text
module3_simulator/
├── __init__.py
├── simulator.py
├── counterfactual.py
└── README.md
```

### Required functions

Two functions, not one — the per-action projection and the ranked
comparison are different shapes:

``` python
scenario   = simulate_action(forecast, action)  # -> one scenario dict
simulation = simulate_all(forecast)             # -> full contract above
```

## 5.4 Module 4 --- SOC Dashboard

### Owner

**Member 4 --- Product/UI Engineer**

### Responsibility

Visual interface, explainability rendering, and `run_pipeline.py`.

### Important development rule

Build against **mock JSON immediately**, using the exact §7 schemas so
integration needs no rework.

### Recommended prototype stack

**Streamlit + Python.**

**Streamlit replay trap — read before coding.** Streamlit re-runs the
whole script on every interaction, so a `while` loop that walks the
replay will block the UI and never render intermediate frames. Advance
**one window per rerun**, holding position in `st.session_state`, and
drive it with `st.autorefresh`:

``` python
if "idx" not in st.session_state:
    st.session_state.idx = 0
st_autorefresh(interval=2000, key="tick")
window = replay[st.session_state.idx]
st.session_state.idx = min(st.session_state.idx + 1, len(replay) - 1)
```

Budget 10 minutes for this pattern up front rather than an hour of
debugging at 03:00.

### Deliverables

``` text
module4_dashboard/
├── __init__.py
├── app.py
├── components/
└── README.md
```

------------------------------------------------------------------------

# 6. Dashboard Design

## 6.1 Header

Status text is **derived from `current_stage`**, never set
independently — it is a rendering of the canonical 5 states, not a
sixth vocabulary:

| Stage | Header status |
|---|---|
| `NORMAL` | 🟢 NORMAL |
| `ANOMALY` | 🟡 ANOMALY DETECTED |
| `SCANNING` | 🟠 THREAT ESCALATING |
| `ATTACK IMMINENT` | 🔴 ATTACK IMMINENT |
| `DDoS` | 🔥 ATTACK IN PROGRESS |
| *(warm-up)* | ⚪ BASELINE WARMING |

``` text
🛡️ PREDICTIVE CYBER DEFENSE

NETWORK STATUS: 🟠 THREAT ESCALATING
```

## 6.2 Threat summary

``` text
THREAT SCORE        87%
THREAT MOMENTUM     +18/min
TIME TO ESCALATION  ~5 min  (4-6)
```

Always render the band. A bare point estimate overstates the precision
of a 5-hour forecasting model.

## 6.3 Live traffic

Time-series charts for: packets/sec, bytes/sec, connection rate, and
**SYN ratio** (a `[0,1]` ratio — plot on its own axis, not alongside
per-second counts).

## 6.4 Attack forecast

Bound to Module 2's `attack_probabilities`. Only the DDoS bar is
model-backed; mark the others as prototype placeholders in the UI so
the demo does not imply four trained models.

``` text
DDoS                 87%   ← modelled
Credential Attack    42%   ← placeholder
Port Scan            23%   ← placeholder
Exfiltration         12%   ← placeholder
```

## 6.5 Attack trajectory

``` text
🟢 NORMAL
   ↓
🟡 ANOMALY
   ↓
🟠 SCANNING
   ↓
🔴 ATTACK IMMINENT
   ↓
🔥 DDoS
```

## 6.6 Explainability

Renders `contributions` from Module 2 beside observed deltas (§3.5):

``` text
WHY THE FORECAST CHANGED

                       observed   contribution
SYN ratio                 ↑ 68%          32.4%
Failed connections        ↑ 72%          20.2%
Traffic volume            ↑ 61%          19.8%
Unique sources            ↑ 54%          18.4%
Traffic acceleration      ↑ 49%           9.2%
```

## 6.7 Counterfactual simulator

``` text
FUTURE SIMULATION  (5-minute horizon)

No action          95% risk
Block sources      40% risk
Isolate server     26% risk

Recommended:
ISOLATE SERVER

Projected risk reduction:
72%  (vs no action)

⚠ Advisory only - no action is executed by this system.
```

------------------------------------------------------------------------

# 7. Integration Contract

Field names below are the **single source of truth**. The most common
integration failure in a time-boxed build is a renamed key, so
`shared/schemas.py` must validate every handoff at runtime.

## 7.1 Module 1 → Module 2

``` json
{
  "timestamp": "...",
  "baseline_ready": true,
  "features": {},
  "anomalies": { "traffic": 0.0, "syn": 0.0, "source": 0.0, "connection": 0.0 }
}
```

## 7.2 Module 2 → Module 3

``` json
{
  "timestamp": "...",
  "threat_score": 0.87,
  "threat_momentum": 0.18,
  "momentum_band": [0.15, 0.22],
  "temporal_acceleration": 0.80,
  "predicted_attack": "DDoS",
  "attack_probability": 0.87,
  "attack_probabilities": {},
  "current_stage": "SCANNING",
  "next_stage": "ATTACK IMMINENT",
  "time_to_escalation_minutes": 5,
  "time_to_escalation_band": [4, 6],
  "contributions": {}
}
```

## 7.3 Module 3 → Module 4

``` json
{
  "timestamp": "...",
  "current_risk": 0.87,
  "horizon_minutes": 5,
  "scenarios": [],
  "recommended_action": "ISOLATE_SERVER",
  "risk_reduction": 0.72,
  "risk_reduction_basis": "vs NO_ACTION at same horizon"
}
```

------------------------------------------------------------------------

# 8. Repository Structure

Package directories use **underscores**. Hyphenated names such as
`module1-traffic` are not valid Python identifiers —
`import module1-traffic.feature_extractor` is a *syntax error*, not a
lookup failure, and would surface exactly at the 02:30 integration.

``` text
predictive-cyber-defense/          # repo name may keep hyphens
│
├── module1_traffic/
│   ├── __init__.py
│   ├── feature_extractor.py
│   ├── baseline.py
│   ├── traffic_generator.py
│   ├── data/
│   └── README.md
│
├── module2_forecast/
│   ├── __init__.py
│   ├── model.py
│   ├── trajectory.py
│   ├── predictor.py
│   └── README.md
│
├── module3_simulator/
│   ├── __init__.py
│   ├── simulator.py
│   ├── counterfactual.py
│   └── README.md
│
├── module4_dashboard/
│   ├── __init__.py
│   ├── app.py
│   ├── components/
│   └── README.md
│
├── shared/
│   ├── __init__.py
│   ├── config.py          # the constants in §2.3
│   ├── schemas.py         # validates every handoff
│   └── sample_data.json
│
├── run_pipeline.py        # 1 → 2 → 3 → 4, the only demo entry point
├── requirements.txt
└── README.md
```

Run everything from the repository root so imports resolve without
`sys.path` surgery.

------------------------------------------------------------------------

# 9. Five-Hour Execution Plan

## 9.1 00:00–00:20 — Team synchronization

Agree and **freeze**: the DDoS scenario, architecture, the §7 schemas,
the §2.3 constants, repo structure, dashboard layout, demo narrative.

**No feature development before the interfaces are fixed.**

## 9.2 Shared-artifact ownership

Previously unassigned and all on the critical path:

| Artifact | Owner | Due |
|---|---|---|
| `shared/config.py`, `shared/schemas.py` | Member 2 | 00:20 |
| `shared/sample_data.json` | Member 2 (hand-written from §2.4) | 00:20 |
| `traffic_generator.py` | Member 1 | 00:50 |
| `run_pipeline.py` | Member 4 | 02:30 |

`sample_data.json` is hand-written from the §2.4 worked example so it
exists *before* Module 1 does — every other member is blocked without
it.

## 9.3 00:20–02:30 — Parallel development

-   **Member 1** — traffic → features → anomalies; generator first.
-   **Member 2** — features → forecast → trajectory; sample JSON until
    Module 1 lands.
-   **Member 3** — forecast → counterfactual; hardcoded forecast first.
-   **Member 4** — dashboard against mock JSON.

## 9.4 Demo timing — replay speed

At `WINDOW_SECONDS = 60`, a full NORMAL → DDoS arc spans 15–20 windows,
i.e. 15–20 minutes of data. Judging slots are 5–10 minutes, so the
demo **cannot run in real time**.

Decouple data-clock from wall-clock: `REPLAY_SPEED = 30` renders one
data-minute per 2 wall-seconds, so a 20-minute arc plays in ~40
seconds. Timestamps shown on the dashboard are data-clock. Say this out
loud during the demo — replayed, time-compressed, prerecorded — rather
than letting it look like live capture.

## 9.5 02:30–03:30 — First integration

Wire `run_pipeline.py` end to end (1 → 2 → 3 → 4) and get one complete
scenario working.

## 9.6 03:30–04:15 — Presentation quality

Charts, threat indicators, trajectory visualization, explainability
with contributions, counterfactual comparison, recommended
intervention.

## 9.7 04:15–04:40 — Demo preparation

``` text
NORMAL → ANOMALY → SCANNING → ATTACK IMMINENT
   → DDoS FORECAST → COUNTERFACTUAL SIMULATION
   → RECOMMENDED DEFENSE → PROJECTED RISK
```

## 9.8 04:40–05:00 — Freeze

Test the full pipeline; remove broken experiments; keep a known-good
demo dataset and mock-data fallback; record screenshots/video; **add no
new features**.

------------------------------------------------------------------------

# 10. Prototype Demo Script

Scores below follow one continuous series:
`12 → 17 → 24 → 31 → … → 42 → 54 → 69 → 87`.

## Scene 1 — Normal network

``` text
Network status: 🟢 NORMAL
Threat score: 12%
```

## Scene 2 — Behavioral change

``` text
Threat score: 31%     (24 → 31)
Momentum: +7/min

⚠️ Behavioral anomaly detected
```

## Scene 3 — Attack trajectory

``` text
Current stage: SCANNING

Predicted next stage:
ATTACK IMMINENT
```

## Scene 4 — Forecast

``` text
DDoS likelihood: 87%
Time to escalation: ~5 min (4-6)
```

## Scene 5 — Explainability

``` text
                      observed   contribution
SYN ratio                +68%         32.4%
Failed connections       +72%         20.2%
Traffic volume           +61%         19.8%
Source diversity         +54%         18.4%
Traffic acceleration     +49%          9.2%
```

## Scene 6 — Counterfactual

``` text
5-minute horizon:

If no action:          95% risk
If sources blocked:    40% risk
If server isolated:    26% risk
```

## Scene 7 — Decision

``` text
RECOMMENDED ACTION:
ISOLATE SERVER

PROJECTED RISK REDUCTION:
72%  (vs no action)

Advisory only - not executed.
```

## Scene 8 — Projected trajectory

**Say "projected", not "re-forecast".** No action is executed and no
new traffic is observed, so this scene displays Module 3's projection —
it is not a fresh forecast from post-intervention data. Claiming
otherwise is the one place this demo could fairly be called
misleading.

``` text
Projected trajectory under ISOLATE_SERVER:
ATTACK IMMINENT → does not reach DDoS

Projected risk at 5 min:
26%   (vs 95% unmitigated)
```

**Optional, if time permits (worth more than any extra chart):** have
`traffic_generator.py` emit a second replay track in which mitigation
was applied, then run the real pipeline over it. That turns Scene 8
into a genuine re-forecast against observed data and lets you claim the
full OBSERVE → … → RE-FORECAST loop honestly.

------------------------------------------------------------------------

# 11. Evaluation Metrics

## 11.1 What can actually be measured

Ground truth exists **only for synthetic and labelled benchmark data**,
where attack onset time is known by construction. State the data source
when quoting any number below.

### Detection / classification

Accuracy, Precision, Recall, F1, ROC-AUC — computed per window against
known labels.

### Temporal forecasting

-   Forecast lead time — warning time before true onset
-   Mean time-to-warning
-   False alarm rate over benign windows
-   Attack-stage prediction accuracy

## 11.2 Baseline comparison (do not skip)

The novelty claim is *early warning*, so the decisive measurement is
against a trivial detector:

``` text
Baseline:  alert when packets_per_second > baseline + 3σ
Metric:    lead time gained = t_baseline_alert - t_our_forecast
```

A single number — "we warn N minutes earlier than a threshold
detector" — is more persuasive than any F1 score, and it is the only
metric that directly evidences the project's central claim.

## 11.3 What cannot be validated

**Projected risk reduction is an output, not a metric.** The
counterfactual is never observed, so no measurement can confirm that
isolating the server *would have* cut risk to 26%. Earlier drafts
listed this under evaluation; that is a category error and a judge may
well probe it.

What *can* be checked about Module 3, and should be reported as such:

-   **Ranking consistency** — does the recommended action stay stable
    across adjacent windows, or does it flip-flop?
-   **Sensitivity** — how much do conclusions move when mitigation
    parameters are perturbed ±20%?
-   **Monotonicity** — does higher momentum always yield higher
    projected risk?

Report these as *model-behaviour checks*, never as accuracy.

## 11.4 System performance

Processing latency, feature-extraction throughput, dashboard response
time.

------------------------------------------------------------------------

# 12. Safety and Prototype Boundaries

Data sources: synthetic traffic, public benchmark datasets,
prerecorded/replayed traffic, controlled lab data only.

Do not perform unauthorized attacks against external systems. The
demonstration shows **analysis, forecasting and simulation** — never
offensive activity against real infrastructure.

**Advisory only.** The system recommends; it does not execute. There is
no enforcement plane, no firewall integration, and no automated
blocking in the prototype. Every recommendation is
human-in-the-loop by design, and the dashboard says so on the
counterfactual panel (§6.7). Automated response appears only in future
work (§14).

------------------------------------------------------------------------

# 13. Known Simplifications

State these before a judge finds them. Each is a deliberate,
defensible prototype choice — the risk is not the simplification, it
is appearing unaware of it.

1.  **One scalar serves three roles.** `threat_score`,
    `attack_probability` and `current_risk` are all `0.87` because the
    prototype treats them as one quantity. Properly, a threat score is
    an anomaly aggregate, an attack probability is a classifier output,
    and risk is probability × impact. Collapsing them is intentional
    for the 5-hour build; asset-weighted impact is future work.
2.  **Mitigation effectiveness is assumed, not learned.** The §2.3
    parameters are engineering judgement. Learning them needs
    intervention data nobody has.
3.  **One modelled attack family.** Three of four dashboard bars are
    placeholders (§2.2).
4.  **The counterfactual model is not causal.** It is a saturating
    extrapolation with hand-set parameters — sound enough to rank
    actions, not to quantify them.
5.  **Momentum is a two-window difference**, so it is noisy; the §3.3
    band exists because of this.
6.  **Scene 8 is a projection, not an observed re-forecast** unless the
    optional second replay track is built (§10).

------------------------------------------------------------------------

# 14. Future Expansion

1.  Multiple attack families.
2.  Real-time Zeek/NetFlow ingestion.
3.  Online model adaptation.
4.  Graph-based attack-path modelling.
5.  Transformer-based temporal forecasting.
6.  Learned counterfactual models from real intervention data.
7.  Automated incident-response orchestration.
8.  Multi-organization network baselines.
9.  Threat-intelligence enrichment.
10. Analyst feedback loops.
11. Distributed inference.
12. Real network digital-twin simulation.
13. Asset-weighted risk (separating probability from impact — see §13.1).

------------------------------------------------------------------------

# 15. One-Line Innovation Statement

> **A predictive cyber-defense platform that learns network behavior,
> measures threat momentum, forecasts attack progression and
> time-to-escalation, explains the evidence behind the forecast, and
> evaluates counterfactual defensive actions before the attack fully
> materializes.**

------------------------------------------------------------------------

# 16. Final Prototype Principle

``` text
OBSERVE → UNDERSTAND → FORECAST → SIMULATE → RECOMMEND → RE-FORECAST
```

The strongest SIH demonstration is not:

> **"Our AI detected a DDoS."**

It is:

> **"Our system saw the network's trajectory changing, forecast the DDoS
> before escalation, showed why it believed the attack was coming,
> simulated three possible futures, selected the most effective
> intervention, and showed how the projected future risk changed."**
