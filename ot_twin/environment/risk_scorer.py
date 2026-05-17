"""
Process Risk Scorer — Quantifies operational risk from current process state.

Produces a 0–100 score based on how far sensor values deviate from safe
operating ranges, active alarms, and actuator state anomalies.  Useful for
dashboards, incident triage, and automated alerting thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ot_twin.models import ProcessState


@dataclass
class RiskFactor:
    """A single contributor to the overall risk score."""
    category: str
    description: str
    points: float


@dataclass
class RiskReport:
    """Full risk assessment for a process state snapshot."""
    score: float                           # 0–100 (clamped)
    level: str                             # low / medium / high / critical
    factors: list[RiskFactor] = field(default_factory=list)


# ── Safe-range definitions ──────────────────────────────────────────────
# (min, max) — values inside this range contribute 0 risk.
_SAFE_RANGES: dict[str, tuple[float, float]] = {
    "tank_level": (15.0, 85.0),
    "ph_level": (6.5, 8.0),
    "chlorine_dosing": (0.5, 3.0),
    "pressure_psi": (20.0, 70.0),
    "temperature_c": (10.0, 35.0),
    "turbidity": (0.0, 1.5),
}

# Weight per parameter — how heavily each contributes to risk.
_WEIGHTS: dict[str, float] = {
    "tank_level": 20.0,
    "ph_level": 20.0,
    "chlorine_dosing": 10.0,
    "pressure_psi": 15.0,
    "temperature_c": 5.0,
    "turbidity": 5.0,
}

# Hard-danger thresholds — immediate critical risk.
_DANGER_THRESHOLDS: dict[str, tuple[float, float]] = {
    "tank_level": (5.0, 95.0),
    "ph_level": (4.0, 10.0),
    "chlorine_dosing": (0.0, 5.0),
    "pressure_psi": (5.0, 90.0),
}

_ALARM_POINTS = 8.0
_ACTUATOR_ANOMALY_POINTS = 5.0


def score_risk(state: ProcessState) -> RiskReport:
    """Compute a risk score for the given process state.

    Returns a RiskReport with score 0–100, a severity level, and a list of
    contributing risk factors.
    """
    factors: list[RiskFactor] = []
    total = 0.0

    # ── Continuous-value deviation scoring ──────────────────────────
    for param, (lo, hi) in _SAFE_RANGES.items():
        value = getattr(state, param)
        weight = _WEIGHTS[param]

        if lo <= value <= hi:
            continue  # within safe range

        # Linear interpolation between safe-range edge and danger threshold
        danger = _DANGER_THRESHOLDS.get(param)
        if value < lo:
            span = lo - (danger[0] if danger else 0.0)
            deviation = min(lo - value, span) / span if span > 0 else 1.0
        else:
            span = (danger[1] if danger else hi + weight) - hi
            deviation = min(value - hi, span) / span if span > 0 else 1.0

        deviation = min(max(deviation, 0.0), 1.0)
        pts = deviation * weight
        total += pts
        factors.append(RiskFactor(
            category=param,
            description=f"{param}={value:.2f} outside safe range [{lo}-{hi}]",
            points=round(pts, 1),
        ))

    # ── Alarm scoring ───────────────────────────────────────────────
    alarm_fields = [
        ("high_level_alarm", "High tank level alarm active"),
        ("low_level_alarm", "Low tank level alarm active"),
        ("ph_alarm", "pH alarm active"),
        ("pressure_alarm", "Pressure alarm active"),
    ]
    for attr, desc in alarm_fields:
        if getattr(state, attr):
            total += _ALARM_POINTS
            factors.append(RiskFactor("alarm", desc, _ALARM_POINTS))

    # ── Actuator anomaly scoring ────────────────────────────────────
    # Pump off while valves open → stagnant water
    if not state.pump_running and (state.inlet_valve_open or state.outlet_valve_open):
        total += _ACTUATOR_ANOMALY_POINTS
        factors.append(RiskFactor(
            "actuator", "Pump stopped while valves open — stagnant flow",
            _ACTUATOR_ANOMALY_POINTS,
        ))

    # Both valves closed → deadheaded system
    if not state.inlet_valve_open and not state.outlet_valve_open:
        total += _ACTUATOR_ANOMALY_POINTS
        factors.append(RiskFactor(
            "actuator", "Both valves closed — no flow path",
            _ACTUATOR_ANOMALY_POINTS,
        ))

    score = min(max(round(total, 1), 0.0), 100.0)
    level = _level_from_score(score)
    return RiskReport(score=score, level=level, factors=factors)


def _level_from_score(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
