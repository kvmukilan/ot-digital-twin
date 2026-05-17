"""
Baseline Profiler — Captures and compares process state against a known-good baseline.

Stores a reference "golden" snapshot and computes per-parameter drift when
compared against a live state.  Essential for ICS change detection: any
deviation from baseline may indicate tampering, misconfiguration, or attack.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ot_twin.models import ProcessState


@dataclass
class Drift:
    """A single parameter deviation from baseline."""
    parameter: str
    baseline_value: float | bool
    current_value: float | bool
    delta: float              # absolute numeric change (0 for bools)
    pct_change: float         # percentage change from baseline (0 for bools)
    is_boolean: bool = False


@dataclass
class BaselineComparison:
    """Result of comparing current state against baseline."""
    drifts: list[Drift] = field(default_factory=list)
    total_parameters: int = 0
    changed_parameters: int = 0

    @property
    def drift_percentage(self) -> float:
        if self.total_parameters == 0:
            return 0.0
        return (self.changed_parameters / self.total_parameters) * 100.0

    @property
    def has_drift(self) -> bool:
        return self.changed_parameters > 0


# Parameters to compare and their tolerance (absolute) before flagging
_NUMERIC_PARAMS: dict[str, float] = {
    "tank_level": 2.0,
    "inflow_rate": 1.0,
    "outflow_rate": 1.0,
    "ph_level": 0.2,
    "chlorine_dosing": 0.1,
    "turbidity": 0.1,
    "pressure_psi": 2.0,
    "temperature_c": 1.0,
}

_BOOLEAN_PARAMS: list[str] = [
    "inlet_valve_open",
    "outlet_valve_open",
    "pump_running",
    "mixer_running",
    "high_level_alarm",
    "low_level_alarm",
    "ph_alarm",
    "pressure_alarm",
]


def capture_baseline(state: ProcessState) -> dict:
    """Capture a baseline snapshot as a plain dict for serialisation.

    Returns a dict of parameter names to their values.
    """
    baseline: dict = {}
    for param in _NUMERIC_PARAMS:
        baseline[param] = getattr(state, param)
    for param in _BOOLEAN_PARAMS:
        baseline[param] = getattr(state, param)
    return baseline


def compare_to_baseline(
    baseline: dict,
    current: ProcessState,
    *,
    tolerance: dict[str, float] | None = None,
) -> BaselineComparison:
    """Compare a live process state against a stored baseline.

    Args:
        baseline: dict from ``capture_baseline()``.
        current: live ProcessState to compare.
        tolerance: optional per-parameter tolerance overrides.

    Returns:
        BaselineComparison with list of drifted parameters.
    """
    tol = {**_NUMERIC_PARAMS}
    if tolerance:
        tol.update(tolerance)

    drifts: list[Drift] = []
    total = 0

    # Numeric parameters
    for param, default_tol in _NUMERIC_PARAMS.items():
        if param not in baseline:
            continue
        total += 1
        base_val = baseline[param]
        curr_val = getattr(current, param)
        delta = abs(curr_val - base_val)
        threshold = tol.get(param, default_tol)

        if delta > threshold:
            pct = (delta / base_val * 100.0) if base_val != 0 else 100.0
            drifts.append(Drift(
                parameter=param,
                baseline_value=base_val,
                current_value=curr_val,
                delta=round(delta, 4),
                pct_change=round(pct, 2),
            ))

    # Boolean parameters
    for param in _BOOLEAN_PARAMS:
        if param not in baseline:
            continue
        total += 1
        base_val = baseline[param]
        curr_val = getattr(current, param)
        if curr_val != base_val:
            drifts.append(Drift(
                parameter=param,
                baseline_value=base_val,
                current_value=curr_val,
                delta=0,
                pct_change=0,
                is_boolean=True,
            ))

    return BaselineComparison(
        drifts=drifts,
        total_parameters=total,
        changed_parameters=len(drifts),
    )
