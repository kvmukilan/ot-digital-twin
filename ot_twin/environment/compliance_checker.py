"""
ICS Compliance Checker — Validates PLC configuration against security best practices.

Performs static checks on the current process state and register configuration
inspired by NIST SP 800-82 and IEC 62443 guidelines.  Identifies misconfigurations
such as disabled alarms, unsafe setpoints, missing safety interlocks, and
operational hygiene issues.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from ot_twin.models import ProcessState


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


@dataclass
class ComplianceCheck:
    """A single compliance check result."""
    check_id: str
    category: str
    description: str
    status: CheckStatus
    detail: str = ""


@dataclass
class ComplianceReport:
    """Full compliance assessment."""
    checks: list[ComplianceCheck] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def compliant(self) -> bool:
        return self.failed == 0


# ── Safe operating parameters ──────────────────────────────────────────
_ALARM_HIGH_RANGE = (80.0, 95.0)   # acceptable high-level alarm setpoint
_ALARM_LOW_RANGE = (5.0, 20.0)     # acceptable low-level alarm setpoint
_PH_SAFE = (6.0, 9.0)
_CHLORINE_SAFE = (0.2, 4.0)       # mg/L
_PRESSURE_SAFE = (10.0, 80.0)     # PSI


def check_compliance(
    state: ProcessState,
    *,
    alarm_high_setpoint: float = 90.0,
    alarm_low_setpoint: float = 10.0,
) -> ComplianceReport:
    """Run all compliance checks against current state and configuration.

    Args:
        state: Current process snapshot.
        alarm_high_setpoint: Configured high-level alarm threshold (%).
        alarm_low_setpoint: Configured low-level alarm threshold (%).

    Returns:
        ComplianceReport with individual check results.
    """
    checks: list[ComplianceCheck] = []

    # ── C01: High-level alarm threshold in acceptable range ─────────
    if _ALARM_HIGH_RANGE[0] <= alarm_high_setpoint <= _ALARM_HIGH_RANGE[1]:
        checks.append(ComplianceCheck(
            "C01", "alarm", "High-level alarm threshold in valid range",
            CheckStatus.PASS,
            f"Set to {alarm_high_setpoint}% (valid: {_ALARM_HIGH_RANGE[0]}-{_ALARM_HIGH_RANGE[1]}%)",
        ))
    else:
        checks.append(ComplianceCheck(
            "C01", "alarm", "High-level alarm threshold in valid range",
            CheckStatus.FAIL,
            f"Set to {alarm_high_setpoint}% — outside {_ALARM_HIGH_RANGE[0]}-{_ALARM_HIGH_RANGE[1]}%",
        ))

    # ── C02: Low-level alarm threshold in acceptable range ──────────
    if _ALARM_LOW_RANGE[0] <= alarm_low_setpoint <= _ALARM_LOW_RANGE[1]:
        checks.append(ComplianceCheck(
            "C02", "alarm", "Low-level alarm threshold in valid range",
            CheckStatus.PASS,
            f"Set to {alarm_low_setpoint}% (valid: {_ALARM_LOW_RANGE[0]}-{_ALARM_LOW_RANGE[1]}%)",
        ))
    else:
        checks.append(ComplianceCheck(
            "C02", "alarm", "Low-level alarm threshold in valid range",
            CheckStatus.FAIL,
            f"Set to {alarm_low_setpoint}% — outside {_ALARM_LOW_RANGE[0]}-{_ALARM_LOW_RANGE[1]}%",
        ))

    # ── C03: Alarm gap — high must be above low ─────────────────────
    gap = alarm_high_setpoint - alarm_low_setpoint
    if gap >= 30:
        checks.append(ComplianceCheck(
            "C03", "alarm", "Alarm deadband gap ≥ 30%",
            CheckStatus.PASS, f"Gap is {gap:.0f}%",
        ))
    elif gap > 0:
        checks.append(ComplianceCheck(
            "C03", "alarm", "Alarm deadband gap ≥ 30%",
            CheckStatus.WARN, f"Gap is only {gap:.0f}% — risk of nuisance alarms",
        ))
    else:
        checks.append(ComplianceCheck(
            "C03", "alarm", "Alarm deadband gap ≥ 30%",
            CheckStatus.FAIL, f"High ({alarm_high_setpoint}%) ≤ low ({alarm_low_setpoint}%)",
        ))

    # ── C04: pH within safe bounds ──────────────────────────────────
    if _PH_SAFE[0] <= state.ph_level <= _PH_SAFE[1]:
        checks.append(ComplianceCheck(
            "C04", "water-quality", "pH level within safe range",
            CheckStatus.PASS, f"pH is {state.ph_level:.2f}",
        ))
    else:
        checks.append(ComplianceCheck(
            "C04", "water-quality", "pH level within safe range",
            CheckStatus.FAIL,
            f"pH is {state.ph_level:.2f} — outside {_PH_SAFE[0]}-{_PH_SAFE[1]}",
        ))

    # ── C05: Chlorine dosing within safe bounds ─────────────────────
    if _CHLORINE_SAFE[0] <= state.chlorine_dosing <= _CHLORINE_SAFE[1]:
        checks.append(ComplianceCheck(
            "C05", "water-quality", "Chlorine dosing within safe range",
            CheckStatus.PASS, f"Cl₂ is {state.chlorine_dosing:.2f} mg/L",
        ))
    else:
        checks.append(ComplianceCheck(
            "C05", "water-quality", "Chlorine dosing within safe range",
            CheckStatus.FAIL,
            f"Cl₂ is {state.chlorine_dosing:.2f} mg/L — outside {_CHLORINE_SAFE[0]}-{_CHLORINE_SAFE[1]}",
        ))

    # ── C06: Pressure within safe bounds ────────────────────────────
    if _PRESSURE_SAFE[0] <= state.pressure_psi <= _PRESSURE_SAFE[1]:
        checks.append(ComplianceCheck(
            "C06", "safety", "System pressure within safe range",
            CheckStatus.PASS, f"Pressure is {state.pressure_psi:.1f} PSI",
        ))
    else:
        checks.append(ComplianceCheck(
            "C06", "safety", "System pressure within safe range",
            CheckStatus.FAIL,
            f"Pressure is {state.pressure_psi:.1f} PSI — outside {_PRESSURE_SAFE[0]}-{_PRESSURE_SAFE[1]}",
        ))

    # ── C07: Pump running when valves open (flow interlock) ─────────
    if state.inlet_valve_open or state.outlet_valve_open:
        if state.pump_running:
            checks.append(ComplianceCheck(
                "C07", "interlock", "Pump running when valves open",
                CheckStatus.PASS, "Flow path has active pump",
            ))
        else:
            checks.append(ComplianceCheck(
                "C07", "interlock", "Pump running when valves open",
                CheckStatus.WARN, "Valves open but pump is stopped — stagnant water risk",
            ))
    else:
        checks.append(ComplianceCheck(
            "C07", "interlock", "Pump running when valves open",
            CheckStatus.PASS, "Valves closed — pump state acceptable",
        ))

    # ── C08: Mixer running during chlorine dosing ───────────────────
    if state.chlorine_dosing > 0.1:
        if state.mixer_running:
            checks.append(ComplianceCheck(
                "C08", "interlock", "Mixer active during chlorine dosing",
                CheckStatus.PASS, "Mixer ensures proper chemical distribution",
            ))
        else:
            checks.append(ComplianceCheck(
                "C08", "interlock", "Mixer active during chlorine dosing",
                CheckStatus.FAIL,
                "Chlorine dosing active without mixer — uneven distribution hazard",
            ))
    else:
        checks.append(ComplianceCheck(
            "C08", "interlock", "Mixer active during chlorine dosing",
            CheckStatus.PASS, "No chlorine dosing active",
        ))

    # ── C09: Tank level not extreme ─────────────────────────────────
    if 5.0 <= state.tank_level <= 95.0:
        checks.append(ComplianceCheck(
            "C09", "safety", "Tank level within operational bounds",
            CheckStatus.PASS, f"Tank at {state.tank_level:.1f}%",
        ))
    else:
        checks.append(ComplianceCheck(
            "C09", "safety", "Tank level within operational bounds",
            CheckStatus.FAIL,
            f"Tank at {state.tank_level:.1f}% — extreme level detected",
        ))

    # ── C10: No simultaneous valve closure with pump running ────────
    if not state.inlet_valve_open and not state.outlet_valve_open and state.pump_running:
        checks.append(ComplianceCheck(
            "C10", "interlock", "No dead-headed pump condition",
            CheckStatus.FAIL,
            "Pump running with both valves closed — dead-head risk",
        ))
    else:
        checks.append(ComplianceCheck(
            "C10", "interlock", "No dead-headed pump condition",
            CheckStatus.PASS, "No dead-head condition",
        ))

    return ComplianceReport(checks=checks)
