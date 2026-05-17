"""
Modbus register map for the water treatment plant PLC.

Address layout (mirrors real Schneider/Allen-Bradley conventions):
  Holding Registers (FC 3/6/16):  0-99
  Input Registers   (FC 4):      0-49
  Coils             (FC 1/5/15): 0-15
  Discrete Inputs   (FC 2):      0-15
"""

from __future__ import annotations

from ot_twin.models import RegisterEntry, RegisterType

# ---------------------------------------------------------------------------
# Holding Registers (read/write) — setpoints and control values
# ---------------------------------------------------------------------------
HOLDING_REGISTERS: list[RegisterEntry] = [
    RegisterEntry(
        address=0, name="tank_level_setpoint",
        register_type=RegisterType.HOLDING,
        description="Tank level setpoint",
        unit="%", min_value=0, max_value=100, default_value=50,
    ),
    RegisterEntry(
        address=1, name="inflow_rate_setpoint",
        register_type=RegisterType.HOLDING,
        description="Inflow rate setpoint",
        unit="L/min", min_value=0, max_value=100, default_value=10,
    ),
    RegisterEntry(
        address=2, name="outflow_rate_setpoint",
        register_type=RegisterType.HOLDING,
        description="Outflow rate setpoint",
        unit="L/min", min_value=0, max_value=100, default_value=10,
    ),
    RegisterEntry(
        address=3, name="ph_setpoint",
        register_type=RegisterType.HOLDING,
        description="pH level setpoint (x100 for precision)",
        unit="pH*100", min_value=0, max_value=1400, default_value=700,
    ),
    RegisterEntry(
        address=4, name="chlorine_dosing_setpoint",
        register_type=RegisterType.HOLDING,
        description="Chlorine dosing rate setpoint (x100)",
        unit="mg/L*100", min_value=0, max_value=500, default_value=150,
    ),
    RegisterEntry(
        address=5, name="pressure_setpoint",
        register_type=RegisterType.HOLDING,
        description="System pressure setpoint",
        unit="PSI", min_value=0, max_value=100, default_value=45,
    ),
    RegisterEntry(
        address=6, name="temperature_setpoint",
        register_type=RegisterType.HOLDING,
        description="Temperature setpoint (x10)",
        unit="°C*10", min_value=0, max_value=500, default_value=220,
    ),
    RegisterEntry(
        address=7, name="mixer_speed",
        register_type=RegisterType.HOLDING,
        description="Mixer motor speed",
        unit="RPM", min_value=0, max_value=3000, default_value=1500,
    ),
    RegisterEntry(
        address=8, name="pump_speed",
        register_type=RegisterType.HOLDING,
        description="Pump motor speed",
        unit="RPM", min_value=0, max_value=3600, default_value=1800,
    ),
    RegisterEntry(
        address=9, name="alarm_threshold_high_level",
        register_type=RegisterType.HOLDING,
        description="High tank level alarm threshold",
        unit="%", min_value=0, max_value=100, default_value=90,
    ),
    RegisterEntry(
        address=10, name="alarm_threshold_low_level",
        register_type=RegisterType.HOLDING,
        description="Low tank level alarm threshold",
        unit="%", min_value=0, max_value=100, default_value=10,
    ),
]

# ---------------------------------------------------------------------------
# Input Registers (read-only) — sensor / process values
# ---------------------------------------------------------------------------
INPUT_REGISTERS: list[RegisterEntry] = [
    RegisterEntry(
        address=0, name="tank_level_pv",
        register_type=RegisterType.INPUT,
        description="Tank level process value",
        unit="%", min_value=0, max_value=100, default_value=50,
    ),
    RegisterEntry(
        address=1, name="inflow_rate_pv",
        register_type=RegisterType.INPUT,
        description="Inflow rate process value",
        unit="L/min", min_value=0, max_value=100, default_value=10,
    ),
    RegisterEntry(
        address=2, name="outflow_rate_pv",
        register_type=RegisterType.INPUT,
        description="Outflow rate process value",
        unit="L/min", min_value=0, max_value=100, default_value=10,
    ),
    RegisterEntry(
        address=3, name="ph_level_pv",
        register_type=RegisterType.INPUT,
        description="pH level process value (x100)",
        unit="pH*100", min_value=0, max_value=1400, default_value=700,
    ),
    RegisterEntry(
        address=4, name="chlorine_level_pv",
        register_type=RegisterType.INPUT,
        description="Chlorine level process value (x100)",
        unit="mg/L*100", min_value=0, max_value=500, default_value=150,
    ),
    RegisterEntry(
        address=5, name="turbidity_pv",
        register_type=RegisterType.INPUT,
        description="Turbidity process value (x100)",
        unit="NTU*100", min_value=0, max_value=1000, default_value=50,
    ),
    RegisterEntry(
        address=6, name="pressure_pv",
        register_type=RegisterType.INPUT,
        description="System pressure process value",
        unit="PSI", min_value=0, max_value=200, default_value=45,
    ),
    RegisterEntry(
        address=7, name="temperature_pv",
        register_type=RegisterType.INPUT,
        description="Temperature process value (x10)",
        unit="°C*10", min_value=0, max_value=500, default_value=220,
    ),
]

# ---------------------------------------------------------------------------
# Coils (read/write boolean) — actuator on/off control
# ---------------------------------------------------------------------------
COILS: list[RegisterEntry] = [
    RegisterEntry(
        address=0, name="inlet_valve",
        register_type=RegisterType.COIL,
        description="Inlet valve open/close",
        min_value=0, max_value=1, default_value=1,
    ),
    RegisterEntry(
        address=1, name="outlet_valve",
        register_type=RegisterType.COIL,
        description="Outlet valve open/close",
        min_value=0, max_value=1, default_value=1,
    ),
    RegisterEntry(
        address=2, name="pump_enable",
        register_type=RegisterType.COIL,
        description="Main pump enable",
        min_value=0, max_value=1, default_value=1,
    ),
    RegisterEntry(
        address=3, name="mixer_enable",
        register_type=RegisterType.COIL,
        description="Chemical mixer enable",
        min_value=0, max_value=1, default_value=1,
    ),
    RegisterEntry(
        address=4, name="chlorine_pump_enable",
        register_type=RegisterType.COIL,
        description="Chlorine dosing pump enable",
        min_value=0, max_value=1, default_value=1,
    ),
    RegisterEntry(
        address=5, name="emergency_stop",
        register_type=RegisterType.COIL,
        description="Emergency stop (all pumps/valves)",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=6, name="alarm_acknowledge",
        register_type=RegisterType.COIL,
        description="Alarm acknowledge",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=7, name="system_reset",
        register_type=RegisterType.COIL,
        description="System reset",
        min_value=0, max_value=1, default_value=0,
    ),
]

# ---------------------------------------------------------------------------
# Discrete Inputs (read-only boolean) — status / alarm flags
# ---------------------------------------------------------------------------
DISCRETE_INPUTS: list[RegisterEntry] = [
    RegisterEntry(
        address=0, name="high_level_alarm",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Tank high level alarm",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=1, name="low_level_alarm",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Tank low level alarm",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=2, name="ph_alarm",
        register_type=RegisterType.DISCRETE_INPUT,
        description="pH out-of-range alarm",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=3, name="pressure_alarm",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Over-pressure alarm",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=4, name="pump_fault",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Pump fault detected",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=5, name="mixer_fault",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Mixer fault detected",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=6, name="flow_sensor_fault",
        register_type=RegisterType.DISCRETE_INPUT,
        description="Flow sensor fault",
        min_value=0, max_value=1, default_value=0,
    ),
    RegisterEntry(
        address=7, name="system_running",
        register_type=RegisterType.DISCRETE_INPUT,
        description="System running status",
        min_value=0, max_value=1, default_value=1,
    ),
]


def get_register_map() -> dict[RegisterType, list[RegisterEntry]]:
    """Return full register map grouped by type."""
    return {
        RegisterType.HOLDING: HOLDING_REGISTERS,
        RegisterType.INPUT: INPUT_REGISTERS,
        RegisterType.COIL: COILS,
        RegisterType.DISCRETE_INPUT: DISCRETE_INPUTS,
    }


def get_register_by_name(name: str) -> RegisterEntry | None:
    """Look up a register entry by its name."""
    for reg_list in get_register_map().values():
        for reg in reg_list:
            if reg.name == name:
                return reg
    return None
