"""
Water treatment plant process simulation.

Simulates realistic physics: tank mass balance, pH drift, pressure dynamics.
Reads setpoints from holding registers, writes sensor values to input registers,
and updates alarm discrete inputs.
"""

from __future__ import annotations

import random

from ot_twin.config import (
    PH_ALARM_HIGH,
    PH_ALARM_LOW,
    PRESSURE_ALARM_HIGH,
    PROCESS_TICK_SECONDS,
    TANK_CAPACITY_LITERS,
    TANK_HIGH_ALARM_PCT,
    TANK_LOW_ALARM_PCT,
)
from ot_twin.models import ProcessState


class WaterTreatmentProcess:
    """Simulates a simple water treatment plant with a single tank."""

    def __init__(self) -> None:
        self.state = ProcessState()
        self._tank_volume = (self.state.tank_level / 100.0) * TANK_CAPACITY_LITERS

    def tick(
        self,
        dt: float = PROCESS_TICK_SECONDS,
        *,
        inlet_valve_open: bool = True,
        outlet_valve_open: bool = True,
        pump_running: bool = True,
        mixer_running: bool = True,
        chlorine_pump_on: bool = True,
        emergency_stop: bool = False,
        inflow_setpoint: float = 10.0,
        outflow_setpoint: float = 10.0,
        ph_setpoint: float = 7.0,
        chlorine_setpoint: float = 1.5,
        pressure_setpoint: float = 45.0,
        temperature_setpoint: float = 22.0,
    ) -> ProcessState:
        """Advance the process by dt seconds and return new state."""

        if emergency_stop:
            inlet_valve_open = False
            outlet_valve_open = False
            pump_running = False
            mixer_running = False
            chlorine_pump_on = False

        # --- Flow dynamics ---
        effective_inflow = inflow_setpoint if (inlet_valve_open and pump_running) else 0.0
        effective_outflow = outflow_setpoint if outlet_valve_open else 0.0

        # Add noise (±2%)
        effective_inflow *= 1.0 + random.uniform(-0.02, 0.02)
        effective_outflow *= 1.0 + random.uniform(-0.02, 0.02)

        # Tank mass balance (liters)
        delta_volume = (effective_inflow - effective_outflow) * (dt / 60.0)
        self._tank_volume = max(0.0, min(TANK_CAPACITY_LITERS, self._tank_volume + delta_volume))
        tank_level = (self._tank_volume / TANK_CAPACITY_LITERS) * 100.0

        # --- pH model ---
        ph_target = ph_setpoint if mixer_running else 7.0
        ph_current = self.state.ph_level
        ph_drift = random.uniform(-0.05, 0.05)
        ph_new = ph_current + (ph_target - ph_current) * 0.05 * dt + ph_drift

        # --- Chlorine ---
        cl_target = chlorine_setpoint if chlorine_pump_on else 0.0
        cl_current = self.state.chlorine_dosing
        cl_new = cl_current + (cl_target - cl_current) * 0.1 * dt + random.uniform(-0.02, 0.02)
        cl_new = max(0.0, cl_new)

        # --- Turbidity (inversely related to chlorine) ---
        turb_base = max(0.1, 2.0 - cl_new * 0.8)
        turbidity = turb_base + random.uniform(-0.05, 0.05)
        turbidity = max(0.0, turbidity)

        # --- Pressure ---
        p_target = pressure_setpoint if pump_running else 10.0
        p_current = self.state.pressure_psi
        pressure = p_current + (p_target - p_current) * 0.08 * dt + random.uniform(-0.5, 0.5)
        pressure = max(0.0, pressure)

        # --- Temperature (slow drift) ---
        t_target = temperature_setpoint
        t_current = self.state.temperature_c
        temperature = t_current + (t_target - t_current) * 0.02 * dt + random.uniform(-0.1, 0.1)

        # --- Alarms ---
        high_level_alarm = tank_level >= TANK_HIGH_ALARM_PCT
        low_level_alarm = tank_level <= TANK_LOW_ALARM_PCT
        ph_alarm = ph_new < PH_ALARM_LOW or ph_new > PH_ALARM_HIGH
        pressure_alarm = pressure > PRESSURE_ALARM_HIGH

        self.state = ProcessState(
            tank_level=round(tank_level, 2),
            inflow_rate=round(effective_inflow, 2),
            outflow_rate=round(effective_outflow, 2),
            ph_level=round(ph_new, 2),
            chlorine_dosing=round(cl_new, 2),
            turbidity=round(turbidity, 2),
            pressure_psi=round(pressure, 2),
            temperature_c=round(temperature, 2),
            inlet_valve_open=inlet_valve_open,
            outlet_valve_open=outlet_valve_open,
            pump_running=pump_running,
            mixer_running=mixer_running,
            high_level_alarm=high_level_alarm,
            low_level_alarm=low_level_alarm,
            ph_alarm=ph_alarm,
            pressure_alarm=pressure_alarm,
        )
        return self.state

    def reset(self) -> None:
        """Reset to default state."""
        self.state = ProcessState()
        self._tank_volume = (self.state.tank_level / 100.0) * TANK_CAPACITY_LITERS
