"""Tests for the water treatment plant process physics."""

from __future__ import annotations

import random

from ot_twin.environment.process_model import WaterTreatmentProcess


def test_mass_balance_fills_when_inflow_exceeds_outflow():
    p = WaterTreatmentProcess()
    start = p.state.tank_level
    state = None
    for _ in range(10):
        state = p.tick(dt=1.0, inflow_setpoint=100, outflow_setpoint=0)
    assert state.tank_level > start


def test_mass_balance_drains_when_outflow_exceeds_inflow():
    p = WaterTreatmentProcess()
    start = p.state.tank_level
    state = None
    for _ in range(10):
        state = p.tick(dt=1.0, inflow_setpoint=0, outflow_setpoint=100)
    assert state.tank_level < start


def test_tank_level_clamped_between_0_and_100():
    p = WaterTreatmentProcess()
    for _ in range(500):
        state = p.tick(dt=1.0, inflow_setpoint=100, outflow_setpoint=0)
    assert 0.0 <= state.tank_level <= 100.0


def test_closed_inlet_valve_stops_inflow():
    p = WaterTreatmentProcess()
    state = p.tick(dt=1.0, inlet_valve_open=False, inflow_setpoint=100)
    assert state.inflow_rate == 0.0


def test_closed_outlet_valve_stops_outflow():
    p = WaterTreatmentProcess()
    state = p.tick(dt=1.0, outlet_valve_open=False, outflow_setpoint=100)
    assert state.outflow_rate == 0.0


def test_emergency_stop_shuts_everything_off():
    p = WaterTreatmentProcess()
    state = p.tick(dt=1.0, emergency_stop=True, inflow_setpoint=100, outflow_setpoint=100)
    assert state.inflow_rate == 0.0
    assert state.outflow_rate == 0.0
    assert not state.pump_running
    assert not state.inlet_valve_open
    assert not state.outlet_valve_open


def test_ph_converges_toward_setpoint():
    random.seed(0)
    p = WaterTreatmentProcess()
    state = None
    for _ in range(80):
        state = p.tick(dt=1.0, ph_setpoint=9.0, mixer_running=True)
    assert state.ph_level > 8.0  # started at 7.0, driven toward 9.0


def test_chlorine_converges_toward_setpoint():
    random.seed(0)
    p = WaterTreatmentProcess()
    state = None
    for _ in range(80):
        state = p.tick(dt=1.0, chlorine_setpoint=3.0, chlorine_pump_on=True)
    assert state.chlorine_dosing > 2.0


def test_chlorine_decays_when_pump_off():
    random.seed(0)
    p = WaterTreatmentProcess()
    state = None
    for _ in range(80):
        state = p.tick(dt=1.0, chlorine_pump_on=False)
    assert state.chlorine_dosing < 0.5


def test_turbidity_inversely_tracks_chlorine():
    random.seed(0)
    p = WaterTreatmentProcess()
    # high chlorine -> low turbidity
    for _ in range(60):
        high_cl = p.tick(dt=1.0, chlorine_setpoint=3.0, chlorine_pump_on=True)
    p.reset()
    for _ in range(60):
        low_cl = p.tick(dt=1.0, chlorine_pump_on=False)
    assert high_cl.turbidity < low_cl.turbidity


def test_high_level_alarm_triggers_on_overflow():
    p = WaterTreatmentProcess()
    state = None
    for _ in range(400):
        state = p.tick(dt=1.0, inflow_setpoint=100, outflow_setpoint=0)
    assert state.tank_level >= 90.0
    assert state.high_level_alarm


def test_low_level_alarm_triggers_on_drain():
    p = WaterTreatmentProcess()
    state = None
    for _ in range(400):
        state = p.tick(dt=1.0, inflow_setpoint=0, outflow_setpoint=100)
    assert state.tank_level <= 10.0
    assert state.low_level_alarm


def test_pressure_alarm_triggers_on_overpressure():
    random.seed(0)
    p = WaterTreatmentProcess()
    state = None
    for _ in range(120):
        state = p.tick(dt=1.0, pressure_setpoint=100, pump_running=True)
    assert state.pressure_psi > 80.0
    assert state.pressure_alarm


def test_ph_alarm_triggers_out_of_range():
    random.seed(0)
    p = WaterTreatmentProcess()
    state = None
    for _ in range(80):
        state = p.tick(dt=1.0, ph_setpoint=11.0, mixer_running=True)
    assert state.ph_alarm


def test_reset_restores_defaults():
    p = WaterTreatmentProcess()
    for _ in range(20):
        p.tick(dt=1.0, inflow_setpoint=100, outflow_setpoint=0)
    p.reset()
    assert p.state.tank_level == 50.0
