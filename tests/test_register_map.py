"""Tests for the PLC register map definition."""

from __future__ import annotations

from ot_twin.environment.register_map import (
    COILS,
    DISCRETE_INPUTS,
    HOLDING_REGISTERS,
    INPUT_REGISTERS,
    get_register_by_name,
    get_register_map,
)
from ot_twin.models import RegisterType


def test_register_map_has_all_four_types():
    m = get_register_map()
    assert set(m) == {
        RegisterType.HOLDING,
        RegisterType.INPUT,
        RegisterType.COIL,
        RegisterType.DISCRETE_INPUT,
    }


def test_register_map_groups_match_source_lists():
    m = get_register_map()
    assert m[RegisterType.HOLDING] is HOLDING_REGISTERS
    assert m[RegisterType.INPUT] is INPUT_REGISTERS
    assert m[RegisterType.COIL] is COILS
    assert m[RegisterType.DISCRETE_INPUT] is DISCRETE_INPUTS


def test_addresses_unique_and_zero_based_per_type():
    for rtype, entries in get_register_map().items():
        addrs = [e.address for e in entries]
        assert len(addrs) == len(set(addrs)), f"duplicate address in {rtype}"
        assert min(addrs) == 0, f"{rtype} is not zero-based"


def test_every_entry_reports_its_own_type():
    for rtype, entries in get_register_map().items():
        for e in entries:
            assert e.register_type == rtype


def test_lookup_by_name_resolves_known_register():
    reg = get_register_by_name("emergency_stop")
    assert reg is not None
    assert reg.register_type == RegisterType.COIL
    assert reg.address == 5
    assert reg.default_value == 0


def test_lookup_by_name_returns_none_for_unknown():
    assert get_register_by_name("no_such_register") is None


def test_coil_defaults_match_documented_actuators():
    coils = {e.address: e for e in COILS}
    assert coils[0].name == "inlet_valve"
    assert coils[0].default_value == 1  # open
    assert coils[2].name == "pump_enable"
    assert coils[2].default_value == 1  # on
    assert coils[5].name == "emergency_stop"
    assert coils[5].default_value == 0  # off


def test_holding_setpoints_have_documented_ranges():
    hr = {e.address: e for e in HOLDING_REGISTERS}
    assert hr[0].name == "tank_level_setpoint"
    assert (hr[0].min_value, hr[0].max_value) == (0, 100)
    assert hr[3].name == "ph_setpoint"
    assert hr[3].default_value == 700  # pH 7.00 scaled x100
