"""Tests for turning an AttackScenario into executable attack objects."""

from __future__ import annotations

from ot_twin.attacks.coil_bruteforce import CoilBruteforceAttack
from ot_twin.attacks.register_scan import RegisterScanAttack
from ot_twin.attacks.unauthorized_write import UnauthorizedWriteAttack
from ot_twin.llm_generator.payload_builder import build_attacks_from_scenario
from ot_twin.llm_generator.scenario_library import get_scenario
from ot_twin.models import AttackScenario, AttackStep, RegisterType


def test_overflow_scenario_builds_scan_and_write_attacks():
    scenario = get_scenario("tank-overflow")
    attacks = build_attacks_from_scenario(scenario, host="127.0.0.1", port=5020)
    names = [a.name for a in attacks]
    assert "register_scan" in names
    assert "unauthorized_write" in names


def test_register_and_coil_writes_grouped_into_unauthorized_write():
    scenario = AttackScenario(
        name="t", description="d", objective="o",
        steps=[
            AttackStep(order=1, description="w", function_code=6,
                       start_address=3, values=[200]),
            AttackStep(order=2, description="c", function_code=5,
                       register_type=RegisterType.COIL, start_address=1, values=[0]),
        ],
    )
    attacks = build_attacks_from_scenario(scenario)
    assert len(attacks) == 1
    uw = attacks[0]
    assert isinstance(uw, UnauthorizedWriteAttack)
    assert uw.target_registers == {3: 200}
    assert uw.target_coils == {1: False}


def test_many_coil_writes_become_bruteforce():
    steps = [
        AttackStep(order=i, description="c", function_code=5,
                   register_type=RegisterType.COIL, start_address=i, values=[1])
        for i in range(5)
    ]
    scenario = AttackScenario(name="t", description="d", objective="o", steps=steps)
    attacks = build_attacks_from_scenario(scenario)
    assert len(attacks) == 1
    assert isinstance(attacks[0], CoilBruteforceAttack)


def test_read_steps_become_register_scan():
    scenario = AttackScenario(
        name="t", description="d", objective="o",
        steps=[AttackStep(order=1, description="r", function_code=3,
                          start_address=0, count=10)],
    )
    attacks = build_attacks_from_scenario(scenario)
    assert len(attacks) == 1
    assert isinstance(attacks[0], RegisterScanAttack)
