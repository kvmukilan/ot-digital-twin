"""Tests for MITRE ATT&CK for ICS technique loading and keyword mapping."""

from __future__ import annotations

from ot_twin.attacks.registry import ATTACK_REGISTRY
from ot_twin.llm_generator.mitre_mapping import (
    KEYWORD_MAP,
    get_technique,
    load_techniques,
    map_description_to_techniques,
)
from ot_twin.llm_generator.scenario_library import SCENARIO_LIBRARY


def _valid_ids() -> set[str]:
    return {t.technique_id for t in load_techniques()}


def test_load_techniques_nonempty_and_well_formed():
    techs = load_techniques()
    assert len(techs) >= 16
    for t in techs:
        assert t.technique_id.startswith("T")
        assert t.name
        assert t.tactic


def test_get_technique_resolves_and_misses():
    t = get_technique("T0831")
    assert t is not None
    assert t.name == "Manipulation of Control"
    assert get_technique("T9999") is None


def test_keyword_mapping_matches_expected_techniques():
    techs = map_description_to_techniques("overflow the tank by manipulating the valve")
    ids = {t.technique_id for t in techs}
    assert "T0831" in ids  # manipulate / overflow / valve


def test_keyword_mapping_falls_back_to_unauthorized_command():
    techs = map_description_to_techniques("completely unrelated phrase xyzzy")
    assert [t.technique_id for t in techs] == ["T0855"]


def test_every_keyword_map_id_exists_in_dataset():
    valid = _valid_ids()
    for ids in KEYWORD_MAP.values():
        for tid in ids:
            assert tid in valid, f"KEYWORD_MAP references unknown technique {tid}"


def test_every_attack_technique_resolves():
    valid = _valid_ids()
    for cls in ATTACK_REGISTRY.values():
        for tid in cls.mitre_techniques:
            assert tid in valid, f"{cls.name} references unknown technique {tid}"


def test_every_scenario_library_technique_resolves():
    valid = _valid_ids()
    for scenario in SCENARIO_LIBRARY.values():
        assert scenario.mitre_techniques, f"{scenario.name} has no techniques"
        for t in scenario.mitre_techniques:
            assert t.technique_id in valid
