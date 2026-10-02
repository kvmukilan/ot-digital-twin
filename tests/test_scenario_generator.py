"""Tests for the LLM scenario generator.

The real OpenAI/LangChain client is NEVER called: offline runs fall back to
rule-based generation, and the LLM path is exercised with a mocked client.
"""

from __future__ import annotations

import json

import ot_twin.llm_generator.scenario_generator as sg
from ot_twin.llm_generator.scenario_generator import (
    _generate_rule_based,
    _parse_scenario_json,
    generate_scenario,
)
from ot_twin.models import RegisterType


def test_get_llm_is_none_without_credentials():
    # The autouse fixture blanks all keys, so no client may be constructed.
    assert sg._get_llm() is None


def test_rule_based_overflow_closes_outlet_and_maxes_inflow():
    scenario = _generate_rule_based("overflow the water tank")
    assert scenario.name == "rule_based_scenario"
    fcs = {(s.function_code, s.start_address) for s in scenario.steps}
    assert (5, 1) in fcs   # close outlet valve (coil 1)
    assert (6, 1) in fcs   # max inflow setpoint (HR 1)
    assert scenario.mitre_techniques


def test_rule_based_shutdown_hits_emergency_stop():
    # The README's marquee example; "shut down" (with a space) must map to the
    # shutdown branch and activate the emergency-stop coil (address 5).
    scenario = _generate_rule_based("shut down the entire plant")
    assert any(s.function_code == 5 and s.start_address == 5 for s in scenario.steps)


def test_rule_based_chemical_sets_dangerous_ph():
    scenario = _generate_rule_based("contaminate the water by poisoning the pH")
    assert any(s.function_code == 6 and s.start_address == 3 for s in scenario.steps)


def test_generate_scenario_offline_uses_rule_based():
    scenario = generate_scenario("overflow the tank")
    assert scenario.name == "rule_based_scenario"


def test_generate_scenario_with_mocked_llm(monkeypatch):
    calls = {"n": 0}

    class FakeMessage:
        def __init__(self, content):
            self.content = content

    class FakeLLM:
        def invoke(self, messages):
            calls["n"] += 1
            return FakeMessage(json.dumps({
                "name": "llm_overflow",
                "description": "generated",
                "objective": "overflow the tank",
                "estimated_impact": "flooding",
                "mitre_techniques": ["T0831", "T0836"],
                "steps": [
                    {"order": 1, "description": "close outlet", "function_code": 5,
                     "register_type": "coil", "start_address": 1, "values": [0]},
                    {"order": 2, "description": "max inflow", "function_code": 6,
                     "register_type": "holding_register", "start_address": 1,
                     "values": [100]},
                ],
                "detection_indicators": ["valve closed while inflow rising"],
            }))

    monkeypatch.setattr(sg, "_get_llm", lambda: FakeLLM())
    scenario = generate_scenario("overflow the tank")

    assert calls["n"] == 1  # the LLM path was taken exactly once
    assert scenario.name == "llm_overflow"
    assert len(scenario.steps) == 2
    assert {t.technique_id for t in scenario.mitre_techniques} == {"T0831", "T0836"}
    assert scenario.detection_indicators == ["valve closed while inflow rising"]


def test_generate_scenario_falls_back_when_llm_raises(monkeypatch):
    class BoomLLM:
        def invoke(self, messages):
            raise RuntimeError("network unavailable")

    monkeypatch.setattr(sg, "_get_llm", lambda: BoomLLM())
    scenario = generate_scenario("overflow the tank")
    assert scenario.name == "rule_based_scenario"  # graceful offline fallback


def test_parse_scenario_json_strips_markdown_fences():
    raw = (
        "```json\n"
        + json.dumps({
            "name": "x",
            "objective": "o",
            "mitre_techniques": ["T0855"],
            "steps": [
                {"order": 1, "description": "d", "function_code": 6,
                 "register_type": "holding_register", "start_address": 0,
                 "values": [1]},
            ],
        })
        + "\n```"
    )
    scenario = _parse_scenario_json(raw, "desc")
    assert scenario.name == "x"
    assert scenario.steps[0].register_type == RegisterType.HOLDING
    assert scenario.mitre_techniques[0].technique_id == "T0855"
