"""
MITRE ATT&CK for ICS technique mapping.

Loads the technique database and maps attack keywords to relevant techniques.
"""

from __future__ import annotations

import json
from pathlib import Path

from ot_twin.config import MITRE_ICS_DATA_PATH
from ot_twin.models import MitreTechnique

_TECHNIQUE_CACHE: list[MitreTechnique] | None = None

# Keyword → technique ID mapping for rule-based fallback
KEYWORD_MAP: dict[str, list[str]] = {
    "scan": ["T0802", "T0861"],
    "enumerate": ["T0802", "T0861"],
    "reconnaissance": ["T0802", "T0861"],
    "discovery": ["T0861"],
    "write": ["T0855", "T0836"],
    "modify": ["T0836", "T0831"],
    "change": ["T0836", "T0831"],
    "setpoint": ["T0836"],
    "parameter": ["T0836"],
    "command": ["T0855"],
    "unauthorized": ["T0855"],
    "inject": ["T0855", "T0830"],
    "manipulate": ["T0831", "T0835"],
    "control": ["T0831", "T0827"],
    "toggle": ["T0855", "T0831"],
    "coil": ["T0855", "T0831"],
    "valve": ["T0831", "T0879"],
    "pump": ["T0831", "T0879"],
    "overflow": ["T0831", "T0879"],
    "spoof": ["T0856", "T0830"],
    "man in the middle": ["T0830"],
    "mitm": ["T0830"],
    "damage": ["T0879"],
    "safety": ["T0880"],
    "denial": ["T0814", "T0826"],
    "dos": ["T0814", "T0826"],
    "shutdown": ["T0826", "T0827"],
    "shut down": ["T0826", "T0827"],
    "stop": ["T0826", "T0827"],
    "alarm": ["T0880", "T0829"],
    "sensor": ["T0856", "T0835"],
    "craft": ["T0855", "T0830"],
    "raw": ["T0855", "T0830"],
    "packet": ["T0855", "T0830"],
}


def load_techniques() -> list[MitreTechnique]:
    """Load MITRE ICS techniques from the JSON data file."""
    global _TECHNIQUE_CACHE
    if _TECHNIQUE_CACHE is not None:
        return _TECHNIQUE_CACHE

    data_path = Path(MITRE_ICS_DATA_PATH)
    if not data_path.exists():
        return []

    with open(data_path) as f:
        data = json.load(f)

    _TECHNIQUE_CACHE = [
        MitreTechnique(**t) for t in data.get("techniques", [])
    ]
    return _TECHNIQUE_CACHE


def get_technique(technique_id: str) -> MitreTechnique | None:
    """Look up a technique by ID."""
    for t in load_techniques():
        if t.technique_id == technique_id:
            return t
    return None


def map_description_to_techniques(description: str) -> list[MitreTechnique]:
    """Map a natural-language attack description to MITRE techniques.

    Uses keyword matching as a rule-based fallback when the LLM is unavailable.
    """
    description_lower = description.lower()
    matched_ids: set[str] = set()

    for keyword, technique_ids in KEYWORD_MAP.items():
        if keyword in description_lower:
            matched_ids.update(technique_ids)

    # Deduplicate and resolve to full technique objects
    techniques = []
    for tid in sorted(matched_ids):
        t = get_technique(tid)
        if t:
            techniques.append(t)

    # Always include at least T0855 if nothing matched (generic unauthorized command)
    if not techniques:
        t = get_technique("T0855")
        if t:
            techniques.append(t)

    return techniques
