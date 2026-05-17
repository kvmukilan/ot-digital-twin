"""
Attack registry — central lookup for all available attacks.
"""

from __future__ import annotations

from ot_twin.attacks.base import BaseAttack
from ot_twin.attacks.coil_bruteforce import CoilBruteforceAttack
from ot_twin.attacks.register_scan import RegisterScanAttack
from ot_twin.attacks.replay import ReplayAttack
from ot_twin.attacks.scapy_crafted import ScapyCraftedAttack
from ot_twin.attacks.unauthorized_write import UnauthorizedWriteAttack

ATTACK_REGISTRY: dict[str, type[BaseAttack]] = {
    "register_scan": RegisterScanAttack,
    "unauthorized_write": UnauthorizedWriteAttack,
    "coil_bruteforce": CoilBruteforceAttack,
    "scapy_crafted": ScapyCraftedAttack,
    "replay": ReplayAttack,
}


def get_attack(name: str) -> type[BaseAttack] | None:
    """Look up an attack class by name."""
    return ATTACK_REGISTRY.get(name)


def list_attacks() -> list[dict[str, str]]:
    """Return metadata for all registered attacks."""
    return [
        {
            "name": cls.name,
            "description": cls.description,
            "mitre_techniques": ", ".join(cls.mitre_techniques),
        }
        for cls in ATTACK_REGISTRY.values()
    ]
