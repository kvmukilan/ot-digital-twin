"""
Payload Builder — Converts LLM-generated attack scenarios into executable attack objects.
"""

from __future__ import annotations

import logging

from ot_twin.attacks.base import BaseAttack
from ot_twin.attacks.coil_bruteforce import CoilBruteforceAttack
from ot_twin.attacks.register_scan import RegisterScanAttack
from ot_twin.attacks.scapy_crafted import ScapyCraftedAttack
from ot_twin.attacks.unauthorized_write import UnauthorizedWriteAttack
from ot_twin.config import PLC_HOST, PLC_PORT
from ot_twin.environment.historian import Historian
from ot_twin.models import AttackScenario, AttackStep

logger = logging.getLogger(__name__)


def build_attacks_from_scenario(
    scenario: AttackScenario,
    host: str = PLC_HOST,
    port: int = PLC_PORT,
    historian: Historian | None = None,
) -> list[BaseAttack]:
    """Convert an AttackScenario into a list of executable attack objects.

    Groups steps by type and creates the appropriate attack class for each group.
    """
    attacks: list[BaseAttack] = []

    # Separate steps by type
    register_writes: dict[int, int] = {}
    coil_writes: dict[int, bool] = {}
    scan_steps: list[AttackStep] = []
    raw_payloads: list[dict] = []

    for step in scenario.steps:
        fc = step.function_code

        if fc in (3, 4):
            # Read operations → register scan
            scan_steps.append(step)
        elif fc == 6:
            # Write single holding register
            if step.values:
                register_writes[step.start_address] = step.values[0]
        elif fc == 16:
            # Write multiple holding registers
            for i, v in enumerate(step.values):
                register_writes[step.start_address + i] = v
        elif fc == 5:
            # Write single coil
            if step.values:
                coil_writes[step.start_address] = bool(step.values[0])
        elif fc == 15:
            # Write multiple coils
            for i, v in enumerate(step.values):
                coil_writes[step.start_address + i] = bool(v)
        else:
            # Unknown FC → treat as raw crafted
            raw_payloads.append({
                "function_code": fc,
                "address": step.start_address,
                "values": step.values or [0],
            })

    # Build attack objects
    if scan_steps:
        attacks.append(RegisterScanAttack(
            host=host, port=port, historian=historian,
        ))

    if register_writes or coil_writes:
        attacks.append(UnauthorizedWriteAttack(
            host=host, port=port, historian=historian,
            target_registers=register_writes if register_writes else None,
            target_coils=coil_writes if coil_writes else None,
        ))

    if raw_payloads:
        attacks.append(ScapyCraftedAttack(
            host=host, port=port, historian=historian,
            payloads=raw_payloads,
        ))

    # If only coil writes and scenario suggests brute-force
    if coil_writes and not register_writes and len(coil_writes) > 3:
        attacks.clear()
        min_addr = min(coil_writes.keys())
        max_addr = max(coil_writes.keys()) + 1
        attacks.append(CoilBruteforceAttack(
            host=host, port=port, historian=historian,
            coil_range=(min_addr, max_addr),
        ))

    logger.info(
        "Built %d attack(s) from scenario '%s'",
        len(attacks), scenario.name,
    )
    return attacks
