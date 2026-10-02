"""
Register Scan Attack — Enumerates all Modbus registers to map the PLC address space.

MITRE ATT&CK for ICS:
  T0802 — Automated Collection
  T0861 — Point & Tag Identification
"""

from __future__ import annotations

import logging
from typing import ClassVar

from ot_twin.attacks.base import BaseAttack
from ot_twin.models import AttackResult, ModbusTransaction, RegisterType

logger = logging.getLogger(__name__)


class RegisterScanAttack(BaseAttack):
    name = "register_scan"
    description = "Enumerate holding/input registers to map PLC address space"
    mitre_techniques: ClassVar[list[str]] = ["T0802", "T0861"]

    def __init__(
        self,
        *args,
        holding_range: tuple[int, int] = (0, 100),
        input_range: tuple[int, int] = (0, 50),
        coil_range: tuple[int, int] = (0, 16),
        scan_batch_size: int = 10,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.holding_range = holding_range
        self.input_range = input_range
        self.coil_range = coil_range
        self.scan_batch_size = scan_batch_size

    async def execute(self) -> AttackResult:
        discovered: dict[str, dict[int, int]] = {
            "holding": {},
            "input": {},
            "coils": {},
        }

        # Scan holding registers
        for start in range(self.holding_range[0], self.holding_range[1], self.scan_batch_size):
            count = min(self.scan_batch_size, self.holding_range[1] - start)
            result = await self.client.read_holding_registers(
                address=start, count=count, device_id=self.unit_id,
            )
            if not result.isError():
                for i, val in enumerate(result.registers):
                    if val != 0:
                        discovered["holding"][start + i] = val
                self._log_transaction(ModbusTransaction(
                    function_code=3,
                    register_type=RegisterType.HOLDING,
                    address=start, count=count,
                    values=list(result.registers),
                ))
            logger.debug("Scanned HR %d-%d", start, start + count)

        # Scan input registers
        for start in range(self.input_range[0], self.input_range[1], self.scan_batch_size):
            count = min(self.scan_batch_size, self.input_range[1] - start)
            result = await self.client.read_input_registers(
                address=start, count=count, device_id=self.unit_id,
            )
            if not result.isError():
                for i, val in enumerate(result.registers):
                    if val != 0:
                        discovered["input"][start + i] = val
                self._log_transaction(ModbusTransaction(
                    function_code=4,
                    register_type=RegisterType.INPUT,
                    address=start, count=count,
                    values=list(result.registers),
                ))

        # Scan coils
        for start in range(self.coil_range[0], self.coil_range[1], self.scan_batch_size):
            count = min(self.scan_batch_size, self.coil_range[1] - start)
            result = await self.client.read_coils(
                address=start, count=count, device_id=self.unit_id,
            )
            if not result.isError():
                for i, val in enumerate(result.bits[:count]):
                    if val:
                        discovered["coils"][start + i] = int(val)
                self._log_transaction(ModbusTransaction(
                    function_code=1,
                    register_type=RegisterType.COIL,
                    address=start, count=count,
                    values=[int(b) for b in result.bits[:count]],
                ))

        total_found = sum(len(v) for v in discovered.values())
        details = (
            f"Discovered {total_found} non-zero registers: "
            f"{len(discovered['holding'])} holding, "
            f"{len(discovered['input'])} input, "
            f"{len(discovered['coils'])} coils"
        )
        logger.info("[%s] %s", self.name, details)

        all_addrs = (
            list(discovered["holding"].keys())
            + list(discovered["input"].keys())
            + list(discovered["coils"].keys())
        )

        return AttackResult(
            attack_name=self.name,
            success=total_found > 0,
            details=details,
            registers_affected=all_addrs,
            values_after={**discovered["holding"], **discovered["input"], **discovered["coils"]},
        )
