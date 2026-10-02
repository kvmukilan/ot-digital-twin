"""
Base class for all Modbus attacks.

Every attack follows the same lifecycle:
  1. connect()  — establish Modbus TCP session
  2. execute()  — run the attack, logging transactions
  3. cleanup()  — close the connection
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from pymodbus.client import AsyncModbusTcpClient

from ot_twin.config import PLC_HOST, PLC_PORT, PLC_UNIT_ID
from ot_twin.environment.historian import Historian
from ot_twin.models import AttackResult, ModbusTransaction

logger = logging.getLogger(__name__)


class BaseAttack(ABC):
    """Abstract base class for Modbus TCP attacks."""

    name: str = "base_attack"
    description: str = "Base attack"
    mitre_techniques: ClassVar[list[str]] = []

    def __init__(
        self,
        host: str = PLC_HOST,
        port: int = PLC_PORT,
        unit_id: int = PLC_UNIT_ID,
        historian: Historian | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.unit_id = unit_id
        # The client is created lazily in connect() rather than here: pymodbus
        # 3.x binds the client to the running event loop at construction time
        # (asyncio.get_running_loop()), so building it in __init__ crashed when
        # attacks are instantiated outside a loop — e.g. build_attacks_from_
        # scenario() in the `generate --execute` and `scenarios --run` commands.
        self.client: AsyncModbusTcpClient | None = None
        self.historian = historian
        self.transactions: list[ModbusTransaction] = []

    async def connect(self) -> bool:
        """Connect to the target PLC."""
        self.client = AsyncModbusTcpClient(self.host, port=self.port)
        connected = await self.client.connect()
        if connected:
            logger.info("[%s] Connected to %s:%d", self.name, self.host, self.port)
        else:
            logger.error("[%s] Connection failed", self.name)
        return connected

    async def cleanup(self) -> None:
        """Close the connection."""
        if self.client is not None:
            self.client.close()
        logger.info("[%s] Connection closed", self.name)

    def _log_transaction(self, tx: ModbusTransaction) -> None:
        """Record a transaction for reporting and historian."""
        tx.is_attack = True
        tx.attack_type = self.name
        self.transactions.append(tx)
        if self.historian:
            self.historian.log_transaction(tx)

    @abstractmethod
    async def execute(self) -> AttackResult:
        """Run the attack. Must be implemented by subclasses."""
        ...

    async def run(self) -> AttackResult:
        """Full attack lifecycle: connect → execute → cleanup."""
        start_time = datetime.now()
        self.transactions = []

        if not await self.connect():
            return AttackResult(
                attack_name=self.name,
                success=False,
                start_time=start_time,
                end_time=datetime.now(),
                details="Connection failed",
                mitre_techniques=self.mitre_techniques,
            )

        try:
            result = await self.execute()
            result.start_time = start_time
            result.end_time = datetime.now()
            result.mitre_techniques = self.mitre_techniques
            result.transactions = self.transactions

            if self.historian:
                self.historian.log_attack_result(result)

            return result
        except Exception as e:
            logger.exception("[%s] Attack failed", self.name)
            return AttackResult(
                attack_name=self.name,
                success=False,
                start_time=start_time,
                end_time=datetime.now(),
                details=f"Exception: {e}",
                mitre_techniques=self.mitre_techniques,
            )
        finally:
            await self.cleanup()
