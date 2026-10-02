"""
SCADA Master — Modbus TCP client that polls the PLC and displays process data.

Periodically reads all registers, logs to the historian, and provides
methods for sending control commands.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from pymodbus.client import AsyncModbusTcpClient

from ot_twin.config import PLC_HOST, PLC_PORT, PLC_UNIT_ID, SCADA_POLL_INTERVAL
from ot_twin.environment.historian import Historian
from ot_twin.models import ModbusTransaction, ProcessState, RegisterType

logger = logging.getLogger(__name__)


class SCADAMaster:
    """Async SCADA HMI that polls PLC registers and logs to historian."""

    def __init__(
        self,
        host: str = PLC_HOST,
        port: int = PLC_PORT,
        historian: Historian | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.client = AsyncModbusTcpClient(host, port=port)
        self.historian = historian or Historian()
        self._running = False
        self._poll_task: asyncio.Task | None = None
        self.last_state: ProcessState | None = None

    async def connect(self) -> bool:
        """Connect to the PLC."""
        connected = await self.client.connect()
        if connected:
            logger.info("SCADA connected to PLC at %s:%d", self.host, self.port)
        else:
            logger.error("SCADA failed to connect to PLC")
        return connected

    async def disconnect(self) -> None:
        """Disconnect from the PLC."""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._poll_task
        self.client.close()
        logger.info("SCADA disconnected")

    async def start_polling(self) -> None:
        """Start the periodic polling loop."""
        self._running = True
        self._poll_task = asyncio.create_task(self._poll_loop())

    async def _poll_loop(self) -> None:
        """Continuously poll PLC registers."""
        while self._running:
            try:
                state = await self.read_process_state()
                if state:
                    self.last_state = state
                    self.historian.log_process_snapshot(state)
                await asyncio.sleep(SCADA_POLL_INTERVAL)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("SCADA poll error")
                await asyncio.sleep(SCADA_POLL_INTERVAL)

    async def read_process_state(self) -> ProcessState | None:
        """Read all PLC registers and return a ProcessState snapshot."""
        try:
            # Read input registers (sensor values)
            ir = await self.client.read_input_registers(
                address=0, count=8, device_id=PLC_UNIT_ID
            )
            if ir.isError():
                logger.error("Failed to read input registers: %s", ir)
                return None

            self.historian.log_transaction(ModbusTransaction(
                function_code=4, register_type=RegisterType.INPUT,
                address=0, count=8, values=list(ir.registers),
            ))

            # Read coils (actuator states)
            coils = await self.client.read_coils(
                address=0, count=8, device_id=PLC_UNIT_ID
            )
            if coils.isError():
                logger.error("Failed to read coils: %s", coils)
                return None

            self.historian.log_transaction(ModbusTransaction(
                function_code=1, register_type=RegisterType.COIL,
                address=0, count=8, values=[int(b) for b in coils.bits[:8]],
            ))

            # Read discrete inputs (alarms)
            di = await self.client.read_discrete_inputs(
                address=0, count=8, device_id=PLC_UNIT_ID
            )
            if di.isError():
                logger.error("Failed to read discrete inputs: %s", di)
                return None

            self.historian.log_transaction(ModbusTransaction(
                function_code=2, register_type=RegisterType.DISCRETE_INPUT,
                address=0, count=8, values=[int(b) for b in di.bits[:8]],
            ))

            return ProcessState(
                tank_level=float(ir.registers[0]),
                inflow_rate=float(ir.registers[1]),
                outflow_rate=float(ir.registers[2]),
                ph_level=ir.registers[3] / 100.0,
                chlorine_dosing=ir.registers[4] / 100.0,
                turbidity=ir.registers[5] / 100.0,
                pressure_psi=float(ir.registers[6]),
                temperature_c=ir.registers[7] / 10.0,
                inlet_valve_open=bool(coils.bits[0]),
                outlet_valve_open=bool(coils.bits[1]),
                pump_running=bool(coils.bits[2]),
                mixer_running=bool(coils.bits[3]),
                high_level_alarm=bool(di.bits[0]),
                low_level_alarm=bool(di.bits[1]),
                ph_alarm=bool(di.bits[2]),
                pressure_alarm=bool(di.bits[3]),
            )
        except Exception:
            logger.exception("Error reading process state")
            return None

    # ---- Control Commands ----

    async def write_holding_register(self, address: int, value: int) -> bool:
        """Write a single holding register."""
        result = await self.client.write_register(
            address=address, value=value, device_id=PLC_UNIT_ID
        )
        if result.isError():
            logger.error("Write holding register %d failed: %s", address, result)
            return False

        self.historian.log_transaction(ModbusTransaction(
            function_code=6, register_type=RegisterType.HOLDING,
            address=address, values=[value], is_write=True,
        ))
        return True

    async def write_coil(self, address: int, value: bool) -> bool:
        """Write a single coil."""
        result = await self.client.write_coil(
            address=address, value=value, device_id=PLC_UNIT_ID
        )
        if result.isError():
            logger.error("Write coil %d failed: %s", address, result)
            return False

        self.historian.log_transaction(ModbusTransaction(
            function_code=5, register_type=RegisterType.COIL,
            address=address, values=[int(value)], is_write=True,
        ))
        return True

    async def read_holding_registers(
        self, address: int = 0, count: int = 11,
    ) -> list[int] | None:
        """Read holding registers."""
        result = await self.client.read_holding_registers(
            address=address, count=count, device_id=PLC_UNIT_ID
        )
        if result.isError():
            logger.error("Read holding registers failed: %s", result)
            return None

        self.historian.log_transaction(ModbusTransaction(
            function_code=3, register_type=RegisterType.HOLDING,
            address=address, count=count, values=list(result.registers),
        ))
        return list(result.registers)

    async def emergency_stop(self) -> bool:
        """Activate emergency stop."""
        logger.warning("SCADA: EMERGENCY STOP activated")
        return await self.write_coil(5, True)

    async def clear_emergency_stop(self) -> bool:
        """Clear emergency stop."""
        logger.info("SCADA: Emergency stop cleared")
        return await self.write_coil(5, False)
