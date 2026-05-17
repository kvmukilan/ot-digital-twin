"""
PLC Slave — Modbus TCP server simulating a water treatment plant PLC.

Runs a pymodbus async server with a background process simulation loop that
updates input registers and discrete inputs based on the process model, while
holding registers and coils are writable by SCADA (or attackers).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartAsyncTcpServer

from ot_twin.config import PLC_HOST, PLC_PORT, PLC_UNIT_ID, PROCESS_TICK_SECONDS
from ot_twin.environment.process_model import WaterTreatmentProcess
from ot_twin.environment.register_map import (
    COILS,
    DISCRETE_INPUTS,
    HOLDING_REGISTERS,
    INPUT_REGISTERS,
)

logger = logging.getLogger(__name__)


def _build_data_block(
    entries: list[Any], size: int, *, is_bool: bool = False,
) -> ModbusSequentialDataBlock:
    """Create a data block initialized with default values."""
    if is_bool:
        values = [False] * size
        for entry in entries:
            if entry.address < size:
                values[entry.address] = bool(int(entry.default_value))
    else:
        values = [0] * size
        for entry in entries:
            if entry.address < size:
                values[entry.address] = int(entry.default_value)
    # pymodbus uses 1-based addressing internally; address=0 -> offset 0
    return ModbusSequentialDataBlock(0, values)


class PLCSlave:
    """Async Modbus TCP server with integrated process simulation."""

    def __init__(
        self,
        host: str = PLC_HOST,
        port: int = PLC_PORT,
    ) -> None:
        self.host = host
        self.port = port
        self.process = WaterTreatmentProcess()
        self._running = False
        self._server_task: asyncio.Task | None = None
        self._sim_task: asyncio.Task | None = None

        # Build data store
        self.context = ModbusDeviceContext(
            di=_build_data_block(DISCRETE_INPUTS, 16, is_bool=True),
            co=_build_data_block(COILS, 16, is_bool=True),
            hr=_build_data_block(HOLDING_REGISTERS, 100),
            ir=_build_data_block(INPUT_REGISTERS, 50),
        )
        self.server_context = ModbusServerContext(
            devices={PLC_UNIT_ID: self.context}, single=False
        )

    async def start(self) -> None:
        """Start the PLC server and simulation loop."""
        self._running = True
        logger.info("PLC Slave starting on %s:%d", self.host, self.port)

        self._sim_task = asyncio.create_task(self._simulation_loop())

        await StartAsyncTcpServer(
            context=self.server_context,
            address=(self.host, self.port),
        )

    async def start_background(self) -> None:
        """Start PLC in the background, returning once the server is listening."""
        self._running = True
        logger.info("PLC Slave starting (background) on %s:%d", self.host, self.port)

        self._sim_task = asyncio.create_task(self._simulation_loop())
        self._server_task = asyncio.create_task(
            StartAsyncTcpServer(
                context=self.server_context,
                address=(self.host, self.port),
            )
        )
        # Give the server a moment to bind
        await asyncio.sleep(0.5)

    async def stop(self) -> None:
        """Stop the server and simulation."""
        self._running = False
        if self._sim_task:
            self._sim_task.cancel()
            try:
                await self._sim_task
            except asyncio.CancelledError:
                pass
        if self._server_task:
            self._server_task.cancel()
            try:
                await self._server_task
            except asyncio.CancelledError:
                pass
        logger.info("PLC Slave stopped")

    def _read_coil(self, address: int) -> bool:
        """Read a coil value from the data store."""
        values = self.context.getValues(1, address, count=1)  # FC 1
        return bool(values[0])

    def _read_holding(self, address: int) -> int:
        """Read a holding register from the data store."""
        values = self.context.getValues(3, address, count=1)  # FC 3
        return int(values[0])

    def _write_input_register(self, address: int, value: int) -> None:
        """Write to an input register (process → PLC direction)."""
        self.context.setValues(4, address, [value])  # FC 4

    def _write_discrete_input(self, address: int, value: bool) -> None:
        """Write to a discrete input (process → PLC direction)."""
        self.context.setValues(2, address, [value])  # FC 2

    async def _simulation_loop(self) -> None:
        """Periodically advance the process model and sync registers."""
        while self._running:
            try:
                # Read actuator commands from coils / holding registers
                inlet_valve = self._read_coil(0)
                outlet_valve = self._read_coil(1)
                pump_enable = self._read_coil(2)
                mixer_enable = self._read_coil(3)
                chlorine_pump = self._read_coil(4)
                estop = self._read_coil(5)

                inflow_sp = self._read_holding(1)
                outflow_sp = self._read_holding(2)
                ph_sp = self._read_holding(3) / 100.0
                chlorine_sp = self._read_holding(4) / 100.0
                pressure_sp = self._read_holding(5)
                temp_sp = self._read_holding(6) / 10.0

                # Tick the process model
                state = self.process.tick(
                    dt=PROCESS_TICK_SECONDS,
                    inlet_valve_open=inlet_valve,
                    outlet_valve_open=outlet_valve,
                    pump_running=pump_enable,
                    mixer_running=mixer_enable,
                    chlorine_pump_on=chlorine_pump,
                    emergency_stop=estop,
                    inflow_setpoint=float(inflow_sp),
                    outflow_setpoint=float(outflow_sp),
                    ph_setpoint=ph_sp,
                    chlorine_setpoint=chlorine_sp,
                    pressure_setpoint=float(pressure_sp),
                    temperature_setpoint=temp_sp,
                )

                # Write process values to input registers
                self._write_input_register(0, int(state.tank_level))
                self._write_input_register(1, int(state.inflow_rate))
                self._write_input_register(2, int(state.outflow_rate))
                self._write_input_register(3, int(state.ph_level * 100))
                self._write_input_register(4, int(state.chlorine_dosing * 100))
                self._write_input_register(5, int(state.turbidity * 100))
                self._write_input_register(6, int(state.pressure_psi))
                self._write_input_register(7, int(state.temperature_c * 10))

                # Write alarm states to discrete inputs
                self._write_discrete_input(0, state.high_level_alarm)
                self._write_discrete_input(1, state.low_level_alarm)
                self._write_discrete_input(2, state.ph_alarm)
                self._write_discrete_input(3, state.pressure_alarm)
                self._write_discrete_input(7, True)  # system running

                await asyncio.sleep(PROCESS_TICK_SECONDS)

            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Simulation loop error")
                await asyncio.sleep(1)
