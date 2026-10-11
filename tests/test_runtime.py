import asyncio

import pytest
from pymodbus.client import AsyncModbusTcpClient

from ot_twin.environment.plc_slave import PLCSlave
from ot_twin.environment.register_map import HOLDING_REGISTERS, COILS
from ot_twin.llm_generator.mitre_mapping import load_techniques


def test_packaged_mitre_catalog_is_available():
    assert any(t.technique_id == 'T0855' for t in load_techniques())


@pytest.mark.asyncio
async def test_register_defaults_use_protocol_addresses():
    plc = PLCSlave(port=0)
    for entry in HOLDING_REGISTERS:
        assert plc._read_holding(entry.address) == int(entry.default_value)
    for entry in COILS:
        assert plc._read_coil(entry.address) == bool(int(entry.default_value))


@pytest.mark.asyncio
async def test_plc_starts_ready_and_releases_port():
    plc = PLCSlave(port=0)
    await plc.start_background()
    client = AsyncModbusTcpClient('127.0.0.1', port=plc.port)
    try:
        assert await client.connect()
        result = await client.read_holding_registers(0, count=4, device_id=1)
        assert not result.isError()
        assert result.registers == [int(e.default_value) for e in HOLDING_REGISTERS[:4]]
    finally:
        client.close()
        await plc.stop()
    replacement = await asyncio.start_server(lambda r, w: w.close(), '127.0.0.1', plc.port)
    replacement.close()
    await replacement.wait_closed()


@pytest.mark.asyncio
async def test_bind_failure_is_reported_without_simulation_task():
    listener = await asyncio.start_server(lambda r, w: w.close(), '127.0.0.1', 0)
    plc = PLCSlave(port=listener.sockets[0].getsockname()[1])
    try:
        with pytest.raises(RuntimeError, match='listen'):
            await plc.start_background()
        assert not plc._running
        assert plc._sim_task is None
    finally:
        listener.close()
        await listener.wait_closed()
        await plc.stop()
