"""Tests for the Modbus attack library, run against a real in-process PLC
slave started on a random localhost port (see the ``plc`` fixture).

These are true behavioural tests: effects are verified by reading the PLC
back with an independent client, not just by trusting the attack's own report.
"""

from __future__ import annotations

from pymodbus.client import AsyncModbusTcpClient

from ot_twin.attacks.coil_bruteforce import CoilBruteforceAttack
from ot_twin.attacks.register_scan import RegisterScanAttack
from ot_twin.attacks.scapy_crafted import ScapyCraftedAttack, build_modbus_tcp_frame
from ot_twin.attacks.unauthorized_write import UnauthorizedWriteAttack
from ot_twin.config import PLC_UNIT_ID


async def _read_holding(host, port, address):
    client = AsyncModbusTcpClient(host, port=port)
    await client.connect()
    try:
        rr = await client.read_holding_registers(
            address=address, count=1, device_id=PLC_UNIT_ID,
        )
        assert not rr.isError()
        return rr.registers[0]
    finally:
        client.close()


async def test_register_scan_discovers_registers(plc, historian):
    host, port = plc
    attack = RegisterScanAttack(
        host=host, port=port, historian=historian,
        holding_range=(0, 11), input_range=(0, 8), coil_range=(0, 8),
    )
    result = await attack.run()
    assert result.success
    # The PLC ships with non-zero defaults (setpoints, open valves), so a scan
    # must surface some of them.
    assert len(result.registers_affected) > 0
    # Transactions were logged to the historian and flagged as attack traffic.
    txs = historian.get_recent_transactions(100)
    assert txs
    assert all(t["is_attack"] == 1 for t in txs)
    assert {t["attack_type"] for t in txs} == {"register_scan"}


async def test_unauthorized_write_changes_register_on_plc(plc, historian):
    host, port = plc
    attack = UnauthorizedWriteAttack(
        host=host, port=port, historian=historian,
        target_registers={1: 77},  # inflow rate setpoint
    )
    result = await attack.run()
    assert result.success
    assert result.values_after.get(1) == 77
    # Independently confirm the value actually persisted on the PLC.
    assert await _read_holding(host, port, 1) == 77


async def test_unauthorized_write_coerces_string_keys(plc, historian):
    """CLI params arrive as JSON with string keys; the attack must coerce them
    to int Modbus addresses (regression for the README -p example)."""
    host, port = plc
    attack = UnauthorizedWriteAttack(
        host=host, port=port, historian=historian,
        target_registers={"5": 88},  # string key, pressure setpoint
    )
    result = await attack.run()
    assert result.success
    assert 5 in attack.target_registers  # coerced to int
    assert await _read_holding(host, port, 5) == 88


async def test_coil_bruteforce_finds_responsive_coils(plc, historian):
    host, port = plc
    attack = CoilBruteforceAttack(
        host=host, port=port, historian=historian,
        coil_range=(0, 6), toggle_delay=0.0, restore=True,
    )
    result = await attack.run()
    assert result.success
    assert len(result.registers_affected) > 0
    # With restore=True the original coil states are put back.
    assert attack.restore is True


async def test_failed_connection_reports_gracefully(historian):
    """Pointing an attack at a dead port yields a clean failure, not a crash."""
    attack = RegisterScanAttack(host="127.0.0.1", port=1, historian=historian)
    result = await attack.run()
    assert result.success is False
    assert "Connection failed" in result.details


async def test_scapy_crafted_raw_frame_write(plc, historian):
    host, port = plc
    attack = ScapyCraftedAttack(
        host=host, port=port, historian=historian,
        payloads=[{"function_code": 6, "address": 0, "values": [123]}],
    )
    result = await attack.run()
    assert result.success
    assert await _read_holding(host, port, 0) == 123


def test_build_modbus_tcp_frame_structure():
    # FC6 write-single-register frame: MBAP header (7 bytes) + FC + 4 data bytes
    frame = build_modbus_tcp_frame(
        transaction_id=1, unit_id=1, function_code=6, data=b"\x00\x00\x00\x63",
    )
    assert frame[:2] == b"\x00\x01"          # transaction id
    assert frame[2:4] == b"\x00\x00"          # protocol id (Modbus)
    assert frame[4:6] == b"\x00\x06"          # length = unit + fc + 4 data
    assert frame[6] == 1                        # unit id
    assert frame[7] == 6                        # function code
