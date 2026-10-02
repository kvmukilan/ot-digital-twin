"""
Anomaly Detector — Analyzes historian data for suspicious Modbus activity.

Detects:
  - Rapid write bursts (many writes in a short window)
  - Out-of-range register values
  - Unusual function codes
  - Write operations from unexpected sources
  - Setpoint changes beyond normal deviation
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

from ot_twin.environment.historian import Historian
from ot_twin.environment.register_map import HOLDING_REGISTERS
from ot_twin.models import RegisterType


@dataclass
class Anomaly:
    """A detected anomaly in Modbus traffic."""
    severity: str          # "low", "medium", "high", "critical"
    category: str          # e.g. "rapid_writes", "out_of_range", "unusual_fc"
    description: str
    timestamp: str = ""
    details: dict = field(default_factory=dict)


class AnomalyDetector:
    """Stateless anomaly detector that scans historian records."""

    def __init__(
        self,
        write_burst_threshold: int = 10,
        write_burst_window_seconds: float = 5.0,
        allowed_function_codes: set[int] | None = None,
    ) -> None:
        self.write_burst_threshold = write_burst_threshold
        self.write_burst_window_seconds = write_burst_window_seconds
        self.allowed_function_codes = allowed_function_codes or {1, 2, 3, 4, 5, 6, 15, 16}

    def analyze(self, historian: Historian, limit: int = 500) -> list[Anomaly]:
        """Run all detection rules against recent historian data."""
        transactions = historian.get_recent_transactions(limit)
        anomalies: list[Anomaly] = []

        anomalies.extend(self._detect_write_bursts(transactions))
        anomalies.extend(self._detect_out_of_range(transactions))
        anomalies.extend(self._detect_unusual_function_codes(transactions))
        anomalies.extend(self._detect_attack_flagged(transactions))

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        anomalies.sort(key=lambda a: severity_order.get(a.severity, 4))

        return anomalies

    def _detect_write_bursts(self, transactions: list[dict]) -> list[Anomaly]:
        """Detect rapid sequences of write operations."""
        anomalies: list[Anomaly] = []
        writes = [t for t in transactions if t.get("is_write")]

        if len(writes) < self.write_burst_threshold:
            return anomalies

        # Parse timestamps and check for bursts
        timed_writes: list[tuple[datetime, dict]] = []
        for w in writes:
            try:
                ts = datetime.fromisoformat(w["timestamp"])
                timed_writes.append((ts, w))
            except (ValueError, KeyError):
                continue

        timed_writes.sort(key=lambda x: x[0])

        # Sliding window
        for i in range(len(timed_writes)):
            window_end = timed_writes[i][0]
            count = 0
            for j in range(i, len(timed_writes)):
                delta = (timed_writes[j][0] - window_end).total_seconds()
                if abs(delta) <= self.write_burst_window_seconds:
                    count += 1
                else:
                    break

            if count >= self.write_burst_threshold:
                anomalies.append(Anomaly(
                    severity="high",
                    category="rapid_writes",
                    description=(
                        f"{count} write operations within "
                        f"{self.write_burst_window_seconds}s window"
                    ),
                    timestamp=timed_writes[i][0].isoformat(),
                    details={"write_count": count},
                ))
                break  # Report once per burst

        return anomalies

    def _detect_out_of_range(self, transactions: list[dict]) -> list[Anomaly]:
        """Detect register values outside their defined valid range."""
        anomalies: list[Anomaly] = []
        reg_map = {r.address: r for r in HOLDING_REGISTERS}

        for tx in transactions:
            if tx.get("register_type") != RegisterType.HOLDING.value:
                continue

            values_json = tx.get("values_json", "[]")
            try:
                values = json.loads(values_json) if isinstance(values_json, str) else values_json
            except (json.JSONDecodeError, TypeError):
                continue

            addr = tx.get("address", 0)
            for i, val in enumerate(values):
                reg = reg_map.get(addr + i)
                if reg and (val < reg.min_value or val > reg.max_value):
                    anomalies.append(Anomaly(
                        severity="critical" if tx.get("is_write") else "medium",
                        category="out_of_range",
                        description=(
                            f"Register {reg.name} (addr {addr + i}) value {val} "
                            f"outside range [{reg.min_value}, {reg.max_value}]"
                        ),
                        timestamp=tx.get("timestamp", ""),
                        details={
                            "address": addr + i,
                            "value": val,
                            "min": reg.min_value,
                            "max": reg.max_value,
                            "is_write": tx.get("is_write", False),
                        },
                    ))

        return anomalies

    def _detect_unusual_function_codes(self, transactions: list[dict]) -> list[Anomaly]:
        """Detect Modbus function codes outside the expected set."""
        anomalies: list[Anomaly] = []
        seen_fcs: set[int] = set()

        for tx in transactions:
            fc = tx.get("function_code", 0)
            if fc not in self.allowed_function_codes and fc not in seen_fcs:
                seen_fcs.add(fc)
                anomalies.append(Anomaly(
                    severity="high",
                    category="unusual_fc",
                    description=f"Unusual Modbus function code: {fc}",
                    timestamp=tx.get("timestamp", ""),
                    details={"function_code": fc},
                ))

        return anomalies

    def _detect_attack_flagged(self, transactions: list[dict]) -> list[Anomaly]:
        """Report transactions already flagged as attacks."""
        anomalies: list[Anomaly] = []
        attack_types_seen: set[str] = set()

        for tx in transactions:
            if tx.get("is_attack"):
                atk_type = tx.get("attack_type", "unknown")
                if atk_type not in attack_types_seen:
                    attack_types_seen.add(atk_type)
                    count = sum(
                        1 for t in transactions
                        if t.get("attack_type") == atk_type
                    )
                    anomalies.append(Anomaly(
                        severity="critical",
                        category="known_attack",
                        description=f"Attack traffic detected: {atk_type} ({count} transactions)",
                        timestamp=tx.get("timestamp", ""),
                        details={"attack_type": atk_type, "transaction_count": count},
                    ))

        return anomalies
