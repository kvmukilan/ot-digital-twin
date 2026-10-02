"""
Traffic Analyzer — Generates summary statistics from historian Modbus traffic.

Produces concise reports useful for incident response:
  - Function code distribution
  - Read vs write ratio
  - Most targeted register addresses
  - Attack traffic percentage
  - Timeline (transactions per minute)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TrafficSummary:
    """Summary statistics for Modbus traffic."""
    total_transactions: int = 0
    total_reads: int = 0
    total_writes: int = 0
    total_attacks: int = 0
    function_code_counts: dict[int, int] = field(default_factory=dict)
    register_type_counts: dict[str, int] = field(default_factory=dict)
    top_write_targets: list[tuple[int, int]] = field(default_factory=list)
    top_read_targets: list[tuple[int, int]] = field(default_factory=list)
    attack_type_counts: dict[str, int] = field(default_factory=dict)
    unique_source_ips: set[str] = field(default_factory=set)
    first_timestamp: str = ""
    last_timestamp: str = ""
    transactions_per_minute: float = 0.0

    @property
    def read_write_ratio(self) -> str:
        if self.total_writes == 0:
            return f"{self.total_reads}:0"
        ratio = self.total_reads / self.total_writes
        return f"{ratio:.1f}:1"

    @property
    def attack_percentage(self) -> float:
        if self.total_transactions == 0:
            return 0.0
        return (self.total_attacks / self.total_transactions) * 100


def analyze_traffic(transactions: list[dict], top_n: int = 5) -> TrafficSummary:
    """Analyze a list of historian transaction records.

    Args:
        transactions: List of dicts from historian.get_recent_transactions().
        top_n: Number of top targets to include.

    Returns:
        A TrafficSummary with computed statistics.
    """
    summary = TrafficSummary()
    summary.total_transactions = len(transactions)

    if not transactions:
        return summary

    fc_counter: Counter[int] = Counter()
    rt_counter: Counter[str] = Counter()
    write_targets: Counter[int] = Counter()
    read_targets: Counter[int] = Counter()
    attack_types: Counter[str] = Counter()
    timestamps: list[datetime] = []

    for tx in transactions:
        fc = tx.get("function_code", 0)
        fc_counter[fc] += 1

        rt = tx.get("register_type", "")
        if rt:
            rt_counter[rt] += 1

        addr = tx.get("address", 0)
        is_write = tx.get("is_write", False)

        if is_write:
            summary.total_writes += 1
            write_targets[addr] += 1
        else:
            summary.total_reads += 1
            read_targets[addr] += 1

        if tx.get("is_attack"):
            summary.total_attacks += 1
            atk_type = tx.get("attack_type", "unknown")
            if atk_type:
                attack_types[atk_type] += 1

        src = tx.get("source_ip", "")
        if src:
            summary.unique_source_ips.add(src)

        try:
            ts = datetime.fromisoformat(tx["timestamp"])
            timestamps.append(ts)
        except (ValueError, KeyError):
            pass

    summary.function_code_counts = dict(fc_counter.most_common())
    summary.register_type_counts = dict(rt_counter.most_common())
    summary.top_write_targets = write_targets.most_common(top_n)
    summary.top_read_targets = read_targets.most_common(top_n)
    summary.attack_type_counts = dict(attack_types.most_common())

    if timestamps:
        timestamps.sort()
        summary.first_timestamp = timestamps[0].isoformat()
        summary.last_timestamp = timestamps[-1].isoformat()
        duration_seconds = (timestamps[-1] - timestamps[0]).total_seconds()
        if duration_seconds > 0:
            summary.transactions_per_minute = (
                summary.total_transactions / (duration_seconds / 60)
            )

    return summary


# Modbus function code names for display
FC_NAMES: dict[int, str] = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}


def fc_name(code: int) -> str:
    """Human-readable name for a Modbus function code."""
    return FC_NAMES.get(code, f"FC{code}")
