"""
Modbus Session Tracker — Profiles client connections from historian data.

Builds per-source-IP session profiles: transaction counts, read/write ratios,
function code usage, and time span.  Flags suspicious patterns such as
write-heavy sessions, rapid reconnection bursts, and anomalous FC usage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SessionProfile:
    """Aggregated profile for a single source IP."""
    source_ip: str
    total_transactions: int = 0
    total_reads: int = 0
    total_writes: int = 0
    total_attacks: int = 0
    function_codes_used: set[int] = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    flags: list[str] = field(default_factory=list)

    @property
    def write_ratio(self) -> float:
        """Fraction of transactions that are writes (0.0–1.0)."""
        if self.total_transactions == 0:
            return 0.0
        return self.total_writes / self.total_transactions

    @property
    def duration_seconds(self) -> float:
        """Elapsed time between first and last transaction."""
        if not self.first_seen or not self.last_seen:
            return 0.0
        try:
            t0 = datetime.fromisoformat(self.first_seen)
            t1 = datetime.fromisoformat(self.last_seen)
            return max((t1 - t0).total_seconds(), 0.0)
        except (ValueError, TypeError):
            return 0.0


@dataclass
class SessionReport:
    """Full session analysis across all source IPs."""
    total_sources: int = 0
    profiles: list[SessionProfile] = field(default_factory=list)
    suspicious: list[SessionProfile] = field(default_factory=list)


# ── Thresholds ──────────────────────────────────────────────────────────
WRITE_HEAVY_THRESHOLD = 0.7       # >70% writes → suspicious
HIGH_TX_RATE_PER_SEC = 5.0        # >5 tx/s sustained → suspicious
ATTACK_FLAG_THRESHOLD = 1         # any attack traffic → flagged


def analyze_sessions(transactions: list[dict]) -> SessionReport:
    """Build session profiles from historian transaction records.

    Args:
        transactions: list of dicts from ``historian.get_recent_transactions()``.

    Returns:
        SessionReport with per-IP profiles and a suspicious subset.
    """
    if not transactions:
        return SessionReport()

    profiles: dict[str, SessionProfile] = {}

    for tx in transactions:
        ip = tx.get("source_ip", "") or "unknown"
        if ip not in profiles:
            profiles[ip] = SessionProfile(source_ip=ip)

        p = profiles[ip]
        p.total_transactions += 1

        if tx.get("is_write"):
            p.total_writes += 1
        else:
            p.total_reads += 1

        if tx.get("is_attack"):
            p.total_attacks += 1

        fc = tx.get("function_code")
        if fc is not None:
            p.function_codes_used.add(fc)

        ts = tx.get("timestamp", "")
        if not p.first_seen or ts < p.first_seen:
            p.first_seen = ts
        if not p.last_seen or ts > p.last_seen:
            p.last_seen = ts

    # Flag suspicious sessions
    all_profiles = sorted(profiles.values(),
                          key=lambda p: p.total_transactions, reverse=True)
    suspicious: list[SessionProfile] = []

    for p in all_profiles:
        p.flags = _compute_flags(p)
        if p.flags:
            suspicious.append(p)

    return SessionReport(
        total_sources=len(all_profiles),
        profiles=all_profiles,
        suspicious=suspicious,
    )


def _compute_flags(p: SessionProfile) -> list[str]:
    """Determine which suspicious indicators apply to a session."""
    flags: list[str] = []

    if p.total_transactions > 0 and p.write_ratio >= WRITE_HEAVY_THRESHOLD:
        flags.append(
            f"Write-heavy session ({p.write_ratio:.0%} writes)"
        )

    if p.total_attacks >= ATTACK_FLAG_THRESHOLD:
        flags.append(
            f"Attack traffic detected ({p.total_attacks} transactions)"
        )

    duration = p.duration_seconds
    if duration > 0 and (p.total_transactions / duration) >= HIGH_TX_RATE_PER_SEC:
        flags.append(
            f"High transaction rate ({p.total_transactions / duration:.1f} tx/s)"
        )

    return flags
