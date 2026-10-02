"""
Forensic Timeline Builder — Reconstructs incident timelines from historian data.

Merges Modbus transactions, process snapshots, and attack results into a single
chronological event stream for post-incident analysis.  Each event is classified
and severity-tagged so analysts can quickly identify the sequence of actions
leading to a process safety event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EventType(str, Enum):
    ATTACK = "attack"
    WRITE = "write"
    ALARM = "alarm"
    SETPOINT_CHANGE = "setpoint"
    READ = "read"


class EventSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TimelineEvent:
    """A single event in the forensic timeline."""
    timestamp: str
    event_type: EventType
    severity: EventSeverity
    source: str             # e.g. "transaction", "snapshot", "attack_result"
    summary: str
    details: dict = field(default_factory=dict)


def build_timeline(
    transactions: list[dict],
    snapshots: list[dict],
    attacks: list[dict],
) -> list[TimelineEvent]:
    """Build a chronological forensic timeline from historian data.

    Args:
        transactions: from ``historian.get_recent_transactions()``
        snapshots: from ``historian.get_recent_snapshots()``
        attacks: from ``historian.get_attack_history()``

    Returns:
        List of TimelineEvents sorted chronologically (oldest first).
    """
    events: list[TimelineEvent] = []

    events.extend(_events_from_transactions(transactions))
    events.extend(_events_from_snapshots(snapshots))
    events.extend(_events_from_attacks(attacks))

    events.sort(key=lambda e: e.timestamp)
    return events


def _events_from_transactions(transactions: list[dict]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for tx in transactions:
        ts = tx.get("timestamp", "")
        is_attack = tx.get("is_attack", False)
        is_write = tx.get("is_write", False)
        fc = tx.get("function_code", 0)
        addr = tx.get("address", 0)

        if is_attack:
            events.append(TimelineEvent(
                timestamp=ts,
                event_type=EventType.ATTACK,
                severity=EventSeverity.CRITICAL,
                source="transaction",
                summary=f"Attack traffic: FC{fc} addr={addr} ({tx.get('attack_type', '')})",
                details={"function_code": fc, "address": addr,
                         "attack_type": tx.get("attack_type", "")},
            ))
        elif is_write:
            # Writes to alarm/safety registers are higher severity
            severity = EventSeverity.MEDIUM
            if addr in (9, 10) or fc == 5:  # alarm threshold registers
                severity = EventSeverity.HIGH

            events.append(TimelineEvent(
                timestamp=ts,
                event_type=EventType.WRITE,
                severity=severity,
                source="transaction",
                summary=f"Write FC{fc} to addr={addr} values={tx.get('values_json', '[]')}",
                details={"function_code": fc, "address": addr,
                         "values": tx.get("values_json", "[]")},
            ))
        else:
            events.append(TimelineEvent(
                timestamp=ts,
                event_type=EventType.READ,
                severity=EventSeverity.INFO,
                source="transaction",
                summary=f"Read FC{fc} addr={addr}",
                details={"function_code": fc, "address": addr},
            ))

    return events


def _events_from_snapshots(snapshots: list[dict]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    alarm_fields = [
        ("high_level_alarm", "High tank level alarm"),
        ("low_level_alarm", "Low tank level alarm"),
        ("ph_alarm", "pH alarm"),
        ("pressure_alarm", "Pressure alarm"),
    ]

    for snap in snapshots:
        ts = snap.get("timestamp", "")
        active_alarms = [
            desc for fld, desc in alarm_fields if snap.get(fld)
        ]
        if active_alarms:
            events.append(TimelineEvent(
                timestamp=ts,
                event_type=EventType.ALARM,
                severity=EventSeverity.HIGH,
                source="snapshot",
                summary=f"Active alarms: {', '.join(active_alarms)}",
                details={
                    "tank_level": snap.get("tank_level"),
                    "ph_level": snap.get("ph_level"),
                    "pressure_psi": snap.get("pressure_psi"),
                    "alarms": active_alarms,
                },
            ))

    return events


def _events_from_attacks(attacks: list[dict]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []
    for atk in attacks:
        ts = atk.get("timestamp", "")
        success = atk.get("success", False)
        name = atk.get("attack_name", "unknown")
        severity = EventSeverity.CRITICAL if success else EventSeverity.HIGH

        events.append(TimelineEvent(
            timestamp=ts,
            event_type=EventType.ATTACK,
            severity=severity,
            source="attack_result",
            summary=f"{'Successful' if success else 'Failed'} attack: {name}",
            details={
                "attack_name": name,
                "success": success,
                "details": atk.get("details", ""),
                "mitre": atk.get("mitre_techniques", ""),
            },
        ))

    return events


def filter_timeline(
    events: list[TimelineEvent],
    *,
    min_severity: EventSeverity | None = None,
    event_types: set[EventType] | None = None,
) -> list[TimelineEvent]:
    """Filter a timeline to only events matching criteria."""
    severity_order = {
        EventSeverity.INFO: 0,
        EventSeverity.LOW: 1,
        EventSeverity.MEDIUM: 2,
        EventSeverity.HIGH: 3,
        EventSeverity.CRITICAL: 4,
    }

    result = events
    if min_severity is not None:
        min_val = severity_order[min_severity]
        result = [e for e in result if severity_order[e.severity] >= min_val]
    if event_types is not None:
        result = [e for e in result if e.event_type in event_types]
    return result
