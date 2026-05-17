"""
Historian — SQLite-backed logger for Modbus transactions and process data.

Records every read/write, process snapshots, and attack events for
forensic analysis and visualization.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from ot_twin.config import HISTORIAN_DB_PATH
from ot_twin.models import AttackResult, ModbusTransaction, ProcessState


class Historian:
    """Thread-safe SQLite historian for OT environment data."""

    def __init__(self, db_path: str = HISTORIAN_DB_PATH) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _init_db(self) -> None:
        with self._lock, self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS modbus_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    function_code INTEGER NOT NULL,
                    register_type TEXT NOT NULL,
                    address INTEGER NOT NULL,
                    count INTEGER DEFAULT 1,
                    values_json TEXT,
                    is_write INTEGER DEFAULT 0,
                    is_attack INTEGER DEFAULT 0,
                    attack_type TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS process_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tank_level REAL,
                    inflow_rate REAL,
                    outflow_rate REAL,
                    ph_level REAL,
                    chlorine_dosing REAL,
                    turbidity REAL,
                    pressure_psi REAL,
                    temperature_c REAL,
                    inlet_valve_open INTEGER,
                    outlet_valve_open INTEGER,
                    pump_running INTEGER,
                    mixer_running INTEGER,
                    high_level_alarm INTEGER,
                    low_level_alarm INTEGER,
                    ph_alarm INTEGER,
                    pressure_alarm INTEGER
                );

                CREATE TABLE IF NOT EXISTS attack_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    attack_name TEXT NOT NULL,
                    success INTEGER,
                    details TEXT,
                    registers_affected TEXT,
                    values_before TEXT,
                    values_after TEXT,
                    mitre_techniques TEXT,
                    duration_seconds REAL
                );

                CREATE INDEX IF NOT EXISTS idx_tx_timestamp
                    ON modbus_transactions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_snap_timestamp
                    ON process_snapshots(timestamp);
                CREATE INDEX IF NOT EXISTS idx_attack_timestamp
                    ON attack_results(timestamp);
            """)

    def log_transaction(self, tx: ModbusTransaction) -> None:
        """Log a Modbus transaction."""
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO modbus_transactions
                   (timestamp, source_ip, function_code, register_type,
                    address, count, values_json, is_write, is_attack, attack_type)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tx.timestamp.isoformat(),
                    tx.source_ip,
                    tx.function_code,
                    tx.register_type.value,
                    tx.address,
                    tx.count,
                    json.dumps(tx.values),
                    int(tx.is_write),
                    int(tx.is_attack),
                    tx.attack_type,
                ),
            )

    def log_process_snapshot(self, state: ProcessState) -> None:
        """Log a process state snapshot."""
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO process_snapshots
                   (timestamp, tank_level, inflow_rate, outflow_rate,
                    ph_level, chlorine_dosing, turbidity, pressure_psi,
                    temperature_c, inlet_valve_open, outlet_valve_open,
                    pump_running, mixer_running, high_level_alarm,
                    low_level_alarm, ph_alarm, pressure_alarm)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    state.timestamp.isoformat(),
                    state.tank_level,
                    state.inflow_rate,
                    state.outflow_rate,
                    state.ph_level,
                    state.chlorine_dosing,
                    state.turbidity,
                    state.pressure_psi,
                    state.temperature_c,
                    int(state.inlet_valve_open),
                    int(state.outlet_valve_open),
                    int(state.pump_running),
                    int(state.mixer_running),
                    int(state.high_level_alarm),
                    int(state.low_level_alarm),
                    int(state.ph_alarm),
                    int(state.pressure_alarm),
                ),
            )

    def log_attack_result(self, result: AttackResult) -> None:
        """Log an attack result."""
        duration = None
        if result.end_time and result.start_time:
            duration = (result.end_time - result.start_time).total_seconds()

        with self._lock, self._get_conn() as conn:
            conn.execute(
                """INSERT INTO attack_results
                   (timestamp, attack_name, success, details,
                    registers_affected, values_before, values_after,
                    mitre_techniques, duration_seconds)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.start_time.isoformat(),
                    result.attack_name,
                    int(result.success),
                    result.details,
                    json.dumps(result.registers_affected),
                    json.dumps(result.values_before),
                    json.dumps(result.values_after),
                    json.dumps(result.mitre_techniques),
                    duration,
                ),
            )

    def get_recent_transactions(self, limit: int = 50) -> list[dict]:
        """Retrieve the most recent Modbus transactions."""
        with self._lock, self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM modbus_transactions ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_recent_snapshots(self, limit: int = 50) -> list[dict]:
        """Retrieve the most recent process snapshots."""
        with self._lock, self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM process_snapshots ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_attack_history(self, limit: int = 20) -> list[dict]:
        """Retrieve the most recent attack results."""
        with self._lock, self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM attack_results ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_transaction_count(self) -> int:
        """Total number of logged transactions."""
        with self._lock, self._get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM modbus_transactions"
            ).fetchone()
            return row[0] if row else 0

    def export_csv(self, table: str, output_path: str) -> int:
        """Export a historian table to CSV. Returns row count."""
        import csv

        valid_tables = {
            "transactions": "modbus_transactions",
            "snapshots": "process_snapshots",
            "attacks": "attack_results",
        }
        db_table = valid_tables.get(table)
        if not db_table:
            raise ValueError(f"Unknown table: {table}. Use: {list(valid_tables)}")

        with self._lock, self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(f"SELECT * FROM {db_table} ORDER BY id").fetchall()

            if not rows:
                return 0

            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))

            return len(rows)

    def clear(self) -> None:
        """Clear all historian data."""
        with self._lock, self._get_conn() as conn:
            conn.executescript("""
                DELETE FROM modbus_transactions;
                DELETE FROM process_snapshots;
                DELETE FROM attack_results;
            """)
