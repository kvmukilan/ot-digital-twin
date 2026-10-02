"""Tests for the SQLite historian: read/write round-trips and the
connection-cleanup fix (previously leaked handles and crashed the demo on
Windows with WinError 32)."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime

import pytest

from ot_twin.environment.historian import Historian
from ot_twin.models import AttackResult, ModbusTransaction, ProcessState, RegisterType


def _tx(**kw) -> ModbusTransaction:
    defaults = dict(
        function_code=6,
        register_type=RegisterType.HOLDING,
        address=0,
        values=[1],
        is_write=True,
    )
    defaults.update(kw)
    return ModbusTransaction(**defaults)


def test_log_and_read_transaction(historian):
    historian.log_transaction(_tx(address=3, values=[700]))
    txs = historian.get_recent_transactions(10)
    assert len(txs) == 1
    assert txs[0]["function_code"] == 6
    assert txs[0]["address"] == 3
    assert txs[0]["is_write"] == 1
    assert historian.get_transaction_count() == 1


def test_recent_transactions_newest_first(historian):
    for addr in range(3):
        historian.log_transaction(_tx(address=addr))
    txs = historian.get_recent_transactions(10)
    assert [t["address"] for t in txs] == [2, 1, 0]


def test_log_and_read_snapshot(historian):
    historian.log_process_snapshot(ProcessState(tank_level=73.5, ph_level=7.2))
    snaps = historian.get_recent_snapshots(10)
    assert len(snaps) == 1
    assert abs(snaps[0]["tank_level"] - 73.5) < 1e-6
    assert snaps[0]["high_level_alarm"] == 0


def test_log_and_read_attack_result(historian):
    historian.log_attack_result(AttackResult(
        attack_name="unauthorized_write",
        success=True,
        details="wrote 2",
        registers_affected=[1, 2],
        mitre_techniques=["T0855", "T0836"],
        end_time=datetime.now(),
    ))
    hist = historian.get_attack_history(10)
    assert len(hist) == 1
    assert hist[0]["attack_name"] == "unauthorized_write"
    assert hist[0]["success"] == 1
    assert hist[0]["duration_seconds"] is not None


def test_export_csv_writes_rows(historian, tmp_path):
    historian.log_transaction(_tx(values=[1, 2]))
    out = tmp_path / "tx.csv"
    count = historian.export_csv("transactions", str(out))
    assert count == 1
    assert out.exists()
    assert "function_code" in out.read_text()


def test_export_csv_empty_returns_zero(historian, tmp_path):
    out = tmp_path / "empty.csv"
    assert historian.export_csv("snapshots", str(out)) == 0


def test_export_csv_unknown_table_raises(historian, tmp_path):
    with pytest.raises(ValueError):
        historian.export_csv("bogus", str(tmp_path / "x.csv"))


def test_clear_removes_all_data(historian):
    historian.log_transaction(_tx())
    historian.log_process_snapshot(ProcessState())
    historian.clear()
    assert historian.get_transaction_count() == 0
    assert historian.get_recent_snapshots(5) == []


def test_connection_is_released_file_is_deletable(tmp_path):
    """Regression for the WinError 32 leak: after any operation the DB file
    must be deletable, i.e. no connection handle is left open."""
    db = tmp_path / "leak.db"
    h = Historian(db_path=str(db))
    h.log_transaction(_tx())
    assert h.get_transaction_count() == 1
    os.remove(str(db))  # raises PermissionError on Windows if a conn is open
    assert not db.exists()


def test_temporarydirectory_cleanup_like_demo():
    """Mirrors the ``demo`` command: a historian created inside a
    TemporaryDirectory must not block its cleanup."""
    with tempfile.TemporaryDirectory() as tmp:
        h = Historian(db_path=os.path.join(tmp, "demo.db"))
        h.log_process_snapshot(ProcessState())
        assert len(h.get_recent_snapshots(1)) == 1
    # Exiting the context without raising PermissionError is the assertion.
