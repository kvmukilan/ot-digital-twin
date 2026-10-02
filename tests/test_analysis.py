"""Tests for the forensic / analysis modules: traffic, sessions, anomalies,
risk scoring, protocol validation, timeline, compliance and baseline drift."""

from __future__ import annotations

from ot_twin.environment.anomaly_detector import AnomalyDetector
from ot_twin.environment.baseline_profiler import capture_baseline, compare_to_baseline
from ot_twin.environment.compliance_checker import check_compliance
from ot_twin.environment.forensic_timeline import build_timeline
from ot_twin.environment.protocol_validator import Severity, validate_transaction
from ot_twin.environment.risk_scorer import score_risk
from ot_twin.environment.session_tracker import analyze_sessions
from ot_twin.environment.traffic_analyzer import analyze_traffic, fc_name
from ot_twin.models import ModbusTransaction, ProcessState, RegisterType


def _tx_dict(i, *, is_write=False, is_attack=False, ip="10.0.0.5", fc=3, addr=0):
    return {
        "function_code": fc,
        "register_type": "holding_register",
        "address": addr,
        "count": 1,
        "values_json": "[1]",
        "is_write": is_write,
        "is_attack": is_attack,
        "attack_type": "unauthorized_write" if is_attack else "",
        "source_ip": ip,
        "timestamp": f"2026-01-01T00:00:{i:02d}",
    }


# ── traffic analyzer ───────────────────────────────────────────────────
def test_traffic_counts_reads_writes_and_attacks():
    txs = [
        _tx_dict(0, fc=3),
        _tx_dict(30, is_write=True, is_attack=True, ip="2.2.2.2", fc=6, addr=1),
    ]
    summary = analyze_traffic(txs)
    assert summary.total_transactions == 2
    assert summary.total_reads == 1
    assert summary.total_writes == 1
    assert summary.total_attacks == 1
    assert len(summary.unique_source_ips) == 2
    assert summary.first_timestamp and summary.last_timestamp


def test_traffic_empty_is_zeroed():
    summary = analyze_traffic([])
    assert summary.total_transactions == 0


def test_fc_name_known_and_unknown():
    assert fc_name(6) == "Write Single Register"
    assert fc_name(99) == "FC99"


# ── session tracker ────────────────────────────────────────────────────
def test_sessions_flag_write_heavy_attack_source():
    txs = [_tx_dict(i, is_write=True, is_attack=True, fc=6) for i in range(5)]
    report = analyze_sessions(txs)
    assert report.total_sources == 1
    profile = report.profiles[0]
    assert profile.total_writes == 5
    assert profile.write_ratio == 1.0
    assert report.suspicious  # write-heavy + attack traffic


def test_sessions_benign_reader_not_suspicious():
    txs = [_tx_dict(i, fc=3) for i in range(5)]
    report = analyze_sessions(txs)
    assert report.total_sources == 1
    assert not report.suspicious


# ── anomaly detector ───────────────────────────────────────────────────
def test_anomaly_detects_attack_and_out_of_range(historian):
    historian.log_transaction(ModbusTransaction(
        function_code=6, register_type=RegisterType.HOLDING,
        address=0, values=[99999], is_write=True,
        is_attack=True, attack_type="unauthorized_write",
    ))
    anomalies = AnomalyDetector().analyze(historian)
    categories = {a.category for a in anomalies}
    assert "known_attack" in categories
    assert "out_of_range" in categories  # 99999 > tank_level_setpoint max (100)


def test_anomaly_detects_unusual_function_code(historian):
    historian.log_transaction(ModbusTransaction(
        function_code=42, register_type=RegisterType.HOLDING,
        address=0, values=[1],
    ))
    anomalies = AnomalyDetector().analyze(historian)
    assert any(a.category == "unusual_fc" for a in anomalies)


def test_anomaly_quiet_on_clean_traffic(historian):
    historian.log_transaction(ModbusTransaction(
        function_code=3, register_type=RegisterType.HOLDING,
        address=0, count=1, values=[50],
    ))
    assert AnomalyDetector().analyze(historian) == []


# ── risk scorer ────────────────────────────────────────────────────────
def test_risk_low_for_nominal_state():
    report = score_risk(ProcessState())
    assert report.level == "low"
    assert report.score < 25


def test_risk_high_for_dangerous_state():
    report = score_risk(ProcessState(
        tank_level=98, ph_level=11, pressure_psi=95,
        high_level_alarm=True, pressure_alarm=True, ph_alarm=True,
        pump_running=False, inlet_valve_open=True, outlet_valve_open=False,
    ))
    assert report.score > 50
    assert report.level in ("high", "critical")
    assert report.factors


# ── protocol validator ─────────────────────────────────────────────────
def test_validate_accepts_good_read():
    result = validate_transaction(3, RegisterType.HOLDING, address=0, count=10)
    assert result.valid
    assert not any(i.severity == Severity.VIOLATION for i in result.issues)


def test_validate_rejects_write_to_read_only():
    result = validate_transaction(6, RegisterType.INPUT, address=0, values=[5])
    assert not result.valid


def test_validate_rejects_unknown_function_code():
    assert not validate_transaction(99, RegisterType.HOLDING, address=0).valid


def test_validate_rejects_out_of_range_value():
    assert not validate_transaction(
        6, RegisterType.HOLDING, address=0, values=[70000],
    ).valid


# ── forensic timeline ──────────────────────────────────────────────────
def test_timeline_merges_and_sorts_chronologically():
    txs = [_tx_dict(0, is_write=True, fc=6)]
    attacks = [{
        "attack_name": "unauthorized_write", "success": 1, "details": "d",
        "mitre_techniques": "[]", "timestamp": "2026-01-01T00:00:05",
    }]
    snapshots = [{
        "tank_level": 95.0, "ph_level": 7.0, "pressure_psi": 45.0,
        "high_level_alarm": 1, "low_level_alarm": 0, "ph_alarm": 0,
        "pressure_alarm": 0, "timestamp": "2026-01-01T00:00:03",
    }]
    events = build_timeline(transactions=txs, snapshots=snapshots, attacks=attacks)
    assert len(events) >= 3
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


# ── compliance checker ─────────────────────────────────────────────────
def test_compliance_passes_for_nominal_config():
    report = check_compliance(ProcessState())
    assert report.compliant
    assert report.failed == 0


def test_compliance_fails_for_dangerous_ph():
    report = check_compliance(ProcessState(ph_level=3.0))
    assert not report.compliant
    assert report.failed >= 1


# ── baseline profiler ──────────────────────────────────────────────────
def test_baseline_no_drift_for_identical_state():
    state = ProcessState()
    baseline = capture_baseline(state)
    result = compare_to_baseline(baseline, state)
    assert not result.has_drift


def test_baseline_detects_numeric_and_boolean_drift():
    baseline = capture_baseline(ProcessState(tank_level=50, pump_running=True))
    result = compare_to_baseline(
        baseline, ProcessState(tank_level=92, pump_running=False),
    )
    assert result.has_drift
    drifted = {d.parameter for d in result.drifts}
    assert "tank_level" in drifted
    assert "pump_running" in drifted
