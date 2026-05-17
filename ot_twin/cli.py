"""
CLI entry point for the OT Digital Twin & LLM Attack Simulator.

Commands:
  start-plc      — Start the PLC slave (Modbus TCP server)
  start-scada    — Start the SCADA master (connects to PLC, polls, displays)
  run-attack     — Execute a predefined attack against the PLC
  generate       — Generate an attack scenario from natural language
  list-attacks   — List available attacks
  list-registers — Show the PLC register map
  history        — Show historian data
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

from ot_twin import __version__

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group()
@click.version_option(version=__version__)
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """OT Digital Twin & LLM Attack Simulator."""
    _setup_logging(verbose)


@cli.command("start-plc")
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=5020, type=int, help="Modbus TCP port")
def start_plc(host: str, port: int) -> None:
    """Start the PLC slave (Modbus TCP server with process simulation)."""
    from ot_twin.environment.plc_slave import PLCSlave

    plc = PLCSlave(host=host, port=port)
    console.print(f"[bold green]Starting PLC Slave on {host}:{port}[/]")
    console.print("Process: Water Treatment Plant simulation")
    console.print("Press Ctrl+C to stop\n")

    try:
        asyncio.run(plc.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]PLC Slave stopped[/]")


@cli.command("start-scada")
@click.option("--host", default="127.0.0.1", help="PLC address")
@click.option("--port", default=5020, type=int, help="PLC port")
@click.option("--interval", default=2.0, type=float, help="Poll interval (seconds)")
def start_scada(host: str, port: int, interval: float) -> None:
    """Start the SCADA master (polls PLC, logs to historian, displays live data)."""
    from ot_twin.environment.historian import Historian
    from ot_twin.environment.scada_master import SCADAMaster

    async def run_scada():
        historian = Historian()
        scada = SCADAMaster(host=host, port=port, historian=historian)

        if not await scada.connect():
            console.print("[bold red]Failed to connect to PLC[/]")
            return

        console.print(f"[bold green]SCADA connected to {host}:{port}[/]")
        console.print(f"Polling every {interval}s. Press Ctrl+C to stop.\n")

        try:
            while True:
                state = await scada.read_process_state()
                if state:
                    _display_process_state(state)
                    historian.log_process_snapshot(state)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass
        finally:
            await scada.disconnect()

    try:
        asyncio.run(run_scada())
    except KeyboardInterrupt:
        console.print("\n[yellow]SCADA Master stopped[/]")


def _display_process_state(state) -> None:
    """Render process state as a Rich table."""
    table = Table(title="Water Treatment Plant — Live Process Data", show_lines=True)
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Status", style="yellow")

    # Determine alarm status
    def alarm_style(active: bool) -> str:
        return "[bold red]ALARM[/]" if active else "[green]OK[/]"

    table.add_row("Tank Level", f"{state.tank_level:.1f} %", alarm_style(state.high_level_alarm or state.low_level_alarm))
    table.add_row("Inflow Rate", f"{state.inflow_rate:.1f} L/min", "")
    table.add_row("Outflow Rate", f"{state.outflow_rate:.1f} L/min", "")
    table.add_row("pH Level", f"{state.ph_level:.2f}", alarm_style(state.ph_alarm))
    table.add_row("Chlorine", f"{state.chlorine_dosing:.2f} mg/L", "")
    table.add_row("Turbidity", f"{state.turbidity:.2f} NTU", "")
    table.add_row("Pressure", f"{state.pressure_psi:.1f} PSI", alarm_style(state.pressure_alarm))
    table.add_row("Temperature", f"{state.temperature_c:.1f} °C", "")
    table.add_row("Inlet Valve", "OPEN" if state.inlet_valve_open else "CLOSED", "")
    table.add_row("Outlet Valve", "OPEN" if state.outlet_valve_open else "CLOSED", "")
    table.add_row("Pump", "RUNNING" if state.pump_running else "STOPPED", "")
    table.add_row("Mixer", "RUNNING" if state.mixer_running else "STOPPED", "")

    console.clear()
    console.print(table)


@cli.command("run-attack")
@click.argument("attack_name")
@click.option("--host", default="127.0.0.1", help="Target PLC address")
@click.option("--port", default=5020, type=int, help="Target PLC port")
@click.option("--param", "-p", multiple=True, help="Attack param as key=value")
def run_attack(attack_name: str, host: str, port: int, param: tuple) -> None:
    """Execute a predefined attack against the PLC.

    Available attacks: register_scan, unauthorized_write, coil_bruteforce, scapy_crafted
    """
    from ot_twin.attacks.registry import get_attack
    from ot_twin.environment.historian import Historian

    attack_cls = get_attack(attack_name)
    if not attack_cls:
        console.print(f"[bold red]Unknown attack: {attack_name}[/]")
        console.print("Use 'list-attacks' to see available attacks.")
        sys.exit(1)

    # Parse params
    kwargs: dict = {}
    for p in param:
        key, _, value = p.partition("=")
        # Try to parse as JSON for complex types
        try:
            kwargs[key] = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            kwargs[key] = value

    historian = Historian()

    async def execute():
        attack = attack_cls(host=host, port=port, historian=historian, **kwargs)
        console.print(f"[bold yellow]Executing: {attack.name}[/]")
        console.print(f"Description: {attack.description}")
        console.print(f"MITRE ATT&CK: {', '.join(attack.mitre_techniques)}\n")

        result = await attack.run()

        if result.success:
            console.print("[bold green]Attack succeeded[/]")
        else:
            console.print("[bold red]Attack failed[/]")

        console.print(f"Details: {result.details}")
        console.print(f"Registers affected: {result.registers_affected}")
        console.print(f"Duration: {(result.end_time - result.start_time).total_seconds():.2f}s")

        if result.values_before:
            console.print(f"Values before: {result.values_before}")
        if result.values_after:
            console.print(f"Values after: {result.values_after}")

    try:
        asyncio.run(execute())
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack cancelled[/]")


@cli.command("generate")
@click.argument("description")
@click.option("--execute", "-x", is_flag=True, help="Execute the generated scenario")
@click.option("--host", default="127.0.0.1", help="Target PLC address")
@click.option("--port", default=5020, type=int, help="Target PLC port")
def generate(description: str, execute: bool, host: str, port: int) -> None:
    """Generate an attack scenario from a natural-language description."""
    from ot_twin.llm_generator.payload_builder import build_attacks_from_scenario
    from ot_twin.llm_generator.scenario_generator import generate_scenario

    console.print(f'[bold]Generating scenario for:[/] "{description}"\n')
    scenario = generate_scenario(description)

    # Display the scenario
    console.print(f"[bold cyan]Scenario: {scenario.name}[/]")
    console.print(f"Objective: {scenario.objective}")
    console.print(f"Impact: {scenario.estimated_impact}\n")

    # MITRE techniques
    if scenario.mitre_techniques:
        tech_table = Table(title="MITRE ATT&CK for ICS Mapping")
        tech_table.add_column("ID", style="red")
        tech_table.add_column("Name", style="cyan")
        tech_table.add_column("Tactic", style="yellow")
        for t in scenario.mitre_techniques:
            tech_table.add_row(t.technique_id, t.name, t.tactic)
        console.print(tech_table)

    # Steps
    step_table = Table(title="Attack Steps")
    step_table.add_column("#", style="bold")
    step_table.add_column("Description")
    step_table.add_column("FC", style="cyan")
    step_table.add_column("Addr", style="green")
    step_table.add_column("Values", style="yellow")
    for s in scenario.steps:
        step_table.add_row(
            str(s.order), s.description,
            str(s.function_code), str(s.start_address),
            str(s.values),
        )
    console.print(step_table)

    # Detection indicators
    if scenario.detection_indicators:
        console.print("\n[bold]Detection Indicators:[/]")
        for ind in scenario.detection_indicators:
            console.print(f"  - {ind}")

    # Execute if requested
    if execute:
        from ot_twin.environment.historian import Historian

        console.print("\n[bold yellow]Executing generated scenario...[/]\n")
        historian = Historian()
        attacks = build_attacks_from_scenario(
            scenario, host=host, port=port, historian=historian,
        )

        async def run_all():
            for attack in attacks:
                console.print(f"Running: {attack.name}")
                result = await attack.run()
                status = "[green]OK[/]" if result.success else "[red]FAIL[/]"
                console.print(f"  Result: {status} — {result.details}")

        try:
            asyncio.run(run_all())
        except KeyboardInterrupt:
            console.print("\n[yellow]Execution cancelled[/]")


@cli.command("list-attacks")
def list_attacks() -> None:
    """List all available attacks."""
    from ot_twin.attacks.registry import list_attacks as get_attacks

    table = Table(title="Available Attacks")
    table.add_column("Name", style="cyan")
    table.add_column("Description")
    table.add_column("MITRE Techniques", style="red")

    for atk in get_attacks():
        table.add_row(atk["name"], atk["description"], atk["mitre_techniques"])

    console.print(table)


@cli.command("list-registers")
def list_registers() -> None:
    """Show the PLC register map."""
    from ot_twin.environment.register_map import get_register_map

    reg_map = get_register_map()
    for reg_type, entries in reg_map.items():
        table = Table(title=f"{reg_type.value.replace('_', ' ').title()}")
        table.add_column("Addr", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description")
        table.add_column("Unit", style="yellow")
        table.add_column("Range")
        table.add_column("Default", style="bold")

        for e in entries:
            table.add_row(
                str(e.address), e.name, e.description,
                e.unit, f"{e.min_value}-{e.max_value}",
                str(int(e.default_value)),
            )
        console.print(table)
        console.print()


@cli.command("history")
@click.option("--type", "data_type", type=click.Choice(["transactions", "snapshots", "attacks"]), default="transactions")
@click.option("--limit", default=20, type=int, help="Number of records to show")
def history(data_type: str, limit: int) -> None:
    """Show historian data."""
    from ot_twin.environment.historian import Historian

    historian = Historian()

    if data_type == "transactions":
        records = historian.get_recent_transactions(limit)
        table = Table(title="Recent Modbus Transactions")
        table.add_column("Time")
        table.add_column("FC", style="cyan")
        table.add_column("Type")
        table.add_column("Addr", style="green")
        table.add_column("Values", style="yellow")
        table.add_column("Write?")
        table.add_column("Attack?", style="red")
        for r in records:
            table.add_row(
                r["timestamp"][:19], str(r["function_code"]),
                r["register_type"], str(r["address"]),
                r.get("values_json", ""), "Y" if r["is_write"] else "",
                r.get("attack_type", "") if r["is_attack"] else "",
            )
    elif data_type == "snapshots":
        records = historian.get_recent_snapshots(limit)
        table = Table(title="Recent Process Snapshots")
        table.add_column("Time")
        table.add_column("Tank %", style="cyan")
        table.add_column("pH")
        table.add_column("PSI", style="green")
        table.add_column("Alarms", style="red")
        for r in records:
            alarms = []
            if r.get("high_level_alarm"): alarms.append("HI-LVL")
            if r.get("low_level_alarm"): alarms.append("LO-LVL")
            if r.get("ph_alarm"): alarms.append("pH")
            if r.get("pressure_alarm"): alarms.append("PSI")
            table.add_row(
                r["timestamp"][:19],
                f"{r['tank_level']:.1f}",
                f"{r['ph_level']:.2f}",
                f"{r['pressure_psi']:.1f}",
                ", ".join(alarms) or "None",
            )
    else:
        records = historian.get_attack_history(limit)
        table = Table(title="Attack History")
        table.add_column("Time")
        table.add_column("Attack", style="cyan")
        table.add_column("Success", style="green")
        table.add_column("Details")
        table.add_column("MITRE", style="red")
        for r in records:
            table.add_row(
                r["timestamp"][:19], r["attack_name"],
                "Yes" if r["success"] else "No",
                r.get("details", ""),
                r.get("mitre_techniques", ""),
            )

    console.print(table)
    console.print(f"\nTotal records shown: {len(records)}")


@cli.command("status")
def status() -> None:
    """Show historian summary statistics."""
    from ot_twin.environment.historian import Historian

    historian = Historian()
    tx_count = historian.get_transaction_count()
    snapshots = historian.get_recent_snapshots(1)
    attacks = historian.get_attack_history(100)

    table = Table(title="OT Digital Twin — Status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Modbus Transactions", str(tx_count))
    table.add_row("Total Attacks Logged", str(len(attacks)))

    if attacks:
        successful = sum(1 for a in attacks if a["success"])
        table.add_row("Successful Attacks", str(successful))
        table.add_row("Failed Attacks", str(len(attacks) - successful))
        table.add_row("Last Attack", f"{attacks[0]['attack_name']} ({attacks[0]['timestamp'][:19]})")

    if snapshots:
        s = snapshots[0]
        table.add_row("", "")
        table.add_row("Latest Tank Level", f"{s['tank_level']:.1f} %")
        table.add_row("Latest pH", f"{s['ph_level']:.2f}")
        table.add_row("Latest Pressure", f"{s['pressure_psi']:.1f} PSI")
        alarms = []
        if s.get("high_level_alarm"): alarms.append("HIGH-LEVEL")
        if s.get("low_level_alarm"): alarms.append("LOW-LEVEL")
        if s.get("ph_alarm"): alarms.append("pH")
        if s.get("pressure_alarm"): alarms.append("PRESSURE")
        table.add_row("Active Alarms", ", ".join(alarms) if alarms else "None")
        table.add_row("Snapshot Time", s["timestamp"][:19])
    else:
        table.add_row("", "")
        table.add_row("Process Data", "No snapshots recorded yet")

    console.print(table)


@cli.command("export")
@click.argument("data_type", type=click.Choice(["transactions", "snapshots", "attacks"]))
@click.option("-o", "--output", default=None, help="Output CSV path (default: data/<type>.csv)")
def export(data_type: str, output: str | None) -> None:
    """Export historian data to CSV for forensic analysis."""
    from ot_twin.config import DATA_DIR
    from ot_twin.environment.historian import Historian

    if output is None:
        output = str(DATA_DIR / f"{data_type}.csv")

    historian = Historian()
    count = historian.export_csv(data_type, output)

    if count > 0:
        console.print(f"[green]Exported {count} {data_type} records to {output}[/]")
    else:
        console.print(f"[yellow]No {data_type} data to export[/]")


@cli.command("analyze")
@click.option("--limit", default=500, type=int, help="Number of transactions to analyze")
def analyze(limit: int) -> None:
    """Analyze historian data for anomalies and suspicious activity."""
    from ot_twin.environment.anomaly_detector import AnomalyDetector
    from ot_twin.environment.historian import Historian

    historian = Historian()
    detector = AnomalyDetector()
    anomalies = detector.analyze(historian, limit=limit)

    if not anomalies:
        console.print("[green]No anomalies detected.[/]")
        return

    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "dim",
    }

    table = Table(title=f"Anomaly Report ({len(anomalies)} findings)")
    table.add_column("Severity", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Description")
    table.add_column("Time")

    for a in anomalies:
        style = severity_styles.get(a.severity, "")
        table.add_row(
            f"[{style}]{a.severity.upper()}[/]",
            a.category,
            a.description,
            a.timestamp[:19] if a.timestamp else "",
        )

    console.print(table)


@cli.command("traffic")
@click.option("--limit", default=500, type=int, help="Number of transactions to analyze")
def traffic(limit: int) -> None:
    """Show Modbus traffic summary statistics."""
    from ot_twin.environment.historian import Historian
    from ot_twin.environment.traffic_analyzer import analyze_traffic, fc_name

    historian = Historian()
    transactions = historian.get_recent_transactions(limit)
    summary = analyze_traffic(transactions)

    if summary.total_transactions == 0:
        console.print("[yellow]No traffic recorded yet.[/]")
        return

    console.print()
    table = Table(title="Modbus Traffic Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total Transactions", str(summary.total_transactions))
    table.add_row("Reads / Writes", f"{summary.total_reads} / {summary.total_writes}")
    table.add_row("Read:Write Ratio", summary.read_write_ratio)
    table.add_row("Attack Traffic", f"{summary.total_attacks} ({summary.attack_percentage:.1f}%)")
    table.add_row("Unique Source IPs", str(len(summary.unique_source_ips)) or "N/A")
    if summary.first_timestamp:
        table.add_row("Time Range", f"{summary.first_timestamp[:19]} → {summary.last_timestamp[:19]}")
    if summary.transactions_per_minute > 0:
        table.add_row("Rate", f"{summary.transactions_per_minute:.1f} tx/min")
    console.print(table)

    # Function code distribution
    if summary.function_code_counts:
        fc_table = Table(title="Function Code Distribution")
        fc_table.add_column("FC", style="cyan")
        fc_table.add_column("Name")
        fc_table.add_column("Count", style="green")
        fc_table.add_column("Pct", style="yellow")
        for code, count in summary.function_code_counts.items():
            pct = (count / summary.total_transactions) * 100
            fc_table.add_row(str(code), fc_name(code), str(count), f"{pct:.1f}%")
        console.print(fc_table)

    # Top write targets
    if summary.top_write_targets:
        wt_table = Table(title="Top Write Targets")
        wt_table.add_column("Address", style="cyan")
        wt_table.add_column("Write Count", style="red")
        for addr, count in summary.top_write_targets:
            wt_table.add_row(str(addr), str(count))
        console.print(wt_table)

    # Attack breakdown
    if summary.attack_type_counts:
        at_table = Table(title="Attack Types")
        at_table.add_column("Type", style="red")
        at_table.add_column("Transactions", style="yellow")
        for atype, count in summary.attack_type_counts.items():
            at_table.add_row(atype, str(count))
        console.print(at_table)

    console.print()


@cli.command("baseline")
@click.option("--capture", "do_capture", is_flag=True, help="Capture current state as baseline")
@click.option("--compare", "do_compare", is_flag=True, help="Compare current state against baseline")
def baseline(do_capture: bool, do_compare: bool) -> None:
    """Capture or compare process state against a known-good baseline."""
    import json as _json

    from ot_twin.config import DATA_DIR
    from ot_twin.environment.baseline_profiler import capture_baseline, compare_to_baseline
    from ot_twin.environment.historian import Historian
    from ot_twin.models import ProcessState

    baseline_path = DATA_DIR / "baseline.json"

    historian = Historian()
    snapshots = historian.get_recent_snapshots(1)

    if not do_capture and not do_compare:
        console.print("Use [bold]--capture[/] to save baseline or [bold]--compare[/] to check drift.")
        return

    def _state_from_snapshot(s: dict) -> ProcessState:
        return ProcessState(
            tank_level=s.get("tank_level", 50.0),
            inflow_rate=s.get("inflow_rate", 10.0),
            outflow_rate=s.get("outflow_rate", 10.0),
            ph_level=s.get("ph_level", 7.0),
            chlorine_dosing=s.get("chlorine_dosing", 1.5),
            turbidity=s.get("turbidity", 0.5),
            pressure_psi=s.get("pressure_psi", 45.0),
            temperature_c=s.get("temperature_c", 22.0),
            inlet_valve_open=bool(s.get("inlet_valve_open", True)),
            outlet_valve_open=bool(s.get("outlet_valve_open", True)),
            pump_running=bool(s.get("pump_running", True)),
            mixer_running=bool(s.get("mixer_running", True)),
            high_level_alarm=bool(s.get("high_level_alarm", False)),
            low_level_alarm=bool(s.get("low_level_alarm", False)),
            ph_alarm=bool(s.get("ph_alarm", False)),
            pressure_alarm=bool(s.get("pressure_alarm", False)),
        )

    if do_capture:
        state = _state_from_snapshot(snapshots[0]) if snapshots else ProcessState()
        bl = capture_baseline(state)
        baseline_path.write_text(_json.dumps(bl, indent=2))
        console.print(f"[green]Baseline captured to {baseline_path}[/]")
        return

    if do_compare:
        if not baseline_path.exists():
            console.print("[red]No baseline found. Run with --capture first.[/]")
            return

        bl = _json.loads(baseline_path.read_text())
        state = _state_from_snapshot(snapshots[0]) if snapshots else ProcessState()

        result = compare_to_baseline(bl, state)

        if not result.has_drift:
            console.print("[bold green]No drift detected — state matches baseline.[/]\n")
            return

        table = Table(title=f"Baseline Drift ({result.changed_parameters}/{result.total_parameters} parameters changed)")
        table.add_column("Parameter", style="cyan")
        table.add_column("Baseline", style="green")
        table.add_column("Current", style="yellow")
        table.add_column("Delta", style="red")

        for d in result.drifts:
            if d.is_boolean:
                table.add_row(d.parameter, str(d.baseline_value), str(d.current_value), "changed")
            else:
                table.add_row(
                    d.parameter, f"{d.baseline_value:.2f}",
                    f"{d.current_value:.2f}", f"{d.delta:.2f} ({d.pct_change:.1f}%)",
                )

        console.print(table)
        console.print(f"\n  Drift: [bold]{result.drift_percentage:.1f}%[/] of parameters changed\n")


@cli.command("compliance")
def compliance() -> None:
    """Check PLC configuration against ICS security best practices."""
    from ot_twin.environment.compliance_checker import CheckStatus, check_compliance
    from ot_twin.environment.historian import Historian
    from ot_twin.models import ProcessState

    historian = Historian()
    snapshots = historian.get_recent_snapshots(1)

    if snapshots:
        s = snapshots[0]
        state = ProcessState(
            tank_level=s["tank_level"], ph_level=s["ph_level"],
            chlorine_dosing=s.get("chlorine_dosing", 1.5),
            pressure_psi=s["pressure_psi"],
            inlet_valve_open=bool(s.get("inlet_valve_open", True)),
            outlet_valve_open=bool(s.get("outlet_valve_open", True)),
            pump_running=bool(s.get("pump_running", True)),
            mixer_running=bool(s.get("mixer_running", True)),
        )
    else:
        state = ProcessState()
        console.print("[dim]No snapshots — checking default configuration.[/]\n")

    report = check_compliance(state)

    status_styles = {
        CheckStatus.PASS: "[green]PASS[/]",
        CheckStatus.FAIL: "[bold red]FAIL[/]",
        CheckStatus.WARN: "[yellow]WARN[/]",
    }

    table = Table(title="ICS Compliance Report")
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    for c in report.checks:
        table.add_row(
            c.check_id, c.category, c.description,
            status_styles[c.status], c.detail,
        )

    console.print(table)
    console.print(
        f"\n  [green]{report.passed} passed[/]  "
        f"[yellow]{report.warnings} warnings[/]  "
        f"[red]{report.failed} failed[/]"
    )
    if report.compliant:
        console.print("  [bold green]COMPLIANT[/]\n")
    else:
        console.print("  [bold red]NON-COMPLIANT[/]\n")


@cli.command("timeline")
@click.option("--limit", default=200, type=int, help="Records to fetch per source")
@click.option("--severity", type=click.Choice(["info", "low", "medium", "high", "critical"]),
              default=None, help="Minimum severity to show")
def timeline(limit: int, severity: str | None) -> None:
    """Reconstruct a forensic incident timeline from historian data."""
    from ot_twin.environment.forensic_timeline import (
        EventSeverity,
        build_timeline,
        filter_timeline,
    )
    from ot_twin.environment.historian import Historian

    historian = Historian()
    events = build_timeline(
        transactions=historian.get_recent_transactions(limit),
        snapshots=historian.get_recent_snapshots(limit),
        attacks=historian.get_attack_history(limit),
    )

    if severity:
        events = filter_timeline(
            events, min_severity=EventSeverity(severity),
        )

    if not events:
        console.print("[yellow]No events for timeline.[/]")
        return

    sev_styles = {
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "yellow",
        "low": "dim",
        "info": "dim cyan",
    }

    table = Table(title=f"Forensic Timeline ({len(events)} events)")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Sev", style="bold")
    table.add_column("Type")
    table.add_column("Summary")

    for e in events:
        style = sev_styles.get(e.severity.value, "")
        table.add_row(
            e.timestamp[:19],
            f"[{style}]{e.severity.value.upper()}[/]",
            e.event_type.value,
            e.summary,
        )

    console.print(table)
    console.print()


@cli.command("sessions")
@click.option("--limit", default=1000, type=int, help="Transactions to analyze")
def sessions(limit: int) -> None:
    """Profile Modbus client sessions and flag suspicious connections."""
    from ot_twin.environment.historian import Historian
    from ot_twin.environment.session_tracker import analyze_sessions

    historian = Historian()
    transactions = historian.get_recent_transactions(limit)
    report = analyze_sessions(transactions)

    if report.total_sources == 0:
        console.print("[yellow]No sessions recorded yet.[/]")
        return

    table = Table(title=f"Client Sessions ({report.total_sources} sources)")
    table.add_column("Source IP", style="cyan")
    table.add_column("Txns", style="green")
    table.add_column("Reads")
    table.add_column("Writes")
    table.add_column("Write%", style="yellow")
    table.add_column("FCs Used")
    table.add_column("Duration")
    table.add_column("Flags", style="red")

    for p in report.profiles:
        dur = f"{p.duration_seconds:.0f}s" if p.duration_seconds > 0 else "-"
        fcs = ", ".join(str(fc) for fc in sorted(p.function_codes_used))
        flags = "; ".join(p.flags) if p.flags else ""
        table.add_row(
            p.source_ip, str(p.total_transactions),
            str(p.total_reads), str(p.total_writes),
            f"{p.write_ratio:.0%}", fcs, dur, flags,
        )

    console.print(table)

    if report.suspicious:
        console.print(f"\n[bold red]{len(report.suspicious)} suspicious session(s) detected.[/]")
    else:
        console.print("\n[green]No suspicious sessions.[/]")
    console.print()


@cli.command("risk")
def risk() -> None:
    """Compute risk score from the latest process snapshot."""
    from ot_twin.environment.historian import Historian
    from ot_twin.environment.risk_scorer import score_risk
    from ot_twin.models import ProcessState

    historian = Historian()
    snapshots = historian.get_recent_snapshots(1)

    if not snapshots:
        console.print("[yellow]No process snapshots available. Run SCADA or demo first.[/]")
        return

    s = snapshots[0]
    state = ProcessState(
        tank_level=s["tank_level"],
        inflow_rate=s.get("inflow_rate", 10.0),
        outflow_rate=s.get("outflow_rate", 10.0),
        ph_level=s["ph_level"],
        chlorine_dosing=s.get("chlorine_dosing", 1.5),
        turbidity=s.get("turbidity", 0.5),
        pressure_psi=s["pressure_psi"],
        temperature_c=s.get("temperature_c", 22.0),
        inlet_valve_open=bool(s.get("inlet_valve_open", True)),
        outlet_valve_open=bool(s.get("outlet_valve_open", True)),
        pump_running=bool(s.get("pump_running", True)),
        mixer_running=bool(s.get("mixer_running", True)),
        high_level_alarm=bool(s.get("high_level_alarm", False)),
        low_level_alarm=bool(s.get("low_level_alarm", False)),
        ph_alarm=bool(s.get("ph_alarm", False)),
        pressure_alarm=bool(s.get("pressure_alarm", False)),
    )

    report = score_risk(state)

    level_styles = {
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
        "critical": "bold white on red",
    }
    style = level_styles.get(report.level, "")

    console.print()
    console.print(f"  Risk Score:  [{style}]{report.score:.0f} / 100  ({report.level.upper()})[/]")
    console.print(f"  Snapshot:    {s['timestamp'][:19]}\n")

    if report.factors:
        table = Table(title="Risk Factors")
        table.add_column("Category", style="cyan")
        table.add_column("Description")
        table.add_column("Points", style="red")
        for f in report.factors:
            table.add_row(f.category, f.description, f"{f.points:.1f}")
        console.print(table)
    else:
        console.print("  [green]No risk factors — plant operating normally.[/]")
    console.print()


@cli.command("scenarios")
@click.option("--run", "run_name", default=None, help="Run a scenario by name")
@click.option("--host", default="127.0.0.1", help="Target PLC address")
@click.option("--port", default=5020, type=int, help="Target PLC port")
def scenarios(run_name: str | None, host: str, port: int) -> None:
    """List pre-built attack scenarios, or run one with --run NAME."""
    from ot_twin.llm_generator.scenario_library import get_scenario, list_scenarios

    if run_name is None:
        # List all scenarios
        items = list_scenarios()
        table = Table(title="Pre-Built Attack Scenarios")
        table.add_column("Name", style="cyan")
        table.add_column("Objective")
        table.add_column("Steps", style="green")
        table.add_column("MITRE", style="red")
        for item in items:
            table.add_row(item["name"], item["objective"], item["steps"], item["mitre"])
        console.print(table)
        console.print(f"\nRun a scenario: [bold]ot-twin scenarios --run <name>[/]")
        return

    scenario = get_scenario(run_name)
    if scenario is None:
        console.print(f"[bold red]Unknown scenario: {run_name}[/]")
        console.print("Use 'scenarios' to see available options.")
        sys.exit(1)

    # Display scenario details
    console.print(f"\n[bold cyan]Scenario: {scenario.name}[/]")
    console.print(f"Objective: {scenario.objective}")
    console.print(f"Impact: {scenario.estimated_impact}\n")

    if scenario.mitre_techniques:
        tech_table = Table(title="MITRE ATT&CK for ICS Mapping")
        tech_table.add_column("ID", style="red")
        tech_table.add_column("Name", style="cyan")
        tech_table.add_column("Tactic", style="yellow")
        for t in scenario.mitre_techniques:
            tech_table.add_row(t.technique_id, t.name, t.tactic)
        console.print(tech_table)

    step_table = Table(title="Attack Steps")
    step_table.add_column("#", style="bold")
    step_table.add_column("Description")
    step_table.add_column("FC", style="cyan")
    step_table.add_column("Addr", style="green")
    step_table.add_column("Values", style="yellow")
    for s in scenario.steps:
        step_table.add_row(
            str(s.order), s.description,
            str(s.function_code), str(s.start_address),
            str(s.values),
        )
    console.print(step_table)

    if scenario.detection_indicators:
        console.print("\n[bold]Detection Indicators:[/]")
        for ind in scenario.detection_indicators:
            console.print(f"  - {ind}")

    # Execute the scenario
    from ot_twin.environment.historian import Historian
    from ot_twin.llm_generator.payload_builder import build_attacks_from_scenario

    console.print("\n[bold yellow]Executing scenario...[/]\n")
    historian = Historian()
    attacks = build_attacks_from_scenario(
        scenario, host=host, port=port, historian=historian,
    )

    async def run_all():
        for attack in attacks:
            console.print(f"  Step: {attack.name}")
            result = await attack.run()
            status = "[green]OK[/]" if result.success else "[red]FAIL[/]"
            console.print(f"    {status} — {result.details}")

    try:
        asyncio.run(run_all())
        console.print("\n[bold green]Scenario complete.[/]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Execution cancelled[/]")


@cli.command("demo")
@click.option("--port", default=5020, type=int, help="PLC port for demo")
def demo(port: int) -> None:
    """Run a self-contained end-to-end demo (PLC + attacks + analysis)."""
    import tempfile

    from ot_twin.attacks.coil_bruteforce import CoilBruteforceAttack
    from ot_twin.attacks.register_scan import RegisterScanAttack
    from ot_twin.attacks.replay import ReplayAttack
    from ot_twin.attacks.unauthorized_write import UnauthorizedWriteAttack
    from ot_twin.environment.anomaly_detector import AnomalyDetector
    from ot_twin.environment.historian import Historian
    from ot_twin.environment.plc_slave import PLCSlave
    from ot_twin.environment.scada_master import SCADAMaster
    from ot_twin.llm_generator.scenario_generator import _generate_rule_based

    async def run_demo():
        # Use a temp DB so we don't pollute the real historian
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = f"{tmpdir}/demo.db"
            historian = Historian(db_path=db_path)

            # Phase 1: Start PLC
            console.rule("[bold cyan]Phase 1: Starting PLC Slave")
            plc = PLCSlave(host="127.0.0.1", port=port)
            await plc.start_background()
            console.print(f"[green]PLC running on 127.0.0.1:{port}[/]\n")

            try:
                # Phase 2: SCADA reads
                console.rule("[bold cyan]Phase 2: SCADA Reading Process State")
                scada = SCADAMaster(
                    host="127.0.0.1", port=port, historian=historian,
                )
                await scada.connect()
                state = await scada.read_process_state()
                if state:
                    console.print(f"  Tank Level:  {state.tank_level:.1f}%")
                    console.print(f"  pH Level:    {state.ph_level:.2f}")
                    console.print(f"  Pressure:    {state.pressure_psi:.1f} PSI")
                    console.print(f"  Pump:        {'RUNNING' if state.pump_running else 'STOPPED'}")
                console.print()

                # Phase 3: Attacks
                console.rule("[bold cyan]Phase 3: Running Attack Library")
                attacks = [
                    ("Register Scan", RegisterScanAttack(
                        host="127.0.0.1", port=port, historian=historian,
                        holding_range=(0, 20), input_range=(0, 10),
                        coil_range=(0, 8),
                    )),
                    ("Unauthorized Write", UnauthorizedWriteAttack(
                        host="127.0.0.1", port=port, historian=historian,
                        target_registers={0: 99, 1: 100},
                        target_coils={1: False},
                    )),
                    ("Coil Brute-Force", CoilBruteforceAttack(
                        host="127.0.0.1", port=port, historian=historian,
                        coil_range=(0, 6), toggle_delay=0.1, restore=True,
                    )),
                    ("Replay", ReplayAttack(
                        host="127.0.0.1", port=port, historian=historian,
                        source_historian=historian, replay_limit=5,
                        replay_delay=0.05,
                    )),
                ]

                for label, attack in attacks:
                    result = await attack.run()
                    status = "[green]SUCCESS[/]" if result.success else "[red]FAILED[/]"
                    console.print(
                        f"  {label:25s} {status}  "
                        f"MITRE: {', '.join(attack.mitre_techniques)}  "
                        f"| {result.details}"
                    )
                console.print()

                # Phase 4: Post-attack SCADA read
                console.rule("[bold cyan]Phase 4: Post-Attack Process State")
                state2 = await scada.read_process_state()
                if state2:
                    console.print(f"  Tank Level:  {state2.tank_level:.1f}%")
                    console.print(f"  pH Level:    {state2.ph_level:.2f}")
                    console.print(f"  Pressure:    {state2.pressure_psi:.1f} PSI")
                    console.print(f"  Pump:        {'RUNNING' if state2.pump_running else 'STOPPED'}")
                console.print()

                await scada.disconnect()

                # Phase 5: LLM scenario generation (rule-based)
                console.rule("[bold cyan]Phase 5: LLM Scenario Generation")
                scenario = _generate_rule_based("overflow the water tank by closing the outlet")
                console.print(f"  Scenario: [bold]{scenario.name}[/]")
                console.print(f"  Steps:    {len(scenario.steps)}")
                techs = ", ".join(
                    f"{t.technique_id} ({t.name})" for t in scenario.mitre_techniques
                )
                console.print(f"  MITRE:    {techs}")
                console.print()

                # Phase 6: Anomaly analysis
                console.rule("[bold cyan]Phase 6: Anomaly Detection")
                detector = AnomalyDetector()
                anomalies = detector.analyze(historian)
                if anomalies:
                    for a in anomalies[:5]:
                        sev_color = {"critical": "red", "high": "red", "medium": "yellow"}.get(a.severity, "dim")
                        console.print(
                            f"  [{sev_color}]{a.severity.upper():8s}[/] "
                            f"{a.category:15s}  {a.description}"
                        )
                    if len(anomalies) > 5:
                        console.print(f"  ... and {len(anomalies) - 5} more")
                else:
                    console.print("  [green]No anomalies detected[/]")
                console.print()

                # Summary
                console.rule("[bold cyan]Demo Summary")
                console.print(f"  Transactions logged:  {historian.get_transaction_count()}")
                console.print(f"  Attacks executed:     {len(attacks)}")
                console.print(f"  Anomalies detected:   {len(anomalies)}")
                console.print()
                console.print("[bold green]Demo complete![/]")

            finally:
                await plc.stop()

    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo cancelled[/]")


def main() -> None:
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
