# OT Digital Twin & LLM Attack Simulator

A pure-Python Modbus TCP OT environment (PLC slave, SCADA master, historian) with a protocol-accurate attack library and LLM-powered attack scenario generator mapped to MITRE ATT&CK for ICS.

## Architecture

```
┌──────────────┐     Modbus TCP      ┌──────────────┐
│  SCADA HMI   │◄───────────────────►│   PLC Slave   │
│  (Master)    │     Port 5020       │  (Server)     │
└──────┬───────┘                     └──────┬───────┘
       │                                    │
       │ logs                               │ process model
       ▼                                    ▼
┌──────────────┐                     ┌──────────────┐
│  Historian   │                     │ Water Plant  │
│  (SQLite)    │                     │  Simulation  │
└──────────────┘                     └──────────────┘

┌──────────────┐     generates       ┌──────────────┐
│ LLM Scenario │────────────────────►│Attack Library │
│  Generator   │  Modbus payloads    │ (5 attacks)  │
└──────────────┘                     └──────────────┘
       │
       │ maps to
       ▼
┌──────────────┐
│ MITRE ATT&CK │
│   for ICS    │
└──────────────┘
```

## Simulated Process

**Water Treatment Plant** with realistic physics:
- Tank level (mass balance with inflow/outflow)
- pH control with chemical dosing
- Chlorine treatment with turbidity correlation
- Pressure dynamics with pump control
- Temperature regulation
- Alarm system (high/low level, pH, pressure)

## Attack Library

| Attack | Description | MITRE ATT&CK |
|--------|-------------|---------------|
| `register_scan` | Enumerate holding/input registers to map PLC address space | T0802, T0861 |
| `unauthorized_write` | Write arbitrary values to registers/coils without auth | T0855, T0836 |
| `coil_bruteforce` | Toggle coils to discover active physical outputs | T0855, T0831 |
| `raw_socket` | Raw Modbus TCP frame crafting via sockets | T0855, T0830 |

## LLM Scenario Generator

Translates natural-language attack descriptions into executable Modbus payloads:

```
"overflow the water tank by manipulating the level sensor readings"
    ↓
AttackScenario(
    steps=[FC5 close outlet, FC6 max inflow, FC6 hide alarm...],
    mitre_techniques=[T0831, T0879, T0836],
    detection_indicators=[...]
)
```

Supports **Azure OpenAI** (primary) and **OpenAI** (fallback), with rule-based generation when no LLM is configured.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/kvmukilan/ot-digital-twin.git
cd ot-digital-twin
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: configure LLM (copy and edit)
cp .env.example .env

# Start the PLC simulator (Terminal 1)
python -m ot_twin.cli start-plc

# Start SCADA HMI (Terminal 2)
python -m ot_twin.cli start-scada

# Run an attack (Terminal 3)
python -m ot_twin.cli run-attack register_scan
python -m ot_twin.cli run-attack unauthorized_write -p 'target_registers={"0": 99}'
python -m ot_twin.cli run-attack coil_bruteforce

# Generate an LLM attack scenario
python -m ot_twin.cli generate "overflow the water tank"
python -m ot_twin.cli generate "shut down the entire plant" --execute

# View data
python -m ot_twin.cli list-attacks
python -m ot_twin.cli list-registers
python -m ot_twin.cli history --type transactions
python -m ot_twin.cli history --type attacks
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `start-plc` | Start Modbus TCP server with process simulation |
| `start-scada` | Start SCADA master (live polling + historian logging) |
| `run-attack <name>` | Execute a predefined attack |
| `generate <description>` | Generate attack scenario from natural language |
| `list-attacks` | Show available attacks with MITRE mappings |
| `list-registers` | Display PLC register map |
| `history` | Query historian (transactions, snapshots, attacks) |

## Register Map

### Holding Registers (Setpoints)
| Addr | Name | Unit | Default |
|------|------|------|---------|
| 0 | Tank Level Setpoint | % | 50 |
| 1 | Inflow Rate Setpoint | L/min | 10 |
| 2 | Outflow Rate Setpoint | L/min | 10 |
| 3 | pH Setpoint | pH*100 | 700 |
| 4 | Chlorine Dosing | mg/L*100 | 150 |
| 5 | Pressure Setpoint | PSI | 45 |
| 6 | Temperature Setpoint | C*10 | 220 |

### Coils (Actuators)
| Addr | Name | Default |
|------|------|---------|
| 0 | Inlet Valve | Open |
| 1 | Outlet Valve | Open |
| 2 | Pump Enable | On |
| 3 | Mixer Enable | On |
| 4 | Chlorine Pump | On |
| 5 | Emergency Stop | Off |

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Unit tests only
python -m pytest tests/ -v --ignore=tests/test_integration.py

# Integration tests (starts a real PLC server)
python -m pytest tests/test_integration.py -v
```

## Tech Stack

- **pymodbus** — Modbus TCP server/client
- **LangChain + OpenAI** — LLM scenario generation
- **Pydantic** — Data models and validation
- **SQLite** — Historian database
- **Rich** — Terminal UI rendering
- **Click** — CLI framework

## Project Structure

```
ot-digital-twin/
├── ot_twin/
│   ├── cli.py                          # CLI entry point
│   ├── config.py                       # Configuration management
│   ├── models.py                       # Pydantic data models
│   ├── environment/
│   │   ├── plc_slave.py                # Modbus TCP server + process sim
│   │   ├── scada_master.py             # Modbus TCP client (HMI)
│   │   ├── historian.py                # SQLite transaction logger
│   │   ├── process_model.py            # Water treatment physics
│   │   └── register_map.py             # PLC address space definition
│   ├── attacks/
│   │   ├── base.py                     # Abstract attack base class
│   │   ├── register_scan.py            # Address space enumeration
│   │   ├── unauthorized_write.py       # Malicious register writes
│   │   ├── coil_bruteforce.py          # Coil toggle discovery
│   │   ├── scapy_crafted.py            # Raw Modbus frame injection
│   │   └── registry.py                 # Attack lookup registry
│   └── llm_generator/
│       ├── scenario_generator.py       # LLM + rule-based generation
│       ├── payload_builder.py          # Scenario → executable attacks
│       ├── mitre_mapping.py            # MITRE ATT&CK for ICS mapping
│       └── prompts.py                  # LLM prompt templates
├── data/
│   └── mitre_ics_techniques.json       # MITRE technique database
├── tests/                              # 180 tests (unit + integration)
├── requirements.txt
├── .env.example
└── .gitignore
```

## Deployment readiness

See [deployment setup, checks, and rollback](docs/production.md).
