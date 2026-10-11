"""Configuration management for the OT Digital Twin."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Paths
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = Path(os.getenv("OT_TWIN_DATA_DIR", str(Path.cwd() / "data"))).expanduser()
DATA_DIR.mkdir(parents=True, exist_ok=True)

# PLC / Modbus Server
PLC_HOST: str = os.getenv("PLC_HOST", "127.0.0.1")
PLC_PORT: int = int(os.getenv("PLC_PORT", "5020"))
PLC_UNIT_ID: int = 1

# SCADA
SCADA_POLL_INTERVAL: float = float(os.getenv("SCADA_POLL_INTERVAL", "2.0"))

# Historian
HISTORIAN_DB_PATH: str = os.getenv(
    "HISTORIAN_DB_PATH", str(DATA_DIR / "historian.db")
)

# Process simulation
PROCESS_TICK_SECONDS: float = 1.0
TANK_CAPACITY_LITERS: float = 1000.0
TANK_HIGH_ALARM_PCT: float = 90.0
TANK_LOW_ALARM_PCT: float = 10.0
PH_ALARM_LOW: float = 6.0
PH_ALARM_HIGH: float = 8.5
PRESSURE_ALARM_HIGH: float = 80.0

# Azure OpenAI
AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_DEPLOYMENT: str = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4")
AZURE_OPENAI_API_VERSION: str = os.getenv(
    "AZURE_OPENAI_API_VERSION", "2024-02-15-preview"
)

# OpenAI (fallback)
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4")

# MITRE data
MITRE_ICS_DATA_PATH: str = os.getenv(
    "MITRE_ICS_DATA_PATH", str(Path(__file__).parent / "data" / "mitre_ics_techniques.json")
)
