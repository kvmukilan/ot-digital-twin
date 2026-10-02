"""Pydantic models for the OT Digital Twin."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class RegisterType(str, Enum):
    HOLDING = "holding_register"
    INPUT = "input_register"
    COIL = "coil"
    DISCRETE_INPUT = "discrete_input"


class RegisterEntry(BaseModel):
    address: int
    name: str
    register_type: RegisterType
    description: str
    unit: str = ""
    min_value: float = 0
    max_value: float = 65535
    default_value: float = 0


class ProcessState(BaseModel):
    """Snapshot of the water treatment plant process."""
    timestamp: datetime = Field(default_factory=datetime.now)
    tank_level: float = 50.0          # percent (0-100)
    inflow_rate: float = 10.0         # liters/min
    outflow_rate: float = 10.0        # liters/min
    ph_level: float = 7.0             # pH (0-14)
    chlorine_dosing: float = 1.5      # mg/L
    turbidity: float = 0.5            # NTU
    pressure_psi: float = 45.0        # PSI
    temperature_c: float = 22.0       # Celsius
    inlet_valve_open: bool = True
    outlet_valve_open: bool = True
    pump_running: bool = True
    mixer_running: bool = True
    high_level_alarm: bool = False
    low_level_alarm: bool = False
    ph_alarm: bool = False
    pressure_alarm: bool = False


class ModbusTransaction(BaseModel):
    """A single Modbus transaction log entry."""
    timestamp: datetime = Field(default_factory=datetime.now)
    source_ip: str = ""
    function_code: int
    register_type: RegisterType
    address: int
    count: int = 1
    values: list[int] = Field(default_factory=list)
    is_write: bool = False
    is_attack: bool = False
    attack_type: str = ""


class AttackResult(BaseModel):
    """Result of an attack execution."""
    attack_name: str
    success: bool
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: datetime | None = None
    details: str = ""
    registers_affected: list[int] = Field(default_factory=list)
    values_before: dict[int, int] = Field(default_factory=dict)
    values_after: dict[int, int] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    transactions: list[ModbusTransaction] = Field(default_factory=list)


class MitreTechnique(BaseModel):
    """MITRE ATT&CK for ICS technique."""
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str = ""


class AttackScenario(BaseModel):
    """LLM-generated attack scenario."""
    name: str
    description: str
    objective: str
    steps: list[AttackStep] = Field(default_factory=list)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    estimated_impact: str = ""
    detection_indicators: list[str] = Field(default_factory=list)


class AttackStep(BaseModel):
    """A single step in an attack scenario."""
    order: int
    description: str
    function_code: int
    register_type: RegisterType = RegisterType.HOLDING
    start_address: int
    values: list[int] = Field(default_factory=list)
    count: int = 1
    delay_seconds: float = 0.0


# Fix forward reference
AttackScenario.model_rebuild()
