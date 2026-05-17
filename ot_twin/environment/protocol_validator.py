"""
Modbus Protocol Validator — Checks transactions against protocol specifications.

Validates:
  - Function code is a known Modbus FC
  - Register addresses are within the PLC's defined address space
  - Values are within 16-bit unsigned range (0-65535)
  - Read counts don't exceed protocol maximums
  - Write operations target writable register types
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ot_twin.environment.register_map import (
    COILS,
    DISCRETE_INPUTS,
    HOLDING_REGISTERS,
    INPUT_REGISTERS,
)
from ot_twin.models import RegisterType


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    VIOLATION = "violation"


@dataclass
class ValidationResult:
    """Result of validating a single Modbus transaction."""
    valid: bool
    issues: list[ValidationIssue]


@dataclass
class ValidationIssue:
    """A single validation finding."""
    severity: Severity
    field: str
    message: str


# Modbus spec limits
MAX_READ_REGISTERS = 125      # FC3/FC4: max registers per read
MAX_READ_COILS = 2000         # FC1/FC2: max coils per read
MAX_WRITE_REGISTERS = 123     # FC16: max registers per write
MAX_WRITE_COILS = 1968        # FC15: max coils per write
MAX_REGISTER_VALUE = 65535    # 16-bit unsigned

VALID_FUNCTION_CODES = {1, 2, 3, 4, 5, 6, 15, 16}
READ_ONLY_TYPES = {RegisterType.INPUT, RegisterType.DISCRETE_INPUT}
WRITE_FUNCTION_CODES = {5, 6, 15, 16}

# Build address space bounds from register map
_HR_MAX = max(r.address for r in HOLDING_REGISTERS) if HOLDING_REGISTERS else 0
_IR_MAX = max(r.address for r in INPUT_REGISTERS) if INPUT_REGISTERS else 0
_COIL_MAX = max(r.address for r in COILS) if COILS else 0
_DI_MAX = max(r.address for r in DISCRETE_INPUTS) if DISCRETE_INPUTS else 0


def validate_transaction(
    function_code: int,
    register_type: RegisterType,
    address: int,
    count: int = 1,
    values: list[int] | None = None,
) -> ValidationResult:
    """Validate a Modbus transaction against protocol spec and PLC register map.

    Args:
        function_code: Modbus function code.
        register_type: Target register type.
        address: Starting register address.
        count: Number of registers/coils.
        values: Values being written (for write operations).

    Returns:
        ValidationResult with valid flag and list of issues.
    """
    issues: list[ValidationIssue] = []
    values = values or []

    # 1. Function code check
    if function_code not in VALID_FUNCTION_CODES:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="function_code",
            message=f"Unknown function code: {function_code}",
        ))

    # 2. Write to read-only check
    if function_code in WRITE_FUNCTION_CODES and register_type in READ_ONLY_TYPES:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="register_type",
            message=f"Write FC{function_code} to read-only {register_type.value}",
        ))

    # 3. Address range check
    max_addr = _get_max_address(register_type)
    if address < 0:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="address",
            message=f"Negative address: {address}",
        ))
    elif address > max_addr:
        issues.append(ValidationIssue(
            severity=Severity.WARNING,
            field="address",
            message=f"Address {address} beyond defined range (max {max_addr})",
        ))

    # 4. Count limits
    if function_code in (3, 4) and count > MAX_READ_REGISTERS:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="count",
            message=f"Read count {count} exceeds max {MAX_READ_REGISTERS}",
        ))
    elif function_code in (1, 2) and count > MAX_READ_COILS:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="count",
            message=f"Coil read count {count} exceeds max {MAX_READ_COILS}",
        ))
    elif function_code == 16 and count > MAX_WRITE_REGISTERS:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="count",
            message=f"Multi-write count {count} exceeds max {MAX_WRITE_REGISTERS}",
        ))
    elif function_code == 15 and count > MAX_WRITE_COILS:
        issues.append(ValidationIssue(
            severity=Severity.VIOLATION,
            field="count",
            message=f"Multi-coil write count {count} exceeds max {MAX_WRITE_COILS}",
        ))

    # 5. Value range check (16-bit unsigned)
    for i, val in enumerate(values):
        if val < 0 or val > MAX_REGISTER_VALUE:
            issues.append(ValidationIssue(
                severity=Severity.VIOLATION,
                field="values",
                message=f"Value {val} at index {i} outside 0-{MAX_REGISTER_VALUE}",
            ))

    valid = not any(issue.severity == Severity.VIOLATION for issue in issues)
    return ValidationResult(valid=valid, issues=issues)


def _get_max_address(register_type: RegisterType) -> int:
    """Get the maximum defined address for a register type."""
    return {
        RegisterType.HOLDING: _HR_MAX,
        RegisterType.INPUT: _IR_MAX,
        RegisterType.COIL: _COIL_MAX,
        RegisterType.DISCRETE_INPUT: _DI_MAX,
    }.get(register_type, 0)
