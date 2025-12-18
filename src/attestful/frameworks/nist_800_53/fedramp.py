"""
FedRAMP baseline definitions for NIST 800-53.

Provides FedRAMP Low, Moderate, and High baseline control selections
based on the official FedRAMP baselines.

FedRAMP (Federal Risk and Authorization Management Program) provides a
standardized approach to security assessment, authorization, and
continuous monitoring for cloud products and services.

Baselines:
- FedRAMP Low: ~125 controls for low-impact systems
- FedRAMP Moderate: ~325 controls for moderate-impact systems
- FedRAMP High: ~421 controls for high-impact systems
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


# =============================================================================
# FedRAMP Baseline Constants
# =============================================================================

FEDRAMP_LOW = "fedramp-low"
FEDRAMP_MODERATE = "fedramp-moderate"
FEDRAMP_HIGH = "fedramp-high"

# FedRAMP-specific parameter values (organization-defined parameters)
# These are the typical FedRAMP values - agencies may customize
FEDRAMP_PARAMETERS = {
    # AC-2 Account Management
    "AC-2_ODP_01": "30 days",  # Time for disabling inactive accounts
    "AC-2_ODP_02": "24 hours",  # Notification time for account changes

    # AC-7 Unsuccessful Logon Attempts
    "AC-7_ODP_01": "3",  # Maximum consecutive invalid attempts
    "AC-7_ODP_02": "15 minutes",  # Time period for counting attempts
    "AC-7_ODP_03": "lockout",  # Action when max exceeded

    # AU-11 Audit Record Retention
    "AU-11_ODP_01": "3 years",  # Minimum audit log retention

    # IA-5(1) Password Requirements
    "IA-5(1)_ODP_01": "12 characters",  # Minimum password length
    "IA-5(1)_ODP_02": "60 days",  # Maximum password age
    "IA-5(1)_ODP_03": "24",  # Password history (generations)

    # SI-2 Flaw Remediation
    "SI-2_ODP_01": "30 days critical, 90 days high, 180 days moderate",  # Patch timelines
}


@dataclass
class FedRAMPBaseline:
    """
    A FedRAMP baseline definition.

    Attributes:
        id: Baseline identifier (fedramp-low, fedramp-moderate, fedramp-high).
        name: Human-readable baseline name.
        impact_level: FIPS 199 impact level (low, moderate, high).
        controls: List of control IDs in the baseline.
        parameters: FedRAMP-specific parameter values.
        description: Baseline description.
    """

    id: str
    name: str
    impact_level: str
    controls: list[str] = field(default_factory=list)
    parameters: dict[str, str] = field(default_factory=dict)
    description: str = ""

    @property
    def control_count(self) -> int:
        """Total number of controls in the baseline."""
        return len(self.controls)

    def has_control(self, control_id: str) -> bool:
        """Check if a control is in the baseline."""
        return control_id in self.controls

    def get_parameter(self, param_id: str) -> str | None:
        """Get a FedRAMP-specific parameter value."""
        return self.parameters.get(param_id)


# =============================================================================
# FedRAMP Low Baseline Controls
# =============================================================================

# Based on FedRAMP Low Baseline Rev 5 (approximately 125 controls)
FEDRAMP_LOW_CONTROLS = [
    # Access Control (AC)
    "AC-1", "AC-2", "AC-3", "AC-6", "AC-7", "AC-8", "AC-14", "AC-17",
    "AC-18", "AC-19", "AC-20", "AC-22",

    # Awareness and Training (AT)
    "AT-1", "AT-2", "AT-3", "AT-4",

    # Audit and Accountability (AU)
    "AU-1", "AU-2", "AU-3", "AU-4", "AU-5", "AU-6", "AU-8", "AU-9",
    "AU-11", "AU-12",

    # Security Assessment and Authorization (CA)
    "CA-1", "CA-2", "CA-3", "CA-5", "CA-6", "CA-7", "CA-9",

    # Configuration Management (CM)
    "CM-1", "CM-2", "CM-4", "CM-5", "CM-6", "CM-7", "CM-8", "CM-10", "CM-11",

    # Contingency Planning (CP)
    "CP-1", "CP-2", "CP-3", "CP-4", "CP-9", "CP-10",

    # Identification and Authentication (IA)
    "IA-1", "IA-2", "IA-2(1)", "IA-2(12)", "IA-4", "IA-5", "IA-5(1)",
    "IA-6", "IA-7", "IA-8", "IA-11",

    # Incident Response (IR)
    "IR-1", "IR-2", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8",

    # Maintenance (MA)
    "MA-1", "MA-2", "MA-4", "MA-5",

    # Media Protection (MP)
    "MP-1", "MP-2", "MP-6", "MP-7",

    # Physical and Environmental Protection (PE)
    "PE-1", "PE-2", "PE-3", "PE-6", "PE-8", "PE-12", "PE-13", "PE-14", "PE-15",

    # Planning (PL)
    "PL-1", "PL-2", "PL-4", "PL-10", "PL-11",

    # Program Management (PM)
    "PM-1", "PM-2", "PM-3", "PM-4", "PM-5", "PM-6", "PM-7", "PM-8", "PM-9",
    "PM-10", "PM-11", "PM-13", "PM-14", "PM-15", "PM-16",

    # Personnel Security (PS)
    "PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8", "PS-9",

    # PII Processing and Transparency (PT)
    "PT-1",

    # Risk Assessment (RA)
    "RA-1", "RA-2", "RA-3", "RA-5", "RA-7",

    # System and Services Acquisition (SA)
    "SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-8", "SA-9", "SA-22",

    # System and Communications Protection (SC)
    "SC-1", "SC-5", "SC-7", "SC-12", "SC-13", "SC-15", "SC-20", "SC-21",
    "SC-22", "SC-39",

    # System and Information Integrity (SI)
    "SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-10", "SI-11", "SI-12", "SI-16",

    # Supply Chain Risk Management (SR)
    "SR-1", "SR-2", "SR-3", "SR-5", "SR-8", "SR-10", "SR-11", "SR-12",
]


# =============================================================================
# FedRAMP Moderate Baseline Controls
# =============================================================================

# Based on FedRAMP Moderate Baseline Rev 5 (approximately 325 controls)
# Includes all Low controls plus additional Moderate controls
FEDRAMP_MODERATE_CONTROLS = FEDRAMP_LOW_CONTROLS + [
    # Access Control (AC) - Additional Moderate
    "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)", "AC-4", "AC-5",
    "AC-6(1)", "AC-6(2)", "AC-6(5)", "AC-6(9)", "AC-6(10)",
    "AC-11", "AC-11(1)", "AC-12", "AC-17(1)", "AC-17(2)", "AC-17(3)", "AC-17(4)",
    "AC-18(1)", "AC-19(5)", "AC-20(1)", "AC-20(2)", "AC-21",

    # Awareness and Training (AT) - Additional Moderate
    "AT-2(2)", "AT-3(3)",

    # Audit and Accountability (AU) - Additional Moderate
    "AU-2(3)", "AU-3(1)", "AU-4(1)", "AU-5(1)", "AU-5(2)",
    "AU-6(1)", "AU-6(3)", "AU-7", "AU-7(1)", "AU-9(4)", "AU-12(3)",

    # Security Assessment and Authorization (CA) - Additional Moderate
    "CA-2(1)", "CA-3(6)", "CA-7(1)", "CA-7(4)", "CA-8",

    # Configuration Management (CM) - Additional Moderate
    "CM-2(2)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-3(1)", "CM-3(2)", "CM-3(4)",
    "CM-4(1)", "CM-6(1)", "CM-6(2)", "CM-7(1)", "CM-7(2)", "CM-7(5)",
    "CM-8(1)", "CM-8(3)", "CM-9", "CM-12", "CM-12(1)",

    # Contingency Planning (CP) - Additional Moderate
    "CP-2(1)", "CP-2(3)", "CP-2(8)", "CP-4(1)", "CP-6", "CP-6(1)", "CP-6(3)",
    "CP-7", "CP-7(1)", "CP-7(2)", "CP-7(3)", "CP-8", "CP-8(1)", "CP-8(2)",
    "CP-9(1)", "CP-9(8)", "CP-10(2)",

    # Identification and Authentication (IA) - Additional Moderate
    "IA-2(2)", "IA-2(8)", "IA-3", "IA-4(4)", "IA-5(2)", "IA-5(6)",
    "IA-8(1)", "IA-8(2)", "IA-8(4)", "IA-12", "IA-12(2)", "IA-12(3)",
    "IA-12(4)", "IA-12(5)",

    # Incident Response (IR) - Additional Moderate
    "IR-2(1)", "IR-2(2)", "IR-3", "IR-3(2)", "IR-4(1)", "IR-4(4)",
    "IR-6(1)", "IR-6(3)", "IR-7(1)", "IR-8(1)",

    # Maintenance (MA) - Additional Moderate
    "MA-2(2)", "MA-3", "MA-3(1)", "MA-3(2)", "MA-4(1)", "MA-4(3)",
    "MA-5(1)", "MA-6",

    # Media Protection (MP) - Additional Moderate
    "MP-3", "MP-4", "MP-5", "MP-6(2)", "MP-7(1)",

    # Physical and Environmental Protection (PE) - Additional Moderate
    "PE-2(3)", "PE-3(1)", "PE-4", "PE-5", "PE-6(1)", "PE-6(4)", "PE-9",
    "PE-10", "PE-11", "PE-13(1)", "PE-13(2)", "PE-14(2)", "PE-15(1)",
    "PE-16", "PE-17", "PE-18",

    # Planning (PL) - Additional Moderate
    "PL-8", "PL-8(1)",

    # Program Management (PM) - Additional Moderate
    "PM-5(1)", "PM-17", "PM-18", "PM-19", "PM-20", "PM-21", "PM-22",
    "PM-23", "PM-24", "PM-25", "PM-26", "PM-27", "PM-28", "PM-30", "PM-31",

    # Personnel Security (PS) - Additional Moderate (none additional required)

    # PII Processing and Transparency (PT) - Additional Moderate
    "PT-2", "PT-3", "PT-4", "PT-5", "PT-5(2)", "PT-6", "PT-6(1)", "PT-6(2)",
    "PT-7", "PT-7(1)", "PT-7(2)", "PT-8",

    # Risk Assessment (RA) - Additional Moderate
    "RA-3(1)", "RA-5(2)", "RA-5(5)", "RA-5(11)",

    # System and Services Acquisition (SA) - Additional Moderate
    "SA-3(1)", "SA-4(1)", "SA-4(2)", "SA-4(5)", "SA-4(9)", "SA-4(10)",
    "SA-8(1)", "SA-8(2)", "SA-8(3)", "SA-8(4)", "SA-8(5)", "SA-8(6)",
    "SA-8(7)", "SA-8(8)", "SA-8(9)", "SA-9(2)", "SA-10", "SA-11",
    "SA-15", "SA-15(3)",

    # System and Communications Protection (SC) - Additional Moderate
    "SC-2", "SC-3", "SC-4", "SC-7(3)", "SC-7(4)", "SC-7(5)", "SC-7(7)",
    "SC-7(8)", "SC-7(18)", "SC-7(21)", "SC-8", "SC-8(1)", "SC-10",
    "SC-12(1)", "SC-17", "SC-18", "SC-23", "SC-23(5)", "SC-28", "SC-28(1)",

    # System and Information Integrity (SI) - Additional Moderate
    "SI-2(2)", "SI-3(1)", "SI-3(2)", "SI-3(4)", "SI-4(2)", "SI-4(4)",
    "SI-4(5)", "SI-6", "SI-7", "SI-7(1)", "SI-7(7)", "SI-8", "SI-8(1)",
    "SI-8(2)", "SI-10(3)",

    # Supply Chain Risk Management (SR) - Additional Moderate
    "SR-2(1)", "SR-3(1)", "SR-3(2)", "SR-5(1)", "SR-5(2)", "SR-6",
    "SR-9", "SR-9(1)", "SR-10(1)", "SR-11(1)", "SR-11(2)",
]


# =============================================================================
# FedRAMP High Baseline Controls
# =============================================================================

# Based on FedRAMP High Baseline Rev 5 (approximately 421 controls)
# Includes all Moderate controls plus additional High controls
FEDRAMP_HIGH_CONTROLS = FEDRAMP_MODERATE_CONTROLS + [
    # Access Control (AC) - Additional High
    "AC-2(5)", "AC-2(11)", "AC-2(12)", "AC-2(13)", "AC-3(3)", "AC-4(4)",
    "AC-4(21)", "AC-6(3)", "AC-6(7)", "AC-6(8)", "AC-10", "AC-16",
    "AC-17(9)", "AC-19(4)",

    # Awareness and Training (AT) - Additional High
    "AT-2(1)", "AT-2(3)", "AT-3(5)",

    # Audit and Accountability (AU) - Additional High
    "AU-3(2)", "AU-5(3)", "AU-5(4)", "AU-6(5)", "AU-6(6)", "AU-9(2)",
    "AU-9(3)", "AU-10", "AU-12(1)", "AU-13", "AU-14", "AU-14(1)",

    # Security Assessment and Authorization (CA) - Additional High
    "CA-2(2)", "CA-3(7)", "CA-7(6)", "CA-8(1)",

    # Configuration Management (CM) - Additional High
    "CM-2(6)", "CM-3(3)", "CM-3(5)", "CM-3(6)", "CM-4(2)", "CM-5(1)",
    "CM-7(4)", "CM-8(4)", "CM-8(5)", "CM-14",

    # Contingency Planning (CP) - Additional High
    "CP-2(4)", "CP-2(5)", "CP-2(6)", "CP-2(7)", "CP-4(2)", "CP-6(2)",
    "CP-7(4)", "CP-8(3)", "CP-8(4)", "CP-9(2)", "CP-9(3)", "CP-9(5)",
    "CP-10(4)",

    # Identification and Authentication (IA) - Additional High
    "IA-2(5)", "IA-2(6)", "IA-3(1)", "IA-4(5)", "IA-4(6)", "IA-5(3)",
    "IA-5(8)", "IA-5(13)", "IA-8(5)", "IA-8(6)",

    # Incident Response (IR) - Additional High
    "IR-3(3)", "IR-4(3)", "IR-4(6)", "IR-4(7)", "IR-4(8)", "IR-4(11)",

    # Maintenance (MA) - Additional High
    "MA-3(3)", "MA-3(4)", "MA-4(4)", "MA-4(5)", "MA-4(6)", "MA-4(7)",
    "MA-5(2)", "MA-6(1)", "MA-6(2)", "MA-6(3)",

    # Media Protection (MP) - Additional High
    "MP-5(1)", "MP-5(2)", "MP-5(3)", "MP-5(4)", "MP-6(1)", "MP-6(3)",
    "MP-6(7)", "MP-6(8)",

    # Physical and Environmental Protection (PE) - Additional High
    "PE-2(1)", "PE-2(2)", "PE-3(2)", "PE-3(3)", "PE-3(5)", "PE-4(1)",
    "PE-6(2)", "PE-6(3)", "PE-8(1)", "PE-9(1)", "PE-11(1)", "PE-12(1)",
    "PE-13(3)", "PE-14(1)", "PE-18(1)", "PE-19", "PE-20",

    # Planning (PL) - Additional High (none additional required)

    # Program Management (PM) - Additional High
    "PM-7(1)", "PM-29", "PM-32",

    # Personnel Security (PS) - Additional High (none additional required)

    # PII Processing and Transparency (PT) - Additional High
    "PT-2(1)", "PT-2(2)",

    # Risk Assessment (RA) - Additional High
    "RA-3(3)", "RA-3(4)", "RA-5(4)", "RA-5(6)", "RA-5(8)", "RA-5(10)",
    "RA-6", "RA-9", "RA-10",

    # System and Services Acquisition (SA) - Additional High
    "SA-4(3)", "SA-8(10)", "SA-8(11)", "SA-8(12)", "SA-8(13)",
    "SA-8(14)", "SA-8(15)", "SA-8(16)", "SA-8(17)", "SA-8(18)",
    "SA-9(3)", "SA-9(5)", "SA-9(6)", "SA-11(1)", "SA-11(2)", "SA-11(4)",
    "SA-11(5)", "SA-12", "SA-15(1)", "SA-15(2)", "SA-15(5)", "SA-15(6)",
    "SA-15(7)", "SA-15(10)", "SA-16", "SA-17",

    # System and Communications Protection (SC) - Additional High
    "SC-3(1)", "SC-3(2)", "SC-3(3)", "SC-3(4)", "SC-3(5)", "SC-4(2)",
    "SC-5(2)", "SC-7(9)", "SC-7(10)", "SC-7(11)", "SC-7(12)", "SC-7(13)",
    "SC-7(14)", "SC-7(15)", "SC-7(17)", "SC-7(19)", "SC-7(20)", "SC-7(24)",
    "SC-8(2)", "SC-8(3)", "SC-8(4)", "SC-8(5)", "SC-11", "SC-12(2)",
    "SC-12(3)", "SC-13(1)", "SC-16", "SC-16(1)", "SC-24", "SC-25",
    "SC-26", "SC-28(2)", "SC-29", "SC-29(1)", "SC-30", "SC-30(2)",
    "SC-30(3)", "SC-30(5)", "SC-31", "SC-32", "SC-36", "SC-36(1)",
    "SC-37", "SC-37(1)", "SC-38", "SC-40", "SC-40(1)", "SC-43",

    # System and Information Integrity (SI) - Additional High
    "SI-2(5)", "SI-2(6)", "SI-3(6)", "SI-3(8)", "SI-3(10)", "SI-4(10)",
    "SI-4(12)", "SI-4(13)", "SI-4(14)", "SI-4(15)", "SI-4(16)", "SI-4(17)",
    "SI-4(18)", "SI-4(19)", "SI-4(20)", "SI-4(22)", "SI-4(23)", "SI-4(24)",
    "SI-7(2)", "SI-7(5)", "SI-7(6)", "SI-7(8)", "SI-7(9)", "SI-7(10)",
    "SI-7(12)", "SI-7(15)", "SI-10(5)", "SI-10(6)", "SI-13", "SI-14",
    "SI-14(1)", "SI-15", "SI-17",

    # Supply Chain Risk Management (SR) - Additional High
    "SR-4", "SR-4(1)", "SR-4(2)", "SR-4(3)", "SR-4(4)", "SR-6(1)",
    "SR-7", "SR-9(1)", "SR-11(3)",
]


# =============================================================================
# Baseline Definitions
# =============================================================================

FEDRAMP_BASELINES: dict[str, FedRAMPBaseline] = {
    FEDRAMP_LOW: FedRAMPBaseline(
        id=FEDRAMP_LOW,
        name="FedRAMP Low",
        impact_level="low",
        controls=FEDRAMP_LOW_CONTROLS,
        parameters=FEDRAMP_PARAMETERS,
        description=(
            "FedRAMP Low baseline for cloud systems where the loss of confidentiality, "
            "integrity, or availability would have a limited adverse effect on "
            "organizational operations, assets, or individuals."
        ),
    ),
    FEDRAMP_MODERATE: FedRAMPBaseline(
        id=FEDRAMP_MODERATE,
        name="FedRAMP Moderate",
        impact_level="moderate",
        controls=FEDRAMP_MODERATE_CONTROLS,
        parameters=FEDRAMP_PARAMETERS,
        description=(
            "FedRAMP Moderate baseline for cloud systems where the loss of confidentiality, "
            "integrity, or availability would have a serious adverse effect on "
            "organizational operations, assets, or individuals."
        ),
    ),
    FEDRAMP_HIGH: FedRAMPBaseline(
        id=FEDRAMP_HIGH,
        name="FedRAMP High",
        impact_level="high",
        controls=FEDRAMP_HIGH_CONTROLS,
        parameters=FEDRAMP_PARAMETERS,
        description=(
            "FedRAMP High baseline for cloud systems where the loss of confidentiality, "
            "integrity, or availability would have a severe or catastrophic adverse "
            "effect on organizational operations, assets, or individuals."
        ),
    ),
}


# =============================================================================
# Lookup Functions
# =============================================================================


def get_fedramp_baseline(baseline_id: str) -> FedRAMPBaseline | None:
    """
    Get a FedRAMP baseline by ID.

    Args:
        baseline_id: Baseline identifier (fedramp-low, fedramp-moderate, fedramp-high).

    Returns:
        The baseline if found, None otherwise.
    """
    return FEDRAMP_BASELINES.get(baseline_id)


def get_fedramp_baseline_controls(baseline_id: str) -> list[str]:
    """
    Get control IDs required for a FedRAMP baseline.

    Args:
        baseline_id: Baseline identifier (fedramp-low, fedramp-moderate, fedramp-high).

    Returns:
        List of control IDs, empty list if baseline not found.
    """
    baseline = FEDRAMP_BASELINES.get(baseline_id)
    if baseline:
        return baseline.controls.copy()
    return []


def get_fedramp_control_parameters(baseline_id: str) -> dict[str, str]:
    """
    Get FedRAMP-specific parameter values for a baseline.

    Args:
        baseline_id: Baseline identifier.

    Returns:
        Dictionary of parameter IDs to values.
    """
    baseline = FEDRAMP_BASELINES.get(baseline_id)
    if baseline:
        return baseline.parameters.copy()
    return {}
