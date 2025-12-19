"""
Cross-Framework Mapping Registry.

Provides a centralized registry of bidirectional control mappings between
all supported compliance frameworks.

Framework Pairs Supported:
--------------------------
1. NIST CSF 2.0 <-> NIST 800-53
2. NIST 800-53 <-> SOC 2
3. NIST 800-53 <-> ISO 27001
4. NIST 800-53 <-> HITRUST
5. SOC 2 <-> ISO 27001
6. NIST CSF 2.0 <-> SOC 2
7. NIST CSF 2.0 <-> ISO 27001
8. NIST CSF 2.0 <-> HITRUST
9. SOC 2 <-> HITRUST
10. ISO 27001 <-> HITRUST

Mapping Sources:
----------------
- NIST official crosswalks
- AICPA mapping guides
- HITRUST framework documentation
- ISO/NIST alignment documents
- Industry best practices
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger("frameworks.mapping.registry")


# =============================================================================
# Enums and Constants
# =============================================================================


class FrameworkID(str, Enum):
    """Supported framework identifiers."""

    NIST_CSF_2 = "nist-csf-2.0"
    NIST_800_53 = "nist-800-53"
    SOC2 = "soc2"
    ISO_27001 = "iso-27001"
    HITRUST = "hitrust"


class MappingDirection(str, Enum):
    """Direction of control mapping."""

    FORWARD = "forward"  # Source -> Target
    REVERSE = "reverse"  # Target -> Source
    BIDIRECTIONAL = "bidirectional"  # Both directions


# Framework display names
FRAMEWORK_NAMES = {
    FrameworkID.NIST_CSF_2: "NIST CSF 2.0",
    FrameworkID.NIST_800_53: "NIST 800-53 Rev 5",
    FrameworkID.SOC2: "SOC 2 Type II",
    FrameworkID.ISO_27001: "ISO 27001:2022",
    FrameworkID.HITRUST: "HITRUST CSF",
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ControlMapping:
    """
    A single control-to-control mapping between frameworks.

    Attributes:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.
        target_control: Target control ID.
        strength: Mapping strength (0.0 - 1.0).
        notes: Mapping notes or rationale.
        source_reference: Reference for this mapping.
        bidirectional: Whether mapping applies in both directions.
    """

    source_framework: FrameworkID
    source_control: str
    target_framework: FrameworkID
    target_control: str
    strength: float = 0.8
    notes: str = ""
    source_reference: str = ""
    bidirectional: bool = True

    def __post_init__(self) -> None:
        """Validate mapping strength."""
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError(f"Mapping strength must be 0.0-1.0, got {self.strength}")

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_framework": self.source_framework.value,
            "source_control": self.source_control,
            "target_framework": self.target_framework.value,
            "target_control": self.target_control,
            "strength": self.strength,
            "notes": self.notes,
            "source_reference": self.source_reference,
            "bidirectional": self.bidirectional,
        }

    def reverse(self) -> "ControlMapping":
        """Create reverse mapping."""
        return ControlMapping(
            source_framework=self.target_framework,
            source_control=self.target_control,
            target_framework=self.source_framework,
            target_control=self.source_control,
            strength=self.strength,
            notes=self.notes,
            source_reference=self.source_reference,
            bidirectional=self.bidirectional,
        )


@dataclass
class FrameworkPairMapping:
    """
    Complete mapping between two frameworks.

    Attributes:
        source_framework: Source framework ID.
        target_framework: Target framework ID.
        mappings: List of control mappings.
        version: Mapping version.
        last_updated: Last update date.
    """

    source_framework: FrameworkID
    target_framework: FrameworkID
    mappings: list[ControlMapping] = field(default_factory=list)
    version: str = "1.0"
    last_updated: str = "2024-01-01"

    @property
    def pair_id(self) -> str:
        """Get unique pair identifier."""
        return f"{self.source_framework.value}:{self.target_framework.value}"

    def get_mappings_for_source(self, source_control: str) -> list[ControlMapping]:
        """Get all mappings for a source control."""
        return [m for m in self.mappings if m.source_control == source_control]

    def get_mappings_for_target(self, target_control: str) -> list[ControlMapping]:
        """Get all mappings to a target control."""
        return [m for m in self.mappings if m.target_control == target_control]

    def get_strongest_mapping(self, source_control: str) -> ControlMapping | None:
        """Get strongest mapping for a source control."""
        mappings = self.get_mappings_for_source(source_control)
        if not mappings:
            return None
        return max(mappings, key=lambda m: m.strength)


# =============================================================================
# Mapping Data
# =============================================================================

# NIST CSF 2.0 <-> NIST 800-53 Mappings
# Based on NIST SP 800-53 Rev 5 to CSF 2.0 crosswalk
NIST_CSF_TO_800_53_MAPPINGS = [
    # GOVERN function
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.OC-01", FrameworkID.NIST_800_53, "PM-1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.OC-02", FrameworkID.NIST_800_53, "PM-2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.RM-01", FrameworkID.NIST_800_53, "RA-1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.RM-02", FrameworkID.NIST_800_53, "RA-3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.RM-03", FrameworkID.NIST_800_53, "PM-9", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.SC-01", FrameworkID.NIST_800_53, "SR-1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.SC-02", FrameworkID.NIST_800_53, "SR-2", 0.9),
    # IDENTIFY function
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.AM-01", FrameworkID.NIST_800_53, "CM-8", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.AM-02", FrameworkID.NIST_800_53, "CM-8", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.AM-03", FrameworkID.NIST_800_53, "AC-20", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.AM-04", FrameworkID.NIST_800_53, "CM-8", 0.7),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.RA-01", FrameworkID.NIST_800_53, "RA-3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.RA-02", FrameworkID.NIST_800_53, "RA-5", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.RA-03", FrameworkID.NIST_800_53, "RA-5", 0.8),
    # PROTECT function
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-01", FrameworkID.NIST_800_53, "AC-2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-02", FrameworkID.NIST_800_53, "IA-2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-03", FrameworkID.NIST_800_53, "AC-3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-04", FrameworkID.NIST_800_53, "AC-6", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-05", FrameworkID.NIST_800_53, "AC-17", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-01", FrameworkID.NIST_800_53, "SC-28", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-02", FrameworkID.NIST_800_53, "SC-8", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-10", FrameworkID.NIST_800_53, "SC-12", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-11", FrameworkID.NIST_800_53, "CP-9", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-01", FrameworkID.NIST_800_53, "CM-2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-02", FrameworkID.NIST_800_53, "CM-7", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-03", FrameworkID.NIST_800_53, "CM-3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.IR-01", FrameworkID.NIST_800_53, "SI-3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.IR-02", FrameworkID.NIST_800_53, "SI-4", 0.9),
    # DETECT function
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-01", FrameworkID.NIST_800_53, "CA-7", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-02", FrameworkID.NIST_800_53, "PE-6", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-03", FrameworkID.NIST_800_53, "AC-2", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-06", FrameworkID.NIST_800_53, "SR-4", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-09", FrameworkID.NIST_800_53, "AU-6", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.AE-02", FrameworkID.NIST_800_53, "SI-4", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.AE-03", FrameworkID.NIST_800_53, "AU-6", 0.9),
    # RESPOND function
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MA-01", FrameworkID.NIST_800_53, "IR-4", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MA-02", FrameworkID.NIST_800_53, "IR-5", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MA-03", FrameworkID.NIST_800_53, "IR-4", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.AN-03", FrameworkID.NIST_800_53, "IR-4", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.CO-02", FrameworkID.NIST_800_53, "IR-6", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MI-01", FrameworkID.NIST_800_53, "IR-4", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MI-02", FrameworkID.NIST_800_53, "IR-4", 0.8),
    # RECOVER function
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.RP-01", FrameworkID.NIST_800_53, "CP-10", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.RP-02", FrameworkID.NIST_800_53, "CP-10", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.RP-03", FrameworkID.NIST_800_53, "CP-9", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.CO-03", FrameworkID.NIST_800_53, "IR-4", 0.7),
]

# NIST 800-53 <-> SOC 2 Mappings
# Based on AICPA Trust Services Criteria mapping
NIST_800_53_TO_SOC2_MAPPINGS = [
    # Access Control (AC) -> CC6 Logical and Physical Access
    ControlMapping(FrameworkID.NIST_800_53, "AC-1", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.SOC2, "CC6.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-3", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-4", FrameworkID.SOC2, "CC6.6", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-5", FrameworkID.SOC2, "CC5.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-6", FrameworkID.SOC2, "CC6.3", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-7", FrameworkID.SOC2, "CC6.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-11", FrameworkID.SOC2, "CC6.1", 0.7),
    ControlMapping(FrameworkID.NIST_800_53, "AC-17", FrameworkID.SOC2, "CC6.6", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-18", FrameworkID.SOC2, "CC6.6", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-19", FrameworkID.SOC2, "CC6.7", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-20", FrameworkID.SOC2, "CC6.6", 0.7),
    # Audit and Accountability (AU) -> CC7 System Operations
    ControlMapping(FrameworkID.NIST_800_53, "AU-1", FrameworkID.SOC2, "CC7.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-2", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-3", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-4", FrameworkID.SOC2, "CC7.2", 0.7),
    ControlMapping(FrameworkID.NIST_800_53, "AU-5", FrameworkID.SOC2, "CC7.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-6", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-7", FrameworkID.SOC2, "CC7.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-9", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-11", FrameworkID.SOC2, "CC7.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-12", FrameworkID.SOC2, "CC7.2", 0.9),
    # Configuration Management (CM) -> CC8 Change Management
    ControlMapping(FrameworkID.NIST_800_53, "CM-1", FrameworkID.SOC2, "CC8.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-2", FrameworkID.SOC2, "CC8.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-3", FrameworkID.SOC2, "CC8.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-4", FrameworkID.SOC2, "CC8.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-5", FrameworkID.SOC2, "CC8.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-6", FrameworkID.SOC2, "CC8.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-7", FrameworkID.SOC2, "CC6.8", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-8", FrameworkID.SOC2, "CC6.1", 0.8),
    # Contingency Planning (CP) -> A1 Availability
    ControlMapping(FrameworkID.NIST_800_53, "CP-1", FrameworkID.SOC2, "A1.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-2", FrameworkID.SOC2, "A1.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-4", FrameworkID.SOC2, "A1.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CP-6", FrameworkID.SOC2, "A1.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CP-7", FrameworkID.SOC2, "A1.2", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CP-9", FrameworkID.SOC2, "A1.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-10", FrameworkID.SOC2, "A1.3", 0.9),
    # Identification and Authentication (IA) -> CC6 Logical Access
    ControlMapping(FrameworkID.NIST_800_53, "IA-1", FrameworkID.SOC2, "CC6.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-2", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IA-4", FrameworkID.SOC2, "CC6.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-5", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IA-6", FrameworkID.SOC2, "CC6.1", 0.7),
    ControlMapping(FrameworkID.NIST_800_53, "IA-8", FrameworkID.SOC2, "CC6.1", 0.8),
    # Incident Response (IR) -> CC7 System Operations
    ControlMapping(FrameworkID.NIST_800_53, "IR-1", FrameworkID.SOC2, "CC7.3", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-2", FrameworkID.SOC2, "CC7.3", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-4", FrameworkID.SOC2, "CC7.4", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-5", FrameworkID.SOC2, "CC7.4", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-6", FrameworkID.SOC2, "CC7.4", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-8", FrameworkID.SOC2, "CC7.3", 0.9),
    # Risk Assessment (RA) -> CC3 Risk Assessment
    ControlMapping(FrameworkID.NIST_800_53, "RA-1", FrameworkID.SOC2, "CC3.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "RA-2", FrameworkID.SOC2, "CC3.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "RA-3", FrameworkID.SOC2, "CC3.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "RA-5", FrameworkID.SOC2, "CC7.1", 0.9),
    # System and Communications Protection (SC) -> CC6 Logical Access
    ControlMapping(FrameworkID.NIST_800_53, "SC-1", FrameworkID.SOC2, "CC6.6", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "SC-7", FrameworkID.SOC2, "CC6.6", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-8", FrameworkID.SOC2, "CC6.7", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-12", FrameworkID.SOC2, "CC6.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "SC-13", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-28", FrameworkID.SOC2, "CC6.1", 0.9),
    # System and Information Integrity (SI) -> CC7 System Operations
    ControlMapping(FrameworkID.NIST_800_53, "SI-1", FrameworkID.SOC2, "CC7.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "SI-2", FrameworkID.SOC2, "CC7.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-3", FrameworkID.SOC2, "CC7.1", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-4", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-5", FrameworkID.SOC2, "CC7.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "SI-10", FrameworkID.SOC2, "CC6.1", 0.7),
]

# NIST 800-53 <-> ISO 27001 Mappings
# Based on NIST/ISO alignment documentation
NIST_800_53_TO_ISO_27001_MAPPINGS = [
    # Access Control
    ControlMapping(FrameworkID.NIST_800_53, "AC-1", FrameworkID.ISO_27001, "A.5.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.ISO_27001, "A.5.16", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.ISO_27001, "A.5.18", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-3", FrameworkID.ISO_27001, "A.5.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-4", FrameworkID.ISO_27001, "A.8.22", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-5", FrameworkID.ISO_27001, "A.5.3", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-6", FrameworkID.ISO_27001, "A.8.2", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-7", FrameworkID.ISO_27001, "A.8.5", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-11", FrameworkID.ISO_27001, "A.8.1", 0.7),
    ControlMapping(FrameworkID.NIST_800_53, "AC-17", FrameworkID.ISO_27001, "A.8.20", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-18", FrameworkID.ISO_27001, "A.8.20", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-19", FrameworkID.ISO_27001, "A.8.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-20", FrameworkID.ISO_27001, "A.5.19", 0.8),
    # Audit and Accountability
    ControlMapping(FrameworkID.NIST_800_53, "AU-1", FrameworkID.ISO_27001, "A.5.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-2", FrameworkID.ISO_27001, "A.8.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-3", FrameworkID.ISO_27001, "A.8.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-6", FrameworkID.ISO_27001, "A.8.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-9", FrameworkID.ISO_27001, "A.8.15", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-12", FrameworkID.ISO_27001, "A.8.15", 0.9),
    # Configuration Management
    ControlMapping(FrameworkID.NIST_800_53, "CM-1", FrameworkID.ISO_27001, "A.5.37", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-2", FrameworkID.ISO_27001, "A.8.9", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-3", FrameworkID.ISO_27001, "A.8.32", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-6", FrameworkID.ISO_27001, "A.8.9", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-7", FrameworkID.ISO_27001, "A.8.19", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-8", FrameworkID.ISO_27001, "A.5.9", 0.9),
    # Contingency Planning
    ControlMapping(FrameworkID.NIST_800_53, "CP-1", FrameworkID.ISO_27001, "A.5.29", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-2", FrameworkID.ISO_27001, "A.5.30", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-4", FrameworkID.ISO_27001, "A.5.30", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CP-9", FrameworkID.ISO_27001, "A.8.13", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-10", FrameworkID.ISO_27001, "A.5.30", 0.9),
    # Identification and Authentication
    ControlMapping(FrameworkID.NIST_800_53, "IA-1", FrameworkID.ISO_27001, "A.5.17", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-2", FrameworkID.ISO_27001, "A.8.5", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IA-4", FrameworkID.ISO_27001, "A.5.16", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-5", FrameworkID.ISO_27001, "A.5.17", 0.9),
    # Incident Response
    ControlMapping(FrameworkID.NIST_800_53, "IR-1", FrameworkID.ISO_27001, "A.5.24", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-2", FrameworkID.ISO_27001, "A.5.24", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-4", FrameworkID.ISO_27001, "A.5.26", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-5", FrameworkID.ISO_27001, "A.5.27", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-6", FrameworkID.ISO_27001, "A.5.25", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-8", FrameworkID.ISO_27001, "A.5.24", 0.9),
    # Risk Assessment
    ControlMapping(FrameworkID.NIST_800_53, "RA-1", FrameworkID.ISO_27001, "A.5.1", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "RA-3", FrameworkID.ISO_27001, "A.5.7", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "RA-5", FrameworkID.ISO_27001, "A.8.8", 0.9),
    # System and Communications Protection
    ControlMapping(FrameworkID.NIST_800_53, "SC-7", FrameworkID.ISO_27001, "A.8.20", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-8", FrameworkID.ISO_27001, "A.8.24", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-12", FrameworkID.ISO_27001, "A.8.24", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-13", FrameworkID.ISO_27001, "A.8.24", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-28", FrameworkID.ISO_27001, "A.8.11", 0.9),
    # System and Information Integrity
    ControlMapping(FrameworkID.NIST_800_53, "SI-2", FrameworkID.ISO_27001, "A.8.8", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-3", FrameworkID.ISO_27001, "A.8.7", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-4", FrameworkID.ISO_27001, "A.8.16", 0.9),
]

# NIST 800-53 <-> HITRUST Mappings
# Based on HITRUST CSF to NIST crosswalk
NIST_800_53_TO_HITRUST_MAPPINGS = [
    # Access Control
    ControlMapping(FrameworkID.NIST_800_53, "AC-1", FrameworkID.HITRUST, "01.a", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.HITRUST, "01.b", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-2", FrameworkID.HITRUST, "01.c", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-3", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-5", FrameworkID.HITRUST, "01.a", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-6", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-7", FrameworkID.HITRUST, "01.d", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-11", FrameworkID.HITRUST, "01.d", 0.7),
    ControlMapping(FrameworkID.NIST_800_53, "AC-17", FrameworkID.HITRUST, "01.j", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AC-18", FrameworkID.HITRUST, "01.j", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-19", FrameworkID.HITRUST, "01.x", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AC-20", FrameworkID.HITRUST, "01.j", 0.7),
    # Audit and Accountability
    ControlMapping(FrameworkID.NIST_800_53, "AU-1", FrameworkID.HITRUST, "09.aa", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-2", FrameworkID.HITRUST, "09.aa", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-3", FrameworkID.HITRUST, "09.aa", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-6", FrameworkID.HITRUST, "09.ab", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "AU-9", FrameworkID.HITRUST, "09.aa", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "AU-12", FrameworkID.HITRUST, "09.aa", 0.9),
    # Configuration Management
    ControlMapping(FrameworkID.NIST_800_53, "CM-2", FrameworkID.HITRUST, "10.h", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-3", FrameworkID.HITRUST, "10.k", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-6", FrameworkID.HITRUST, "10.h", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CM-7", FrameworkID.HITRUST, "10.h", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "CM-8", FrameworkID.HITRUST, "07.a", 0.9),
    # Contingency Planning
    ControlMapping(FrameworkID.NIST_800_53, "CP-1", FrameworkID.HITRUST, "12.a", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-2", FrameworkID.HITRUST, "12.b", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-4", FrameworkID.HITRUST, "12.c", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-9", FrameworkID.HITRUST, "09.l", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "CP-10", FrameworkID.HITRUST, "12.c", 0.9),
    # Identification and Authentication
    ControlMapping(FrameworkID.NIST_800_53, "IA-1", FrameworkID.HITRUST, "01.d", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-2", FrameworkID.HITRUST, "01.d", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IA-4", FrameworkID.HITRUST, "01.b", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IA-5", FrameworkID.HITRUST, "01.d", 0.9),
    # Incident Response
    ControlMapping(FrameworkID.NIST_800_53, "IR-1", FrameworkID.HITRUST, "11.a", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-2", FrameworkID.HITRUST, "11.a", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-4", FrameworkID.HITRUST, "11.c", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-5", FrameworkID.HITRUST, "11.c", 0.8),
    ControlMapping(FrameworkID.NIST_800_53, "IR-6", FrameworkID.HITRUST, "11.b", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "IR-8", FrameworkID.HITRUST, "11.a", 0.9),
    # Risk Assessment
    ControlMapping(FrameworkID.NIST_800_53, "RA-1", FrameworkID.HITRUST, "03.a", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "RA-3", FrameworkID.HITRUST, "03.b", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "RA-5", FrameworkID.HITRUST, "10.m", 0.9),
    # System and Communications Protection
    ControlMapping(FrameworkID.NIST_800_53, "SC-7", FrameworkID.HITRUST, "09.m", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-8", FrameworkID.HITRUST, "09.y", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-12", FrameworkID.HITRUST, "06.d", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-13", FrameworkID.HITRUST, "06.d", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SC-28", FrameworkID.HITRUST, "06.d", 0.9),
    # System and Information Integrity
    ControlMapping(FrameworkID.NIST_800_53, "SI-2", FrameworkID.HITRUST, "10.m", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-3", FrameworkID.HITRUST, "09.j", 0.9),
    ControlMapping(FrameworkID.NIST_800_53, "SI-4", FrameworkID.HITRUST, "09.ab", 0.9),
]

# SOC 2 <-> ISO 27001 Mappings
# Based on AICPA/ISO mapping documentation
SOC2_TO_ISO_27001_MAPPINGS = [
    # CC1 Control Environment -> A.5 Organizational
    ControlMapping(FrameworkID.SOC2, "CC1.1", FrameworkID.ISO_27001, "A.5.1", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC1.2", FrameworkID.ISO_27001, "A.5.4", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC1.3", FrameworkID.ISO_27001, "A.5.2", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC1.4", FrameworkID.ISO_27001, "A.5.4", 0.7),
    ControlMapping(FrameworkID.SOC2, "CC1.5", FrameworkID.ISO_27001, "A.5.5", 0.8),
    # CC2 Communication -> A.5 Information
    ControlMapping(FrameworkID.SOC2, "CC2.1", FrameworkID.ISO_27001, "A.5.1", 0.7),
    ControlMapping(FrameworkID.SOC2, "CC2.2", FrameworkID.ISO_27001, "A.5.5", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC2.3", FrameworkID.ISO_27001, "A.5.5", 0.7),
    # CC3 Risk Assessment -> A.5.7
    ControlMapping(FrameworkID.SOC2, "CC3.1", FrameworkID.ISO_27001, "A.5.7", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC3.2", FrameworkID.ISO_27001, "A.5.7", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC3.3", FrameworkID.ISO_27001, "A.5.8", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC3.4", FrameworkID.ISO_27001, "A.5.7", 0.8),
    # CC4 Monitoring -> Various
    ControlMapping(FrameworkID.SOC2, "CC4.1", FrameworkID.ISO_27001, "A.5.35", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC4.2", FrameworkID.ISO_27001, "A.5.36", 0.8),
    # CC5 Control Activities -> A.5.3
    ControlMapping(FrameworkID.SOC2, "CC5.1", FrameworkID.ISO_27001, "A.5.3", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC5.2", FrameworkID.ISO_27001, "A.8.32", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC5.3", FrameworkID.ISO_27001, "A.8.9", 0.8),
    # CC6 Logical Access -> A.5.15, A.8
    ControlMapping(FrameworkID.SOC2, "CC6.1", FrameworkID.ISO_27001, "A.5.15", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.1", FrameworkID.ISO_27001, "A.5.16", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.2", FrameworkID.ISO_27001, "A.5.18", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.3", FrameworkID.ISO_27001, "A.8.2", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.4", FrameworkID.ISO_27001, "A.7.1", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC6.5", FrameworkID.ISO_27001, "A.7.2", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC6.6", FrameworkID.ISO_27001, "A.8.20", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.7", FrameworkID.ISO_27001, "A.8.24", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.8", FrameworkID.ISO_27001, "A.8.19", 0.8),
    # CC7 System Operations -> A.8
    ControlMapping(FrameworkID.SOC2, "CC7.1", FrameworkID.ISO_27001, "A.8.8", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.2", FrameworkID.ISO_27001, "A.8.15", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.2", FrameworkID.ISO_27001, "A.8.16", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.3", FrameworkID.ISO_27001, "A.5.24", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.4", FrameworkID.ISO_27001, "A.5.26", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.5", FrameworkID.ISO_27001, "A.5.26", 0.8),
    # CC8 Change Management -> A.8.32
    ControlMapping(FrameworkID.SOC2, "CC8.1", FrameworkID.ISO_27001, "A.8.32", 0.9),
    # CC9 Risk Mitigation -> A.5.8
    ControlMapping(FrameworkID.SOC2, "CC9.1", FrameworkID.ISO_27001, "A.5.8", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC9.2", FrameworkID.ISO_27001, "A.5.23", 0.8),
    # A1 Availability -> A.5.29, A.5.30
    ControlMapping(FrameworkID.SOC2, "A1.1", FrameworkID.ISO_27001, "A.5.29", 0.9),
    ControlMapping(FrameworkID.SOC2, "A1.2", FrameworkID.ISO_27001, "A.5.30", 0.9),
    ControlMapping(FrameworkID.SOC2, "A1.3", FrameworkID.ISO_27001, "A.8.13", 0.9),
    # C1 Confidentiality -> A.8.11
    ControlMapping(FrameworkID.SOC2, "C1.1", FrameworkID.ISO_27001, "A.8.11", 0.9),
    ControlMapping(FrameworkID.SOC2, "C1.2", FrameworkID.ISO_27001, "A.8.10", 0.9),
    # PI Processing Integrity -> A.8
    ControlMapping(FrameworkID.SOC2, "PI1.1", FrameworkID.ISO_27001, "A.8.6", 0.8),
    ControlMapping(FrameworkID.SOC2, "PI1.2", FrameworkID.ISO_27001, "A.8.6", 0.8),
    ControlMapping(FrameworkID.SOC2, "PI1.3", FrameworkID.ISO_27001, "A.8.33", 0.8),
]

# SOC 2 <-> HITRUST Mappings
SOC2_TO_HITRUST_MAPPINGS = [
    # CC3 Risk -> 03 Risk Management
    ControlMapping(FrameworkID.SOC2, "CC3.1", FrameworkID.HITRUST, "03.a", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC3.2", FrameworkID.HITRUST, "03.b", 0.9),
    # CC5 Control Activities -> 00 ISMP
    ControlMapping(FrameworkID.SOC2, "CC5.1", FrameworkID.HITRUST, "00.a", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC5.2", FrameworkID.HITRUST, "10.k", 0.8),
    # CC6 Logical Access -> 01 Access Control
    ControlMapping(FrameworkID.SOC2, "CC6.1", FrameworkID.HITRUST, "01.a", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.1", FrameworkID.HITRUST, "01.b", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.1", FrameworkID.HITRUST, "01.d", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.2", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.3", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.4", FrameworkID.HITRUST, "08.b", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC6.5", FrameworkID.HITRUST, "08.b", 0.8),
    ControlMapping(FrameworkID.SOC2, "CC6.6", FrameworkID.HITRUST, "09.m", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.6", FrameworkID.HITRUST, "01.j", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC6.7", FrameworkID.HITRUST, "09.y", 0.9),
    # CC7 System Operations -> 09 Communications
    ControlMapping(FrameworkID.SOC2, "CC7.1", FrameworkID.HITRUST, "10.m", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.2", FrameworkID.HITRUST, "09.aa", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.2", FrameworkID.HITRUST, "09.ab", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.3", FrameworkID.HITRUST, "11.a", 0.9),
    ControlMapping(FrameworkID.SOC2, "CC7.4", FrameworkID.HITRUST, "11.c", 0.9),
    # CC8 Change Management -> 10 SDLC
    ControlMapping(FrameworkID.SOC2, "CC8.1", FrameworkID.HITRUST, "10.k", 0.9),
    # A1 Availability -> 12 BCM
    ControlMapping(FrameworkID.SOC2, "A1.1", FrameworkID.HITRUST, "12.a", 0.9),
    ControlMapping(FrameworkID.SOC2, "A1.2", FrameworkID.HITRUST, "12.b", 0.9),
    ControlMapping(FrameworkID.SOC2, "A1.3", FrameworkID.HITRUST, "09.l", 0.9),
    # C1 Confidentiality -> 06 Compliance (encryption)
    ControlMapping(FrameworkID.SOC2, "C1.1", FrameworkID.HITRUST, "06.d", 0.9),
    ControlMapping(FrameworkID.SOC2, "C1.2", FrameworkID.HITRUST, "06.d", 0.8),
]

# ISO 27001 <-> HITRUST Mappings
ISO_27001_TO_HITRUST_MAPPINGS = [
    # A.5 Organizational -> HITRUST Governance
    ControlMapping(FrameworkID.ISO_27001, "A.5.1", FrameworkID.HITRUST, "04.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.2", FrameworkID.HITRUST, "05.a", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.3", FrameworkID.HITRUST, "01.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.4", FrameworkID.HITRUST, "00.a", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.5", FrameworkID.HITRUST, "05.c", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.7", FrameworkID.HITRUST, "03.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.8", FrameworkID.HITRUST, "03.c", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.9", FrameworkID.HITRUST, "07.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.10", FrameworkID.HITRUST, "07.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.15", FrameworkID.HITRUST, "01.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.16", FrameworkID.HITRUST, "01.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.17", FrameworkID.HITRUST, "01.d", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.18", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.19", FrameworkID.HITRUST, "01.h", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.24", FrameworkID.HITRUST, "11.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.25", FrameworkID.HITRUST, "11.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.26", FrameworkID.HITRUST, "11.c", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.27", FrameworkID.HITRUST, "11.d", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.5.29", FrameworkID.HITRUST, "12.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.5.30", FrameworkID.HITRUST, "12.b", 0.9),
    # A.6 People -> 02 HR Security
    ControlMapping(FrameworkID.ISO_27001, "A.6.1", FrameworkID.HITRUST, "02.a", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.6.2", FrameworkID.HITRUST, "02.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.6.3", FrameworkID.HITRUST, "02.e", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.6.4", FrameworkID.HITRUST, "02.f", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.6.5", FrameworkID.HITRUST, "02.g", 0.8),
    # A.7 Physical -> 08 Physical
    ControlMapping(FrameworkID.ISO_27001, "A.7.1", FrameworkID.HITRUST, "08.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.7.2", FrameworkID.HITRUST, "08.b", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.7.3", FrameworkID.HITRUST, "08.c", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.7.4", FrameworkID.HITRUST, "08.e", 0.8),
    # A.8 Technological -> Various HITRUST
    ControlMapping(FrameworkID.ISO_27001, "A.8.1", FrameworkID.HITRUST, "01.x", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.8.2", FrameworkID.HITRUST, "01.c", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.5", FrameworkID.HITRUST, "01.d", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.7", FrameworkID.HITRUST, "09.j", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.8", FrameworkID.HITRUST, "10.m", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.9", FrameworkID.HITRUST, "10.h", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.11", FrameworkID.HITRUST, "06.d", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.13", FrameworkID.HITRUST, "09.l", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.15", FrameworkID.HITRUST, "09.aa", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.16", FrameworkID.HITRUST, "09.ab", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.19", FrameworkID.HITRUST, "10.i", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.8.20", FrameworkID.HITRUST, "09.m", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.22", FrameworkID.HITRUST, "09.m", 0.8),
    ControlMapping(FrameworkID.ISO_27001, "A.8.24", FrameworkID.HITRUST, "06.d", 0.9),
    ControlMapping(FrameworkID.ISO_27001, "A.8.32", FrameworkID.HITRUST, "10.k", 0.9),
]

# NIST CSF 2.0 <-> SOC 2 (via intermediate mappings)
NIST_CSF_TO_SOC2_MAPPINGS = [
    # GOVERN -> CC1, CC2
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.OC-01", FrameworkID.SOC2, "CC1.1", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.OC-02", FrameworkID.SOC2, "CC1.2", 0.7),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.RM-01", FrameworkID.SOC2, "CC3.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "GV.RM-02", FrameworkID.SOC2, "CC3.2", 0.9),
    # IDENTIFY -> CC3
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.AM-01", FrameworkID.SOC2, "CC6.1", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.RA-01", FrameworkID.SOC2, "CC3.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "ID.RA-02", FrameworkID.SOC2, "CC7.1", 0.9),
    # PROTECT -> CC5, CC6
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-01", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-02", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-03", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-04", FrameworkID.SOC2, "CC6.3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.AA-05", FrameworkID.SOC2, "CC6.6", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-01", FrameworkID.SOC2, "CC6.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.DS-02", FrameworkID.SOC2, "CC6.7", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-01", FrameworkID.SOC2, "CC8.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-02", FrameworkID.SOC2, "CC6.8", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "PR.PS-03", FrameworkID.SOC2, "CC8.1", 0.9),
    # DETECT -> CC7
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-01", FrameworkID.SOC2, "CC7.1", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.CM-09", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.AE-02", FrameworkID.SOC2, "CC7.2", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "DE.AE-03", FrameworkID.SOC2, "CC7.2", 0.9),
    # RESPOND -> CC7
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MA-01", FrameworkID.SOC2, "CC7.4", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.MA-02", FrameworkID.SOC2, "CC7.4", 0.8),
    ControlMapping(FrameworkID.NIST_CSF_2, "RS.CO-02", FrameworkID.SOC2, "CC7.4", 0.9),
    # RECOVER -> A1
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.RP-01", FrameworkID.SOC2, "A1.3", 0.9),
    ControlMapping(FrameworkID.NIST_CSF_2, "RC.RP-03", FrameworkID.SOC2, "A1.2", 0.9),
]


# =============================================================================
# Mapping Registry Class
# =============================================================================


class MappingRegistry:
    """
    Central registry for all cross-framework control mappings.

    Provides lookup functions for finding mappings between any two
    supported frameworks.
    """

    def __init__(self) -> None:
        """Initialize the mapping registry."""
        self._pair_mappings: dict[str, FrameworkPairMapping] = {}
        self._load_all_mappings()

    def _load_all_mappings(self) -> None:
        """Load all predefined mapping sets."""
        mapping_sets = [
            (FrameworkID.NIST_CSF_2, FrameworkID.NIST_800_53, NIST_CSF_TO_800_53_MAPPINGS),
            (FrameworkID.NIST_800_53, FrameworkID.SOC2, NIST_800_53_TO_SOC2_MAPPINGS),
            (FrameworkID.NIST_800_53, FrameworkID.ISO_27001, NIST_800_53_TO_ISO_27001_MAPPINGS),
            (FrameworkID.NIST_800_53, FrameworkID.HITRUST, NIST_800_53_TO_HITRUST_MAPPINGS),
            (FrameworkID.SOC2, FrameworkID.ISO_27001, SOC2_TO_ISO_27001_MAPPINGS),
            (FrameworkID.SOC2, FrameworkID.HITRUST, SOC2_TO_HITRUST_MAPPINGS),
            (FrameworkID.ISO_27001, FrameworkID.HITRUST, ISO_27001_TO_HITRUST_MAPPINGS),
            (FrameworkID.NIST_CSF_2, FrameworkID.SOC2, NIST_CSF_TO_SOC2_MAPPINGS),
        ]

        for source, target, mappings in mapping_sets:
            pair = FrameworkPairMapping(
                source_framework=source,
                target_framework=target,
                mappings=mappings,
            )
            self._pair_mappings[pair.pair_id] = pair

            # Also create reverse pair for bidirectional mappings
            reverse_mappings = [m.reverse() for m in mappings if m.bidirectional]
            if reverse_mappings:
                reverse_pair = FrameworkPairMapping(
                    source_framework=target,
                    target_framework=source,
                    mappings=reverse_mappings,
                )
                self._pair_mappings[reverse_pair.pair_id] = reverse_pair

        logger.info(f"Loaded {len(self._pair_mappings)} framework pair mappings")

    def get_pair_mapping(
        self,
        source: FrameworkID,
        target: FrameworkID,
    ) -> FrameworkPairMapping | None:
        """Get mapping set for a framework pair."""
        pair_id = f"{source.value}:{target.value}"
        return self._pair_mappings.get(pair_id)

    def get_all_pairs(self) -> list[tuple[FrameworkID, FrameworkID]]:
        """Get all available framework pairs."""
        pairs = []
        for pair_id in self._pair_mappings:
            source, target = pair_id.split(":")
            pairs.append((FrameworkID(source), FrameworkID(target)))
        return pairs

    def get_mappings_for_control(
        self,
        framework: FrameworkID,
        control_id: str,
    ) -> dict[FrameworkID, list[ControlMapping]]:
        """Get all mappings from a control to all other frameworks."""
        result: dict[FrameworkID, list[ControlMapping]] = {}

        for pair in self._pair_mappings.values():
            if pair.source_framework == framework:
                mappings = pair.get_mappings_for_source(control_id)
                if mappings:
                    if pair.target_framework not in result:
                        result[pair.target_framework] = []
                    result[pair.target_framework].extend(mappings)

        return result

    def get_mapping_statistics(self) -> dict[str, Any]:
        """Get statistics about the mapping registry."""
        total_mappings = sum(len(p.mappings) for p in self._pair_mappings.values())

        pair_stats = []
        for pair in self._pair_mappings.values():
            pair_stats.append({
                "source": pair.source_framework.value,
                "target": pair.target_framework.value,
                "mapping_count": len(pair.mappings),
                "avg_strength": (
                    sum(m.strength for m in pair.mappings) / len(pair.mappings)
                    if pair.mappings else 0
                ),
            })

        return {
            "total_pairs": len(self._pair_mappings),
            "total_mappings": total_mappings,
            "frameworks": [f.value for f in FrameworkID],
            "pair_statistics": pair_stats,
        }


# =============================================================================
# Module-Level Functions
# =============================================================================

# Global registry instance
_registry: MappingRegistry | None = None


def get_mapping_registry() -> MappingRegistry:
    """Get the global mapping registry instance."""
    global _registry
    if _registry is None:
        _registry = MappingRegistry()
    return _registry


def get_mapping(
    source_framework: FrameworkID,
    source_control: str,
    target_framework: FrameworkID,
) -> list[ControlMapping]:
    """
    Get mappings for a control to a target framework.

    Args:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.

    Returns:
        List of mappings to target framework.
    """
    registry = get_mapping_registry()
    pair = registry.get_pair_mapping(source_framework, target_framework)
    if not pair:
        return []
    return pair.get_mappings_for_source(source_control)


def get_mappings_for_control(
    framework: FrameworkID,
    control_id: str,
) -> dict[FrameworkID, list[ControlMapping]]:
    """
    Get all mappings for a control to all frameworks.

    Args:
        framework: Source framework ID.
        control_id: Control ID.

    Returns:
        Dictionary mapping target frameworks to control mappings.
    """
    registry = get_mapping_registry()
    return registry.get_mappings_for_control(framework, control_id)


def get_all_mappings_between(
    source: FrameworkID,
    target: FrameworkID,
) -> list[ControlMapping]:
    """
    Get all mappings between two frameworks.

    Args:
        source: Source framework ID.
        target: Target framework ID.

    Returns:
        List of all mappings from source to target.
    """
    registry = get_mapping_registry()
    pair = registry.get_pair_mapping(source, target)
    return pair.mappings if pair else []


def get_strongest_mapping(
    source_framework: FrameworkID,
    source_control: str,
    target_framework: FrameworkID,
) -> ControlMapping | None:
    """
    Get the strongest mapping for a control to a target framework.

    Args:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.

    Returns:
        Strongest mapping or None.
    """
    mappings = get_mapping(source_framework, source_control, target_framework)
    if not mappings:
        return None
    return max(mappings, key=lambda m: m.strength)


def get_mapping_strength(
    source_framework: FrameworkID,
    source_control: str,
    target_framework: FrameworkID,
    target_control: str,
) -> float:
    """
    Get the strength of a specific control-to-control mapping.

    Args:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.
        target_control: Target control ID.

    Returns:
        Mapping strength (0.0 - 1.0), or 0.0 if no mapping exists.
    """
    mappings = get_mapping(source_framework, source_control, target_framework)
    for m in mappings:
        if m.target_control == target_control:
            return m.strength
    return 0.0


__all__ = [
    # Enums
    "FrameworkID",
    "MappingDirection",
    # Constants
    "FRAMEWORK_NAMES",
    # Data classes
    "ControlMapping",
    "FrameworkPairMapping",
    # Registry
    "MappingRegistry",
    # Functions
    "get_mapping_registry",
    "get_mapping",
    "get_mappings_for_control",
    "get_all_mappings_between",
    "get_strongest_mapping",
    "get_mapping_strength",
]
