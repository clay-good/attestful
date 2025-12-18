"""
Cross-framework control mapping (crosswalk) for Attestful.

Provides bidirectional mappings between compliance frameworks,
enabling unified multi-framework compliance analysis.

Supported Frameworks:
- NIST 800-53 Rev 5
- SOC 2 Type II (TSC)
- ISO 27001:2022
- HITRUST CSF v11

Mappings are based on:
- Official NIST control mappings
- AICPA Trust Services Criteria mapping guidance
- ISO/NIST control alignment documents
- HITRUST CSF authoritative sources
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class Framework(str, Enum):
    """Supported compliance frameworks."""

    NIST_800_53 = "nist-800-53"
    SOC2 = "soc2"
    ISO_27001 = "iso-27001"
    HITRUST = "hitrust"


class MappingStrength(str, Enum):
    """
    Strength of control mapping between frameworks.

    EXACT: Controls have essentially the same requirements
    STRONG: Controls have significant overlap
    PARTIAL: Controls have some overlap but differ in scope
    RELATED: Controls address similar topics but differ in approach
    """

    EXACT = "exact"
    STRONG = "strong"
    PARTIAL = "partial"
    RELATED = "related"


@dataclass
class ControlMapping:
    """
    Mapping between controls in different frameworks.

    Attributes:
        source_framework: Source framework identifier.
        source_control: Source control ID.
        target_framework: Target framework identifier.
        target_control: Target control ID.
        strength: Mapping strength.
        notes: Additional notes about the mapping.
    """

    source_framework: Framework
    source_control: str
    target_framework: Framework
    target_control: str
    strength: MappingStrength = MappingStrength.STRONG
    notes: str = ""


@dataclass
class CrosswalkResult:
    """
    Result of a crosswalk lookup.

    Attributes:
        source_framework: Source framework.
        source_control: Source control ID.
        mappings: List of mappings to other frameworks.
    """

    source_framework: Framework
    source_control: str
    mappings: list[ControlMapping] = field(default_factory=list)

    def get_mappings_for_framework(self, framework: Framework) -> list[ControlMapping]:
        """Get mappings for a specific target framework."""
        return [m for m in self.mappings if m.target_framework == framework]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_framework": self.source_framework.value,
            "source_control": self.source_control,
            "mappings": [
                {
                    "target_framework": m.target_framework.value,
                    "target_control": m.target_control,
                    "strength": m.strength.value,
                    "notes": m.notes,
                }
                for m in self.mappings
            ],
        }


@dataclass
class GapAnalysisComparison:
    """
    Comparison of compliance across multiple frameworks.

    Attributes:
        control_id: Control being analyzed.
        framework: Framework of the control.
        equivalent_controls: Controls in other frameworks.
        coverage_status: Whether this control has coverage.
        inherited_coverage: Coverage inherited from mapped controls.
    """

    control_id: str
    framework: Framework
    equivalent_controls: dict[Framework, list[str]]
    coverage_status: str  # "covered", "partial", "none"
    inherited_coverage: dict[Framework, bool] = field(default_factory=dict)


class FrameworkCrosswalk:
    """
    Cross-framework control mapping engine.

    Provides bidirectional mappings between compliance frameworks
    to enable multi-framework compliance analysis.

    Example:
        crosswalk = FrameworkCrosswalk()

        # Find SOC 2 equivalents for NIST AC-2
        result = crosswalk.get_mappings(
            Framework.NIST_800_53, "AC-2"
        )

        for mapping in result.get_mappings_for_framework(Framework.SOC2):
            print(f"NIST AC-2 -> SOC 2 {mapping.target_control}")

        # Check if a control has equivalent in another framework
        if crosswalk.has_equivalent(
            Framework.ISO_27001, "A.5.15",
            Framework.SOC2
        ):
            print("ISO A.5.15 maps to SOC 2")
    """

    def __init__(self) -> None:
        """Initialize the crosswalk with built-in mappings."""
        self._mappings: list[ControlMapping] = []
        self._load_builtin_mappings()

    def _load_builtin_mappings(self) -> None:
        """Load built-in control mappings."""
        # NIST 800-53 to SOC 2 mappings
        self._add_nist_to_soc2_mappings()

        # NIST 800-53 to ISO 27001 mappings
        self._add_nist_to_iso_mappings()

        # NIST 800-53 to HITRUST mappings
        self._add_nist_to_hitrust_mappings()

        # SOC 2 to ISO 27001 mappings
        self._add_soc2_to_iso_mappings()

        # SOC 2 to HITRUST mappings
        self._add_soc2_to_hitrust_mappings()

        # ISO 27001 to HITRUST mappings
        self._add_iso_to_hitrust_mappings()

        logger.info(f"Loaded {len(self._mappings)} control mappings")

    def _add_mapping(
        self,
        source_framework: Framework,
        source_control: str,
        target_framework: Framework,
        target_control: str,
        strength: MappingStrength = MappingStrength.STRONG,
        notes: str = "",
        bidirectional: bool = True,
    ) -> None:
        """Add a control mapping."""
        self._mappings.append(ControlMapping(
            source_framework=source_framework,
            source_control=source_control,
            target_framework=target_framework,
            target_control=target_control,
            strength=strength,
            notes=notes,
        ))

        # Add reverse mapping
        if bidirectional:
            self._mappings.append(ControlMapping(
                source_framework=target_framework,
                source_control=target_control,
                target_framework=source_framework,
                target_control=source_control,
                strength=strength,
                notes=notes,
            ))

    def _add_nist_to_soc2_mappings(self) -> None:
        """Add NIST 800-53 to SOC 2 control mappings."""
        mappings = [
            # Access Control (AC)
            ("AC-1", "CC6.1", MappingStrength.STRONG, "Access control policy"),
            ("AC-2", "CC6.1", MappingStrength.STRONG, "Account management"),
            ("AC-2", "CC6.2", MappingStrength.PARTIAL, "User registration"),
            ("AC-3", "CC6.1", MappingStrength.STRONG, "Access enforcement"),
            ("AC-4", "CC6.1", MappingStrength.STRONG, "Information flow enforcement"),
            ("AC-5", "CC6.1", MappingStrength.STRONG, "Separation of duties"),
            ("AC-6", "CC6.1", MappingStrength.STRONG, "Least privilege"),
            ("AC-6", "CC6.3", MappingStrength.PARTIAL, "Privileged access"),
            ("AC-7", "CC6.1", MappingStrength.STRONG, "Unsuccessful login attempts"),
            ("AC-11", "CC6.1", MappingStrength.PARTIAL, "Session lock"),
            ("AC-17", "CC6.1", MappingStrength.STRONG, "Remote access"),
            ("AC-17", "CC6.6", MappingStrength.PARTIAL, "External access"),
            ("AC-19", "CC6.1", MappingStrength.STRONG, "Mobile device access"),

            # Audit (AU)
            ("AU-2", "CC7.2", MappingStrength.STRONG, "Audit events"),
            ("AU-3", "CC7.2", MappingStrength.STRONG, "Content of audit records"),
            ("AU-6", "CC7.2", MappingStrength.STRONG, "Audit review"),
            ("AU-6", "CC4.1", MappingStrength.PARTIAL, "Monitoring"),
            ("AU-9", "CC7.2", MappingStrength.STRONG, "Protection of audit info"),
            ("AU-12", "CC7.2", MappingStrength.STRONG, "Audit generation"),

            # Configuration Management (CM)
            ("CM-2", "CC8.1", MappingStrength.STRONG, "Baseline configuration"),
            ("CM-3", "CC8.1", MappingStrength.EXACT, "Configuration change control"),
            ("CM-4", "CC8.1", MappingStrength.STRONG, "Security impact analysis"),
            ("CM-6", "CC8.1", MappingStrength.STRONG, "Configuration settings"),
            ("CM-7", "CC6.8", MappingStrength.PARTIAL, "Least functionality"),
            ("CM-8", "CC6.8", MappingStrength.PARTIAL, "System component inventory"),

            # Contingency Planning (CP)
            ("CP-2", "A1.2", MappingStrength.STRONG, "Contingency plan"),
            ("CP-4", "A1.2", MappingStrength.STRONG, "Contingency plan testing"),
            ("CP-9", "A1.2", MappingStrength.STRONG, "System backup"),
            ("CP-10", "A1.2", MappingStrength.STRONG, "Recovery and reconstitution"),

            # Identification and Authentication (IA)
            ("IA-2", "CC6.1", MappingStrength.STRONG, "User identification"),
            ("IA-4", "CC6.1", MappingStrength.STRONG, "Identifier management"),
            ("IA-5", "CC6.1", MappingStrength.STRONG, "Authenticator management"),

            # Incident Response (IR)
            ("IR-1", "CC7.3", MappingStrength.STRONG, "Incident response policy"),
            ("IR-2", "CC7.3", MappingStrength.STRONG, "Incident response training"),
            ("IR-4", "CC7.4", MappingStrength.STRONG, "Incident handling"),
            ("IR-5", "CC7.3", MappingStrength.STRONG, "Incident monitoring"),
            ("IR-6", "CC7.5", MappingStrength.STRONG, "Incident reporting"),
            ("IR-8", "CC7.3", MappingStrength.STRONG, "Incident response plan"),

            # Risk Assessment (RA)
            ("RA-3", "CC3.2", MappingStrength.STRONG, "Risk assessment"),
            ("RA-5", "CC7.1", MappingStrength.STRONG, "Vulnerability scanning"),

            # System and Communications Protection (SC)
            ("SC-7", "CC6.6", MappingStrength.STRONG, "Boundary protection"),
            ("SC-8", "CC6.1", MappingStrength.STRONG, "Transmission protection"),
            ("SC-12", "CC6.1", MappingStrength.STRONG, "Cryptographic key management"),
            ("SC-13", "CC6.1", MappingStrength.STRONG, "Cryptographic protection"),
            ("SC-28", "CC6.1", MappingStrength.STRONG, "Protection at rest"),

            # System and Information Integrity (SI)
            ("SI-2", "CC7.1", MappingStrength.STRONG, "Flaw remediation"),
            ("SI-3", "CC6.8", MappingStrength.STRONG, "Malicious code protection"),
            ("SI-4", "CC7.2", MappingStrength.STRONG, "System monitoring"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.NIST_800_53, source,
                Framework.SOC2, target,
                strength, notes,
            )

    def _add_nist_to_iso_mappings(self) -> None:
        """Add NIST 800-53 to ISO 27001 control mappings."""
        mappings = [
            # Access Control
            ("AC-1", "A.5.15", MappingStrength.STRONG, "Access control policy"),
            ("AC-2", "A.5.16", MappingStrength.STRONG, "Identity management"),
            ("AC-2", "A.5.18", MappingStrength.PARTIAL, "Access rights"),
            ("AC-3", "A.8.3", MappingStrength.STRONG, "Information access restriction"),
            ("AC-5", "A.5.3", MappingStrength.STRONG, "Segregation of duties"),
            ("AC-6", "A.8.2", MappingStrength.STRONG, "Privileged access rights"),
            ("AC-7", "A.8.5", MappingStrength.PARTIAL, "Secure authentication"),
            ("AC-11", "A.8.5", MappingStrength.PARTIAL, "Automatic session termination"),
            ("AC-17", "A.8.5", MappingStrength.STRONG, "Secure authentication for remote"),
            ("AC-19", "A.8.1", MappingStrength.STRONG, "User endpoint devices"),

            # Audit and Accountability
            ("AU-2", "A.8.15", MappingStrength.STRONG, "Logging"),
            ("AU-3", "A.8.15", MappingStrength.STRONG, "Logging content"),
            ("AU-6", "A.8.15", MappingStrength.STRONG, "Log analysis"),
            ("AU-9", "A.8.15", MappingStrength.STRONG, "Protection of logs"),
            ("AU-12", "A.8.15", MappingStrength.EXACT, "Audit record generation"),

            # Configuration Management
            ("CM-2", "A.8.9", MappingStrength.STRONG, "Configuration management"),
            ("CM-3", "A.8.32", MappingStrength.STRONG, "Change management"),
            ("CM-6", "A.8.9", MappingStrength.STRONG, "Configuration settings"),
            ("CM-8", "A.5.9", MappingStrength.STRONG, "Inventory of assets"),

            # Contingency Planning
            ("CP-2", "A.5.29", MappingStrength.STRONG, "ICT continuity planning"),
            ("CP-4", "A.5.30", MappingStrength.STRONG, "ICT readiness testing"),
            ("CP-9", "A.8.13", MappingStrength.STRONG, "Information backup"),
            ("CP-10", "A.5.29", MappingStrength.PARTIAL, "Recovery planning"),

            # Identification and Authentication
            ("IA-2", "A.8.5", MappingStrength.STRONG, "Secure authentication"),
            ("IA-4", "A.5.16", MappingStrength.STRONG, "Identity management"),
            ("IA-5", "A.5.17", MappingStrength.STRONG, "Authentication information"),

            # Incident Response
            ("IR-1", "A.5.24", MappingStrength.STRONG, "Incident management planning"),
            ("IR-4", "A.5.26", MappingStrength.STRONG, "Incident response"),
            ("IR-5", "A.5.25", MappingStrength.STRONG, "Incident assessment"),
            ("IR-6", "A.6.8", MappingStrength.STRONG, "Incident reporting"),

            # Risk Assessment
            ("RA-3", "A.5.8", MappingStrength.STRONG, "Information security in projects"),
            ("RA-5", "A.8.8", MappingStrength.STRONG, "Technical vulnerability management"),

            # System and Communications Protection
            ("SC-7", "A.8.20", MappingStrength.STRONG, "Networks security"),
            ("SC-7", "A.8.21", MappingStrength.PARTIAL, "Network services security"),
            ("SC-7", "A.8.22", MappingStrength.PARTIAL, "Network segregation"),
            ("SC-8", "A.8.24", MappingStrength.STRONG, "Use of cryptography"),
            ("SC-12", "A.8.24", MappingStrength.STRONG, "Cryptographic controls"),
            ("SC-13", "A.8.24", MappingStrength.EXACT, "Cryptographic protection"),
            ("SC-28", "A.8.24", MappingStrength.STRONG, "Data protection at rest"),

            # System and Information Integrity
            ("SI-2", "A.8.8", MappingStrength.STRONG, "Patch management"),
            ("SI-3", "A.8.7", MappingStrength.STRONG, "Protection against malware"),
            ("SI-4", "A.8.16", MappingStrength.STRONG, "Monitoring activities"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.NIST_800_53, source,
                Framework.ISO_27001, target,
                strength, notes,
            )

    def _add_nist_to_hitrust_mappings(self) -> None:
        """Add NIST 800-53 to HITRUST control mappings."""
        mappings = [
            # Access Control
            ("AC-1", "01.a", MappingStrength.EXACT, "Access control policy"),
            ("AC-2", "01.b", MappingStrength.STRONG, "User registration"),
            ("AC-2", "01.e", MappingStrength.PARTIAL, "Access rights review"),
            ("AC-3", "01.v", MappingStrength.STRONG, "Information access restriction"),
            ("AC-5", "09.c", MappingStrength.EXACT, "Segregation of duties"),
            ("AC-6", "01.c", MappingStrength.STRONG, "Privilege management"),
            ("AC-7", "01.p", MappingStrength.STRONG, "Secure log-on procedures"),
            ("AC-11", "01.t", MappingStrength.EXACT, "Session time-out"),
            ("AC-17", "01.j", MappingStrength.STRONG, "Remote access authentication"),

            # Audit and Accountability
            ("AU-2", "09.aa", MappingStrength.STRONG, "Audit logging"),
            ("AU-3", "09.aa", MappingStrength.STRONG, "Audit content"),
            ("AU-6", "09.ab", MappingStrength.STRONG, "Monitoring system use"),
            ("AU-9", "09.ac", MappingStrength.EXACT, "Protection of log information"),
            ("AU-12", "09.ad", MappingStrength.STRONG, "Administrator logs"),

            # Configuration Management
            ("CM-3", "09.b", MappingStrength.EXACT, "Change management"),
            ("CM-3", "10.k", MappingStrength.STRONG, "Change control procedures"),
            ("CM-4", "09.d", MappingStrength.STRONG, "Separation of environments"),
            ("CM-5", "10.h", MappingStrength.STRONG, "Software installation control"),

            # Contingency Planning
            ("CP-9", "09.m", MappingStrength.EXACT, "Information backup"),
            ("CP-10", "09.m", MappingStrength.PARTIAL, "Recovery capabilities"),

            # Identification and Authentication
            ("IA-2", "01.q", MappingStrength.EXACT, "User identification and authentication"),
            ("IA-4", "01.q", MappingStrength.PARTIAL, "Identifier management"),
            ("IA-5", "01.d", MappingStrength.STRONG, "Password management"),
            ("IA-5", "01.r", MappingStrength.STRONG, "Password management system"),

            # Incident Response
            ("IR-1", "11.c", MappingStrength.EXACT, "Incident response procedures"),
            ("IR-4", "11.d", MappingStrength.STRONG, "Learning from incidents"),
            ("IR-6", "11.a", MappingStrength.STRONG, "Incident reporting"),

            # Risk Assessment
            ("RA-5", "10.p", MappingStrength.EXACT, "Technical vulnerability management"),

            # System and Communications Protection
            ("SC-7", "01.m", MappingStrength.STRONG, "Network segregation"),
            ("SC-7", "01.n", MappingStrength.PARTIAL, "Network connection control"),
            ("SC-8", "09.n", MappingStrength.STRONG, "Network controls"),
            ("SC-12", "10.g", MappingStrength.EXACT, "Key management"),
            ("SC-13", "10.f", MappingStrength.EXACT, "Cryptographic controls policy"),

            # System and Information Integrity
            ("SI-2", "10.p", MappingStrength.PARTIAL, "Vulnerability remediation"),
            ("SI-3", "09.k", MappingStrength.EXACT, "Controls against malicious code"),
            ("SI-4", "09.ab", MappingStrength.STRONG, "System monitoring"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.NIST_800_53, source,
                Framework.HITRUST, target,
                strength, notes,
            )

    def _add_soc2_to_iso_mappings(self) -> None:
        """Add SOC 2 to ISO 27001 control mappings."""
        mappings = [
            # CC6 - Logical and Physical Access
            ("CC6.1", "A.5.15", MappingStrength.STRONG, "Access control"),
            ("CC6.1", "A.5.16", MappingStrength.PARTIAL, "Identity management"),
            ("CC6.1", "A.8.2", MappingStrength.PARTIAL, "Privileged access"),
            ("CC6.1", "A.8.3", MappingStrength.PARTIAL, "Information access restriction"),
            ("CC6.1", "A.8.5", MappingStrength.PARTIAL, "Secure authentication"),
            ("CC6.2", "A.5.16", MappingStrength.STRONG, "Identity management"),
            ("CC6.3", "A.8.2", MappingStrength.STRONG, "Privileged access rights"),
            ("CC6.6", "A.8.20", MappingStrength.STRONG, "Networks security"),
            ("CC6.6", "A.8.21", MappingStrength.PARTIAL, "Security of network services"),
            ("CC6.7", "A.7.1", MappingStrength.STRONG, "Physical security perimeters"),
            ("CC6.8", "A.8.7", MappingStrength.STRONG, "Protection against malware"),

            # CC7 - System Operations
            ("CC7.1", "A.8.8", MappingStrength.STRONG, "Technical vulnerability management"),
            ("CC7.2", "A.8.15", MappingStrength.EXACT, "Logging"),
            ("CC7.2", "A.8.16", MappingStrength.PARTIAL, "Monitoring activities"),
            ("CC7.3", "A.5.24", MappingStrength.STRONG, "Incident management planning"),
            ("CC7.4", "A.5.26", MappingStrength.STRONG, "Response to incidents"),
            ("CC7.5", "A.5.27", MappingStrength.STRONG, "Learning from incidents"),

            # CC8 - Change Management
            ("CC8.1", "A.8.32", MappingStrength.EXACT, "Change management"),

            # A1 - Availability
            ("A1.1", "A.5.29", MappingStrength.STRONG, "ICT continuity"),
            ("A1.2", "A.5.30", MappingStrength.STRONG, "ICT readiness"),
            ("A1.2", "A.8.13", MappingStrength.PARTIAL, "Information backup"),

            # C1 - Confidentiality
            ("C1.1", "A.5.12", MappingStrength.STRONG, "Classification of information"),
            ("C1.2", "A.5.13", MappingStrength.STRONG, "Labelling of information"),

            # CC3 - Risk Assessment
            ("CC3.1", "A.5.8", MappingStrength.STRONG, "Information security in projects"),
            ("CC3.2", "A.5.8", MappingStrength.PARTIAL, "Risk assessment"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.SOC2, source,
                Framework.ISO_27001, target,
                strength, notes,
            )

    def _add_soc2_to_hitrust_mappings(self) -> None:
        """Add SOC 2 to HITRUST control mappings."""
        mappings = [
            # CC6 - Logical and Physical Access
            ("CC6.1", "01.a", MappingStrength.STRONG, "Access control policy"),
            ("CC6.1", "01.b", MappingStrength.PARTIAL, "User registration"),
            ("CC6.1", "01.v", MappingStrength.PARTIAL, "Information access restriction"),
            ("CC6.2", "01.b", MappingStrength.STRONG, "User registration"),
            ("CC6.2", "01.e", MappingStrength.PARTIAL, "Access rights review"),
            ("CC6.3", "01.c", MappingStrength.STRONG, "Privilege management"),
            ("CC6.6", "01.m", MappingStrength.STRONG, "Network segregation"),
            ("CC6.6", "09.n", MappingStrength.PARTIAL, "Network controls"),

            # CC7 - System Operations
            ("CC7.1", "10.p", MappingStrength.STRONG, "Technical vulnerability management"),
            ("CC7.2", "09.aa", MappingStrength.EXACT, "Audit logging"),
            ("CC7.2", "09.ab", MappingStrength.PARTIAL, "Monitoring system use"),
            ("CC7.3", "11.c", MappingStrength.STRONG, "Incident response procedures"),
            ("CC7.4", "11.c", MappingStrength.PARTIAL, "Incident handling"),
            ("CC7.5", "11.a", MappingStrength.STRONG, "Incident reporting"),

            # CC8 - Change Management
            ("CC8.1", "09.b", MappingStrength.EXACT, "Change management"),
            ("CC8.1", "10.k", MappingStrength.PARTIAL, "Change control procedures"),

            # A1 - Availability
            ("A1.2", "09.m", MappingStrength.STRONG, "Information backup"),

            # CC3 - Risk Assessment
            ("CC3.2", "10.p", MappingStrength.PARTIAL, "Risk/vulnerability assessment"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.SOC2, source,
                Framework.HITRUST, target,
                strength, notes,
            )

    def _add_iso_to_hitrust_mappings(self) -> None:
        """Add ISO 27001 to HITRUST control mappings."""
        mappings = [
            # A.5 Organizational controls
            ("A.5.15", "01.a", MappingStrength.EXACT, "Access control"),
            ("A.5.16", "01.b", MappingStrength.STRONG, "Identity management"),
            ("A.5.17", "01.d", MappingStrength.STRONG, "Authentication information"),
            ("A.5.18", "01.e", MappingStrength.STRONG, "Access rights"),
            ("A.5.3", "09.c", MappingStrength.EXACT, "Segregation of duties"),
            ("A.5.24", "11.c", MappingStrength.STRONG, "Incident management planning"),
            ("A.5.25", "11.d", MappingStrength.STRONG, "Assessment and decision"),
            ("A.5.26", "11.c", MappingStrength.PARTIAL, "Response to incidents"),
            ("A.5.27", "11.d", MappingStrength.EXACT, "Learning from incidents"),
            ("A.5.29", "09.m", MappingStrength.PARTIAL, "ICT continuity/backup"),
            ("A.5.37", "09.a", MappingStrength.STRONG, "Documented operating procedures"),

            # A.6 People controls
            ("A.6.8", "11.a", MappingStrength.STRONG, "Information security event reporting"),

            # A.7 Physical controls
            ("A.7.10", "09.p", MappingStrength.STRONG, "Storage media"),

            # A.8 Technological controls
            ("A.8.2", "01.c", MappingStrength.EXACT, "Privileged access rights"),
            ("A.8.3", "01.v", MappingStrength.STRONG, "Information access restriction"),
            ("A.8.5", "01.q", MappingStrength.STRONG, "Secure authentication"),
            ("A.8.5", "01.p", MappingStrength.PARTIAL, "Secure log-on procedures"),
            ("A.8.5", "01.t", MappingStrength.PARTIAL, "Session time-out"),
            ("A.8.7", "09.k", MappingStrength.EXACT, "Protection against malware"),
            ("A.8.8", "10.p", MappingStrength.EXACT, "Technical vulnerability management"),
            ("A.8.9", "09.b", MappingStrength.PARTIAL, "Configuration management"),
            ("A.8.13", "09.m", MappingStrength.EXACT, "Information backup"),
            ("A.8.15", "09.aa", MappingStrength.EXACT, "Logging"),
            ("A.8.15", "09.ac", MappingStrength.PARTIAL, "Protection of log information"),
            ("A.8.16", "09.ab", MappingStrength.EXACT, "Monitoring activities"),
            ("A.8.20", "09.n", MappingStrength.STRONG, "Networks security"),
            ("A.8.20", "01.m", MappingStrength.PARTIAL, "Segregation in networks"),
            ("A.8.22", "01.m", MappingStrength.STRONG, "Segregation of networks"),
            ("A.8.24", "10.f", MappingStrength.EXACT, "Use of cryptography"),
            ("A.8.24", "10.g", MappingStrength.PARTIAL, "Key management"),
            ("A.8.32", "09.b", MappingStrength.STRONG, "Change management"),
            ("A.8.32", "10.k", MappingStrength.PARTIAL, "Change control procedures"),
        ]

        for source, target, strength, notes in mappings:
            self._add_mapping(
                Framework.ISO_27001, source,
                Framework.HITRUST, target,
                strength, notes,
            )

    def get_mappings(
        self,
        source_framework: Framework,
        source_control: str,
    ) -> CrosswalkResult:
        """
        Get all mappings for a source control.

        Args:
            source_framework: Source framework.
            source_control: Source control ID.

        Returns:
            CrosswalkResult with all mappings.
        """
        mappings = [
            m for m in self._mappings
            if m.source_framework == source_framework
            and m.source_control == source_control
        ]

        return CrosswalkResult(
            source_framework=source_framework,
            source_control=source_control,
            mappings=mappings,
        )

    def get_equivalent_controls(
        self,
        source_framework: Framework,
        source_control: str,
        target_framework: Framework,
        *,
        min_strength: MappingStrength = MappingStrength.PARTIAL,
    ) -> list[str]:
        """
        Get equivalent control IDs in target framework.

        Args:
            source_framework: Source framework.
            source_control: Source control ID.
            target_framework: Target framework.
            min_strength: Minimum mapping strength to include.

        Returns:
            List of equivalent control IDs.
        """
        strength_order = [
            MappingStrength.EXACT,
            MappingStrength.STRONG,
            MappingStrength.PARTIAL,
            MappingStrength.RELATED,
        ]
        min_idx = strength_order.index(min_strength)

        result = self.get_mappings(source_framework, source_control)
        target_mappings = result.get_mappings_for_framework(target_framework)

        return [
            m.target_control
            for m in target_mappings
            if strength_order.index(m.strength) <= min_idx
        ]

    def has_equivalent(
        self,
        source_framework: Framework,
        source_control: str,
        target_framework: Framework,
    ) -> bool:
        """
        Check if a control has any equivalent in target framework.

        Args:
            source_framework: Source framework.
            source_control: Source control ID.
            target_framework: Target framework.

        Returns:
            True if equivalent exists.
        """
        return bool(self.get_equivalent_controls(
            source_framework, source_control, target_framework
        ))

    def get_coverage_analysis(
        self,
        covered_controls: dict[Framework, set[str]],
    ) -> dict[Framework, dict[str, Any]]:
        """
        Analyze coverage across frameworks using mappings.

        Args:
            covered_controls: Dict mapping framework to set of covered control IDs.

        Returns:
            Coverage analysis by framework.
        """
        analysis = {}

        for framework in Framework:
            direct_covered = covered_controls.get(framework, set())
            inherited_covered: set[str] = set()

            # Check what can be inherited from other frameworks
            for other_framework in Framework:
                if other_framework == framework:
                    continue

                other_covered = covered_controls.get(other_framework, set())
                for control_id in other_covered:
                    equivalents = self.get_equivalent_controls(
                        other_framework, control_id, framework,
                        min_strength=MappingStrength.STRONG,
                    )
                    inherited_covered.update(equivalents)

            # Remove already directly covered
            inherited_only = inherited_covered - direct_covered

            analysis[framework] = {
                "direct_coverage": len(direct_covered),
                "inherited_coverage": len(inherited_only),
                "total_coverage": len(direct_covered | inherited_covered),
                "inherited_from": {
                    f.value: [
                        ctrl for ctrl in covered_controls.get(f, set())
                        if self.get_equivalent_controls(f, ctrl, framework)
                    ]
                    for f in Framework if f != framework
                },
            }

        return analysis

    def get_multi_framework_gaps(
        self,
        failed_controls: dict[Framework, set[str]],
    ) -> list[dict[str, Any]]:
        """
        Identify gaps that affect multiple frameworks.

        Args:
            failed_controls: Dict mapping framework to set of failed control IDs.

        Returns:
            List of multi-framework gaps.
        """
        gaps = []
        seen_combinations: set[frozenset[tuple[str, str]]] = set()

        for framework, controls in failed_controls.items():
            for control_id in controls:
                affected_frameworks = {(framework.value, control_id)}

                # Find equivalent failures in other frameworks
                for other_framework in Framework:
                    if other_framework == framework:
                        continue

                    equivalents = self.get_equivalent_controls(
                        framework, control_id, other_framework
                    )
                    for eq_control in equivalents:
                        if eq_control in failed_controls.get(other_framework, set()):
                            affected_frameworks.add((other_framework.value, eq_control))

                # Only report if it affects multiple frameworks
                if len(affected_frameworks) > 1:
                    combo_key = frozenset(affected_frameworks)
                    if combo_key not in seen_combinations:
                        seen_combinations.add(combo_key)
                        gaps.append({
                            "primary_control": {
                                "framework": framework.value,
                                "control_id": control_id,
                            },
                            "affected_frameworks": list(affected_frameworks),
                            "impact_count": len(affected_frameworks),
                        })

        # Sort by impact
        gaps.sort(key=lambda g: -g["impact_count"])
        return gaps

    def get_all_mappings(self) -> list[ControlMapping]:
        """Get all control mappings."""
        return self._mappings.copy()

    def get_mapping_statistics(self) -> dict[str, Any]:
        """Get statistics about loaded mappings."""
        stats: dict[str, Any] = {
            "total_mappings": len(self._mappings),
            "by_source_framework": {},
            "by_strength": {},
            "framework_pairs": {},
        }

        for mapping in self._mappings:
            # By source framework
            src = mapping.source_framework.value
            if src not in stats["by_source_framework"]:
                stats["by_source_framework"][src] = 0
            stats["by_source_framework"][src] += 1

            # By strength
            strength = mapping.strength.value
            if strength not in stats["by_strength"]:
                stats["by_strength"][strength] = 0
            stats["by_strength"][strength] += 1

            # By framework pair
            pair = f"{mapping.source_framework.value} -> {mapping.target_framework.value}"
            if pair not in stats["framework_pairs"]:
                stats["framework_pairs"][pair] = 0
            stats["framework_pairs"][pair] += 1

        return stats


# =============================================================================
# Factory Functions
# =============================================================================


def get_crosswalk() -> FrameworkCrosswalk:
    """
    Get a configured crosswalk instance.

    Returns:
        FrameworkCrosswalk with all built-in mappings.
    """
    return FrameworkCrosswalk()


def find_equivalent_controls(
    control_id: str,
    source_framework: str,
    target_framework: str,
) -> list[str]:
    """
    Find equivalent controls between frameworks.

    Args:
        control_id: Source control ID.
        source_framework: Source framework ID (e.g., "nist-800-53").
        target_framework: Target framework ID (e.g., "soc2").

    Returns:
        List of equivalent control IDs in target framework.
    """
    crosswalk = get_crosswalk()

    try:
        src = Framework(source_framework)
        tgt = Framework(target_framework)
    except ValueError:
        logger.warning(f"Unknown framework: {source_framework} or {target_framework}")
        return []

    return crosswalk.get_equivalent_controls(src, control_id, tgt)


def get_control_coverage_map(
    control_id: str,
    source_framework: str,
) -> dict[str, list[str]]:
    """
    Get a map of all equivalent controls across all frameworks.

    Args:
        control_id: Source control ID.
        source_framework: Source framework ID.

    Returns:
        Dict mapping framework ID to list of equivalent control IDs.
    """
    crosswalk = get_crosswalk()

    try:
        src = Framework(source_framework)
    except ValueError:
        logger.warning(f"Unknown framework: {source_framework}")
        return {}

    result = crosswalk.get_mappings(src, control_id)

    coverage: dict[str, list[str]] = {}
    for framework in Framework:
        if framework == src:
            continue
        mappings = result.get_mappings_for_framework(framework)
        if mappings:
            coverage[framework.value] = [m.target_control for m in mappings]

    return coverage
