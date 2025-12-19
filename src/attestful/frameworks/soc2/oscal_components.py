"""
SOC 2 OSCAL Component Definition Generator.

Converts SOC 2 automated check definitions to OSCAL component definitions
with implemented-requirement entries linking checks to Trust Services Criteria.

OSCAL Component Structure:
- Component: Attestful SOC 2 Automated Checks
  - Implemented Requirements: One per automated check
    - Links to Control: Trust Services Criterion ID
    - Description: Check description
    - Props: severity, resource_types, automation_status
    - Parts: remediation, condition
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.soc2.checks import (
    get_soc2_aws_checks,
    get_soc2_azure_checks,
    get_soc2_gcp_checks,
)

logger = get_logger("frameworks.soc2.oscal_components")


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class ImplementedRequirement:
    """
    An OSCAL implemented-requirement for a SOC 2 check.

    Represents a single automated check that provides evidence for
    meeting a Trust Services Criterion.
    """

    uuid: str
    control_id: str  # The TSC criterion (e.g., "CC6.1")
    check_id: str  # The check identifier
    description: str
    severity: str
    resource_types: list[str]
    provider: str  # aws, azure, gcp
    condition_type: str  # simple, compound
    remediation: str | None = None
    nist_mappings: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_oscal(self) -> dict:
        """Convert to OSCAL implemented-requirement format."""
        props = [
            {
                "name": "check-id",
                "value": self.check_id,
                "uuid": str(uuid.uuid4()),
            },
            {
                "name": "severity",
                "value": self.severity,
                "uuid": str(uuid.uuid4()),
            },
            {
                "name": "provider",
                "value": self.provider,
                "uuid": str(uuid.uuid4()),
            },
            {
                "name": "automation-status",
                "value": "automated",
                "uuid": str(uuid.uuid4()),
            },
        ]

        # Add resource types as props
        for rt in self.resource_types:
            props.append({
                "name": "resource-type",
                "value": rt,
                "uuid": str(uuid.uuid4()),
            })

        # Add tags as props
        for tag in self.tags:
            props.append({
                "name": "tag",
                "value": tag,
                "uuid": str(uuid.uuid4()),
            })

        parts = [
            {
                "id": f"{self.check_id}_stmt",
                "name": "statement",
                "prose": self.description,
            }
        ]

        if self.remediation:
            parts.append({
                "id": f"{self.check_id}_remediation",
                "name": "guidance",
                "title": "Remediation",
                "prose": self.remediation,
            })

        result = {
            "uuid": self.uuid,
            "control-id": self.control_id,
            "props": props,
            "parts": parts,
        }

        # Add NIST mappings as links
        if self.nist_mappings:
            result["links"] = [
                {
                    "href": f"#nist-800-53-{ctrl.lower()}",
                    "rel": "related",
                    "text": f"NIST 800-53 {ctrl}",
                }
                for ctrl in self.nist_mappings
            ]

        return result


@dataclass
class ComponentDefinition:
    """
    An OSCAL component-definition for SOC 2 automated checks.

    Groups all implemented requirements by cloud provider.
    """

    uuid: str
    title: str
    description: str
    version: str
    last_modified: str
    implemented_requirements: list[ImplementedRequirement] = field(default_factory=list)

    def to_oscal(self) -> dict:
        """Convert to OSCAL component-definition format."""
        # Group requirements by control
        control_implementations = []

        # Get unique control IDs
        control_ids = sorted(set(req.control_id for req in self.implemented_requirements))

        for control_id in control_ids:
            reqs = [
                req.to_oscal()
                for req in self.implemented_requirements
                if req.control_id == control_id
            ]
            control_implementations.extend(reqs)

        return {
            "component-definition": {
                "uuid": self.uuid,
                "metadata": {
                    "title": self.title,
                    "last-modified": self.last_modified,
                    "version": self.version,
                    "oscal-version": "1.1.2",
                    "props": [
                        {
                            "name": "framework",
                            "value": "SOC2",
                            "uuid": str(uuid.uuid4()),
                        },
                        {
                            "name": "component-type",
                            "value": "automated-checks",
                            "uuid": str(uuid.uuid4()),
                        },
                    ],
                },
                "components": [
                    {
                        "uuid": str(uuid.uuid4()),
                        "type": "software",
                        "title": "Attestful SOC 2 Automated Compliance Checks",
                        "description": self.description,
                        "props": [
                            {
                                "name": "total-checks",
                                "value": str(len(self.implemented_requirements)),
                                "uuid": str(uuid.uuid4()),
                            },
                            {
                                "name": "aws-checks",
                                "value": str(sum(1 for r in self.implemented_requirements if r.provider == "aws")),
                                "uuid": str(uuid.uuid4()),
                            },
                            {
                                "name": "azure-checks",
                                "value": str(sum(1 for r in self.implemented_requirements if r.provider == "azure")),
                                "uuid": str(uuid.uuid4()),
                            },
                            {
                                "name": "gcp-checks",
                                "value": str(sum(1 for r in self.implemented_requirements if r.provider == "gcp")),
                                "uuid": str(uuid.uuid4()),
                            },
                        ],
                        "control-implementations": [
                            {
                                "uuid": str(uuid.uuid4()),
                                "source": "soc2-trust-services-criteria",
                                "description": "SOC 2 Trust Services Criteria compliance checks",
                                "implemented-requirements": control_implementations,
                            }
                        ],
                    }
                ],
            }
        }


# =============================================================================
# Conversion Functions
# =============================================================================


def convert_check_to_requirement(check: Any, provider: str) -> list[ImplementedRequirement]:
    """
    Convert a CheckDefinition to OSCAL ImplementedRequirements.

    Creates one requirement per SOC 2 control the check maps to.

    Args:
        check: The CheckDefinition object.
        provider: Cloud provider (aws, azure, gcp).

    Returns:
        List of ImplementedRequirement objects.
    """
    requirements = []

    soc2_controls = check.frameworks.get("soc2", [])
    nist_controls = check.frameworks.get("nist-800-53", [])

    # Determine condition type
    condition_type = "compound" if hasattr(check.condition, "conditions") else "simple"

    for control_id in soc2_controls:
        req = ImplementedRequirement(
            uuid=str(uuid.uuid4()),
            control_id=control_id,
            check_id=check.id,
            description=check.description,
            severity=check.severity,
            resource_types=check.resource_types,
            provider=provider,
            condition_type=condition_type,
            remediation=check.remediation,
            nist_mappings=nist_controls,
            tags=check.tags if hasattr(check, "tags") else [],
        )
        requirements.append(req)

    return requirements


def generate_soc2_component_definition() -> ComponentDefinition:
    """
    Generate a complete OSCAL component definition for SOC 2 checks.

    Returns:
        ComponentDefinition containing all automated checks.
    """
    requirements: list[ImplementedRequirement] = []

    # Convert AWS checks
    for check in get_soc2_aws_checks():
        requirements.extend(convert_check_to_requirement(check, "aws"))

    # Convert Azure checks
    for check in get_soc2_azure_checks():
        requirements.extend(convert_check_to_requirement(check, "azure"))

    # Convert GCP checks
    for check in get_soc2_gcp_checks():
        requirements.extend(convert_check_to_requirement(check, "gcp"))

    component = ComponentDefinition(
        uuid=str(uuid.uuid4()),
        title="Attestful SOC 2 Automated Compliance Component",
        description=(
            "OSCAL component definition containing automated compliance checks "
            "for SOC 2 Trust Services Criteria. These checks provide continuous "
            "monitoring and evidence collection for CC6-CC9 (Security), A1 (Availability), "
            "and other optional criteria across AWS, Azure, and GCP."
        ),
        version="2024.1",
        last_modified=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        implemented_requirements=requirements,
    )

    logger.info(
        f"Generated SOC 2 component definition with {len(requirements)} implemented requirements"
    )

    return component


# =============================================================================
# Export Functions
# =============================================================================


def export_component_to_json(path: Path | str | None = None) -> str:
    """
    Export the SOC 2 component definition to JSON.

    Args:
        path: Optional path to write the JSON file.

    Returns:
        The JSON string.
    """
    component = generate_soc2_component_definition()
    oscal_data = component.to_oscal()

    json_str = json.dumps(oscal_data, indent=2)

    if path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_str, encoding="utf-8")
        logger.info(f"Exported SOC 2 component definition to {path}")

    return json_str


def get_implemented_requirements_by_control() -> dict[str, list[dict]]:
    """
    Get implemented requirements grouped by control ID.

    Returns:
        Dictionary mapping control IDs to their implemented requirements.
    """
    component = generate_soc2_component_definition()

    by_control: dict[str, list[dict]] = {}
    for req in component.implemented_requirements:
        if req.control_id not in by_control:
            by_control[req.control_id] = []
        by_control[req.control_id].append({
            "check_id": req.check_id,
            "description": req.description,
            "severity": req.severity,
            "provider": req.provider,
            "resource_types": req.resource_types,
        })

    return by_control


def get_component_statistics() -> dict:
    """
    Get statistics about the component definition.

    Returns:
        Dictionary with component statistics.
    """
    component = generate_soc2_component_definition()

    # Count by provider
    provider_counts: dict[str, int] = {}
    for req in component.implemented_requirements:
        provider_counts[req.provider] = provider_counts.get(req.provider, 0) + 1

    # Count by control
    control_counts: dict[str, int] = {}
    for req in component.implemented_requirements:
        control_counts[req.control_id] = control_counts.get(req.control_id, 0) + 1

    # Count by severity
    severity_counts: dict[str, int] = {}
    for req in component.implemented_requirements:
        severity_counts[req.severity] = severity_counts.get(req.severity, 0) + 1

    # Get unique controls covered
    unique_controls = sorted(set(req.control_id for req in component.implemented_requirements))

    return {
        "total_requirements": len(component.implemented_requirements),
        "unique_controls": len(unique_controls),
        "controls_covered": unique_controls,
        "provider_distribution": provider_counts,
        "control_distribution": control_counts,
        "severity_distribution": severity_counts,
    }


def get_control_coverage() -> dict[str, dict]:
    """
    Get coverage statistics for each Trust Services Criterion.

    Returns:
        Dictionary mapping control IDs to their coverage info.
    """
    by_control = get_implemented_requirements_by_control()

    coverage: dict[str, dict] = {}
    for control_id, reqs in by_control.items():
        # Determine category
        if control_id.startswith("CC"):
            category = "Security (Common Criteria)"
        elif control_id.startswith("A"):
            category = "Availability"
        elif control_id.startswith("PI"):
            category = "Processing Integrity"
        elif control_id.startswith("C"):
            category = "Confidentiality"
        elif control_id.startswith("P"):
            category = "Privacy"
        else:
            category = "Unknown"

        providers = set(req["provider"] for req in reqs)
        severities = set(req["severity"] for req in reqs)

        coverage[control_id] = {
            "category": category,
            "check_count": len(reqs),
            "providers": sorted(providers),
            "severities": sorted(severities),
            "automation_status": "automated",
            "checks": [req["check_id"] for req in reqs],
        }

    return coverage


__all__ = [
    # Data classes
    "ImplementedRequirement",
    "ComponentDefinition",
    # Conversion
    "convert_check_to_requirement",
    "generate_soc2_component_definition",
    # Export
    "export_component_to_json",
    # Statistics
    "get_implemented_requirements_by_control",
    "get_component_statistics",
    "get_control_coverage",
]
