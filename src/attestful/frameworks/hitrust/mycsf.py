"""
HITRUST MyCSF Integration Module.

Provides integration points for HITRUST MyCSF (My Compliance Security Framework),
HITRUST's official assessment platform for managing HITRUST CSF assessments.

MyCSF Integration Features:
---------------------------
1. Assessment Export: Export Attestful assessment data in MyCSF-compatible format
2. Assessment Import: Import MyCSF assessment results into Attestful
3. Evidence Mapping: Map Attestful evidence to MyCSF evidence requirements
4. Gap Synchronization: Sync gap analysis between platforms

MyCSF API Structure:
--------------------
MyCSF uses a REST API with the following key endpoints:
- /assessments - Assessment management
- /controls - Control status and scoring
- /evidence - Evidence upload and management
- /reports - Report generation

Export Formats:
---------------
- JSON: Native MyCSF import format
- CSV: Bulk control status updates
- Excel: Comprehensive assessment workbooks

This module does not directly connect to MyCSF API (requires organization credentials)
but provides data transformation and formatting for manual import/export workflows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
import json

from attestful.core.logging import get_logger
from attestful.frameworks.hitrust.controls import (
    HITRUST_CONTROLS,
    HITRUST_VERSION,
    CATEGORY_NAMES,
    MATURITY_LEVEL_NAMES,
    get_control,
)
from attestful.frameworks.hitrust.maturity import (
    HITRUSTMaturityBreakdown,
    HITRUSTControlScore,
    HITRUSTCertificationType,
    CERTIFICATION_REQUIREMENTS,
)

logger = get_logger("frameworks.hitrust.mycsf")


# =============================================================================
# Enums and Constants
# =============================================================================


class MyCSFAssessmentType(str, Enum):
    """MyCSF assessment types."""

    SELF_ASSESSMENT = "self"
    VALIDATED_ASSESSMENT = "validated"
    CERTIFICATION_ASSESSMENT = "certification"


class MyCSFControlStatus(str, Enum):
    """MyCSF control implementation status values."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"
    ALTERNATIVE_CONTROL = "alternative_control"


class MyCSFEvidenceType(str, Enum):
    """MyCSF evidence types."""

    POLICY = "policy"
    PROCEDURE = "procedure"
    SCREENSHOT = "screenshot"
    CONFIGURATION = "configuration"
    LOG_SAMPLE = "log_sample"
    AUDIT_REPORT = "audit_report"
    ATTESTATION = "attestation"
    OTHER = "other"


# MyCSF field mappings
MYCSF_STATUS_FROM_LEVEL = {
    0: MyCSFControlStatus.NOT_STARTED,
    1: MyCSFControlStatus.IN_PROGRESS,
    2: MyCSFControlStatus.IN_PROGRESS,
    3: MyCSFControlStatus.IMPLEMENTED,
    4: MyCSFControlStatus.IMPLEMENTED,
    5: MyCSFControlStatus.IMPLEMENTED,
}

# MyCSF maturity level mappings (MyCSF uses 1-5 scale)
MYCSF_MATURITY_LABELS = {
    1: "Policy",
    2: "Procedure",
    3: "Implemented",
    4: "Measured",
    5: "Managed",
}

# Evidence type mappings from Attestful to MyCSF
EVIDENCE_TYPE_MAPPING = {
    "policy_document": MyCSFEvidenceType.POLICY,
    "procedure_document": MyCSFEvidenceType.PROCEDURE,
    "configuration_evidence": MyCSFEvidenceType.CONFIGURATION,
    "automated_check_results": MyCSFEvidenceType.CONFIGURATION,
    "audit_logs": MyCSFEvidenceType.LOG_SAMPLE,
    "metrics": MyCSFEvidenceType.AUDIT_REPORT,
    "training_records": MyCSFEvidenceType.ATTESTATION,
}


# =============================================================================
# Data Classes for MyCSF Integration
# =============================================================================


@dataclass
class MyCSFControlExport:
    """
    Control data formatted for MyCSF import.

    Attributes:
        control_id: HITRUST control ID.
        control_reference: Full control reference string.
        title: Control title.
        category: Category code.
        category_name: Category display name.
        status: Implementation status.
        maturity_level: Maturity level (1-5).
        policy_score: Level 1 score (0-100).
        procedure_score: Level 2 score (0-100).
        implementation_score: Level 3 score (0-100).
        measurement_score: Level 4 score (0-100).
        management_score: Level 5 score (0-100).
        evidence_summary: Summary of available evidence.
        gaps: Identified gaps.
        notes: Additional notes.
    """

    control_id: str
    control_reference: str
    title: str
    category: str
    category_name: str
    status: MyCSFControlStatus
    maturity_level: int = 0
    policy_score: float = 0.0
    procedure_score: float = 0.0
    implementation_score: float = 0.0
    measurement_score: float = 0.0
    management_score: float = 0.0
    evidence_summary: str = ""
    gaps: list[str] = field(default_factory=list)
    notes: str = ""

    def to_mycsf_dict(self) -> dict[str, Any]:
        """Convert to MyCSF import format."""
        return {
            "controlId": self.control_id,
            "controlReference": self.control_reference,
            "title": self.title,
            "category": self.category,
            "categoryName": self.category_name,
            "implementationStatus": self.status.value,
            "maturityLevel": self.maturity_level,
            "scores": {
                "policy": round(self.policy_score, 1),
                "procedure": round(self.procedure_score, 1),
                "implementation": round(self.implementation_score, 1),
                "measurement": round(self.measurement_score, 1),
                "management": round(self.management_score, 1),
            },
            "evidenceSummary": self.evidence_summary,
            "gaps": self.gaps,
            "notes": self.notes,
        }

    def to_csv_row(self) -> dict[str, str]:
        """Convert to CSV row format."""
        return {
            "Control ID": self.control_id,
            "Control Reference": self.control_reference,
            "Title": self.title,
            "Category": f"{self.category} - {self.category_name}",
            "Status": self.status.value,
            "Maturity Level": str(self.maturity_level),
            "Policy Score": f"{self.policy_score:.1f}",
            "Procedure Score": f"{self.procedure_score:.1f}",
            "Implementation Score": f"{self.implementation_score:.1f}",
            "Measurement Score": f"{self.measurement_score:.1f}",
            "Management Score": f"{self.management_score:.1f}",
            "Evidence Summary": self.evidence_summary,
            "Gaps": "; ".join(self.gaps),
            "Notes": self.notes,
        }


@dataclass
class MyCSFAssessmentExport:
    """
    Complete assessment export for MyCSF.

    Attributes:
        assessment_id: Unique assessment identifier.
        assessment_type: Type of assessment.
        organization_name: Organization name.
        framework_version: HITRUST CSF version.
        assessment_date: Date of assessment.
        certification_target: Target certification type.
        overall_maturity: Overall maturity level.
        overall_average: Overall average score.
        controls: List of control exports.
        summary: Assessment summary.
    """

    assessment_id: str
    assessment_type: MyCSFAssessmentType
    organization_name: str
    framework_version: str
    assessment_date: datetime
    certification_target: HITRUSTCertificationType | None
    overall_maturity: int
    overall_average: float
    controls: list[MyCSFControlExport]
    summary: dict[str, Any]

    def to_mycsf_json(self) -> dict[str, Any]:
        """Convert to full MyCSF JSON export format."""
        return {
            "assessmentInfo": {
                "assessmentId": self.assessment_id,
                "assessmentType": self.assessment_type.value,
                "organizationName": self.organization_name,
                "frameworkVersion": self.framework_version,
                "assessmentDate": self.assessment_date.isoformat(),
                "certificationTarget": (
                    self.certification_target.value
                    if self.certification_target else None
                ),
            },
            "overallResults": {
                "maturityLevel": self.overall_maturity,
                "averageScore": round(self.overall_average, 2),
                "maturityLevelName": MYCSF_MATURITY_LABELS.get(
                    self.overall_maturity, "Not Achieved"
                ),
            },
            "controls": [c.to_mycsf_dict() for c in self.controls],
            "summary": self.summary,
            "metadata": {
                "exportedAt": datetime.now(UTC).isoformat(),
                "exportedBy": "Attestful",
                "exportVersion": "1.0",
            },
        }


@dataclass
class MyCSFEvidenceMapping:
    """
    Evidence mapping for MyCSF upload.

    Attributes:
        control_id: HITRUST control ID.
        evidence_type: MyCSF evidence type.
        file_name: Evidence file name.
        file_path: Path to evidence file.
        description: Evidence description.
        collected_date: When evidence was collected.
        maturity_level: Which maturity level this evidence supports.
    """

    control_id: str
    evidence_type: MyCSFEvidenceType
    file_name: str
    file_path: str
    description: str
    collected_date: datetime
    maturity_level: int

    def to_mycsf_dict(self) -> dict[str, Any]:
        """Convert to MyCSF evidence format."""
        return {
            "controlId": self.control_id,
            "evidenceType": self.evidence_type.value,
            "fileName": self.file_name,
            "description": self.description,
            "collectedDate": self.collected_date.isoformat(),
            "maturityLevel": self.maturity_level,
        }


@dataclass
class MyCSFImportResult:
    """
    Result of importing MyCSF assessment data.

    Attributes:
        success: Whether import was successful.
        controls_imported: Number of controls imported.
        controls_updated: Number of existing controls updated.
        errors: List of import errors.
        warnings: List of import warnings.
    """

    success: bool
    controls_imported: int
    controls_updated: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# =============================================================================
# Export Functions
# =============================================================================


def export_to_mycsf_format(
    breakdown: HITRUSTMaturityBreakdown,
    organization_name: str,
    assessment_type: MyCSFAssessmentType = MyCSFAssessmentType.SELF_ASSESSMENT,
    certification_target: HITRUSTCertificationType | None = None,
) -> MyCSFAssessmentExport:
    """
    Export Attestful maturity breakdown to MyCSF format.

    Args:
        breakdown: Complete HITRUST maturity breakdown.
        organization_name: Name of the organization.
        assessment_type: Type of MyCSF assessment.
        certification_target: Target certification type.

    Returns:
        MyCSFAssessmentExport ready for JSON serialization.
    """
    # Convert control scores to MyCSF format
    control_exports = []

    for control_id, score in breakdown.by_control.items():
        control = get_control(control_id)
        if not control:
            continue

        # Build evidence summary
        evidence_parts = []
        if score.evidence_count > 0:
            evidence_parts.append(f"{score.evidence_count} evidence items")
        if score.automated_checks_total > 0:
            evidence_parts.append(
                f"{score.automated_checks_passed}/{score.automated_checks_total} checks passed"
            )
        evidence_summary = "; ".join(evidence_parts) if evidence_parts else "No evidence"

        export = MyCSFControlExport(
            control_id=control_id,
            control_reference=control.control_reference or control_id,
            title=control.title,
            category=control.category,
            category_name=CATEGORY_NAMES.get(control.category, "Unknown"),
            status=MYCSF_STATUS_FROM_LEVEL.get(score.overall_level, MyCSFControlStatus.NOT_STARTED),
            maturity_level=score.overall_level,
            policy_score=score.policy_score,
            procedure_score=score.procedure_score,
            implementation_score=score.implemented_score,
            measurement_score=score.measured_score,
            management_score=score.managed_score,
            evidence_summary=evidence_summary,
            gaps=score.evidence_gaps,
            notes=score.explanation,
        )
        control_exports.append(export)

    # Sort by control ID
    control_exports.sort(key=lambda x: x.control_id)

    # Build summary
    summary = {
        "totalControls": len(control_exports),
        "controlsByStatus": {
            status.value: sum(1 for c in control_exports if c.status == status)
            for status in MyCSFControlStatus
        },
        "controlsByMaturityLevel": {
            str(level): sum(1 for c in control_exports if c.maturity_level == level)
            for level in range(6)
        },
        "categoryBreakdown": {
            code: {
                "name": name,
                "avgLevel": (
                    round(cat_score.avg_level, 2)
                    if (cat_score := breakdown.by_category.get(code)) else 0
                ),
                "controlCount": sum(1 for c in control_exports if c.category == code),
            }
            for code, name in CATEGORY_NAMES.items()
        },
        "certificationEligibility": breakdown.certification_eligibility,
    }

    # Generate assessment ID
    assessment_id = f"ATTESTFUL-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"

    return MyCSFAssessmentExport(
        assessment_id=assessment_id,
        assessment_type=assessment_type,
        organization_name=organization_name,
        framework_version=HITRUST_VERSION,
        assessment_date=breakdown.timestamp,
        certification_target=certification_target,
        overall_maturity=breakdown.overall_level,
        overall_average=breakdown.overall_avg,
        controls=control_exports,
        summary=summary,
    )


def export_to_mycsf_json(
    breakdown: HITRUSTMaturityBreakdown,
    organization_name: str,
    output_path: str | None = None,
    **kwargs: Any,
) -> str:
    """
    Export to MyCSF JSON format and optionally save to file.

    Args:
        breakdown: Complete HITRUST maturity breakdown.
        organization_name: Name of the organization.
        output_path: Optional path to save JSON file.
        **kwargs: Additional arguments for export_to_mycsf_format.

    Returns:
        JSON string of the export.
    """
    export = export_to_mycsf_format(breakdown, organization_name, **kwargs)
    json_data = export.to_mycsf_json()
    json_str = json.dumps(json_data, indent=2, default=str)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)
        logger.info(f"Exported MyCSF assessment to {output_path}")

    return json_str


def export_to_mycsf_csv(
    breakdown: HITRUSTMaturityBreakdown,
    organization_name: str,
    output_path: str | None = None,
    **kwargs: Any,
) -> list[dict[str, str]]:
    """
    Export to CSV format for MyCSF bulk import.

    Args:
        breakdown: Complete HITRUST maturity breakdown.
        organization_name: Name of the organization.
        output_path: Optional path to save CSV file.
        **kwargs: Additional arguments for export_to_mycsf_format.

    Returns:
        List of CSV row dictionaries.
    """
    export = export_to_mycsf_format(breakdown, organization_name, **kwargs)
    rows = [control.to_csv_row() for control in export.controls]

    if output_path:
        import csv

        if rows:
            fieldnames = list(rows[0].keys())
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Exported MyCSF CSV to {output_path}")

    return rows


# =============================================================================
# Import Functions
# =============================================================================


def parse_mycsf_import(json_data: str | dict) -> dict[str, HITRUSTControlScore]:
    """
    Parse MyCSF assessment data into Attestful control scores.

    Args:
        json_data: JSON string or dictionary of MyCSF assessment.

    Returns:
        Dictionary mapping control IDs to HITRUSTControlScore objects.
    """
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data

    control_scores: dict[str, HITRUSTControlScore] = {}

    controls = data.get("controls", [])

    for control_data in controls:
        control_id = control_data.get("controlId", "")
        if not control_id:
            continue

        scores = control_data.get("scores", {})

        score = HITRUSTControlScore(
            control_id=control_id,
            control_title=control_data.get("title", ""),
            category=control_data.get("category", "00"),
            policy_score=float(scores.get("policy", 0)),
            procedure_score=float(scores.get("procedure", 0)),
            implemented_score=float(scores.get("implementation", 0)),
            measured_score=float(scores.get("measurement", 0)),
            managed_score=float(scores.get("management", 0)),
            overall_level=int(control_data.get("maturityLevel", 0)),
            evidence_gaps=control_data.get("gaps", []),
            explanation=control_data.get("notes", ""),
        )

        control_scores[control_id] = score

    return control_scores


def import_from_mycsf_file(file_path: str) -> tuple[dict[str, HITRUSTControlScore], MyCSFImportResult]:
    """
    Import MyCSF assessment from file.

    Args:
        file_path: Path to MyCSF JSON file.

    Returns:
        Tuple of (control_scores, import_result).
    """
    errors = []
    warnings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            json_data = f.read()
    except FileNotFoundError:
        return {}, MyCSFImportResult(
            success=False,
            controls_imported=0,
            controls_updated=0,
            errors=[f"File not found: {file_path}"],
        )
    except Exception as e:
        return {}, MyCSFImportResult(
            success=False,
            controls_imported=0,
            controls_updated=0,
            errors=[f"Error reading file: {e}"],
        )

    try:
        control_scores = parse_mycsf_import(json_data)
    except json.JSONDecodeError as e:
        return {}, MyCSFImportResult(
            success=False,
            controls_imported=0,
            controls_updated=0,
            errors=[f"Invalid JSON: {e}"],
        )
    except Exception as e:
        return {}, MyCSFImportResult(
            success=False,
            controls_imported=0,
            controls_updated=0,
            errors=[f"Error parsing MyCSF data: {e}"],
        )

    # Validate imported controls
    valid_controls = 0
    for control_id in control_scores:
        if control_id in HITRUST_CONTROLS:
            valid_controls += 1
        else:
            warnings.append(f"Unknown control ID: {control_id}")

    result = MyCSFImportResult(
        success=True,
        controls_imported=valid_controls,
        controls_updated=0,
        errors=errors,
        warnings=warnings,
    )

    logger.info(f"Imported {valid_controls} controls from {file_path}")

    return control_scores, result


# =============================================================================
# Evidence Mapping Functions
# =============================================================================


def map_evidence_to_mycsf(
    evidence_items: list[dict[str, Any]],
) -> list[MyCSFEvidenceMapping]:
    """
    Map Attestful evidence items to MyCSF evidence format.

    Args:
        evidence_items: List of evidence items from Attestful.

    Returns:
        List of MyCSF evidence mappings.
    """
    mappings = []

    for item in evidence_items:
        control_id = item.get("control_id", "")
        evidence_type = item.get("type", "other")

        # Map to MyCSF evidence type
        mycsf_type = EVIDENCE_TYPE_MAPPING.get(
            evidence_type, MyCSFEvidenceType.OTHER
        )

        # Parse collected date
        collected_date = item.get("collected_at")
        if isinstance(collected_date, str):
            try:
                collected_date = datetime.fromisoformat(
                    collected_date.replace("Z", "+00:00")
                )
            except ValueError:
                collected_date = datetime.now(UTC)
        elif not isinstance(collected_date, datetime):
            collected_date = datetime.now(UTC)

        mapping = MyCSFEvidenceMapping(
            control_id=control_id,
            evidence_type=mycsf_type,
            file_name=item.get("file_name", "evidence"),
            file_path=item.get("file_path", ""),
            description=item.get("description", ""),
            collected_date=collected_date,
            maturity_level=item.get("maturity_level", 3),
        )
        mappings.append(mapping)

    return mappings


def generate_evidence_manifest(
    mappings: list[MyCSFEvidenceMapping],
    output_path: str | None = None,
) -> dict[str, Any]:
    """
    Generate evidence manifest for MyCSF upload.

    Args:
        mappings: List of evidence mappings.
        output_path: Optional path to save manifest.

    Returns:
        Evidence manifest dictionary.
    """
    # Group by control
    by_control: dict[str, list[MyCSFEvidenceMapping]] = {}
    for mapping in mappings:
        if mapping.control_id not in by_control:
            by_control[mapping.control_id] = []
        by_control[mapping.control_id].append(mapping)

    manifest = {
        "manifestVersion": "1.0",
        "generatedAt": datetime.now(UTC).isoformat(),
        "generatedBy": "Attestful",
        "evidenceCount": len(mappings),
        "controlCount": len(by_control),
        "evidenceByControl": {
            control_id: [m.to_mycsf_dict() for m in control_mappings]
            for control_id, control_mappings in sorted(by_control.items())
        },
        "evidenceByType": {
            evidence_type.value: sum(
                1 for m in mappings if m.evidence_type == evidence_type
            )
            for evidence_type in MyCSFEvidenceType
        },
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, default=str)
        logger.info(f"Generated evidence manifest at {output_path}")

    return manifest


# =============================================================================
# Gap Synchronization Functions
# =============================================================================


def sync_gaps_to_mycsf(
    breakdown: HITRUSTMaturityBreakdown,
    target_certification: HITRUSTCertificationType,
) -> dict[str, Any]:
    """
    Generate gap synchronization data for MyCSF.

    Args:
        breakdown: Complete HITRUST maturity breakdown.
        target_certification: Target certification type.

    Returns:
        Gap synchronization data for MyCSF.
    """
    requirements = CERTIFICATION_REQUIREMENTS[target_certification]
    min_level = requirements["min_level"]

    gaps = []
    for control_id, score in breakdown.by_control.items():
        if score.overall_level < min_level:
            control = get_control(control_id)
            gap_info = {
                "controlId": control_id,
                "controlTitle": control.title if control else "",
                "category": score.category,
                "currentLevel": score.overall_level,
                "requiredLevel": min_level,
                "gapSize": min_level - score.overall_level,
                "evidenceGaps": score.evidence_gaps,
                "recommendedActions": _get_remediation_actions(score, min_level),
            }
            gaps.append(gap_info)

    # Sort by gap size (largest first)
    gaps.sort(key=lambda x: -x["gapSize"])

    return {
        "syncVersion": "1.0",
        "syncedAt": datetime.now(UTC).isoformat(),
        "targetCertification": target_certification.value,
        "requiredLevel": min_level,
        "totalGaps": len(gaps),
        "gaps": gaps,
        "summary": {
            "controlsAtTarget": sum(
                1 for s in breakdown.by_control.values()
                if s.overall_level >= min_level
            ),
            "controlsBelowTarget": len(gaps),
            "averageGapSize": (
                sum(g["gapSize"] for g in gaps) / len(gaps) if gaps else 0
            ),
        },
    }


def _get_remediation_actions(
    score: HITRUSTControlScore,
    target_level: int,
) -> list[str]:
    """Generate remediation action recommendations."""
    actions = []

    if score.policy_score < 80 and target_level >= 1:
        actions.append("Document and approve policy for this control")

    if score.procedure_score < 80 and target_level >= 2:
        actions.append("Document procedures and provide training")

    if score.implemented_score < 80 and target_level >= 3:
        actions.append("Implement technical controls and collect configuration evidence")

    if score.measured_score < 80 and target_level >= 4:
        actions.append("Establish metrics and KPIs for control monitoring")

    if score.managed_score < 80 and target_level >= 5:
        actions.append("Implement continuous improvement processes")

    return actions


# =============================================================================
# Utility Functions
# =============================================================================


def get_mycsf_api_template() -> dict[str, Any]:
    """
    Get template for MyCSF API integration configuration.

    Returns:
        API configuration template.
    """
    return {
        "apiVersion": "v2",
        "baseUrl": "https://mycsf.hitrust.net/api",
        "endpoints": {
            "assessments": "/assessments",
            "controls": "/assessments/{assessment_id}/controls",
            "evidence": "/assessments/{assessment_id}/evidence",
            "reports": "/assessments/{assessment_id}/reports",
        },
        "authMethod": "oauth2",
        "scopes": ["assessments:read", "assessments:write", "evidence:write"],
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        "note": "Requires valid MyCSF organization credentials",
    }


def validate_mycsf_export(export_data: dict[str, Any]) -> tuple[bool, list[str]]:
    """
    Validate MyCSF export data structure.

    Args:
        export_data: Export data to validate.

    Returns:
        Tuple of (is_valid, error_messages).
    """
    errors = []

    # Check required top-level fields
    required_fields = ["assessmentInfo", "overallResults", "controls"]
    for field in required_fields:
        if field not in export_data:
            errors.append(f"Missing required field: {field}")

    # Check assessment info
    if "assessmentInfo" in export_data:
        info = export_data["assessmentInfo"]
        info_fields = ["assessmentId", "organizationName", "frameworkVersion"]
        for field in info_fields:
            if field not in info:
                errors.append(f"Missing assessment info field: {field}")

    # Check controls
    if "controls" in export_data:
        controls = export_data["controls"]
        if not isinstance(controls, list):
            errors.append("Controls must be a list")
        else:
            for i, control in enumerate(controls):
                if "controlId" not in control:
                    errors.append(f"Control {i} missing controlId")
                if "maturityLevel" not in control:
                    errors.append(f"Control {i} missing maturityLevel")

    return len(errors) == 0, errors


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Enums
    "MyCSFAssessmentType",
    "MyCSFControlStatus",
    "MyCSFEvidenceType",
    # Data classes
    "MyCSFControlExport",
    "MyCSFAssessmentExport",
    "MyCSFEvidenceMapping",
    "MyCSFImportResult",
    # Constants
    "MYCSF_STATUS_FROM_LEVEL",
    "MYCSF_MATURITY_LABELS",
    "EVIDENCE_TYPE_MAPPING",
    # Export functions
    "export_to_mycsf_format",
    "export_to_mycsf_json",
    "export_to_mycsf_csv",
    # Import functions
    "parse_mycsf_import",
    "import_from_mycsf_file",
    # Evidence mapping
    "map_evidence_to_mycsf",
    "generate_evidence_manifest",
    # Gap sync
    "sync_gaps_to_mycsf",
    # Utilities
    "get_mycsf_api_template",
    "validate_mycsf_export",
]
