"""
ISO 27001:2022 compliance framework implementation.

Provides ISO 27001:2022 Annex A control definitions, automated checks,
and OSCAL conversion for ISO 27001 certification assessments.

Key components:
- ISO 27001:2022 Annex A control definitions (93 controls)
- OSCAL catalog with ISMS requirements (Clauses 4-10) and Annex A controls
- Automated compliance checks for AWS, Azure, GCP
- NIST 800-53 and SOC 2 cross-framework mappings
- Statement of Applicability (SoA) generation
- Certification audit support

ISO 27001:2022 Annex A Control Domains:
- A.5: Organizational controls (37 controls)
- A.6: People controls (8 controls)
- A.7: Physical controls (14 controls)
- A.8: Technological controls (34 controls)

Total: 93 controls (reduced from 114 in ISO 27001:2013)
"""

from attestful.frameworks.iso27001.controls import (
    ISO_27001_FRAMEWORK_ID,
    ISO_27001_VERSION,
    DOMAIN_ORGANIZATIONAL,
    DOMAIN_PEOPLE,
    DOMAIN_PHYSICAL,
    DOMAIN_TECHNOLOGICAL,
    DOMAIN_NAMES,
    ISO27001Control,
    ISO27001Framework,
    ISO_27001_CONTROLS,
    get_control,
    get_controls_by_domain,
    get_all_controls,
    get_all_domains,
    get_control_count_by_domain,
    get_controls_by_nist_mapping,
    get_controls_by_soc2_mapping,
)
from attestful.frameworks.iso27001.oscal_catalog import (
    ISO27001_OSCAL_CATALOG_PATH,
    ISO27001_CATALOG_SHA256,
    ANNEX_A_DOMAINS,
    ISMS_CLAUSES,
    CONTROL_TYPES,
    get_catalog_path,
    verify_catalog_integrity,
    load_iso27001_catalog,
    get_iso27001_catalog_index,
    get_oscal_control,
    get_control_statement,
    get_control_guidance,
    get_control_automation_status,
    get_control_type,
    get_domain_controls,
    get_clause_requirements,
    get_all_control_ids,
    get_annex_a_controls,
    get_isms_requirements,
    get_catalog_statistics,
    get_catalog_metadata,
    search_controls,
    get_controls_by_automation_status,
    get_controls_by_type,
)
from attestful.frameworks.iso27001.nist_mapping import (
    MappingStrength,
    ControlMapping,
    ISO27001MappingSummary,
    NIST_CONTROL_FAMILIES,
    STRONG_MAPPINGS,
    PARTIAL_MAPPINGS,
    ISO_UNIQUE_CONTROLS,
    get_iso_to_nist_mappings,
    get_nist_to_iso_mappings,
    get_nist_controls_for_iso,
    get_iso_controls_for_nist,
    get_mapping_strength,
    get_mapping_summary,
    get_unmapped_iso_controls,
    get_unmapped_nist_families,
    get_mapping_coverage_by_domain,
    get_nist_family_coverage,
    export_mapping_matrix,
    export_reverse_mapping_matrix,
    get_mapping_statistics,
)
from attestful.frameworks.iso27001.checks import (
    InheritedCheck,
    CheckCoverageReport,
    get_soc2_checks_by_nist,
    get_inherited_checks_for_iso_control,
    get_all_inherited_checks,
    get_check_coverage_report,
    get_controls_needing_checks,
    get_controls_with_full_coverage,
    get_coverage_by_domain,
    get_iso27001_checks_for_control,
    get_all_iso27001_checks,
    get_check_statistics,
    get_inheritance_summary,
)
from attestful.frameworks.iso27001.reports import (
    ApplicabilityStatus,
    ImplementationStatus,
    RiskTreatmentOption,
    AuditFindingType,
    AuditFindingStatus,
    SoAControlEntry,
    StatementOfApplicability,
    generate_soa_template,
    RiskTreatmentEntry,
    RiskTreatmentPlan,
    generate_risk_treatment_template,
    AuditFinding,
    InternalAuditReport,
    generate_internal_audit_template,
    ManagementReviewMinutes,
    generate_management_review_template,
    export_soa_to_json,
    export_soa_to_markdown,
    export_audit_report_to_json,
    get_report_statistics,
)
from attestful.frameworks.iso27001.certification import (
    AuditStage,
    NonconformityGrade,
    CorrectiveActionStatus,
    EvidenceType,
    DocumentStatus,
    ISMSDocument,
    Stage1DocumentationPackage,
    MANDATORY_DOCUMENTS,
    generate_stage1_package,
    AuditEvidence,
    ControlEvidenceRequirement,
    Stage2EvidenceWorkflow,
    DOMAIN_EVIDENCE_GUIDANCE,
    generate_stage2_workflow,
    Nonconformity,
    CorrectiveActionPlan,
    create_corrective_action_plan,
    create_nonconformity,
    export_stage1_package,
    export_stage2_workflow,
    export_corrective_action_plan,
    export_nonconformity_summary_markdown,
    get_certification_statistics,
)

__all__ = [
    # Framework constants
    "ISO_27001_FRAMEWORK_ID",
    "ISO_27001_VERSION",
    # Domain constants
    "DOMAIN_ORGANIZATIONAL",
    "DOMAIN_PEOPLE",
    "DOMAIN_PHYSICAL",
    "DOMAIN_TECHNOLOGICAL",
    "DOMAIN_NAMES",
    # Data classes
    "ISO27001Control",
    "ISO27001Framework",
    # Control definitions
    "ISO_27001_CONTROLS",
    # Lookup functions (controls.py)
    "get_control",
    "get_controls_by_domain",
    "get_all_controls",
    "get_all_domains",
    "get_control_count_by_domain",
    "get_controls_by_nist_mapping",
    "get_controls_by_soc2_mapping",
    # OSCAL catalog constants
    "ISO27001_OSCAL_CATALOG_PATH",
    "ISO27001_CATALOG_SHA256",
    "ANNEX_A_DOMAINS",
    "ISMS_CLAUSES",
    "CONTROL_TYPES",
    # OSCAL catalog functions
    "get_catalog_path",
    "verify_catalog_integrity",
    "load_iso27001_catalog",
    "get_iso27001_catalog_index",
    "get_oscal_control",
    "get_control_statement",
    "get_control_guidance",
    "get_control_automation_status",
    "get_control_type",
    "get_domain_controls",
    "get_clause_requirements",
    "get_all_control_ids",
    "get_annex_a_controls",
    "get_isms_requirements",
    "get_catalog_statistics",
    "get_catalog_metadata",
    "search_controls",
    "get_controls_by_automation_status",
    "get_controls_by_type",
    # NIST 800-53 mapping classes
    "MappingStrength",
    "ControlMapping",
    "ISO27001MappingSummary",
    # NIST mapping constants
    "NIST_CONTROL_FAMILIES",
    "STRONG_MAPPINGS",
    "PARTIAL_MAPPINGS",
    "ISO_UNIQUE_CONTROLS",
    # Bidirectional mapping functions
    "get_iso_to_nist_mappings",
    "get_nist_to_iso_mappings",
    "get_nist_controls_for_iso",
    "get_iso_controls_for_nist",
    "get_mapping_strength",
    # Mapping analysis functions
    "get_mapping_summary",
    "get_unmapped_iso_controls",
    "get_unmapped_nist_families",
    "get_mapping_coverage_by_domain",
    "get_nist_family_coverage",
    # Mapping export functions
    "export_mapping_matrix",
    "export_reverse_mapping_matrix",
    "get_mapping_statistics",
    # Check inheritance classes
    "InheritedCheck",
    "CheckCoverageReport",
    # Check inheritance functions
    "get_soc2_checks_by_nist",
    "get_inherited_checks_for_iso_control",
    "get_all_inherited_checks",
    # Coverage analysis
    "get_check_coverage_report",
    "get_controls_needing_checks",
    "get_controls_with_full_coverage",
    "get_coverage_by_domain",
    # Check retrieval
    "get_iso27001_checks_for_control",
    "get_all_iso27001_checks",
    # Check statistics
    "get_check_statistics",
    "get_inheritance_summary",
    # Report enums (reports.py)
    "ApplicabilityStatus",
    "ImplementationStatus",
    "RiskTreatmentOption",
    "AuditFindingType",
    "AuditFindingStatus",
    # Statement of Applicability
    "SoAControlEntry",
    "StatementOfApplicability",
    "generate_soa_template",
    # Risk treatment
    "RiskTreatmentEntry",
    "RiskTreatmentPlan",
    "generate_risk_treatment_template",
    # Internal audit
    "AuditFinding",
    "InternalAuditReport",
    "generate_internal_audit_template",
    # Management review
    "ManagementReviewMinutes",
    "generate_management_review_template",
    # Report export functions
    "export_soa_to_json",
    "export_soa_to_markdown",
    "export_audit_report_to_json",
    "get_report_statistics",
    # Certification audit enums (certification.py)
    "AuditStage",
    "NonconformityGrade",
    "CorrectiveActionStatus",
    "EvidenceType",
    "DocumentStatus",
    # Stage 1 documentation
    "ISMSDocument",
    "Stage1DocumentationPackage",
    "MANDATORY_DOCUMENTS",
    "generate_stage1_package",
    # Stage 2 evidence collection
    "AuditEvidence",
    "ControlEvidenceRequirement",
    "Stage2EvidenceWorkflow",
    "DOMAIN_EVIDENCE_GUIDANCE",
    "generate_stage2_workflow",
    # Nonconformity tracking
    "Nonconformity",
    "CorrectiveActionPlan",
    "create_corrective_action_plan",
    "create_nonconformity",
    # Certification export functions
    "export_stage1_package",
    "export_stage2_workflow",
    "export_corrective_action_plan",
    "export_nonconformity_summary_markdown",
    "get_certification_statistics",
]
