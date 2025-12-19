"""
SOC 2 Type II compliance framework implementation.

Provides Trust Services Criteria control definitions, automated checks,
and OSCAL conversion for SOC 2 Type II assessments.

Key components:
- Trust Services Criteria control definitions (CC, A, PI, C, P)
- Automated compliance checks for AWS, Azure, GCP, Kubernetes
- OSCAL catalog generation
- Evidence collection mappings
- Audit reporting templates

Trust Services Categories:
- Security (Common Criteria CC1-CC9) - Mandatory
- Availability (A1) - Optional
- Processing Integrity (PI1) - Optional
- Confidentiality (C1) - Optional
- Privacy (P1-P8) - Optional
"""

from attestful.frameworks.soc2.controls import (
    SOC2_FRAMEWORK_ID,
    SOC2_VERSION,
    SOC2Control,
    SOC2Framework,
    SOC2_CONTROLS,
    TSC_SECURITY,
    TSC_AVAILABILITY,
    TSC_PROCESSING_INTEGRITY,
    TSC_CONFIDENTIALITY,
    TSC_PRIVACY,
    CC6_LOGICAL_PHYSICAL_ACCESS,
    CC7_SYSTEM_OPERATIONS,
    CC8_CHANGE_MANAGEMENT,
    CC9_RISK_MITIGATION,
    get_control,
    get_controls_by_category,
    get_all_controls,
    get_all_categories,
)
from attestful.frameworks.soc2.checks import (
    get_soc2_aws_checks,
    get_soc2_azure_checks,
    get_soc2_gcp_checks,
    create_soc2_evaluator,
    get_soc2_framework,
    get_check_statistics,
)
from attestful.frameworks.soc2.oscal_catalog import (
    SOC2_OSCAL_CATALOG_PATH,
    SOC2_CATALOG_SHA256,
    TSC_CATEGORIES,
    CC_GROUPS,
    get_catalog_path,
    verify_catalog_integrity,
    load_soc2_catalog,
    get_soc2_catalog_index,
    get_oscal_criterion,
    get_criterion_statement,
    get_criterion_points_of_focus,
    get_criterion_automation_status,
    get_category_criteria,
    get_group_criteria,
    get_all_criteria_ids,
    get_mandatory_criteria,
    get_optional_categories,
    get_catalog_statistics,
    get_catalog_metadata,
    search_criteria,
)
from attestful.frameworks.soc2.oscal_components import (
    ImplementedRequirement,
    ComponentDefinition,
    convert_check_to_requirement,
    generate_soc2_component_definition,
    export_component_to_json,
    get_implemented_requirements_by_control,
    get_component_statistics,
    get_control_coverage,
)
from attestful.frameworks.soc2.evidence_mappings import (
    EvidenceRequirement,
    EvidenceFrequency,
    EvidenceSource,
    SOC2EvidenceMapping,
    CC1_EVIDENCE_MAPPINGS,
    CC2_EVIDENCE_MAPPINGS,
    CC3_EVIDENCE_MAPPINGS,
    CC4_EVIDENCE_MAPPINGS,
    CC5_EVIDENCE_MAPPINGS,
    ALL_MANUAL_CONTROL_MAPPINGS,
    MAPPING_INDEX,
    get_evidence_mapping,
    get_mappings_by_category,
    get_required_evidence_types,
    get_platforms_for_criterion,
    get_evidence_collection_schedule,
    get_manual_control_statistics,
)
from attestful.frameworks.soc2.reports import (
    TestResult,
    ControlStatus,
    ControlTestResult,
    ManagementAssertion,
    SystemDescription,
    TestResultsSummary,
    SOC2EvidencePackage,
    generate_control_matrix,
    generate_testing_procedures,
    generate_evidence_package,
    export_evidence_package,
    get_report_statistics,
)

__all__ = [
    # Framework constants
    "SOC2_FRAMEWORK_ID",
    "SOC2_VERSION",
    # Control classes
    "SOC2Control",
    "SOC2Framework",
    "SOC2_CONTROLS",
    # Trust Services Categories
    "TSC_SECURITY",
    "TSC_AVAILABILITY",
    "TSC_PROCESSING_INTEGRITY",
    "TSC_CONFIDENTIALITY",
    "TSC_PRIVACY",
    # Common Criteria Groups
    "CC6_LOGICAL_PHYSICAL_ACCESS",
    "CC7_SYSTEM_OPERATIONS",
    "CC8_CHANGE_MANAGEMENT",
    "CC9_RISK_MITIGATION",
    # Control lookup functions
    "get_control",
    "get_controls_by_category",
    "get_all_controls",
    "get_all_categories",
    # Checks and evaluator
    "get_soc2_aws_checks",
    "get_soc2_azure_checks",
    "get_soc2_gcp_checks",
    "create_soc2_evaluator",
    "get_soc2_framework",
    # Statistics
    "get_check_statistics",
    # OSCAL catalog constants
    "SOC2_OSCAL_CATALOG_PATH",
    "SOC2_CATALOG_SHA256",
    "TSC_CATEGORIES",
    "CC_GROUPS",
    # OSCAL catalog functions
    "get_catalog_path",
    "verify_catalog_integrity",
    "load_soc2_catalog",
    "get_soc2_catalog_index",
    "get_oscal_criterion",
    "get_criterion_statement",
    "get_criterion_points_of_focus",
    "get_criterion_automation_status",
    "get_category_criteria",
    "get_group_criteria",
    "get_all_criteria_ids",
    "get_mandatory_criteria",
    "get_optional_categories",
    "get_catalog_statistics",
    "get_catalog_metadata",
    "search_criteria",
    # OSCAL component definitions
    "ImplementedRequirement",
    "ComponentDefinition",
    "convert_check_to_requirement",
    "generate_soc2_component_definition",
    "export_component_to_json",
    "get_implemented_requirements_by_control",
    "get_component_statistics",
    "get_control_coverage",
    # Evidence mappings (CC1-CC5 manual controls)
    "EvidenceRequirement",
    "EvidenceFrequency",
    "EvidenceSource",
    "SOC2EvidenceMapping",
    "CC1_EVIDENCE_MAPPINGS",
    "CC2_EVIDENCE_MAPPINGS",
    "CC3_EVIDENCE_MAPPINGS",
    "CC4_EVIDENCE_MAPPINGS",
    "CC5_EVIDENCE_MAPPINGS",
    "ALL_MANUAL_CONTROL_MAPPINGS",
    "MAPPING_INDEX",
    "get_evidence_mapping",
    "get_mappings_by_category",
    "get_required_evidence_types",
    "get_platforms_for_criterion",
    "get_evidence_collection_schedule",
    "get_manual_control_statistics",
    # SOC 2 reporting templates
    "TestResult",
    "ControlStatus",
    "ControlTestResult",
    "ManagementAssertion",
    "SystemDescription",
    "TestResultsSummary",
    "SOC2EvidencePackage",
    "generate_control_matrix",
    "generate_testing_procedures",
    "generate_evidence_package",
    "export_evidence_package",
    "get_report_statistics",
]
