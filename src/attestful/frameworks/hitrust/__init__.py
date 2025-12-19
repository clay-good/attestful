"""
HITRUST CSF compliance framework implementation.

Provides HITRUST Common Security Framework (CSF) control definitions,
automated checks, and OSCAL conversion for HITRUST assessments.

Key components:
- HITRUST CSF control definitions (14 categories)
- OSCAL catalog with control requirements
- Automated compliance checks for cloud platforms
- Cross-framework mappings to NIST 800-53, ISO 27001, HIPAA, PCI DSS
- 5-level maturity model implementation
- MyCSF integration support

HITRUST CSF Control Categories:
- 00: Information Security Management Program
- 01: Access Control
- 02: Human Resources Security
- 03: Risk Management
- 04: Security Policy
- 05: Organization of Information Security
- 06: Compliance
- 07: Asset Management
- 08: Physical and Environmental Security
- 09: Communications and Operations Management
- 10: Information Systems Acquisition, Development, and Maintenance
- 11: Information Security Incident Management
- 12: Business Continuity Management
- 13: Privacy Practices

HITRUST Maturity Levels:
- Level 1 (Policy): Policy exists
- Level 2 (Procedure): Procedure exists and is implemented
- Level 3 (Implemented): Control is implemented
- Level 4 (Measured): Control is measured
- Level 5 (Managed): Control is managed and optimized
"""

from attestful.frameworks.hitrust.controls import (
    HITRUST_FRAMEWORK_ID,
    HITRUST_VERSION,
    # Category constants
    CATEGORY_ISMP,
    CATEGORY_ACCESS_CONTROL,
    CATEGORY_HR_SECURITY,
    CATEGORY_RISK_MANAGEMENT,
    CATEGORY_SECURITY_POLICY,
    CATEGORY_ORG_SECURITY,
    CATEGORY_COMPLIANCE,
    CATEGORY_ASSET_MGMT,
    CATEGORY_PHYSICAL,
    CATEGORY_OPERATIONS,
    CATEGORY_SDLC,
    CATEGORY_INCIDENT,
    CATEGORY_BCM,
    CATEGORY_PRIVACY,
    CATEGORY_NAMES,
    # Maturity constants
    MATURITY_POLICY,
    MATURITY_PROCEDURE,
    MATURITY_IMPLEMENTED,
    MATURITY_MEASURED,
    MATURITY_MANAGED,
    MATURITY_LEVEL_NAMES,
    # Data classes
    HITRUSTControl,
    HITRUSTFramework,
    # Control definitions
    HITRUST_CONTROLS,
    # Lookup functions
    get_control,
    get_controls_by_category,
    get_all_controls,
    get_all_categories,
    get_control_count_by_category,
    get_controls_by_nist_mapping,
    get_controls_by_iso_mapping,
    get_controls_by_hipaa_mapping,
    get_controls_by_maturity_level,
    get_control_statistics,
)
from attestful.frameworks.hitrust.oscal_catalog import (
    HITRUST_OSCAL_CATALOG_PATH,
    HITRUST_CATALOG_SHA256,
    CONTROL_CATEGORIES,
    MATURITY_LEVELS,
    CONTROL_TYPES,
    get_catalog_path,
    verify_catalog_integrity,
    load_hitrust_catalog,
    get_hitrust_catalog_index,
    get_oscal_control,
    get_control_statement,
    get_control_guidance,
    get_control_automation_status,
    get_control_maturity_level,
    get_control_type,
    get_category_controls,
    get_all_control_ids,
    get_controls_by_maturity,
    get_catalog_statistics,
    get_catalog_metadata,
    search_controls,
    get_controls_by_automation_status,
    get_controls_by_type,
)
from attestful.frameworks.hitrust.framework_mappings import (
    MappingStrength,
    FrameworkType,
    FrameworkMapping,
    HITRUSTMappingSummary,
    NIST_CONTROL_FAMILIES,
    HIPAA_REQUIREMENTS,
    PCI_DSS_REQUIREMENTS,
    HITRUST_TO_NIST_STRONG,
    HITRUST_TO_ISO_STRONG,
    get_nist_controls_for_hitrust,
    get_iso_controls_for_hitrust,
    get_hipaa_requirements_for_hitrust,
    get_pci_requirements_for_hitrust,
    get_all_mappings_for_hitrust,
    get_hitrust_controls_for_nist,
    get_hitrust_controls_for_iso,
    get_hitrust_controls_for_hipaa,
    get_hitrust_controls_for_pci,
    get_mapping_coverage_by_category,
    get_unmapped_hitrust_controls,
    get_nist_family_coverage,
    export_mapping_matrix,
    get_mapping_statistics,
)
from attestful.frameworks.hitrust.checks import (
    InheritedCheck,
    CheckCoverageReport,
    get_soc2_checks_by_nist,
    get_iso27001_checks_by_control,
    get_checks_via_nist_bridge,
    get_checks_via_iso_bridge,
    get_inherited_checks_for_hitrust_control,
    get_all_inherited_checks,
    get_check_coverage_report,
    get_controls_needing_checks,
    get_controls_with_full_coverage,
    get_coverage_by_category,
    get_coverage_by_maturity_level,
    get_hitrust_checks_for_control,
    get_all_hitrust_checks,
    get_checks_by_category,
    get_check_statistics,
    get_inheritance_summary,
    export_coverage_matrix,
)
from attestful.frameworks.hitrust.maturity import (
    HITRUSTCertificationType,
    MaturityEntityType,
    CERTIFICATION_REQUIREMENTS,
    LEVEL_EVIDENCE_REQUIREMENTS,
    HITRUSTMaturityConfig,
    HITRUSTControlScore,
    HITRUSTCategoryScore,
    HITRUSTMaturityBreakdown,
    CertificationGapAnalysis,
    ControlEvidenceInput,
    HITRUSTMaturityCalculator,
)
from attestful.frameworks.hitrust.mycsf import (
    MyCSFAssessmentType,
    MyCSFControlStatus,
    MyCSFEvidenceType,
    MyCSFControlExport,
    MyCSFAssessmentExport,
    MyCSFEvidenceMapping,
    MyCSFImportResult,
    MYCSF_STATUS_FROM_LEVEL,
    MYCSF_MATURITY_LABELS,
    EVIDENCE_TYPE_MAPPING,
    export_to_mycsf_format,
    export_to_mycsf_json,
    export_to_mycsf_csv,
    parse_mycsf_import,
    import_from_mycsf_file,
    map_evidence_to_mycsf,
    generate_evidence_manifest,
    sync_gaps_to_mycsf,
    get_mycsf_api_template,
    validate_mycsf_export,
)

__all__ = [
    # Framework constants
    "HITRUST_FRAMEWORK_ID",
    "HITRUST_VERSION",
    # Category constants
    "CATEGORY_ISMP",
    "CATEGORY_ACCESS_CONTROL",
    "CATEGORY_HR_SECURITY",
    "CATEGORY_RISK_MANAGEMENT",
    "CATEGORY_SECURITY_POLICY",
    "CATEGORY_ORG_SECURITY",
    "CATEGORY_COMPLIANCE",
    "CATEGORY_ASSET_MGMT",
    "CATEGORY_PHYSICAL",
    "CATEGORY_OPERATIONS",
    "CATEGORY_SDLC",
    "CATEGORY_INCIDENT",
    "CATEGORY_BCM",
    "CATEGORY_PRIVACY",
    "CATEGORY_NAMES",
    # Maturity constants
    "MATURITY_POLICY",
    "MATURITY_PROCEDURE",
    "MATURITY_IMPLEMENTED",
    "MATURITY_MEASURED",
    "MATURITY_MANAGED",
    "MATURITY_LEVEL_NAMES",
    # Data classes
    "HITRUSTControl",
    "HITRUSTFramework",
    # Control definitions
    "HITRUST_CONTROLS",
    # Lookup functions
    "get_control",
    "get_controls_by_category",
    "get_all_controls",
    "get_all_categories",
    "get_control_count_by_category",
    "get_controls_by_nist_mapping",
    "get_controls_by_iso_mapping",
    "get_controls_by_hipaa_mapping",
    "get_controls_by_maturity_level",
    "get_control_statistics",
    # OSCAL catalog constants
    "HITRUST_OSCAL_CATALOG_PATH",
    "HITRUST_CATALOG_SHA256",
    "CONTROL_CATEGORIES",
    "MATURITY_LEVELS",
    "CONTROL_TYPES",
    # OSCAL catalog functions
    "get_catalog_path",
    "verify_catalog_integrity",
    "load_hitrust_catalog",
    "get_hitrust_catalog_index",
    "get_oscal_control",
    "get_control_statement",
    "get_control_guidance",
    "get_control_automation_status",
    "get_control_maturity_level",
    "get_control_type",
    "get_category_controls",
    "get_all_control_ids",
    "get_controls_by_maturity",
    "get_catalog_statistics",
    "get_catalog_metadata",
    "search_controls",
    "get_controls_by_automation_status",
    "get_controls_by_type",
    # Framework mapping types
    "MappingStrength",
    "FrameworkType",
    "FrameworkMapping",
    "HITRUSTMappingSummary",
    # Framework mapping constants
    "NIST_CONTROL_FAMILIES",
    "HIPAA_REQUIREMENTS",
    "PCI_DSS_REQUIREMENTS",
    "HITRUST_TO_NIST_STRONG",
    "HITRUST_TO_ISO_STRONG",
    # Framework mapping functions
    "get_nist_controls_for_hitrust",
    "get_iso_controls_for_hitrust",
    "get_hipaa_requirements_for_hitrust",
    "get_pci_requirements_for_hitrust",
    "get_all_mappings_for_hitrust",
    "get_hitrust_controls_for_nist",
    "get_hitrust_controls_for_iso",
    "get_hitrust_controls_for_hipaa",
    "get_hitrust_controls_for_pci",
    "get_mapping_coverage_by_category",
    "get_unmapped_hitrust_controls",
    "get_nist_family_coverage",
    "export_mapping_matrix",
    "get_mapping_statistics",
    # Check inheritance data classes
    "InheritedCheck",
    "CheckCoverageReport",
    # Check lookup functions
    "get_soc2_checks_by_nist",
    "get_iso27001_checks_by_control",
    # Check inheritance functions
    "get_checks_via_nist_bridge",
    "get_checks_via_iso_bridge",
    "get_inherited_checks_for_hitrust_control",
    "get_all_inherited_checks",
    # Coverage analysis functions
    "get_check_coverage_report",
    "get_controls_needing_checks",
    "get_controls_with_full_coverage",
    "get_coverage_by_category",
    "get_coverage_by_maturity_level",
    # Check retrieval functions
    "get_hitrust_checks_for_control",
    "get_all_hitrust_checks",
    "get_checks_by_category",
    # Check statistics functions
    "get_check_statistics",
    "get_inheritance_summary",
    "export_coverage_matrix",
    # Maturity scoring enums
    "HITRUSTCertificationType",
    "MaturityEntityType",
    # Maturity scoring constants
    "CERTIFICATION_REQUIREMENTS",
    "LEVEL_EVIDENCE_REQUIREMENTS",
    # Maturity scoring configuration
    "HITRUSTMaturityConfig",
    # Maturity scoring data classes
    "HITRUSTControlScore",
    "HITRUSTCategoryScore",
    "HITRUSTMaturityBreakdown",
    "CertificationGapAnalysis",
    "ControlEvidenceInput",
    # Maturity calculator
    "HITRUSTMaturityCalculator",
    # MyCSF integration enums
    "MyCSFAssessmentType",
    "MyCSFControlStatus",
    "MyCSFEvidenceType",
    # MyCSF integration data classes
    "MyCSFControlExport",
    "MyCSFAssessmentExport",
    "MyCSFEvidenceMapping",
    "MyCSFImportResult",
    # MyCSF integration constants
    "MYCSF_STATUS_FROM_LEVEL",
    "MYCSF_MATURITY_LABELS",
    "EVIDENCE_TYPE_MAPPING",
    # MyCSF export functions
    "export_to_mycsf_format",
    "export_to_mycsf_json",
    "export_to_mycsf_csv",
    # MyCSF import functions
    "parse_mycsf_import",
    "import_from_mycsf_file",
    # MyCSF evidence functions
    "map_evidence_to_mycsf",
    "generate_evidence_manifest",
    # MyCSF gap sync
    "sync_gaps_to_mycsf",
    # MyCSF utilities
    "get_mycsf_api_template",
    "validate_mycsf_export",
]
