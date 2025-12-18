"""
NIST 800-53 Rev 5 and FedRAMP framework implementation.

Provides control definitions, automated checks, FedRAMP baselines,
and OSCAL conversion for NIST Special Publication 800-53.

Key components:
- Control definitions for 1000+ security and privacy controls
- FedRAMP Low, Moderate, and High baseline profiles
- Automated checks mapped to controls
- OSCAL catalog and profile generation
- Cross-framework mappings (CIS, SOC 2, ISO 27001)

Control Families:
- AC: Access Control
- AU: Audit and Accountability
- AT: Awareness and Training
- CM: Configuration Management
- CP: Contingency Planning
- IA: Identification and Authentication
- IR: Incident Response
- MA: Maintenance
- MP: Media Protection
- PE: Physical and Environmental Protection
- PL: Planning
- PM: Program Management
- PS: Personnel Security
- PT: PII Processing and Transparency
- RA: Risk Assessment
- SA: System and Services Acquisition
- SC: System and Communications Protection
- SI: System and Information Integrity
- SR: Supply Chain Risk Management
"""

from attestful.frameworks.nist_800_53.controls import (
    NIST_800_53_CONTROLS,
    NIST_800_53_FRAMEWORK_ID,
    NIST_800_53_VERSION,
    NIST80053Control,
    NIST80053Framework,
    FAMILY_AC,
    FAMILY_AU,
    FAMILY_AT,
    FAMILY_CM,
    FAMILY_CP,
    FAMILY_IA,
    FAMILY_IR,
    FAMILY_MA,
    FAMILY_MP,
    FAMILY_PE,
    FAMILY_PL,
    FAMILY_PM,
    FAMILY_PS,
    FAMILY_PT,
    FAMILY_RA,
    FAMILY_SA,
    FAMILY_SC,
    FAMILY_SI,
    FAMILY_SR,
    get_control,
    get_controls_by_family,
    get_all_controls,
    get_all_families,
)
from attestful.frameworks.nist_800_53.fedramp import (
    FEDRAMP_LOW,
    FEDRAMP_MODERATE,
    FEDRAMP_HIGH,
    FedRAMPBaseline,
    get_fedramp_baseline,
    get_fedramp_baseline_controls,
    get_fedramp_control_parameters,
)
from attestful.frameworks.nist_800_53.checks import (
    get_nist_800_53_aws_checks,
    get_nist_800_53_azure_checks,
    get_nist_800_53_gcp_checks,
    create_nist_800_53_evaluator,
    get_nist_800_53_framework,
)
from attestful.frameworks.nist_800_53.oscal_catalog import (
    NIST_800_53_OSCAL_CATALOG_PATH,
    NIST_800_53_CATALOG_SHA256,
    CONTROL_FAMILIES,
    get_catalog_path,
    verify_catalog_integrity,
    load_nist_800_53_catalog,
    get_nist_800_53_catalog_index,
    get_oscal_control,
    get_oscal_control_family,
    get_oscal_control_enhancements,
    search_oscal_controls,
    get_catalog_statistics,
)
from attestful.frameworks.nist_800_53.oscal_profiles import (
    FedRAMPImpactLevel,
    FEDRAMP_PROFILES_DIR,
    FEDRAMP_LOW_PROFILE_PATH,
    FEDRAMP_MODERATE_PROFILE_PATH,
    FEDRAMP_HIGH_PROFILE_PATH,
    get_fedramp_profile_path,
    verify_profile_integrity,
    load_fedramp_profile_raw,
    get_fedramp_profile_control_ids,
    get_fedramp_profile_metadata,
    get_fedramp_profile_set_parameters,
    compare_baselines,
    get_all_fedramp_statistics,
)
from attestful.frameworks.nist_800_53.cis_mappings import (
    CISMapping,
    CIS_AWS_TO_NIST_800_53,
    CIS_AZURE_TO_NIST_800_53,
    CIS_GCP_TO_NIST_800_53,
    get_cis_to_nist_mapping,
    get_nist_controls_for_cis,
    get_cis_checks_for_nist,
    get_all_mapped_nist_controls,
    get_mapping_statistics as get_cis_mapping_statistics,
)
from attestful.frameworks.nist_800_53.soc2_mappings import (
    SOC2Mapping,
    SOC2_CC_TO_NIST_800_53,
    SOC2_AVAILABILITY_TO_NIST_800_53,
    SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53,
    SOC2_CONFIDENTIALITY_TO_NIST_800_53,
    SOC2_PRIVACY_TO_NIST_800_53,
    get_all_soc2_mappings,
    get_soc2_to_nist_mapping,
    get_nist_controls_for_soc2,
    get_soc2_criteria_for_nist,
    get_all_mapped_nist_controls_from_soc2,
    get_soc2_mapping_statistics,
    get_soc2_category_coverage,
)
from attestful.frameworks.nist_800_53.fedramp_reports import (
    FedRAMPDocumentType,
    ControlStatus,
    POAMStatus,
    FindingSeverity,
    SystemInfo,
    SystemOwner,
    ControlImplementation,
    SSPTemplate,
    POAMItem,
    POAMTemplate,
    VulnerabilityScan,
    InventoryChange,
    SecurityEvent,
    ContinuousMonitoringReport,
    ImpactedControl,
    SignificantChangeRequest,
    create_ssp_template,
    create_poam_template,
    create_continuous_monitoring_report,
    create_significant_change_request,
    export_ssp_to_markdown,
    export_poam_to_markdown,
)

__all__ = [
    # Framework constants
    "NIST_800_53_CONTROLS",
    "NIST_800_53_FRAMEWORK_ID",
    "NIST_800_53_VERSION",
    # Control classes
    "NIST80053Control",
    "NIST80053Framework",
    # Control families
    "FAMILY_AC",
    "FAMILY_AU",
    "FAMILY_AT",
    "FAMILY_CM",
    "FAMILY_CP",
    "FAMILY_IA",
    "FAMILY_IR",
    "FAMILY_MA",
    "FAMILY_MP",
    "FAMILY_PE",
    "FAMILY_PL",
    "FAMILY_PM",
    "FAMILY_PS",
    "FAMILY_PT",
    "FAMILY_RA",
    "FAMILY_SA",
    "FAMILY_SC",
    "FAMILY_SI",
    "FAMILY_SR",
    # Control lookup functions
    "get_control",
    "get_controls_by_family",
    "get_all_controls",
    "get_all_families",
    # FedRAMP baselines
    "FEDRAMP_LOW",
    "FEDRAMP_MODERATE",
    "FEDRAMP_HIGH",
    "FedRAMPBaseline",
    "get_fedramp_baseline",
    "get_fedramp_baseline_controls",
    "get_fedramp_control_parameters",
    # Checks and evaluator
    "get_nist_800_53_aws_checks",
    "get_nist_800_53_azure_checks",
    "get_nist_800_53_gcp_checks",
    "create_nist_800_53_evaluator",
    "get_nist_800_53_framework",
    # OSCAL catalog
    "NIST_800_53_OSCAL_CATALOG_PATH",
    "NIST_800_53_CATALOG_SHA256",
    "CONTROL_FAMILIES",
    "get_catalog_path",
    "verify_catalog_integrity",
    "load_nist_800_53_catalog",
    "get_nist_800_53_catalog_index",
    "get_oscal_control",
    "get_oscal_control_family",
    "get_oscal_control_enhancements",
    "search_oscal_controls",
    "get_catalog_statistics",
    # OSCAL profiles (FedRAMP)
    "FedRAMPImpactLevel",
    "FEDRAMP_PROFILES_DIR",
    "FEDRAMP_LOW_PROFILE_PATH",
    "FEDRAMP_MODERATE_PROFILE_PATH",
    "FEDRAMP_HIGH_PROFILE_PATH",
    "get_fedramp_profile_path",
    "verify_profile_integrity",
    "load_fedramp_profile_raw",
    "get_fedramp_profile_control_ids",
    "get_fedramp_profile_metadata",
    "get_fedramp_profile_set_parameters",
    "compare_baselines",
    "get_all_fedramp_statistics",
    # CIS Benchmark mappings
    "CISMapping",
    "CIS_AWS_TO_NIST_800_53",
    "CIS_AZURE_TO_NIST_800_53",
    "CIS_GCP_TO_NIST_800_53",
    "get_cis_to_nist_mapping",
    "get_nist_controls_for_cis",
    "get_cis_checks_for_nist",
    "get_all_mapped_nist_controls",
    "get_cis_mapping_statistics",
    # SOC 2 mappings
    "SOC2Mapping",
    "SOC2_CC_TO_NIST_800_53",
    "SOC2_AVAILABILITY_TO_NIST_800_53",
    "SOC2_PROCESSING_INTEGRITY_TO_NIST_800_53",
    "SOC2_CONFIDENTIALITY_TO_NIST_800_53",
    "SOC2_PRIVACY_TO_NIST_800_53",
    "get_all_soc2_mappings",
    "get_soc2_to_nist_mapping",
    "get_nist_controls_for_soc2",
    "get_soc2_criteria_for_nist",
    "get_all_mapped_nist_controls_from_soc2",
    "get_soc2_mapping_statistics",
    "get_soc2_category_coverage",
    # FedRAMP reporting templates
    "FedRAMPDocumentType",
    "ControlStatus",
    "POAMStatus",
    "FindingSeverity",
    "SystemInfo",
    "SystemOwner",
    "ControlImplementation",
    "SSPTemplate",
    "POAMItem",
    "POAMTemplate",
    "VulnerabilityScan",
    "InventoryChange",
    "SecurityEvent",
    "ContinuousMonitoringReport",
    "ImpactedControl",
    "SignificantChangeRequest",
    "create_ssp_template",
    "create_poam_template",
    "create_continuous_monitoring_report",
    "create_significant_change_request",
    "export_ssp_to_markdown",
    "export_poam_to_markdown",
]
