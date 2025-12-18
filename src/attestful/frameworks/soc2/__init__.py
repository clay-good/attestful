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
]
