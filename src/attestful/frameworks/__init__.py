"""
Framework implementations for Attestful.

Provides framework-specific logic for NIST CSF 2.0, NIST 800-53,
FedRAMP, SOC 2, ISO 27001, and HITRUST.
"""

from attestful.frameworks.soc2 import (
    SOC2_CONTROLS,
    SOC2_FRAMEWORK_ID,
    SOC2_VERSION,
    SOC2Control,
    SOC2Framework,
    TSC_AVAILABILITY,
    TSC_CONFIDENTIALITY,
    TSC_PRIVACY,
    TSC_PROCESSING_INTEGRITY,
    TSC_SECURITY,
    create_soc2_evaluator,
    get_soc2_aws_checks,
    get_soc2_framework,
)

__all__ = [
    # SOC 2
    "SOC2_CONTROLS",
    "SOC2_FRAMEWORK_ID",
    "SOC2_VERSION",
    "SOC2Control",
    "SOC2Framework",
    "TSC_AVAILABILITY",
    "TSC_CONFIDENTIALITY",
    "TSC_PRIVACY",
    "TSC_PROCESSING_INTEGRITY",
    "TSC_SECURITY",
    "create_soc2_evaluator",
    "get_soc2_aws_checks",
    "get_soc2_framework",
]
