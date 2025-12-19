"""
NIST CSF 2.0 framework implementation.

Provides control definitions, evidence mapping, and maturity calculation
for the NIST Cybersecurity Framework 2.0.
"""

from attestful.frameworks.nist.csf2_controls import (
    MaturityCriteria,
    NistCategory,
    NistFunction,
    NistSubcategory,
    get_all_categories,
    get_all_functions,
    get_all_subcategories,
    get_category,
    get_function,
    get_subcategory,
)
from attestful.frameworks.nist.mapping_engine import (
    ControlMappingResult,
    EvidenceMapping,
    MappingEngine,
    MappingLogic,
    MappingStatus,
)
from attestful.frameworks.nist.maturity_calculator import (
    EntityType,
    MaturityBreakdown,
    MaturityCalculator,
    MaturityConfig,
    MaturityScore,
)
from attestful.frameworks.nist.oscal_converter import (
    EVIDENCE_PLATFORMS,
    NistCSF2ComponentGenerator,
    NistCSF2OSCALConverter,
    NistCSF2ProfileGenerator,
    create_nist_csf2_catalog,
    create_nist_csf2_component_definition,
    create_nist_csf2_profile,
    ensure_csf2_catalog_exists,
    ensure_csf2_components_exist,
    ensure_csf2_profiles_exist,
    get_csf2_catalog_path,
    get_csf2_component_path,
    get_csf2_profile_path,
    save_nist_csf2_catalog,
    save_nist_csf2_profile,
)

__all__ = [
    # Control definitions
    "MaturityCriteria",
    "NistCategory",
    "NistFunction",
    "NistSubcategory",
    "get_all_categories",
    "get_all_functions",
    "get_all_subcategories",
    "get_category",
    "get_function",
    "get_subcategory",
    # Mapping engine
    "ControlMappingResult",
    "EvidenceMapping",
    "MappingEngine",
    "MappingLogic",
    "MappingStatus",
    # Maturity calculator
    "EntityType",
    "MaturityBreakdown",
    "MaturityCalculator",
    "MaturityConfig",
    "MaturityScore",
    # OSCAL Converter
    "EVIDENCE_PLATFORMS",
    "NistCSF2ComponentGenerator",
    "NistCSF2OSCALConverter",
    "NistCSF2ProfileGenerator",
    "create_nist_csf2_catalog",
    "create_nist_csf2_component_definition",
    "create_nist_csf2_profile",
    "ensure_csf2_catalog_exists",
    "ensure_csf2_components_exist",
    "ensure_csf2_profiles_exist",
    "get_csf2_catalog_path",
    "get_csf2_component_path",
    "get_csf2_profile_path",
    "save_nist_csf2_catalog",
    "save_nist_csf2_profile",
]
