"""
OSCAL (Open Security Controls Assessment Language) implementation.

This module provides Pydantic models and utilities for working with OSCAL
documents including catalogs, profiles, components, SSPs, and assessments.
"""

from attestful.oscal.models import (
    # Common
    OSCALDocument,
    Metadata,
    Property,
    Link,
    ResponsibleParty,
    Party,
    Role,
    BackMatter,
    Resource,
    # Catalog
    Catalog,
    Group,
    Control,
    Parameter,
    Part,
    # Profile
    Profile,
    Import,
    Merge,
    Modify,
    # Component
    ComponentDefinition,
    Component,
    ControlImplementation,
    ImplementedRequirement,
    # SSP
    SystemSecurityPlan,
    SystemCharacteristics,
    SystemImplementation,
    SSPControlImplementation,
    SSPImplementedRequirement,
    SystemComponent,
    SystemUser,
    SystemId,
    SystemStatus,
    ImportProfile,
    AuthorizationBoundary,
    ByComponent,
    # Assessment
    AssessmentResults,
    Result,
    Finding,
    Observation,
)
from attestful.oscal.ssp import (
    SSPGenerator,
    SSPLoader,
    SystemConfig,
    ComponentConfig,
    UserConfig,
    create_ssp_from_scan_results,
)
from attestful.oscal.assessment import (
    AssessmentResultsGenerator,
    AssessmentResultsLoader,
    AssessmentConfig,
    create_assessment_from_scan,
    get_assessment_summary,
)

__all__ = [
    # Common
    "OSCALDocument",
    "Metadata",
    "Property",
    "Link",
    "ResponsibleParty",
    "Party",
    "Role",
    "BackMatter",
    "Resource",
    # Catalog
    "Catalog",
    "Group",
    "Control",
    "Parameter",
    "Part",
    # Profile
    "Profile",
    "Import",
    "Merge",
    "Modify",
    # Component
    "ComponentDefinition",
    "Component",
    "ControlImplementation",
    "ImplementedRequirement",
    # SSP
    "SystemSecurityPlan",
    "SystemCharacteristics",
    "SystemImplementation",
    "SSPControlImplementation",
    "SSPImplementedRequirement",
    "SystemComponent",
    "SystemUser",
    "SystemId",
    "SystemStatus",
    "ImportProfile",
    "AuthorizationBoundary",
    "ByComponent",
    # SSP Generator
    "SSPGenerator",
    "SSPLoader",
    "SystemConfig",
    "ComponentConfig",
    "UserConfig",
    "create_ssp_from_scan_results",
    # Assessment
    "AssessmentResults",
    "Result",
    "Finding",
    "Observation",
    # Assessment Generator
    "AssessmentResultsGenerator",
    "AssessmentResultsLoader",
    "AssessmentConfig",
    "create_assessment_from_scan",
    "get_assessment_summary",
]
