"""
Core module - Base classes, exceptions, logging, and utilities.
"""

from attestful.core.exceptions import (
    AttestfulError,
    CatalogError,
    CollectionError,
    ConfigurationError,
    EvaluationError,
    MigrationError,
    ProfileError,
    StorageError,
    ValidationError,
)
from attestful.core.logging import get_logger, setup_logging
from attestful.core.models import Resource, Evidence, CollectionResult, CheckResult, ComplianceCheck
from attestful.core.evaluator import (
    Evaluator,
    CheckDefinition,
    Condition,
    ConditionGroup,
    Operator,
    create_default_evaluator,
)

__all__ = [
    # Exceptions
    "AttestfulError",
    "CatalogError",
    "CollectionError",
    "ConfigurationError",
    "EvaluationError",
    "MigrationError",
    "ProfileError",
    "StorageError",
    "ValidationError",
    # Logging
    "get_logger",
    "setup_logging",
    # Models
    "Resource",
    "Evidence",
    "CollectionResult",
    "CheckResult",
    "ComplianceCheck",
    # Evaluator
    "Evaluator",
    "CheckDefinition",
    "Condition",
    "ConditionGroup",
    "Operator",
    "create_default_evaluator",
]
