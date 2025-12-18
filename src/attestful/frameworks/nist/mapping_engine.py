"""
NIST CSF 2.0 evidence mapping engine.

This module provides deterministic logic for mapping collected evidence
to NIST CSF 2.0 controls. All mapping decisions are auditable and
traceable - no machine learning or probabilistic inference is used.

Mapping Process:
    1. Load mapping configuration from data/control_evidence_mappings.json
    2. For each control, check if required evidence types are present
    3. Calculate confidence based on evidence freshness and completeness
    4. Generate human-readable explanations for all decisions

Mapping Logic Types:
    - all_required: All required evidence types must be present
    - any_required: At least one required evidence type must be present
    - weighted: Configurable weights per evidence type (partial satisfaction)

Freshness Calculation:
    - Evidence within freshness_days: Full confidence
    - Evidence between 1x and 2x freshness_days: Reduced confidence (linear decay)
    - Evidence older than 2x freshness_days: Considered stale (minimal confidence)
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from attestful.frameworks.nist.csf2_controls import get_all_subcategories, get_subcategory


class EvidenceLike(Protocol):
    """Protocol for evidence-like objects (Evidence or StoredEvidence)."""

    @property
    def id(self) -> str: ...
    @property
    def evidence_type(self) -> str: ...
    @property
    def collected_at(self) -> datetime: ...

logger = logging.getLogger(__name__)


class MappingStatus(str, Enum):
    """Status of a control mapping."""

    SATISFIED = "satisfied"
    PARTIAL = "partial"
    UNSATISFIED = "unsatisfied"
    NOT_APPLICABLE = "not_applicable"


class MappingLogic(str, Enum):
    """Types of mapping logic."""

    ALL_REQUIRED = "all_required"
    ANY_REQUIRED = "any_required"
    WEIGHTED = "weighted"


@dataclass
class EvidenceMapping:
    """
    Configuration for how evidence maps to a control.

    Loaded from the mapping configuration file.

    Attributes:
        control_id: NIST control ID (e.g., "PR.AC-01").
        required_evidence_types: Evidence types that must be present.
        optional_evidence_types: Evidence types that improve confidence.
        platforms: Platforms that can provide this evidence.
        logic: How to combine evidence (all_required, any_required, weighted).
        freshness_days: Days before evidence is considered stale.
        weights: Per-evidence-type weights for weighted logic.
        description: Human-readable description of what satisfies this control.
    """

    control_id: str
    required_evidence_types: list[str]
    optional_evidence_types: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    logic: MappingLogic = MappingLogic.ALL_REQUIRED
    freshness_days: int = 30
    weights: dict[str, float] = field(default_factory=dict)
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceMapping:
        """Create from dictionary."""
        logic = data.get("logic", "all_required")
        if isinstance(logic, str):
            logic = MappingLogic(logic)

        return cls(
            control_id=data["control_id"],
            required_evidence_types=data.get("required_evidence_types", []),
            optional_evidence_types=data.get("optional_evidence_types", []),
            platforms=data.get("platforms", []),
            logic=logic,
            freshness_days=data.get("freshness_days", 30),
            weights=data.get("weights", {}),
            description=data.get("description", ""),
        )


@dataclass
class ControlMappingResult:
    """
    Result of mapping evidence to a control.

    Attributes:
        control_id: NIST control ID.
        status: Mapping status (satisfied, partial, unsatisfied, not_applicable).
        confidence: Confidence score (0.0 - 1.0).
        evidence_ids: IDs of evidence that contributed to this mapping.
        evidence_types_found: Evidence types that were found.
        evidence_types_missing: Required evidence types that were missing.
        last_evidence_date: Most recent evidence date.
        explanation: Human-readable explanation of the mapping decision.
        freshness_penalty: Confidence reduction due to stale evidence.
    """

    control_id: str
    status: MappingStatus
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    evidence_types_found: list[str] = field(default_factory=list)
    evidence_types_missing: list[str] = field(default_factory=list)
    last_evidence_date: datetime | None = None
    explanation: str = ""
    freshness_penalty: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "status": self.status.value,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "evidence_types_found": self.evidence_types_found,
            "evidence_types_missing": self.evidence_types_missing,
            "last_evidence_date": (
                self.last_evidence_date.isoformat()
                if self.last_evidence_date
                else None
            ),
            "explanation": self.explanation,
            "freshness_penalty": self.freshness_penalty,
        }


class MappingEngine:
    """
    Engine for mapping evidence to NIST CSF 2.0 controls.

    The mapping engine uses deterministic rules to determine which controls
    are satisfied by collected evidence. All decisions are logged and
    explainable.

    Example:
        engine = MappingEngine()

        # Map evidence to controls
        results = engine.map_evidence(evidence_items)

        # Get evidence for a specific control
        evidence = engine.get_evidence_for_control("PR.AC-01", evidence_items)

        # Get controls without evidence
        unmapped = engine.get_unmapped_controls(evidence_items)

        # Get explanation for a mapping
        explanation = engine.get_mapping_explanation("PR.AC-01", evidence_items)

    Attributes:
        mappings: Dictionary of control_id to EvidenceMapping.
        config_path: Path to the mapping configuration file.
    """

    def __init__(self, config_path: Path | str | None = None) -> None:
        """
        Initialize the mapping engine.

        Args:
            config_path: Path to mapping configuration file.
                Defaults to data/control_evidence_mappings.json
        """
        if config_path is None:
            # Look in package data directory
            package_dir = Path(__file__).parent.parent.parent.parent
            config_path = package_dir / "data" / "control_evidence_mappings.json"

        self.config_path = Path(config_path)
        self.mappings: dict[str, EvidenceMapping] = {}

        self._load_mappings()

    def _load_mappings(self) -> None:
        """Load mapping configuration from file."""
        if not self.config_path.exists():
            logger.warning(
                f"Mapping configuration not found at {self.config_path}. "
                "Using empty mappings."
            )
            return

        try:
            with open(self.config_path) as f:
                config = json.load(f)

            for mapping_data in config.get("mappings", []):
                mapping = EvidenceMapping.from_dict(mapping_data)
                self.mappings[mapping.control_id] = mapping

            logger.info(f"Loaded {len(self.mappings)} control mappings")

        except json.JSONDecodeError as e:
            logger.error(f"Invalid mapping configuration JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to load mapping configuration: {e}")

    def reload_mappings(self) -> None:
        """Reload mappings from configuration file."""
        self.mappings.clear()
        self._load_mappings()

    def map_evidence(
        self,
        evidence_items: Sequence[EvidenceLike],
        reference_time: datetime | None = None,
    ) -> list[ControlMappingResult]:
        """
        Map evidence items to NIST controls.

        Args:
            evidence_items: List of Evidence or StoredEvidence objects to map.
            reference_time: Time to use for freshness calculation.
                Defaults to current UTC time.

        Returns:
            List of ControlMappingResult for each configured control.
        """
        if reference_time is None:
            reference_time = datetime.now(UTC)

        # Index evidence by type for efficient lookup
        evidence_by_type: dict[str, list[EvidenceLike]] = {}
        for evidence in evidence_items:
            if evidence.evidence_type not in evidence_by_type:
                evidence_by_type[evidence.evidence_type] = []
            evidence_by_type[evidence.evidence_type].append(evidence)

        results = []
        for control_id, mapping in self.mappings.items():
            result = self._map_control(
                mapping, evidence_by_type, reference_time
            )
            results.append(result)
            logger.debug(
                f"Mapped {control_id}: {result.status.value} "
                f"(confidence: {result.confidence:.2f})"
            )

        return results

    # Alias for backward compatibility
    map_all_evidence = map_evidence

    def _map_control(
        self,
        mapping: EvidenceMapping,
        evidence_by_type: dict[str, list[EvidenceLike]],
        reference_time: datetime,
    ) -> ControlMappingResult:
        """
        Map evidence to a single control.

        Args:
            mapping: The control mapping configuration.
            evidence_by_type: Evidence indexed by type.
            reference_time: Reference time for freshness calculation.

        Returns:
            ControlMappingResult for this control.
        """
        control_id = mapping.control_id

        # Find evidence for this control
        found_evidence: list[EvidenceLike] = []
        found_types: list[str] = []
        missing_types: list[str] = []

        # Check required evidence types
        for evidence_type in mapping.required_evidence_types:
            type_evidence = evidence_by_type.get(evidence_type, [])
            if type_evidence:
                found_evidence.extend(type_evidence)
                found_types.append(evidence_type)
            else:
                missing_types.append(evidence_type)

        # Check optional evidence types
        optional_found: list[str] = []
        for evidence_type in mapping.optional_evidence_types:
            type_evidence = evidence_by_type.get(evidence_type, [])
            if type_evidence:
                found_evidence.extend(type_evidence)
                optional_found.append(evidence_type)

        # Determine status based on logic type
        if mapping.logic == MappingLogic.ALL_REQUIRED:
            status, base_confidence = self._evaluate_all_required(
                mapping, found_types, missing_types
            )
        elif mapping.logic == MappingLogic.ANY_REQUIRED:
            status, base_confidence = self._evaluate_any_required(
                mapping, found_types
            )
        elif mapping.logic == MappingLogic.WEIGHTED:
            status, base_confidence = self._evaluate_weighted(
                mapping, found_types, evidence_by_type
            )
        else:
            status = MappingStatus.UNSATISFIED
            base_confidence = 0.0

        # Calculate freshness penalty
        freshness_penalty = 0.0
        last_evidence_date = None

        if found_evidence:
            # Find most recent evidence
            dates = [e.collected_at for e in found_evidence if e.collected_at]
            if dates:
                last_evidence_date = max(dates)

                # Calculate freshness penalty
                age = reference_time - last_evidence_date
                freshness_threshold = timedelta(days=mapping.freshness_days)
                stale_threshold = timedelta(days=mapping.freshness_days * 2)

                if age > stale_threshold:
                    # Very stale - significant penalty
                    freshness_penalty = 0.5
                elif age > freshness_threshold:
                    # Somewhat stale - linear penalty
                    staleness_ratio = (age - freshness_threshold) / freshness_threshold
                    freshness_penalty = min(0.5, staleness_ratio * 0.5)

        # Apply freshness penalty
        final_confidence = max(0.0, base_confidence - freshness_penalty)

        # Boost confidence slightly for optional evidence
        if optional_found and final_confidence > 0:
            optional_boost = min(0.1, len(optional_found) * 0.03)
            final_confidence = min(1.0, final_confidence + optional_boost)

        # Generate explanation
        explanation = self._generate_explanation(
            mapping,
            status,
            found_types,
            missing_types,
            optional_found,
            freshness_penalty,
            last_evidence_date,
            reference_time,
        )

        return ControlMappingResult(
            control_id=control_id,
            status=status,
            confidence=round(final_confidence, 3),
            evidence_ids=[e.id for e in found_evidence],
            evidence_types_found=found_types + optional_found,
            evidence_types_missing=missing_types,
            last_evidence_date=last_evidence_date,
            explanation=explanation,
            freshness_penalty=round(freshness_penalty, 3),
        )

    def _evaluate_all_required(
        self,
        mapping: EvidenceMapping,
        found_types: list[str],
        missing_types: list[str],
    ) -> tuple[MappingStatus, float]:
        """
        Evaluate using all_required logic.

        All required evidence types must be present for satisfaction.

        Returns:
            Tuple of (status, base_confidence).
        """
        if not mapping.required_evidence_types:
            return MappingStatus.NOT_APPLICABLE, 0.0

        if not missing_types:
            # All required evidence present
            return MappingStatus.SATISFIED, 1.0
        elif found_types:
            # Some required evidence present
            ratio = len(found_types) / len(mapping.required_evidence_types)
            return MappingStatus.PARTIAL, ratio * 0.7
        else:
            # No required evidence
            return MappingStatus.UNSATISFIED, 0.0

    def _evaluate_any_required(
        self,
        mapping: EvidenceMapping,
        found_types: list[str],
    ) -> tuple[MappingStatus, float]:
        """
        Evaluate using any_required logic.

        At least one required evidence type must be present.

        Returns:
            Tuple of (status, base_confidence).
        """
        if not mapping.required_evidence_types:
            return MappingStatus.NOT_APPLICABLE, 0.0

        if found_types:
            # At least one required evidence present
            ratio = len(found_types) / len(mapping.required_evidence_types)
            if ratio >= 0.5:
                return MappingStatus.SATISFIED, 0.8 + (ratio * 0.2)
            else:
                return MappingStatus.PARTIAL, 0.5 + (ratio * 0.3)
        else:
            return MappingStatus.UNSATISFIED, 0.0

    def _evaluate_weighted(
        self,
        mapping: EvidenceMapping,
        found_types: list[str],
        evidence_by_type: dict[str, list[EvidenceLike]],
    ) -> tuple[MappingStatus, float]:
        """
        Evaluate using weighted logic.

        Each evidence type has a configurable weight.

        Returns:
            Tuple of (status, base_confidence).
        """
        if not mapping.required_evidence_types:
            return MappingStatus.NOT_APPLICABLE, 0.0

        # Calculate total possible weight
        total_weight = 0.0
        achieved_weight = 0.0

        for evidence_type in mapping.required_evidence_types:
            weight = mapping.weights.get(evidence_type, 1.0)
            total_weight += weight
            if evidence_type in found_types:
                achieved_weight += weight

        if total_weight == 0:
            return MappingStatus.NOT_APPLICABLE, 0.0

        ratio = achieved_weight / total_weight

        if ratio >= 0.9:
            return MappingStatus.SATISFIED, ratio
        elif ratio >= 0.5:
            return MappingStatus.PARTIAL, ratio * 0.9
        elif ratio > 0:
            return MappingStatus.PARTIAL, ratio * 0.7
        else:
            return MappingStatus.UNSATISFIED, 0.0

    def _generate_explanation(
        self,
        mapping: EvidenceMapping,
        status: MappingStatus,
        found_types: list[str],
        missing_types: list[str],
        optional_found: list[str],
        freshness_penalty: float,
        last_evidence_date: datetime | None,
        reference_time: datetime,
    ) -> str:
        """Generate a human-readable explanation for the mapping decision."""
        parts = []

        # Status summary
        control = get_subcategory(mapping.control_id)
        control_name = control.name if control else mapping.control_id

        if status == MappingStatus.SATISFIED:
            parts.append(f"Control {mapping.control_id} ({control_name}) is SATISFIED.")
        elif status == MappingStatus.PARTIAL:
            parts.append(
                f"Control {mapping.control_id} ({control_name}) is PARTIALLY satisfied."
            )
        elif status == MappingStatus.NOT_APPLICABLE:
            parts.append(
                f"Control {mapping.control_id} ({control_name}) has no mapping configuration."
            )
        else:
            parts.append(
                f"Control {mapping.control_id} ({control_name}) is NOT satisfied."
            )

        # Evidence details
        if found_types:
            parts.append(f"Found evidence: {', '.join(found_types)}.")
        if missing_types:
            parts.append(f"Missing evidence: {', '.join(missing_types)}.")
        if optional_found:
            parts.append(f"Optional evidence found: {', '.join(optional_found)}.")

        # Freshness
        if last_evidence_date:
            age_days = (reference_time - last_evidence_date).days
            if freshness_penalty > 0:
                parts.append(
                    f"Evidence is {age_days} days old "
                    f"(threshold: {mapping.freshness_days} days). "
                    f"Confidence reduced by {freshness_penalty:.0%}."
                )
            else:
                parts.append(f"Evidence is {age_days} days old (fresh).")

        # Logic explanation
        if mapping.logic == MappingLogic.ALL_REQUIRED:
            parts.append(
                f"Logic: All {len(mapping.required_evidence_types)} "
                "required evidence types must be present."
            )
        elif mapping.logic == MappingLogic.ANY_REQUIRED:
            parts.append(
                f"Logic: At least one of {len(mapping.required_evidence_types)} "
                "required evidence types must be present."
            )
        elif mapping.logic == MappingLogic.WEIGHTED:
            parts.append("Logic: Weighted scoring based on evidence type importance.")

        return " ".join(parts)

    def get_evidence_for_control(
        self,
        control_id: str,
        evidence_items: Sequence[EvidenceLike],
    ) -> list[EvidenceLike]:
        """
        Get evidence items that map to a specific control.

        Args:
            control_id: NIST control ID.
            evidence_items: List of Evidence or StoredEvidence objects.

        Returns:
            List of evidence objects that map to this control.
        """
        mapping = self.mappings.get(control_id)
        if not mapping:
            return []

        all_types = set(mapping.required_evidence_types + mapping.optional_evidence_types)

        return [e for e in evidence_items if e.evidence_type in all_types]

    def get_unmapped_controls(
        self,
        evidence_items: Sequence[EvidenceLike],
    ) -> list[str]:
        """
        Get controls that have no evidence.

        Args:
            evidence_items: List of Evidence or StoredEvidence objects.

        Returns:
            List of control IDs with no mapped evidence.
        """
        evidence_types = {e.evidence_type for e in evidence_items}
        unmapped = []

        for control_id, mapping in self.mappings.items():
            required_types = set(mapping.required_evidence_types)
            if not required_types.intersection(evidence_types):
                unmapped.append(control_id)

        return unmapped

    def get_controls_without_mapping(self) -> list[str]:
        """
        Get all NIST subcategories that have no mapping configuration.

        Returns:
            List of control IDs without mapping configuration.
        """
        all_subcategories = get_all_subcategories()
        configured_controls = set(self.mappings.keys())

        return [s.id for s in all_subcategories if s.id not in configured_controls]

    def get_mapping_explanation(
        self,
        control_id: str,
        evidence_items: Sequence[EvidenceLike],
        reference_time: datetime | None = None,
    ) -> str:
        """
        Get a detailed explanation for a control mapping.

        Args:
            control_id: NIST control ID.
            evidence_items: List of Evidence or StoredEvidence objects.
            reference_time: Reference time for freshness calculation.

        Returns:
            Human-readable explanation string.
        """
        if reference_time is None:
            reference_time = datetime.now(UTC)

        mapping = self.mappings.get(control_id)
        if not mapping:
            control = get_subcategory(control_id)
            if control:
                return (
                    f"Control {control_id} ({control.name}) has no mapping configuration. "
                    "This control requires manual evidence collection."
                )
            return f"Control {control_id} is not a valid NIST CSF 2.0 subcategory."

        # Index evidence
        evidence_by_type: dict[str, list[EvidenceLike]] = {}
        for evidence in evidence_items:
            if evidence.evidence_type not in evidence_by_type:
                evidence_by_type[evidence.evidence_type] = []
            evidence_by_type[evidence.evidence_type].append(evidence)

        # Generate mapping result
        result = self._map_control(mapping, evidence_by_type, reference_time)

        return result.explanation

    def get_mapping_summary(self) -> dict[str, Any]:
        """
        Get a summary of the mapping configuration.

        Returns:
            Dictionary with mapping statistics.
        """
        all_subcategories = get_all_subcategories()

        # Count by status
        configured = len(self.mappings)
        unconfigured = len(all_subcategories) - configured

        # Group by function
        by_function: dict[str, dict[str, int]] = {}
        for control_id in self.mappings:
            function_id = control_id.split(".")[0]
            if function_id not in by_function:
                by_function[function_id] = {"configured": 0, "total": 0}
            by_function[function_id]["configured"] += 1

        for subcategory in all_subcategories:
            function_id = subcategory.id.split(".")[0]
            if function_id not in by_function:
                by_function[function_id] = {"configured": 0, "total": 0}
            by_function[function_id]["total"] += 1

        # Evidence types used
        all_evidence_types: set[str] = set()
        for mapping in self.mappings.values():
            all_evidence_types.update(mapping.required_evidence_types)
            all_evidence_types.update(mapping.optional_evidence_types)

        # Platforms used
        all_platforms: set[str] = set()
        for mapping in self.mappings.values():
            all_platforms.update(mapping.platforms)

        return {
            "total_subcategories": len(all_subcategories),
            "configured_mappings": configured,
            "unconfigured_mappings": unconfigured,
            "coverage_percent": round(configured / len(all_subcategories) * 100, 1),
            "by_function": by_function,
            "evidence_types_used": sorted(all_evidence_types),
            "platforms_used": sorted(all_platforms),
        }
