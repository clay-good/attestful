"""
Maturity calculator for compliance frameworks.

Implements NIST-style maturity scoring based on evidence quality,
automation level, and control implementation status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any

from attestful.core.logging import get_logger
from attestful.core.models import CheckResult, Evidence

logger = get_logger(__name__)


class MaturityLevel(IntEnum):
    """
    NIST-style maturity levels.

    Based on NIST Cybersecurity Framework Implementation Tiers
    and common maturity model conventions.
    """

    INITIAL = 1  # Ad-hoc, reactive
    DEVELOPING = 2  # Documented but inconsistent
    DEFINED = 3  # Standardized and consistent
    MANAGED = 4  # Measured and controlled
    OPTIMIZING = 5  # Continuous improvement

    @classmethod
    def from_score(cls, score: float) -> MaturityLevel:
        """Convert a numeric score (0-100) to maturity level."""
        if score >= 90:
            return cls.OPTIMIZING
        elif score >= 70:
            return cls.MANAGED
        elif score >= 50:
            return cls.DEFINED
        elif score >= 25:
            return cls.DEVELOPING
        else:
            return cls.INITIAL

    @property
    def description(self) -> str:
        """Get description for this maturity level."""
        descriptions = {
            MaturityLevel.INITIAL: "Ad-hoc processes with reactive risk management",
            MaturityLevel.DEVELOPING: "Documented processes but inconsistent implementation",
            MaturityLevel.DEFINED: "Standardized processes with organization-wide policies",
            MaturityLevel.MANAGED: "Quantitatively measured and actively managed",
            MaturityLevel.OPTIMIZING: "Continuous improvement with adaptive practices",
        }
        return descriptions[self]


@dataclass
class MaturityScore:
    """
    Maturity score for a single control or subcategory.

    Attributes:
        control_id: Control or subcategory identifier.
        score: Numeric score (0-100).
        level: Maturity level.
        evidence_count: Number of evidence items supporting this score.
        automation_rate: Percentage of automated evidence (0-100).
        last_assessed: When this was last assessed.
        details: Additional scoring details.
    """

    control_id: str
    score: float
    level: MaturityLevel
    evidence_count: int = 0
    automation_rate: float = 0.0
    last_assessed: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "control_id": self.control_id,
            "score": self.score,
            "level": self.level.name,
            "level_value": self.level.value,
            "evidence_count": self.evidence_count,
            "automation_rate": self.automation_rate,
            "last_assessed": self.last_assessed.isoformat(),
            "details": self.details,
        }


@dataclass
class CategoryScore:
    """
    Aggregated score for a category or function.

    Attributes:
        category_id: Category identifier (e.g., "GOVERN", "PROTECT").
        name: Category name.
        score: Average score across subcategories.
        level: Overall maturity level.
        subcategory_scores: Individual subcategory scores.
        control_count: Total controls in this category.
        implemented_count: Controls with score >= 50.
    """

    category_id: str
    name: str
    score: float
    level: MaturityLevel
    subcategory_scores: list[MaturityScore] = field(default_factory=list)
    control_count: int = 0
    implemented_count: int = 0

    @property
    def implementation_rate(self) -> float:
        """Percentage of controls implemented."""
        if self.control_count == 0:
            return 0.0
        return (self.implemented_count / self.control_count) * 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category_id": self.category_id,
            "name": self.name,
            "score": self.score,
            "level": self.level.name,
            "level_value": self.level.value,
            "control_count": self.control_count,
            "implemented_count": self.implemented_count,
            "implementation_rate": self.implementation_rate,
            "subcategory_scores": [s.to_dict() for s in self.subcategory_scores],
        }


@dataclass
class FrameworkMaturity:
    """
    Overall maturity assessment for a framework.

    Attributes:
        framework: Framework identifier.
        overall_score: Overall maturity score (0-100).
        overall_level: Overall maturity level.
        category_scores: Scores by category/function.
        total_controls: Total controls assessed.
        assessed_at: When this assessment was performed.
        metadata: Additional assessment metadata.
    """

    framework: str
    overall_score: float
    overall_level: MaturityLevel
    category_scores: list[CategoryScore] = field(default_factory=list)
    total_controls: int = 0
    assessed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "overall_score": self.overall_score,
            "overall_level": self.overall_level.name,
            "overall_level_value": self.overall_level.value,
            "total_controls": self.total_controls,
            "assessed_at": self.assessed_at.isoformat(),
            "category_scores": [c.to_dict() for c in self.category_scores],
            "metadata": self.metadata,
        }


# NIST CSF 2.0 Function and Category definitions
NIST_CSF_2_STRUCTURE = {
    "GOVERN": {
        "name": "Govern",
        "description": "Establish and monitor cybersecurity risk management strategy",
        "categories": {
            "GV.OC": "Organizational Context",
            "GV.RM": "Risk Management Strategy",
            "GV.RR": "Roles, Responsibilities, and Authorities",
            "GV.PO": "Policy",
            "GV.OV": "Oversight",
            "GV.SC": "Cybersecurity Supply Chain Risk Management",
        },
    },
    "IDENTIFY": {
        "name": "Identify",
        "description": "Understand organizational assets, risks, and context",
        "categories": {
            "ID.AM": "Asset Management",
            "ID.RA": "Risk Assessment",
            "ID.IM": "Improvement",
        },
    },
    "PROTECT": {
        "name": "Protect",
        "description": "Implement safeguards to ensure delivery of services",
        "categories": {
            "PR.AA": "Identity Management, Authentication, and Access Control",
            "PR.AT": "Awareness and Training",
            "PR.DS": "Data Security",
            "PR.PS": "Platform Security",
            "PR.IR": "Technology Infrastructure Resilience",
        },
    },
    "DETECT": {
        "name": "Detect",
        "description": "Identify cybersecurity events in a timely manner",
        "categories": {
            "DE.CM": "Continuous Monitoring",
            "DE.AE": "Adverse Event Analysis",
        },
    },
    "RESPOND": {
        "name": "Respond",
        "description": "Take action regarding detected cybersecurity events",
        "categories": {
            "RS.MA": "Incident Management",
            "RS.AN": "Incident Analysis",
            "RS.CO": "Incident Response Reporting and Communication",
            "RS.MI": "Incident Mitigation",
        },
    },
    "RECOVER": {
        "name": "Recover",
        "description": "Restore capabilities impaired by cybersecurity events",
        "categories": {
            "RC.RP": "Incident Recovery Plan Execution",
            "RC.CO": "Incident Recovery Communication",
        },
    },
}

# Evidence type to NIST CSF category mappings
EVIDENCE_TO_CSF_MAPPING: dict[str, list[str]] = {
    # AWS evidence mappings
    "account_info": ["GV.OC", "ID.AM"],
    "iam_credential_report": ["PR.AA", "GV.RR"],
    "password_policy": ["PR.AA", "GV.PO"],
    "cloudtrail_status": ["DE.CM", "GV.OV"],
    "config_recorder_status": ["DE.CM", "ID.AM"],
    "guardduty_status": ["DE.CM", "DE.AE"],
    "security_hub_status": ["DE.CM", "GV.OV"],
    "access_analyzer_status": ["PR.AA", "DE.CM"],
    # Okta evidence mappings
    "okta_users": ["PR.AA", "ID.AM"],
    "okta_mfa_status": ["PR.AA"],
    "okta_password_policy": ["PR.AA", "GV.PO"],
    "okta_system_log": ["DE.CM", "RS.AN"],
    # Generic mappings
    "backup_status": ["PR.IR", "RC.RP"],
    "encryption_status": ["PR.DS"],
    "network_security": ["PR.PS", "PR.IR"],
    "access_logs": ["DE.CM"],
    "incident_response_plan": ["RS.MA", "RS.CO"],
    "security_training": ["PR.AT"],
    "vendor_assessments": ["GV.SC"],
    "risk_assessments": ["ID.RA", "GV.RM"],
    "policy_documents": ["GV.PO"],
}


class MaturityCalculator:
    """
    Calculate maturity scores for compliance frameworks.

    Supports NIST CSF 2.0 and can be extended to other frameworks.

    The calculator uses evidence and check results to determine
    maturity scores based on:
    - Evidence completeness (do we have evidence for this control?)
    - Evidence quality (how recent and comprehensive is the evidence?)
    - Automation level (is evidence collected automatically?)
    - Check results (do automated checks pass?)

    Example:
        calculator = MaturityCalculator(framework="nist-csf-2")

        # Add evidence
        calculator.add_evidence(evidence_items)

        # Add check results
        calculator.add_check_results(check_results)

        # Calculate maturity
        maturity = calculator.calculate()
        print(f"Overall score: {maturity.overall_score}")
    """

    SUPPORTED_FRAMEWORKS = ["nist-csf-2", "nist-800-53", "soc2"]

    def __init__(
        self,
        framework: str = "nist-csf-2",
        *,
        evidence_weight: float = 0.4,
        automation_weight: float = 0.3,
        check_weight: float = 0.3,
    ) -> None:
        """
        Initialize the maturity calculator.

        Args:
            framework: Framework to calculate maturity for.
            evidence_weight: Weight for evidence completeness (0-1).
            automation_weight: Weight for automation level (0-1).
            check_weight: Weight for check results (0-1).
        """
        if framework not in self.SUPPORTED_FRAMEWORKS:
            raise ValueError(f"Unsupported framework: {framework}")

        self.framework = framework
        self.evidence_weight = evidence_weight
        self.automation_weight = automation_weight
        self.check_weight = check_weight

        self._evidence: list[Evidence] = []
        self._check_results: list[CheckResult] = []
        self._category_evidence: dict[str, list[Evidence]] = {}
        self._category_checks: dict[str, list[CheckResult]] = {}

    def add_evidence(self, evidence: list[Evidence]) -> None:
        """
        Add evidence items for maturity calculation.

        Args:
            evidence: List of evidence items.
        """
        self._evidence.extend(evidence)

        # Map evidence to categories
        for item in evidence:
            categories = EVIDENCE_TO_CSF_MAPPING.get(item.evidence_type, [])
            for category in categories:
                if category not in self._category_evidence:
                    self._category_evidence[category] = []
                self._category_evidence[category].append(item)

    def add_check_results(self, results: list[CheckResult]) -> None:
        """
        Add check results for maturity calculation.

        Args:
            results: List of check results.
        """
        self._check_results.extend(results)

        # Map check results to categories based on framework mappings
        for result in results:
            framework_mappings = result.check.framework_mappings or {}

            # Get mappings for our framework
            if self.framework == "nist-csf-2":
                # Map from other frameworks to CSF categories
                control_ids = framework_mappings.get("nist-csf", [])
                for control_id in control_ids:
                    # Extract category (e.g., "PR.AA" from "PR.AA-01")
                    category = ".".join(control_id.split(".")[:2]) if "." in control_id else control_id
                    if category not in self._category_checks:
                        self._category_checks[category] = []
                    self._category_checks[category].append(result)

    def calculate(self) -> FrameworkMaturity:
        """
        Calculate overall maturity for the framework.

        Returns:
            FrameworkMaturity with scores by category.
        """
        if self.framework == "nist-csf-2":
            return self._calculate_nist_csf()
        else:
            raise NotImplementedError(f"Calculator for {self.framework} not implemented")

    def _calculate_nist_csf(self) -> FrameworkMaturity:
        """Calculate NIST CSF 2.0 maturity."""
        category_scores: list[CategoryScore] = []
        total_score = 0.0
        total_weight = 0.0

        for function_id, function_data in NIST_CSF_2_STRUCTURE.items():
            subcategory_scores: list[MaturityScore] = []

            for category_id, category_name in function_data["categories"].items():
                score = self._calculate_category_score(category_id)
                subcategory_scores.append(score)

            # Calculate function score
            if subcategory_scores:
                function_score = sum(s.score for s in subcategory_scores) / len(subcategory_scores)
            else:
                function_score = 0.0

            implemented = sum(1 for s in subcategory_scores if s.score >= 50)

            category_scores.append(CategoryScore(
                category_id=function_id,
                name=function_data["name"],
                score=function_score,
                level=MaturityLevel.from_score(function_score),
                subcategory_scores=subcategory_scores,
                control_count=len(subcategory_scores),
                implemented_count=implemented,
            ))

            total_score += function_score
            total_weight += 1

        overall_score = total_score / total_weight if total_weight > 0 else 0.0

        return FrameworkMaturity(
            framework=self.framework,
            overall_score=overall_score,
            overall_level=MaturityLevel.from_score(overall_score),
            category_scores=category_scores,
            total_controls=sum(c.control_count for c in category_scores),
            metadata={
                "evidence_count": len(self._evidence),
                "check_count": len(self._check_results),
            },
        )

    def _calculate_category_score(self, category_id: str) -> MaturityScore:
        """Calculate maturity score for a single category."""
        evidence = self._category_evidence.get(category_id, [])
        checks = self._category_checks.get(category_id, [])

        # Evidence score (0-100)
        evidence_score = self._calculate_evidence_score(evidence)

        # Automation score (0-100)
        automation_score = self._calculate_automation_score(evidence)

        # Check score (0-100)
        check_score = self._calculate_check_score(checks)

        # Weighted average
        total_score = (
            evidence_score * self.evidence_weight +
            automation_score * self.automation_weight +
            check_score * self.check_weight
        )

        return MaturityScore(
            control_id=category_id,
            score=total_score,
            level=MaturityLevel.from_score(total_score),
            evidence_count=len(evidence),
            automation_rate=automation_score,
            details={
                "evidence_score": evidence_score,
                "automation_score": automation_score,
                "check_score": check_score,
                "check_count": len(checks),
                "checks_passed": sum(1 for c in checks if c.passed),
            },
        )

    def _calculate_evidence_score(self, evidence: list[Evidence]) -> float:
        """
        Calculate evidence completeness score.

        Factors:
        - Existence of evidence (base score)
        - Recency of evidence (decay for old evidence)
        - Diversity of evidence types
        """
        if not evidence:
            return 0.0

        base_score = min(100, len(evidence) * 20)  # More evidence = higher score, max 100

        # Recency factor (evidence older than 90 days starts decaying)
        now = datetime.now(timezone.utc)
        recency_scores = []
        for item in evidence:
            age_days = (now - item.collected_at).days
            if age_days <= 30:
                recency_scores.append(100)
            elif age_days <= 90:
                recency_scores.append(80)
            elif age_days <= 180:
                recency_scores.append(50)
            else:
                recency_scores.append(20)

        recency_factor = sum(recency_scores) / len(recency_scores) / 100

        return base_score * recency_factor

    def _calculate_automation_score(self, evidence: list[Evidence]) -> float:
        """
        Calculate automation level score.

        Higher scores for evidence collected via automated methods.
        """
        if not evidence:
            return 0.0

        automated_count = sum(
            1 for e in evidence
            if e.metadata.get("collection_method") == "automated" or
            e.metadata.get("source", "").startswith("collector:")
        )

        # Give partial credit even for manual evidence if it exists
        base_score = 50 if evidence else 0
        automation_bonus = (automated_count / len(evidence)) * 50

        return base_score + automation_bonus

    def _calculate_check_score(self, checks: list[CheckResult]) -> float:
        """
        Calculate score based on check results.

        Pass rate determines the score.
        """
        if not checks:
            return 50.0  # Neutral if no checks

        passed = sum(1 for c in checks if c.passed)
        return (passed / len(checks)) * 100

    def get_improvement_recommendations(
        self,
        maturity: FrameworkMaturity,
    ) -> list[dict[str, Any]]:
        """
        Generate recommendations for improving maturity.

        Args:
            maturity: Calculated maturity assessment.

        Returns:
            List of recommendations sorted by priority.
        """
        recommendations: list[dict[str, Any]] = []

        for category in maturity.category_scores:
            for subcategory in category.subcategory_scores:
                if subcategory.score < 50:
                    priority = "high" if subcategory.score < 25 else "medium"

                    rec = {
                        "category": category.category_id,
                        "subcategory": subcategory.control_id,
                        "current_score": subcategory.score,
                        "current_level": subcategory.level.name,
                        "priority": priority,
                        "recommendations": [],
                    }

                    details = subcategory.details

                    if details.get("evidence_score", 0) < 50:
                        rec["recommendations"].append(
                            "Collect more evidence for this control area"
                        )

                    if details.get("automation_score", 0) < 50:
                        rec["recommendations"].append(
                            "Implement automated evidence collection"
                        )

                    if details.get("check_score", 100) < 70:
                        failed = details.get("check_count", 0) - details.get("checks_passed", 0)
                        rec["recommendations"].append(
                            f"Address {failed} failing compliance checks"
                        )

                    recommendations.append(rec)

        # Sort by priority and score
        priority_order = {"high": 0, "medium": 1, "low": 2}
        recommendations.sort(
            key=lambda r: (priority_order.get(r["priority"], 2), r["current_score"])
        )

        return recommendations
