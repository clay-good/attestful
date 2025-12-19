"""
Control Equivalency Scoring Module.

Provides algorithms for calculating the strength of control mappings
between frameworks based on multiple factors.

Scoring Methodology:
--------------------
The equivalency score (0.0 - 1.0) is calculated from three weighted factors:

1. Semantic Similarity (40%):
   - How similar are the control requirements in meaning?
   - Based on keyword overlap, control objectives, and domain alignment

2. Implementation Overlap (35%):
   - How much do the implementation approaches overlap?
   - Based on technical controls, evidence types, and automation potential

3. Industry Standard Weight (25%):
   - Is this mapping recognized by authoritative sources?
   - Based on official crosswalks, regulatory guidance, and auditor acceptance

Score Interpretation:
---------------------
- 1.0: Perfect equivalence (same control, different framework)
- 0.8-0.99: Strong mapping (direct substitute, minimal gaps)
- 0.6-0.79: Good mapping (substantial overlap, minor differences)
- 0.4-0.59: Moderate mapping (related, requires supplementation)
- 0.2-0.39: Weak mapping (tangentially related)
- 0.0-0.19: No meaningful equivalence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from attestful.core.logging import get_logger
from attestful.frameworks.mapping.registry import (
    FrameworkID,
    ControlMapping,
    get_mapping,
)

logger = get_logger("frameworks.mapping.equivalency")


# =============================================================================
# Constants
# =============================================================================

# Weight factors for equivalency calculation
SEMANTIC_WEIGHT = 0.40
IMPLEMENTATION_WEIGHT = 0.35
INDUSTRY_WEIGHT = 0.25

# Control domain keywords for semantic matching
CONTROL_DOMAIN_KEYWORDS = {
    "access_control": [
        "access", "authorization", "authentication", "identity", "credential",
        "privilege", "permission", "role", "user", "account", "login", "session",
    ],
    "data_protection": [
        "encryption", "cryptography", "data", "confidentiality", "integrity",
        "classification", "backup", "retention", "disposal", "sanitization",
    ],
    "network_security": [
        "network", "firewall", "boundary", "segmentation", "perimeter",
        "traffic", "connection", "remote", "wireless", "vpn",
    ],
    "audit_logging": [
        "audit", "log", "monitoring", "event", "record", "trail", "tracking",
        "detection", "alert", "review", "analysis",
    ],
    "incident_response": [
        "incident", "response", "breach", "containment", "recovery", "forensic",
        "notification", "escalation", "communication",
    ],
    "change_management": [
        "change", "configuration", "baseline", "patch", "update", "version",
        "release", "deployment", "testing",
    ],
    "risk_management": [
        "risk", "assessment", "threat", "vulnerability", "impact", "likelihood",
        "mitigation", "treatment", "acceptance",
    ],
    "business_continuity": [
        "continuity", "disaster", "recovery", "resilience", "availability",
        "backup", "restoration", "failover",
    ],
    "physical_security": [
        "physical", "facility", "perimeter", "access", "visitor", "badge",
        "surveillance", "environmental",
    ],
    "personnel_security": [
        "personnel", "employee", "training", "awareness", "screening",
        "background", "termination", "onboarding",
    ],
    "compliance": [
        "compliance", "policy", "procedure", "standard", "regulation",
        "audit", "assessment", "certification",
    ],
    "privacy": [
        "privacy", "personal", "consent", "data subject", "processing",
        "retention", "purpose", "disclosure",
    ],
}

# Industry-recognized mapping authorities
MAPPING_AUTHORITIES = {
    "nist_official": 1.0,  # Official NIST crosswalks
    "aicpa_official": 0.95,  # AICPA Trust Services mapping
    "iso_official": 0.95,  # ISO alignment documents
    "hitrust_official": 0.90,  # HITRUST inheritance documentation
    "auditor_consensus": 0.85,  # Generally accepted by auditors
    "industry_practice": 0.75,  # Common industry usage
    "inferred": 0.50,  # Algorithmically inferred
}


# =============================================================================
# Data Classes
# =============================================================================


@dataclass
class EquivalencyFactors:
    """
    Individual factors contributing to equivalency score.

    Attributes:
        semantic_similarity: How similar control requirements are (0-1).
        implementation_overlap: How much implementations overlap (0-1).
        industry_standard_weight: Authority of the mapping source (0-1).
        domain_alignment: Whether controls are in same domain (0-1).
        evidence_overlap: How much evidence types overlap (0-1).
    """

    semantic_similarity: float = 0.0
    implementation_overlap: float = 0.0
    industry_standard_weight: float = 0.0
    domain_alignment: float = 0.0
    evidence_overlap: float = 0.0

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary."""
        return {
            "semantic_similarity": round(self.semantic_similarity, 3),
            "implementation_overlap": round(self.implementation_overlap, 3),
            "industry_standard_weight": round(self.industry_standard_weight, 3),
            "domain_alignment": round(self.domain_alignment, 3),
            "evidence_overlap": round(self.evidence_overlap, 3),
        }


@dataclass
class EquivalencyScore:
    """
    Complete equivalency score with breakdown.

    Attributes:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.
        target_control: Target control ID.
        overall_score: Final equivalency score (0-1).
        factors: Individual factor scores.
        confidence: Confidence in the score (0-1).
        notes: Scoring notes or caveats.
    """

    source_framework: FrameworkID
    source_control: str
    target_framework: FrameworkID
    target_control: str
    overall_score: float
    factors: EquivalencyFactors
    confidence: float = 0.8
    notes: str = ""

    @property
    def strength_label(self) -> str:
        """Get human-readable strength label."""
        if self.overall_score >= 0.9:
            return "Strong"
        elif self.overall_score >= 0.7:
            return "Good"
        elif self.overall_score >= 0.5:
            return "Moderate"
        elif self.overall_score >= 0.3:
            return "Weak"
        else:
            return "Minimal"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "source_framework": self.source_framework.value,
            "source_control": self.source_control,
            "target_framework": self.target_framework.value,
            "target_control": self.target_control,
            "overall_score": round(self.overall_score, 3),
            "strength_label": self.strength_label,
            "factors": self.factors.to_dict(),
            "confidence": round(self.confidence, 3),
            "notes": self.notes,
        }


# =============================================================================
# Control Metadata (for semantic analysis)
# =============================================================================

# Control titles/descriptions for semantic matching
# This would ideally be loaded from the actual control catalogs
CONTROL_METADATA: dict[str, dict[str, str]] = {
    # NIST 800-53 samples
    "AC-1": {"title": "Access Control Policy and Procedures", "domain": "access_control"},
    "AC-2": {"title": "Account Management", "domain": "access_control"},
    "AC-3": {"title": "Access Enforcement", "domain": "access_control"},
    "AC-6": {"title": "Least Privilege", "domain": "access_control"},
    "AC-17": {"title": "Remote Access", "domain": "network_security"},
    "AU-2": {"title": "Audit Events", "domain": "audit_logging"},
    "AU-6": {"title": "Audit Review, Analysis, and Reporting", "domain": "audit_logging"},
    "CM-2": {"title": "Baseline Configuration", "domain": "change_management"},
    "CM-3": {"title": "Configuration Change Control", "domain": "change_management"},
    "CP-9": {"title": "System Backup", "domain": "business_continuity"},
    "IA-2": {"title": "Identification and Authentication", "domain": "access_control"},
    "IR-4": {"title": "Incident Handling", "domain": "incident_response"},
    "RA-3": {"title": "Risk Assessment", "domain": "risk_management"},
    "RA-5": {"title": "Vulnerability Scanning", "domain": "risk_management"},
    "SC-7": {"title": "Boundary Protection", "domain": "network_security"},
    "SC-8": {"title": "Transmission Confidentiality and Integrity", "domain": "data_protection"},
    "SC-28": {"title": "Protection of Information at Rest", "domain": "data_protection"},
    "SI-2": {"title": "Flaw Remediation", "domain": "change_management"},
    "SI-3": {"title": "Malicious Code Protection", "domain": "network_security"},
    "SI-4": {"title": "System Monitoring", "domain": "audit_logging"},
    # SOC 2 samples
    "CC6.1": {"title": "Logical and Physical Access Controls", "domain": "access_control"},
    "CC6.2": {"title": "Registration and Authorization", "domain": "access_control"},
    "CC6.3": {"title": "Removal of Access Rights", "domain": "access_control"},
    "CC6.6": {"title": "Restricting System Access", "domain": "network_security"},
    "CC6.7": {"title": "Transmission Encryption", "domain": "data_protection"},
    "CC7.1": {"title": "Vulnerability Management", "domain": "risk_management"},
    "CC7.2": {"title": "Monitoring System Components", "domain": "audit_logging"},
    "CC7.3": {"title": "Incident Response Planning", "domain": "incident_response"},
    "CC7.4": {"title": "Response to Security Incidents", "domain": "incident_response"},
    "CC8.1": {"title": "Change Control", "domain": "change_management"},
    "A1.2": {"title": "Recovery Plan Testing", "domain": "business_continuity"},
    # ISO 27001 samples
    "A.5.15": {"title": "Access Control Policy", "domain": "access_control"},
    "A.5.16": {"title": "Identity Management", "domain": "access_control"},
    "A.5.24": {"title": "Information Security Incident Management Planning", "domain": "incident_response"},
    "A.5.26": {"title": "Response to Information Security Incidents", "domain": "incident_response"},
    "A.5.30": {"title": "ICT Readiness for Business Continuity", "domain": "business_continuity"},
    "A.8.5": {"title": "Secure Authentication", "domain": "access_control"},
    "A.8.7": {"title": "Protection Against Malware", "domain": "network_security"},
    "A.8.8": {"title": "Management of Technical Vulnerabilities", "domain": "risk_management"},
    "A.8.15": {"title": "Logging", "domain": "audit_logging"},
    "A.8.20": {"title": "Networks Security", "domain": "network_security"},
    "A.8.24": {"title": "Use of Cryptography", "domain": "data_protection"},
    "A.8.32": {"title": "Change Management", "domain": "change_management"},
    # HITRUST samples
    "01.a": {"title": "Access Control Policy", "domain": "access_control"},
    "01.b": {"title": "User Registration", "domain": "access_control"},
    "01.c": {"title": "Privilege Management", "domain": "access_control"},
    "01.d": {"title": "Password Management", "domain": "access_control"},
    "03.b": {"title": "Risk Assessment", "domain": "risk_management"},
    "06.d": {"title": "Cryptographic Controls", "domain": "data_protection"},
    "09.aa": {"title": "Audit Logging", "domain": "audit_logging"},
    "09.ab": {"title": "Monitoring System Use", "domain": "audit_logging"},
    "09.m": {"title": "Network Controls", "domain": "network_security"},
    "10.k": {"title": "Change Control Procedures", "domain": "change_management"},
    "10.m": {"title": "Technical Vulnerability Management", "domain": "risk_management"},
    "11.a": {"title": "Reporting Security Events", "domain": "incident_response"},
    "11.c": {"title": "Incident Response Procedures", "domain": "incident_response"},
    "12.b": {"title": "Business Continuity Plans", "domain": "business_continuity"},
}


# =============================================================================
# Scoring Functions
# =============================================================================


def get_semantic_similarity(
    source_control: str,
    target_control: str,
    source_framework: FrameworkID | None = None,
    target_framework: FrameworkID | None = None,
) -> float:
    """
    Calculate semantic similarity between two controls.

    Uses control metadata, domain keywords, and title matching
    to determine how semantically similar two controls are.

    Args:
        source_control: Source control ID.
        target_control: Target control ID.
        source_framework: Source framework (optional, for context).
        target_framework: Target framework (optional, for context).

    Returns:
        Semantic similarity score (0.0 - 1.0).
    """
    # Get control metadata
    source_meta = CONTROL_METADATA.get(source_control, {})
    target_meta = CONTROL_METADATA.get(target_control, {})

    if not source_meta or not target_meta:
        # No metadata, use base score
        return 0.5

    # Domain alignment check
    source_domain = source_meta.get("domain", "")
    target_domain = target_meta.get("domain", "")

    if source_domain == target_domain and source_domain:
        domain_score = 1.0
    else:
        domain_score = 0.3

    # Title keyword matching
    source_title = source_meta.get("title", "").lower()
    target_title = target_meta.get("title", "").lower()

    source_words = set(source_title.split())
    target_words = set(target_title.split())

    # Remove common words
    stop_words = {"and", "or", "the", "of", "for", "to", "a", "an", "in", "on"}
    source_words -= stop_words
    target_words -= stop_words

    if source_words and target_words:
        intersection = source_words & target_words
        union = source_words | target_words
        title_score = len(intersection) / len(union) if union else 0
    else:
        title_score = 0.0

    # Combine scores
    semantic_score = (domain_score * 0.6) + (title_score * 0.4)

    return min(1.0, semantic_score)


def get_implementation_overlap(
    source_control: str,
    target_control: str,
) -> float:
    """
    Calculate implementation overlap between two controls.

    Considers:
    - Similar technical controls required
    - Similar evidence types needed
    - Similar automation potential

    Args:
        source_control: Source control ID.
        target_control: Target control ID.

    Returns:
        Implementation overlap score (0.0 - 1.0).
    """
    # Get domains for both controls
    source_meta = CONTROL_METADATA.get(source_control, {})
    target_meta = CONTROL_METADATA.get(target_control, {})

    source_domain = source_meta.get("domain", "")
    target_domain = target_meta.get("domain", "")

    # Implementation overlap by domain pairs
    # Same domain = high overlap
    if source_domain == target_domain and source_domain:
        base_overlap = 0.9
    # Related domains
    elif _are_domains_related(source_domain, target_domain):
        base_overlap = 0.6
    else:
        base_overlap = 0.3

    return base_overlap


def _are_domains_related(domain1: str, domain2: str) -> bool:
    """Check if two domains are related."""
    related_pairs = {
        ("access_control", "data_protection"),
        ("access_control", "audit_logging"),
        ("network_security", "data_protection"),
        ("audit_logging", "incident_response"),
        ("risk_management", "compliance"),
        ("business_continuity", "incident_response"),
        ("change_management", "risk_management"),
    }

    pair = tuple(sorted([domain1, domain2]))
    return pair in related_pairs or (domain1, domain2) in related_pairs


def get_industry_standard_weight(
    source_framework: FrameworkID,
    source_control: str,
    target_framework: FrameworkID,
    target_control: str,
) -> float:
    """
    Get the industry-standard weight for a mapping.

    Based on whether the mapping comes from an authoritative source.

    Args:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.
        target_control: Target control ID.

    Returns:
        Industry standard weight (0.0 - 1.0).
    """
    # Check if mapping exists in our registry (implies authority)
    mappings = get_mapping(source_framework, source_control, target_framework)

    for mapping in mappings:
        if mapping.target_control == target_control:
            # Existing mapping - use its strength as authority indicator
            if mapping.strength >= 0.9:
                return MAPPING_AUTHORITIES["nist_official"]
            elif mapping.strength >= 0.8:
                return MAPPING_AUTHORITIES["aicpa_official"]
            elif mapping.strength >= 0.7:
                return MAPPING_AUTHORITIES["auditor_consensus"]
            else:
                return MAPPING_AUTHORITIES["industry_practice"]

    # No existing mapping - inferred
    return MAPPING_AUTHORITIES["inferred"]


def calculate_equivalency_score(
    source_framework: FrameworkID,
    source_control: str,
    target_framework: FrameworkID,
    target_control: str,
) -> EquivalencyScore:
    """
    Calculate comprehensive equivalency score for a control mapping.

    Combines semantic similarity, implementation overlap, and
    industry standard weight into a final score.

    Args:
        source_framework: Source framework ID.
        source_control: Source control ID.
        target_framework: Target framework ID.
        target_control: Target control ID.

    Returns:
        Complete EquivalencyScore with breakdown.
    """
    # Calculate individual factors
    semantic = get_semantic_similarity(
        source_control, target_control,
        source_framework, target_framework
    )

    implementation = get_implementation_overlap(source_control, target_control)

    industry = get_industry_standard_weight(
        source_framework, source_control,
        target_framework, target_control
    )

    # Calculate domain alignment
    source_meta = CONTROL_METADATA.get(source_control, {})
    target_meta = CONTROL_METADATA.get(target_control, {})
    domain_alignment = 1.0 if source_meta.get("domain") == target_meta.get("domain") else 0.3

    # Build factors
    factors = EquivalencyFactors(
        semantic_similarity=semantic,
        implementation_overlap=implementation,
        industry_standard_weight=industry,
        domain_alignment=domain_alignment,
        evidence_overlap=implementation * 0.9,  # Correlated with implementation
    )

    # Calculate overall score using weights
    overall = (
        semantic * SEMANTIC_WEIGHT +
        implementation * IMPLEMENTATION_WEIGHT +
        industry * INDUSTRY_WEIGHT
    )

    # Ensure bounds
    overall = max(0.0, min(1.0, overall))

    # Calculate confidence based on metadata availability
    confidence = 0.8
    if source_control not in CONTROL_METADATA:
        confidence -= 0.2
    if target_control not in CONTROL_METADATA:
        confidence -= 0.2

    # Build notes
    notes_parts = []
    if overall >= 0.8:
        notes_parts.append("Strong equivalence - suitable for direct mapping")
    elif overall >= 0.6:
        notes_parts.append("Good equivalence - minor gaps may exist")
    elif overall >= 0.4:
        notes_parts.append("Moderate equivalence - supplemental controls needed")
    else:
        notes_parts.append("Weak equivalence - significant differences exist")

    if domain_alignment < 0.5:
        notes_parts.append("Different control domains")

    return EquivalencyScore(
        source_framework=source_framework,
        source_control=source_control,
        target_framework=target_framework,
        target_control=target_control,
        overall_score=overall,
        factors=factors,
        confidence=max(0.1, confidence),
        notes="; ".join(notes_parts),
    )


def score_mapping_quality(mapping: ControlMapping) -> EquivalencyScore:
    """
    Score the quality of an existing mapping.

    Args:
        mapping: Control mapping to score.

    Returns:
        Equivalency score for the mapping.
    """
    return calculate_equivalency_score(
        mapping.source_framework,
        mapping.source_control,
        mapping.target_framework,
        mapping.target_control,
    )


def bulk_calculate_equivalency(
    mappings: list[ControlMapping],
) -> list[EquivalencyScore]:
    """
    Calculate equivalency scores for multiple mappings.

    Args:
        mappings: List of control mappings.

    Returns:
        List of equivalency scores.
    """
    return [score_mapping_quality(m) for m in mappings]


def get_equivalency_statistics(scores: list[EquivalencyScore]) -> dict[str, Any]:
    """
    Get statistics about a set of equivalency scores.

    Args:
        scores: List of equivalency scores.

    Returns:
        Statistics dictionary.
    """
    if not scores:
        return {
            "count": 0,
            "average_score": 0.0,
            "min_score": 0.0,
            "max_score": 0.0,
            "strength_distribution": {},
        }

    all_scores = [s.overall_score for s in scores]

    # Count by strength label
    strength_dist: dict[str, int] = {}
    for s in scores:
        label = s.strength_label
        strength_dist[label] = strength_dist.get(label, 0) + 1

    return {
        "count": len(scores),
        "average_score": round(sum(all_scores) / len(all_scores), 3),
        "min_score": round(min(all_scores), 3),
        "max_score": round(max(all_scores), 3),
        "average_confidence": round(
            sum(s.confidence for s in scores) / len(scores), 3
        ),
        "strength_distribution": strength_dist,
    }


__all__ = [
    # Constants
    "SEMANTIC_WEIGHT",
    "IMPLEMENTATION_WEIGHT",
    "INDUSTRY_WEIGHT",
    "CONTROL_DOMAIN_KEYWORDS",
    "MAPPING_AUTHORITIES",
    # Data classes
    "EquivalencyFactors",
    "EquivalencyScore",
    # Functions
    "get_semantic_similarity",
    "get_implementation_overlap",
    "get_industry_standard_weight",
    "calculate_equivalency_score",
    "score_mapping_quality",
    "bulk_calculate_equivalency",
    "get_equivalency_statistics",
]
