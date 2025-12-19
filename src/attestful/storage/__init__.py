"""
Storage layer for database and file-based evidence storage.

Provides:
- SQLAlchemy models for all Attestful data
- File-based evidence storage with integrity verification
- Database utilities
- OSCAL document storage
- Remediation tracking
"""

from attestful.storage.models import (
    # Base
    Base,
    # Organization & Users
    Organization,
    User,
    Team,
    TeamMember,
    # Compliance Scanning
    Scan,
    ScanResult,
    Resource,
    # Evidence Collection
    CollectionRun,
    EvidenceItem,
    # OSCAL Documents
    OSCALCatalog,
    OSCALProfile,
    OSCALSSP,
    OSCALAssessment,
    # Frameworks
    Framework,
    FrameworkMapping,
    # Maturity
    MaturitySnapshot,
    # Remediation
    RemediationAction,
    RemediationHistory,
    # Audit
    AuditLog,
)
from attestful.storage.database import (
    get_engine,
    get_session,
    init_database,
)
from attestful.storage.evidence import (
    EvidenceStore,
    StoredEvidence,
)

__all__ = [
    # Base
    "Base",
    # Organization & Users
    "Organization",
    "User",
    "Team",
    "TeamMember",
    # Compliance Scanning
    "Scan",
    "ScanResult",
    "Resource",
    # Evidence Collection
    "CollectionRun",
    "EvidenceItem",
    # OSCAL Documents
    "OSCALCatalog",
    "OSCALProfile",
    "OSCALSSP",
    "OSCALAssessment",
    # Frameworks
    "Framework",
    "FrameworkMapping",
    # Maturity
    "MaturitySnapshot",
    # Remediation
    "RemediationAction",
    "RemediationHistory",
    # Audit
    "AuditLog",
    # Database
    "get_engine",
    "get_session",
    "init_database",
    # Evidence Store
    "EvidenceStore",
    "StoredEvidence",
]
