"""
Storage layer for database and file-based evidence storage.
"""

from attestful.storage.models import (
    Base,
    Organization,
    User,
    Scan,
    ScanResult,
    CollectionRun,
    EvidenceItem,
    MaturitySnapshot,
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
from attestful.storage.migrations import (
    NisifyMigration,
    NisifySchemaMapper,
    NisifyEvidenceConverter,
    NisifyMaturityPreserver,
    NisifyTrendMigrator,
    migrate_nisify_database,
)

__all__ = [
    # Models
    "Base",
    "Organization",
    "User",
    "Scan",
    "ScanResult",
    "CollectionRun",
    "EvidenceItem",
    "MaturitySnapshot",
    "AuditLog",
    # Database
    "get_engine",
    "get_session",
    "init_database",
    # Evidence Store
    "EvidenceStore",
    "StoredEvidence",
    # Migrations
    "NisifyMigration",
    "NisifySchemaMapper",
    "NisifyEvidenceConverter",
    "NisifyMaturityPreserver",
    "NisifyTrendMigrator",
    "migrate_nisify_database",
]
