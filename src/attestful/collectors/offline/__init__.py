"""
Offline Collection Mode for Air-Gapped Environments.

Provides evidence bundle creation, signing, verification, and transfer
for disconnected/air-gapped network deployments.

Key Components:
- EvidenceBundle: Container format for offline evidence transfer
- BundleExporter: Creates signed, checksummed evidence bundles
- BundleImporter: Validates and imports evidence bundles
- OfflineAgent: Standalone collection agent for isolated networks
- KeyManager: Manages signing keys for bundle authenticity

Bundle Format:
- manifest.json: Collection metadata and file inventory
- checksums.json: SHA-256 hashes for all evidence files
- signature.sig: GPG or RSA signature for authenticity
- evidence/: Directory containing evidence files organized by platform/type
"""

from attestful.collectors.offline.bundle import (
    BundleFormat,
    BundleManifest,
    BundleChecksum,
    BundleSignature,
    EvidenceBundle,
    create_bundle_manifest,
    calculate_file_checksum,
    validate_bundle_structure,
)
from attestful.collectors.offline.exporter import (
    BundleExporter,
    ExportConfig,
    ExportResult,
    export_evidence_bundle,
)
from attestful.collectors.offline.importer import (
    BundleImporter,
    ImportConfig,
    ImportResult,
    import_evidence_bundle,
)
from attestful.collectors.offline.signing import (
    KeyManager,
    SigningKey,
    VerificationKey,
    sign_bundle,
    verify_bundle_signature,
    generate_keypair,
)
from attestful.collectors.offline.agent import (
    OfflineAgent,
    AgentConfig,
    run_offline_collection,
)

__all__ = [
    # Bundle types
    "BundleFormat",
    "BundleManifest",
    "BundleChecksum",
    "BundleSignature",
    "EvidenceBundle",
    # Bundle functions
    "create_bundle_manifest",
    "calculate_file_checksum",
    "validate_bundle_structure",
    # Exporter types
    "BundleExporter",
    "ExportConfig",
    "ExportResult",
    # Exporter functions
    "export_evidence_bundle",
    # Importer types
    "BundleImporter",
    "ImportConfig",
    "ImportResult",
    # Importer functions
    "import_evidence_bundle",
    # Signing types
    "KeyManager",
    "SigningKey",
    "VerificationKey",
    # Signing functions
    "sign_bundle",
    "verify_bundle_signature",
    "generate_keypair",
    # Agent types
    "OfflineAgent",
    "AgentConfig",
    # Agent functions
    "run_offline_collection",
]
