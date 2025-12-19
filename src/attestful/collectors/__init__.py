"""
Collectors for resources and evidence.

This module provides the unified collector architecture that supports both:
- Resource collection for compliance checking
- Evidence collection for proof gathering

Submodules:
- cloud: AWS, Azure, GCP infrastructure collectors
- platforms: SaaS platform collectors (Okta, GitHub, etc.)
- containers: Kubernetes and Docker collectors
- offline: Air-gapped collection and bundle transfer
- optimization: Exponential backoff, caching, and batch processing
"""

from attestful.collectors.base import (
    BaseCollector,
    CollectorMetadata,
    CollectorMode,
    CollectorRegistry,
    collector_registry,
    register_collector,
)
from attestful.collectors.offline import (
    # Bundle types
    BundleFormat,
    BundleManifest,
    BundleChecksum,
    BundleSignature,
    EvidenceBundle,
    # Exporter
    BundleExporter,
    ExportConfig,
    ExportResult,
    export_evidence_bundle,
    # Importer
    BundleImporter,
    ImportConfig,
    ImportResult,
    import_evidence_bundle,
    # Agent
    OfflineAgent,
    AgentConfig,
    run_offline_collection,
    # Signing
    KeyManager,
    SigningKey,
    VerificationKey,
    sign_bundle,
    verify_bundle_signature,
    generate_keypair,
)
from attestful.collectors.optimization import (
    BatchProcessor,
    ExponentialBackoff,
    RequestCache,
    with_exponential_backoff,
    with_request_cache,
)

__all__ = [
    # Base collector
    "BaseCollector",
    "CollectorMetadata",
    "CollectorMode",
    "CollectorRegistry",
    "collector_registry",
    "register_collector",
    # Offline bundle types
    "BundleFormat",
    "BundleManifest",
    "BundleChecksum",
    "BundleSignature",
    "EvidenceBundle",
    # Offline exporter
    "BundleExporter",
    "ExportConfig",
    "ExportResult",
    "export_evidence_bundle",
    # Offline importer
    "BundleImporter",
    "ImportConfig",
    "ImportResult",
    "import_evidence_bundle",
    # Offline agent
    "OfflineAgent",
    "AgentConfig",
    "run_offline_collection",
    # Signing
    "KeyManager",
    "SigningKey",
    "VerificationKey",
    "sign_bundle",
    "verify_bundle_signature",
    "generate_keypair",
    # Optimization utilities
    "ExponentialBackoff",
    "RequestCache",
    "BatchProcessor",
    "with_exponential_backoff",
    "with_request_cache",
]
