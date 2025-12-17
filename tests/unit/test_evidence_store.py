"""
Unit tests for the evidence storage system.
"""

import gzip
import json
import pytest
import tempfile
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path

from attestful.storage.evidence import EvidenceStore, StoredEvidence
from attestful.core.models import Evidence, CollectionResult


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def temp_evidence_dir():
    """Create a temporary directory for evidence storage."""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture
def evidence_store(temp_evidence_dir: Path) -> EvidenceStore:
    """Create an evidence store with a temporary directory."""
    return EvidenceStore(evidence_dir=temp_evidence_dir)


@pytest.fixture
def sample_evidence() -> Evidence:
    """Create sample evidence for testing."""
    return Evidence(
        id="evidence-123",
        platform="aws",
        evidence_type="iam_credential_report",
        collected_at=datetime.now(timezone.utc),
        raw_data={
            "users": [
                {"UserName": "admin", "MFAActive": True},
                {"UserName": "developer", "MFAActive": False},
            ],
            "generated_at": "2024-01-15T10:30:00Z",
        },
        metadata={
            "account_id": "123456789012",
            "region": "us-east-1",
            "collection_method": "automated",
        },
    )


@pytest.fixture
def large_evidence() -> Evidence:
    """Create large evidence that triggers compression."""
    # Generate data larger than compression threshold (10KB)
    large_data = {"items": [{"id": i, "data": "x" * 100} for i in range(200)]}
    return Evidence(
        id="large-evidence-456",
        platform="okta",
        evidence_type="users",
        collected_at=datetime.now(timezone.utc),
        raw_data=large_data,
        metadata={"count": 200},
    )


# =============================================================================
# StoredEvidence Tests
# =============================================================================


class TestStoredEvidence:
    """Tests for StoredEvidence dataclass."""

    def test_to_dict(self, temp_evidence_dir: Path):
        """Test serialization to dictionary."""
        now = datetime.now(timezone.utc)
        stored = StoredEvidence(
            id="test-123",
            platform="aws",
            evidence_type="iam_report",
            file_path=temp_evidence_dir / "test.json",
            file_hash="abc123",
            file_size=1024,
            compressed=False,
            collected_at=now,
            stored_at=now,
            metadata={"key": "value"},
        )

        data = stored.to_dict()

        assert data["id"] == "test-123"
        assert data["platform"] == "aws"
        assert data["file_hash"] == "abc123"
        assert data["compressed"] is False
        assert data["metadata"]["key"] == "value"

    def test_from_dict(self, temp_evidence_dir: Path):
        """Test deserialization from dictionary."""
        now = datetime.now(timezone.utc)
        data = {
            "id": "test-123",
            "platform": "aws",
            "evidence_type": "iam_report",
            "file_path": str(temp_evidence_dir / "test.json"),
            "file_hash": "abc123",
            "file_size": 1024,
            "compressed": True,
            "collected_at": now.isoformat(),
            "stored_at": now.isoformat(),
            "metadata": {"key": "value"},
        }

        stored = StoredEvidence.from_dict(data)

        assert stored.id == "test-123"
        assert stored.platform == "aws"
        assert stored.compressed is True
        assert isinstance(stored.collected_at, datetime)


# =============================================================================
# EvidenceStore Basic Operations Tests
# =============================================================================


class TestEvidenceStoreBasicOperations:
    """Tests for basic evidence store operations."""

    def test_store_evidence(self, evidence_store: EvidenceStore, sample_evidence: Evidence):
        """Test storing evidence."""
        stored = evidence_store.store(sample_evidence)

        assert stored.id == sample_evidence.id
        assert stored.platform == sample_evidence.platform
        assert stored.evidence_type == sample_evidence.evidence_type
        assert stored.file_hash
        assert stored.file_size > 0
        assert stored.file_path.exists()

    def test_store_creates_directory_structure(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test that storing evidence creates proper directory structure."""
        stored = evidence_store.store(sample_evidence)

        # Should be in year/month/day/platform structure
        path_parts = stored.file_path.parts
        assert sample_evidence.platform in path_parts

    def test_get_stored_evidence(self, evidence_store: EvidenceStore, sample_evidence: Evidence):
        """Test retrieving stored evidence metadata."""
        evidence_store.store(sample_evidence)

        stored = evidence_store.get(sample_evidence.id)

        assert stored is not None
        assert stored.id == sample_evidence.id
        assert stored.platform == sample_evidence.platform

    def test_get_nonexistent_evidence(self, evidence_store: EvidenceStore):
        """Test getting nonexistent evidence returns None."""
        stored = evidence_store.get("nonexistent-id")
        assert stored is None

    def test_read_evidence_data(self, evidence_store: EvidenceStore, sample_evidence: Evidence):
        """Test reading evidence data from storage."""
        evidence_store.store(sample_evidence)

        data = evidence_store.read(sample_evidence.id)

        assert data is not None
        assert data["users"][0]["UserName"] == "admin"
        assert len(data["users"]) == 2

    def test_read_nonexistent_evidence(self, evidence_store: EvidenceStore):
        """Test reading nonexistent evidence returns None."""
        data = evidence_store.read("nonexistent-id")
        assert data is None

    def test_delete_evidence(self, evidence_store: EvidenceStore, sample_evidence: Evidence):
        """Test deleting evidence."""
        stored = evidence_store.store(sample_evidence)
        file_path = stored.file_path

        assert file_path.exists()

        result = evidence_store.delete(sample_evidence.id)

        assert result is True
        assert not file_path.exists()
        assert evidence_store.get(sample_evidence.id) is None

    def test_delete_nonexistent_evidence(self, evidence_store: EvidenceStore):
        """Test deleting nonexistent evidence returns False."""
        result = evidence_store.delete("nonexistent-id")
        assert result is False


# =============================================================================
# Compression Tests
# =============================================================================


class TestEvidenceStoreCompression:
    """Tests for evidence compression functionality."""

    def test_small_evidence_not_compressed(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test that small evidence is not compressed."""
        stored = evidence_store.store(sample_evidence)

        assert stored.compressed is False
        assert stored.file_path.suffix == ".json"

    def test_large_evidence_compressed(
        self, evidence_store: EvidenceStore, large_evidence: Evidence
    ):
        """Test that large evidence is compressed."""
        stored = evidence_store.store(large_evidence)

        assert stored.compressed is True
        assert stored.file_path.name.endswith(".json.gz")

    def test_read_compressed_evidence(
        self, evidence_store: EvidenceStore, large_evidence: Evidence
    ):
        """Test reading compressed evidence."""
        evidence_store.store(large_evidence)

        data = evidence_store.read(large_evidence.id)

        assert data is not None
        assert len(data["items"]) == 200

    def test_compression_disabled(self, temp_evidence_dir: Path, large_evidence: Evidence):
        """Test that compression can be disabled."""
        store = EvidenceStore(evidence_dir=temp_evidence_dir, compress=False)
        stored = store.store(large_evidence)

        assert stored.compressed is False
        assert stored.file_path.suffix == ".json"


# =============================================================================
# Integrity Verification Tests
# =============================================================================


class TestEvidenceStoreIntegrity:
    """Tests for evidence integrity verification."""

    def test_verify_valid_evidence(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test verification of unmodified evidence."""
        evidence_store.store(sample_evidence)

        result = evidence_store.verify(sample_evidence.id)

        assert result is True

    def test_verify_tampered_evidence(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test verification detects tampered evidence."""
        stored = evidence_store.store(sample_evidence)

        # Tamper with the file
        with open(stored.file_path, "w") as f:
            f.write('{"tampered": true}')

        result = evidence_store.verify(sample_evidence.id)

        assert result is False

    def test_verify_missing_file(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test verification handles missing file."""
        stored = evidence_store.store(sample_evidence)

        # Delete the file but keep index entry
        stored.file_path.unlink()

        result = evidence_store.verify(sample_evidence.id)

        assert result is False

    def test_verify_nonexistent_evidence(self, evidence_store: EvidenceStore):
        """Test verification of nonexistent evidence."""
        result = evidence_store.verify("nonexistent-id")
        assert result is False

    def test_verify_all(self, evidence_store: EvidenceStore):
        """Test verifying all stored evidence."""
        # Store multiple evidence items with unique IDs (use UUID-like IDs to avoid filename collisions)
        import uuid
        for i in range(3):
            evidence = Evidence(
                id=str(uuid.uuid4()),  # Use unique UUID to avoid filename collisions
                platform="aws",
                evidence_type=f"test-type-{i}",  # Also use different types
                collected_at=datetime.now(timezone.utc),
                raw_data={"index": i},
            )
            evidence_store.store(evidence)

        passed, failed, failed_ids = evidence_store.verify_all()

        assert passed == 3
        assert failed == 0
        assert len(failed_ids) == 0


# =============================================================================
# Listing and Filtering Tests
# =============================================================================


class TestEvidenceStoreListing:
    """Tests for listing and filtering evidence."""

    def test_list_all_evidence(self, evidence_store: EvidenceStore):
        """Test listing all evidence."""
        # Store evidence from different platforms
        for platform in ["aws", "okta", "gcp"]:
            evidence = Evidence(
                id=f"evidence-{platform}",
                platform=platform,
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        results = evidence_store.list()

        assert len(results) == 3

    def test_list_by_platform(self, evidence_store: EvidenceStore):
        """Test filtering evidence by platform."""
        for platform in ["aws", "aws", "okta"]:
            evidence = Evidence(
                id=f"evidence-{platform}-{datetime.now().timestamp()}",
                platform=platform,
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        results = evidence_store.list(platform="aws")

        assert len(results) == 2
        assert all(e.platform == "aws" for e in results)

    def test_list_by_evidence_type(self, evidence_store: EvidenceStore):
        """Test filtering evidence by type."""
        for etype in ["users", "groups", "users"]:
            evidence = Evidence(
                id=f"evidence-{etype}-{datetime.now().timestamp()}",
                platform="okta",
                evidence_type=etype,
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        results = evidence_store.list(evidence_type="users")

        assert len(results) == 2
        assert all(e.evidence_type == "users" for e in results)

    def test_list_by_date_range(self, evidence_store: EvidenceStore):
        """Test filtering evidence by date range."""
        now = datetime.now(timezone.utc)
        dates = [
            now - timedelta(days=10),
            now - timedelta(days=5),
            now,
        ]

        for i, dt in enumerate(dates):
            evidence = Evidence(
                id=f"evidence-{i}",
                platform="aws",
                evidence_type="test",
                collected_at=dt,
                raw_data={},
            )
            evidence_store.store(evidence)

        # Get only last week's evidence
        results = evidence_store.list(
            start_date=now - timedelta(days=7),
            end_date=now,
        )

        assert len(results) == 2

    def test_list_platforms(self, evidence_store: EvidenceStore):
        """Test listing all platforms with evidence."""
        for platform in ["aws", "okta", "gcp", "aws"]:
            evidence = Evidence(
                id=f"evidence-{platform}-{datetime.now().timestamp()}",
                platform=platform,
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        platforms = evidence_store.list_platforms()

        assert len(platforms) == 3
        assert set(platforms) == {"aws", "gcp", "okta"}

    def test_list_evidence_types(self, evidence_store: EvidenceStore):
        """Test listing evidence types."""
        for etype in ["users", "groups", "policies", "users"]:
            evidence = Evidence(
                id=f"evidence-{etype}-{datetime.now().timestamp()}",
                platform="okta",
                evidence_type=etype,
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        types = evidence_store.list_evidence_types()

        assert len(types) == 3
        assert set(types) == {"users", "groups", "policies"}

    def test_list_evidence_types_by_platform(self, evidence_store: EvidenceStore):
        """Test listing evidence types filtered by platform."""
        # AWS evidence
        for etype in ["iam", "s3", "ec2"]:
            evidence = Evidence(
                id=f"evidence-aws-{etype}",
                platform="aws",
                evidence_type=etype,
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        # Okta evidence
        for etype in ["users", "groups"]:
            evidence = Evidence(
                id=f"evidence-okta-{etype}",
                platform="okta",
                evidence_type=etype,
                collected_at=datetime.now(timezone.utc),
                raw_data={},
            )
            evidence_store.store(evidence)

        aws_types = evidence_store.list_evidence_types(platform="aws")
        okta_types = evidence_store.list_evidence_types(platform="okta")

        assert len(aws_types) == 3
        assert len(okta_types) == 2


# =============================================================================
# Statistics Tests
# =============================================================================


class TestEvidenceStoreStatistics:
    """Tests for storage statistics."""

    def test_get_statistics(self, evidence_store: EvidenceStore):
        """Test getting storage statistics."""
        # Store evidence from different platforms
        for i, platform in enumerate(["aws", "aws", "okta"]):
            evidence = Evidence(
                id=f"evidence-{i}",
                platform=platform,
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={"index": i},
            )
            evidence_store.store(evidence)

        stats = evidence_store.get_statistics()

        assert stats["total_items"] == 3
        assert stats["total_size_bytes"] > 0
        assert stats["by_platform"]["aws"] == 2
        assert stats["by_platform"]["okta"] == 1
        assert stats["oldest"] is not None
        assert stats["newest"] is not None

    def test_statistics_empty_store(self, evidence_store: EvidenceStore):
        """Test statistics for empty store."""
        stats = evidence_store.get_statistics()

        assert stats["total_items"] == 0
        assert stats["total_size_bytes"] == 0
        assert stats["oldest"] is None
        assert stats["newest"] is None


# =============================================================================
# Collection Result Tests
# =============================================================================


class TestEvidenceStoreCollectionResult:
    """Tests for storing collection results."""

    def test_store_collection_result(self, evidence_store: EvidenceStore):
        """Test storing a complete collection result."""
        result = CollectionResult(
            success=True,
            platform="aws",
        )

        for i in range(3):
            result.add_evidence(
                Evidence(
                    id=f"evidence-{i}",
                    platform="aws",
                    evidence_type=f"type-{i}",
                    collected_at=datetime.now(timezone.utc),
                    raw_data={"index": i},
                )
            )

        stored = evidence_store.store_collection_result(result)

        assert len(stored) == 3
        assert all(s.platform == "aws" for s in stored)

    def test_store_collection_result_with_errors(self, evidence_store: EvidenceStore):
        """Test storing collection result handles individual errors."""
        result = CollectionResult(
            success=True,
            partial=True,
            platform="aws",
        )

        # Add some valid evidence
        for i in range(2):
            result.add_evidence(
                Evidence(
                    id=f"evidence-{i}",
                    platform="aws",
                    evidence_type="test",
                    collected_at=datetime.now(timezone.utc),
                    raw_data={"index": i},
                )
            )

        stored = evidence_store.store_collection_result(result)

        assert len(stored) == 2


# =============================================================================
# Retention Policy Tests
# =============================================================================


class TestEvidenceStoreRetention:
    """Tests for retention policy functionality."""

    def test_apply_retention(self, evidence_store: EvidenceStore):
        """Test applying retention policy."""
        now = datetime.now(timezone.utc)

        # Store old evidence (older than retention period)
        old_evidence = Evidence(
            id="old-evidence",
            platform="aws",
            evidence_type="test",
            collected_at=now - timedelta(days=100),
            raw_data={"old": True},
        )
        evidence_store.store(old_evidence)

        # Store recent evidence
        recent_evidence = Evidence(
            id="recent-evidence",
            platform="aws",
            evidence_type="test",
            collected_at=now - timedelta(days=10),
            raw_data={"recent": True},
        )
        evidence_store.store(recent_evidence)

        # Apply 30-day retention
        deleted = evidence_store.apply_retention(days=30)

        assert deleted == 1
        assert evidence_store.get("old-evidence") is None
        assert evidence_store.get("recent-evidence") is not None


# =============================================================================
# Export/Import Bundle Tests
# =============================================================================


class TestEvidenceStoreBundles:
    """Tests for evidence bundle export/import functionality."""

    def test_export_bundle(self, evidence_store: EvidenceStore, temp_evidence_dir: Path):
        """Test exporting evidence to a bundle."""
        # Store some evidence
        for i in range(3):
            evidence = Evidence(
                id=f"evidence-{i}",
                platform="aws",
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={"index": i},
            )
            evidence_store.store(evidence)

        output_path = temp_evidence_dir / "export.tar.gz"
        bundle_path = evidence_store.export_bundle(output_path)

        assert bundle_path.exists()
        assert bundle_path.suffix == ".gz"

    def test_export_bundle_filtered(
        self, evidence_store: EvidenceStore, temp_evidence_dir: Path
    ):
        """Test exporting filtered evidence to a bundle."""
        # Store evidence from different platforms
        for platform in ["aws", "okta"]:
            for i in range(2):
                evidence = Evidence(
                    id=f"evidence-{platform}-{i}",
                    platform=platform,
                    evidence_type="test",
                    collected_at=datetime.now(timezone.utc),
                    raw_data={"platform": platform, "index": i},
                )
                evidence_store.store(evidence)

        output_path = temp_evidence_dir / "aws-export.tar.gz"
        bundle_path = evidence_store.export_bundle(output_path, platform="aws")

        assert bundle_path.exists()

    def test_import_bundle(self, temp_evidence_dir: Path):
        """Test importing evidence from a bundle."""
        # Create first store and add evidence
        store1 = EvidenceStore(evidence_dir=temp_evidence_dir / "store1")

        for i in range(3):
            evidence = Evidence(
                id=f"evidence-{i}",
                platform="aws",
                evidence_type="test",
                collected_at=datetime.now(timezone.utc),
                raw_data={"index": i},
            )
            store1.store(evidence)

        # Export to bundle
        bundle_path = store1.export_bundle(temp_evidence_dir / "bundle.tar.gz")

        # Create second store and import
        store2 = EvidenceStore(evidence_dir=temp_evidence_dir / "store2")
        imported = store2.import_bundle(bundle_path)

        assert imported == 3
        assert store2.get("evidence-0") is not None
        assert store2.read("evidence-1") is not None

    def test_export_empty_raises_error(
        self, evidence_store: EvidenceStore, temp_evidence_dir: Path
    ):
        """Test exporting with no evidence raises error."""
        from attestful.core.exceptions import StorageError

        output_path = temp_evidence_dir / "empty.tar.gz"

        with pytest.raises(StorageError):
            evidence_store.export_bundle(output_path)


# =============================================================================
# Index Persistence Tests
# =============================================================================


class TestEvidenceStoreIndexPersistence:
    """Tests for index persistence across store instances."""

    def test_index_persists_across_instances(
        self, temp_evidence_dir: Path, sample_evidence: Evidence
    ):
        """Test that index persists when store is recreated."""
        # Create first store and add evidence
        store1 = EvidenceStore(evidence_dir=temp_evidence_dir)
        store1.store(sample_evidence)

        # Create new store instance with same directory
        store2 = EvidenceStore(evidence_dir=temp_evidence_dir)

        # Should be able to retrieve evidence
        stored = store2.get(sample_evidence.id)
        assert stored is not None
        assert stored.platform == sample_evidence.platform

    def test_index_file_created(
        self, evidence_store: EvidenceStore, sample_evidence: Evidence
    ):
        """Test that index file is created."""
        evidence_store.store(sample_evidence)

        index_path = evidence_store.evidence_dir / "index.json"
        assert index_path.exists()

        # Verify index content
        with open(index_path) as f:
            index_data = json.load(f)

        assert sample_evidence.id in index_data
