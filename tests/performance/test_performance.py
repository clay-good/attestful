"""
Performance tests for Attestful.

Tests cover:
- Scan performance with varying resource counts
- Collection performance with large evidence sets
- Database query performance
- Report generation performance
- Memory usage benchmarks
"""

from __future__ import annotations

import gc
import json
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Callable

import pytest

from attestful.core.evaluator import (
    Evaluator,
    CheckDefinition,
    Condition,
    Operator,
    create_default_evaluator,
)
from attestful.core.models import (
    CollectionResult,
    Evidence,
    Resource,
)
from attestful.analysis.maturity import MaturityCalculator
from attestful.storage.evidence import EvidenceStore
from attestful.oscal.catalog import CatalogLoader, CatalogIndex
from attestful.oscal.models import (
    Catalog,
    Control,
    Group,
    Metadata,
)


# =============================================================================
# Benchmark Utilities
# =============================================================================


def benchmark(
    func: Callable,
    *args: Any,
    iterations: int = 3,
    **kwargs: Any,
) -> dict[str, float]:
    """
    Benchmark a function.

    Returns:
        Dictionary with min, max, avg execution times in seconds.
    """
    times = []

    for _ in range(iterations):
        gc.collect()  # Clean up before each iteration
        start = time.perf_counter()
        func(*args, **kwargs)
        end = time.perf_counter()
        times.append(end - start)

    return {
        "min": min(times),
        "max": max(times),
        "avg": sum(times) / len(times),
        "iterations": iterations,
    }


def measure_memory() -> int:
    """Get current memory usage in bytes."""
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss
    except ImportError:
        # Fallback if psutil not available
        import resource
        import sys
        maxrss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # On Linux, maxrss is in KB. On macOS/BSD, it's in bytes.
        if sys.platform == "darwin":
            return maxrss
        return maxrss * 1024


# =============================================================================
# Resource Generation Helpers
# =============================================================================


def generate_s3_buckets(count: int) -> list[Resource]:
    """Generate sample S3 bucket resources."""
    resources = []
    for i in range(count):
        encrypted = i % 3 != 0  # 2/3 encrypted
        versioned = i % 2 == 0  # 1/2 versioned

        raw_data: dict[str, Any] = {"Name": f"bucket-{i}"}

        if encrypted:
            raw_data["Encryption"] = {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                    ]
                }
            }

        if versioned:
            raw_data["Versioning"] = {"Status": "Enabled"}
        else:
            raw_data["Versioning"] = {"Status": "Suspended"}

        raw_data["PublicAccessBlock"] = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            }
        }

        resources.append(
            Resource(
                id=f"bucket-{i}",
                type="s3_bucket",
                provider="aws",
                region="us-east-1",
                name=f"test-bucket-{i}",
                raw_data=raw_data,
            )
        )

    return resources


def generate_ec2_instances(count: int) -> list[Resource]:
    """Generate sample EC2 instance resources."""
    resources = []
    for i in range(count):
        imdsv2 = i % 4 != 0  # 3/4 have IMDSv2

        resources.append(
            Resource(
                id=f"i-{i:012d}",
                type="ec2_instance",
                provider="aws",
                region="us-west-2",
                name=f"instance-{i}",
                raw_data={
                    "InstanceId": f"i-{i:012d}",
                    "MetadataOptions": {
                        "HttpTokens": "required" if imdsv2 else "optional"
                    },
                    "PublicIpAddress": None if i % 2 == 0 else f"1.2.3.{i % 256}",
                    "State": {"Name": "running"},
                },
            )
        )

    return resources


def generate_iam_users(count: int) -> list[Resource]:
    """Generate sample IAM user resources."""
    resources = []
    for i in range(count):
        has_mfa = i % 5 != 0  # 4/5 have MFA

        mfa_devices = []
        if has_mfa:
            mfa_devices = [{"SerialNumber": f"arn:aws:iam::123456789012:mfa/user-{i}"}]

        resources.append(
            Resource(
                id=f"user-{i}",
                type="iam_user",
                provider="aws",
                name=f"user-{i}",
                raw_data={
                    "UserName": f"user-{i}",
                    "MFADevices": mfa_devices,
                    "AccessKeys": [
                        {"AccessKeyId": f"AKIA{i:016d}", "Status": "Active"}
                    ],
                },
            )
        )

    return resources


def generate_mixed_resources(count: int) -> list[Resource]:
    """Generate a mix of different resource types."""
    s3_count = count // 3
    ec2_count = count // 3
    iam_count = count - s3_count - ec2_count

    resources = []
    resources.extend(generate_s3_buckets(s3_count))
    resources.extend(generate_ec2_instances(ec2_count))
    resources.extend(generate_iam_users(iam_count))

    return resources


def generate_evidence(count: int) -> list[Evidence]:
    """Generate sample evidence items."""
    evidence_types = [
        "iam_credential_report",
        "password_policy",
        "cloudtrail_status",
        "guardduty_status",
        "config_status",
        "securityhub_findings",
    ]

    evidence_items = []
    for i in range(count):
        evidence_type = evidence_types[i % len(evidence_types)]

        evidence_items.append(
            Evidence(
                platform="aws",
                evidence_type=evidence_type,
                collected_at=datetime.now(timezone.utc) - timedelta(hours=i),
                raw_data={
                    "type": evidence_type,
                    "index": i,
                    "data": {"key": f"value-{i}" * 100},  # Some data volume
                },
                metadata={"collection_method": "automated" if i % 2 == 0 else "manual"},
            )
        )

    return evidence_items


def generate_controls(count: int) -> list[Control]:
    """Generate sample OSCAL controls."""
    return [
        Control(id=f"CTRL-{i}", title=f"Control {i}")
        for i in range(count)
    ]


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def evaluator() -> Evaluator:
    """Default evaluator with checks."""
    return create_default_evaluator()


@pytest.fixture
def temp_store(tmp_path: Path) -> EvidenceStore:
    """Temporary evidence store."""
    return EvidenceStore(evidence_dir=tmp_path)


# =============================================================================
# Scan Performance Tests (Step 11.5.1)
# =============================================================================


@pytest.mark.slow
class TestScanPerformance:
    """Tests for scan performance benchmarks."""

    @pytest.mark.parametrize("resource_count", [100, 1000, 10000])
    def test_scan_performance_scaling(
        self,
        evaluator: Evaluator,
        resource_count: int,
    ) -> None:
        """Test scan performance with varying resource counts."""
        resources = generate_mixed_resources(resource_count)

        result = benchmark(
            evaluator.evaluate,
            resources,
            iterations=3,
        )

        # Log results
        print(f"\nScan performance ({resource_count} resources):")
        print(f"  Min: {result['min']:.3f}s")
        print(f"  Max: {result['max']:.3f}s")
        print(f"  Avg: {result['avg']:.3f}s")
        print(f"  Resources/sec: {resource_count / result['avg']:.0f}")

        # Performance assertions
        # Should process at least 100 resources/second
        assert result["avg"] < resource_count / 100

    def test_scan_memory_usage(
        self, evaluator: Evaluator
    ) -> None:
        """Test memory usage during scan."""
        resource_count = 10000
        resources = generate_mixed_resources(resource_count)

        gc.collect()
        memory_before = measure_memory()

        results = evaluator.evaluate(resources)

        memory_after = measure_memory()
        memory_used = memory_after - memory_before

        print(f"\nScan memory usage ({resource_count} resources):")
        print(f"  Memory used: {memory_used / 1024 / 1024:.2f} MB")
        print(f"  Results count: {len(results)}")
        print(f"  Memory per resource: {memory_used / resource_count / 1024:.2f} KB")

        # Should use less than 100MB for 10k resources
        assert memory_used < 100 * 1024 * 1024

    def test_scan_check_evaluation_performance(
        self, evaluator: Evaluator
    ) -> None:
        """Test individual check evaluation performance."""
        # Single resource, many checks
        resource = generate_s3_buckets(1)[0]

        result = benchmark(
            evaluator.evaluate,
            [resource],
            iterations=10,
        )

        checks_count = len(evaluator.list_checks(resource_type="s3_bucket"))

        print(f"\nCheck evaluation performance:")
        print(f"  Checks evaluated: {checks_count}")
        print(f"  Avg time: {result['avg'] * 1000:.2f}ms")
        print(f"  Time per check: {result['avg'] / checks_count * 1000:.2f}ms")

        # Each check should complete in < 1ms average
        assert result["avg"] / checks_count < 0.001


# =============================================================================
# Collection Performance Tests (Step 11.5.2)
# =============================================================================


@pytest.mark.slow
class TestCollectionPerformance:
    """Tests for collection performance benchmarks."""

    @pytest.mark.parametrize("evidence_count", [100, 500, 1000])
    def test_evidence_storage_performance(
        self,
        temp_store: EvidenceStore,
        evidence_count: int,
    ) -> None:
        """Test evidence storage performance."""
        evidence_items = generate_evidence(evidence_count)

        def store_all():
            for e in evidence_items:
                temp_store.store(e)

        result = benchmark(store_all, iterations=1)

        print(f"\nEvidence storage ({evidence_count} items):")
        print(f"  Time: {result['avg']:.3f}s")
        print(f"  Items/sec: {evidence_count / result['avg']:.0f}")

        # Should store at least 100 items/second
        assert result["avg"] < evidence_count / 100

    def test_maturity_calculation_performance(self) -> None:
        """Test maturity calculation performance."""
        evidence_counts = [10, 50, 100, 200]

        for count in evidence_counts:
            evidence = generate_evidence(count)
            calc = MaturityCalculator(framework="nist-csf-2")

            def calculate_maturity():
                calc._evidence = []
                calc._category_evidence = {}
                calc.add_evidence(evidence)
                return calc.calculate()

            result = benchmark(calculate_maturity, iterations=3)

            print(f"\nMaturity calculation ({count} evidence items):")
            print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # With 200 evidence items, should complete in < 1 second
        assert result["avg"] < 1.0

    def test_evidence_retrieval_performance(
        self, temp_store: EvidenceStore
    ) -> None:
        """Test evidence retrieval performance."""
        # Store evidence first
        evidence_items = generate_evidence(500)
        stored_items = [temp_store.store(e) for e in evidence_items]

        # Benchmark retrieval - use stored.id instead of stored directly
        def retrieve_all():
            for stored in stored_items:
                temp_store.get(stored.id)

        result = benchmark(retrieve_all, iterations=3)

        print(f"\nEvidence retrieval (500 items):")
        print(f"  Time: {result['avg']:.3f}s")
        print(f"  Items/sec: {500 / result['avg']:.0f}")

        # Should retrieve at least 500 items/second
        assert result["avg"] < 1.0


# =============================================================================
# Database Query Performance Tests (Step 11.5.3)
# =============================================================================


@pytest.mark.slow
class TestDatabasePerformance:
    """Tests for database query performance."""

    def test_evidence_query_by_type_performance(
        self, temp_store: EvidenceStore
    ) -> None:
        """Test querying evidence by type performance."""
        # Store mixed evidence
        evidence_items = generate_evidence(1000)
        for e in evidence_items:
            temp_store.store(e)

        def query_by_type():
            return temp_store.get_by_type(
                platform="aws",
                evidence_type="iam_credential_report",
            )

        result = benchmark(query_by_type, iterations=5)

        print(f"\nQuery by type (from 1000 items):")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # Query should complete in < 100ms
        assert result["avg"] < 0.1

    def test_evidence_query_by_date_performance(
        self, temp_store: EvidenceStore
    ) -> None:
        """Test querying evidence by date range performance."""
        # Store evidence with dates spread over 30 days
        evidence_items = generate_evidence(1000)
        for e in evidence_items:
            temp_store.store(e)

        def query_by_date():
            return temp_store.get_by_date_range(
                start=datetime.now(timezone.utc) - timedelta(days=7),
                end=datetime.now(timezone.utc),
            )

        result = benchmark(query_by_date, iterations=5)

        print(f"\nQuery by date range (from 1000 items):")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # Query should complete in < 200ms
        assert result["avg"] < 0.2

    def test_evidence_aggregation_performance(
        self, temp_store: EvidenceStore
    ) -> None:
        """Test evidence aggregation performance."""
        evidence_items = generate_evidence(500)
        for e in evidence_items:
            temp_store.store(e)

        def aggregate():
            all_evidence = temp_store.get_all()
            by_type: dict[str, list] = {}
            for e in all_evidence:
                if e.evidence_type not in by_type:
                    by_type[e.evidence_type] = []
                by_type[e.evidence_type].append(e)
            return by_type

        result = benchmark(aggregate, iterations=5)

        print(f"\nEvidence aggregation (500 items):")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # Aggregation should complete in < 500ms
        assert result["avg"] < 0.5


# =============================================================================
# Report Generation Performance Tests (Step 11.5.4)
# =============================================================================


@pytest.mark.slow
class TestReportPerformance:
    """Tests for report generation performance."""

    @pytest.mark.parametrize("finding_count", [100, 1000, 10000])
    def test_report_data_generation_performance(
        self,
        evaluator: Evaluator,
        finding_count: int,
    ) -> None:
        """Test report data generation with many findings."""
        # Generate resources to produce findings
        resource_count = finding_count // 5  # Assume ~5 checks per resource
        resources = generate_mixed_resources(resource_count)

        # Run scan to get findings
        scan_results = evaluator.evaluate(resources)

        def generate_report_data():
            # Simulate report data generation
            report_data = {
                "title": "Compliance Report",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total_resources": len(resources),
                    "total_checks": len(scan_results),
                    "passed": sum(1 for r in scan_results if r.passed),
                    "failed": sum(1 for r in scan_results if not r.passed),
                },
                "findings": [
                    {
                        "check_id": r.check.id,
                        "check_title": r.check.title,
                        "severity": r.check.severity,
                        "resource_id": r.resource_id,
                        "passed": r.passed,
                        "details": r.details,
                    }
                    for r in scan_results
                ],
            }
            return json.dumps(report_data)

        result = benchmark(generate_report_data, iterations=3)

        print(f"\nReport generation ({len(scan_results)} findings):")
        print(f"  Time: {result['avg']:.3f}s")
        print(f"  Findings/sec: {len(scan_results) / result['avg']:.0f}")

        # Should generate report in < 5 seconds for 10k findings
        assert result["avg"] < 5.0

    def test_report_memory_usage(
        self, evaluator: Evaluator
    ) -> None:
        """Test memory usage during report generation."""
        resources = generate_mixed_resources(5000)
        scan_results = evaluator.evaluate(resources)

        gc.collect()
        memory_before = measure_memory()

        # Generate report data
        report_data = {
            "findings": [
                {
                    "check_id": r.check.id,
                    "resource_id": r.resource_id,
                    "passed": r.passed,
                    "details": r.details,
                }
                for r in scan_results
            ],
        }
        report_json = json.dumps(report_data)

        memory_after = measure_memory()
        memory_used = memory_after - memory_before

        print(f"\nReport memory usage ({len(scan_results)} findings):")
        print(f"  Report size: {len(report_json) / 1024 / 1024:.2f} MB")
        print(f"  Memory used: {memory_used / 1024 / 1024:.2f} MB")

        # Should use less than 200MB for report with 5000+ findings
        assert memory_used < 200 * 1024 * 1024


# =============================================================================
# OSCAL Performance Tests
# =============================================================================


@pytest.mark.slow
class TestOSCALPerformance:
    """Tests for OSCAL operations performance."""

    def test_catalog_indexing_performance(self) -> None:
        """Test catalog indexing performance with many controls."""
        control_counts = [100, 500, 1000]

        for count in control_counts:
            # Create catalog with many controls
            controls = generate_controls(count)
            catalog = Catalog(
                uuid=__import__("uuid").uuid4(),
                metadata=Metadata(
                    title="Test Catalog",
                    last_modified=datetime.now(timezone.utc),
                    version="1.0",
                ),
                controls=controls,
            )

            def create_index():
                return CatalogIndex(catalog)

            result = benchmark(create_index, iterations=5)

            print(f"\nCatalog indexing ({count} controls):")
            print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # Indexing 1000 controls should take < 100ms
        assert result["avg"] < 0.1

    def test_control_lookup_performance(self) -> None:
        """Test control lookup performance."""
        controls = generate_controls(1000)
        catalog = Catalog(
            uuid=__import__("uuid").uuid4(),
            metadata=Metadata(
                title="Test Catalog",
                last_modified=datetime.now(timezone.utc),
                version="1.0",
            ),
            controls=controls,
        )
        index = CatalogIndex(catalog)

        def lookup_controls():
            # Look up 100 random controls
            for i in range(0, 1000, 10):
                index.get_control(f"CTRL-{i}")

        result = benchmark(lookup_controls, iterations=10)

        print(f"\nControl lookup (100 lookups from 1000):")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")
        print(f"  Lookups/sec: {100 / result['avg']:.0f}")

        # 100 lookups should complete in < 10ms (O(1) per lookup)
        assert result["avg"] < 0.01

    def test_oscal_serialization_performance(self) -> None:
        """Test OSCAL JSON serialization performance."""
        controls = generate_controls(500)
        catalog = Catalog(
            uuid=__import__("uuid").uuid4(),
            metadata=Metadata(
                title="Test Catalog",
                last_modified=datetime.now(timezone.utc),
                version="1.0",
            ),
            controls=controls,
        )

        def serialize():
            return catalog.to_json()

        result = benchmark(serialize, iterations=5)

        json_output = catalog.to_json()

        print(f"\nOSCAL serialization ({len(controls)} controls):")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")
        print(f"  Output size: {len(json_output) / 1024:.2f} KB")

        # Serialization should complete in < 100ms
        assert result["avg"] < 0.1


# =============================================================================
# Stress Tests
# =============================================================================


@pytest.mark.slow
class TestStress:
    """Stress tests for edge cases."""

    def test_concurrent_evidence_storage(
        self, tmp_path: Path
    ) -> None:
        """Test concurrent evidence storage (simulated)."""
        import threading

        store = EvidenceStore(evidence_dir=tmp_path)
        evidence_items = generate_evidence(100)

        errors: list[Exception] = []

        def store_evidence(items):
            try:
                for e in items:
                    store.store(e)
            except Exception as ex:
                errors.append(ex)

        # Simulate concurrent access
        threads = []
        chunk_size = 20
        for i in range(0, len(evidence_items), chunk_size):
            chunk = evidence_items[i:i + chunk_size]
            t = threading.Thread(target=store_evidence, args=(chunk,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        print(f"\nConcurrent storage test:")
        print(f"  Threads: {len(threads)}")
        print(f"  Items stored: {len(evidence_items)}")
        print(f"  Errors: {len(errors)}")

        # Should handle concurrent access without errors
        assert len(errors) == 0

    def test_large_resource_data(
        self, evaluator: Evaluator
    ) -> None:
        """Test handling resources with large raw_data."""
        # Create resource with large data
        large_data = {f"key_{i}": f"value_{i}" * 1000 for i in range(100)}

        resource = Resource(
            id="large-resource",
            type="s3_bucket",
            provider="aws",
            region="us-east-1",
            name="large-bucket",
            raw_data={
                "Name": "large-bucket",
                "Encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                },
                "extra_data": large_data,
            },
        )

        result = benchmark(
            evaluator.evaluate,
            [resource],
            iterations=10,
        )

        print(f"\nLarge resource evaluation:")
        print(f"  Raw data size: ~{len(json.dumps(resource.raw_data)) / 1024:.2f} KB")
        print(f"  Time: {result['avg'] * 1000:.2f}ms")

        # Should still complete quickly
        assert result["avg"] < 0.1
