"""
Unit tests for OSCAL Assessment Results generation.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import yaml

from attestful.core.models import ComplianceCheck, CheckResult, CheckStatus, Evidence, Severity
from attestful.oscal.assessment import (
    AssessmentConfig,
    AssessmentResultsGenerator,
    AssessmentResultsLoader,
    create_assessment_from_scan,
    get_assessment_summary,
)
from attestful.oscal.models import AssessmentResults


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def assessment_config():
    """Sample assessment configuration."""
    return AssessmentConfig(
        title="Test Assessment",
        description="Automated compliance assessment for testing",
        organization_name="Test Organization",
        assessor_name="Attestful Test Scanner",
        version="1.0.0",
    )


@pytest.fixture
def sample_check():
    """Sample compliance check."""
    return ComplianceCheck(
        id="s3-encryption",
        title="S3 Bucket Encryption",
        description="Ensure S3 buckets have encryption enabled",
        severity="high",
        resource_types=["s3_bucket"],
        remediation="Enable default encryption on the S3 bucket",
        framework_mappings={
            "soc2": ["CC6.1"],
            "nist-800-53": ["SC-28"],
        },
    )


@pytest.fixture
def sample_check_results(sample_check):
    """Sample check results for testing."""
    return [
        CheckResult(
            check=sample_check,
            check_id=sample_check.id,
            resource_id="bucket-1",
            resource_type="s3_bucket",
            passed=True,
            status=CheckStatus.PASS,
            severity=Severity.HIGH,
            message="Encryption is enabled",
            evaluated_at=datetime.now(timezone.utc),
        ),
        CheckResult(
            check=sample_check,
            check_id=sample_check.id,
            resource_id="bucket-2",
            resource_type="s3_bucket",
            passed=False,
            status=CheckStatus.FAIL,
            severity=Severity.HIGH,
            message="Encryption is not enabled",
            evaluated_at=datetime.now(timezone.utc),
        ),
        CheckResult(
            check=sample_check,
            check_id=sample_check.id,
            resource_id="bucket-3",
            resource_type="s3_bucket",
            passed=True,
            status=CheckStatus.PASS,
            severity=Severity.HIGH,
            message="Encryption is enabled",
            evaluated_at=datetime.now(timezone.utc),
        ),
    ]


@pytest.fixture
def sample_evidence():
    """Sample evidence items for testing."""
    return [
        Evidence(
            id=str(uuid4()),
            evidence_type="iam_users",
            platform="aws",
            collected_at=datetime.now(timezone.utc),
            raw_data={"users": ["admin", "developer"]},
        ),
        Evidence(
            id=str(uuid4()),
            evidence_type="mfa_status",
            platform="okta",
            collected_at=datetime.now(timezone.utc),
            raw_data={"mfa_enabled": True},
        ),
    ]


# =============================================================================
# AssessmentConfig Tests
# =============================================================================


class TestAssessmentConfig:
    """Tests for AssessmentConfig dataclass."""

    def test_config_defaults(self):
        """Test default values."""
        config = AssessmentConfig(title="Test")
        assert config.title == "Test"
        assert config.description == "Automated compliance assessment"
        assert config.organization_name == "Organization"
        assert config.version == "1.0.0"
        assert config.assessment_plan_href == "#assessment-plan"

    def test_config_custom_values(self):
        """Test custom configuration values."""
        custom_uuid = uuid4()
        config = AssessmentConfig(
            title="Custom Assessment",
            description="Custom description",
            organization_name="Custom Org",
            organization_uuid=custom_uuid,
            assessor_name="Custom Scanner",
            version="2.0.0",
        )
        assert config.title == "Custom Assessment"
        assert config.organization_uuid == custom_uuid
        assert config.version == "2.0.0"


# =============================================================================
# AssessmentResultsGenerator Tests
# =============================================================================


class TestAssessmentResultsGenerator:
    """Tests for AssessmentResultsGenerator."""

    def test_init(self, assessment_config):
        """Test generator initialization."""
        generator = AssessmentResultsGenerator(assessment_config)
        assert generator.config == assessment_config
        assert generator.check_results == []
        assert generator.evidence_items == []
        assert generator.start_time is not None

    def test_add_check_results(self, assessment_config, sample_check_results):
        """Test adding check results."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        assert len(generator.check_results) == 3

    def test_add_evidence(self, assessment_config, sample_evidence):
        """Test adding evidence items."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_evidence(sample_evidence)
        assert len(generator.evidence_items) == 2

    def test_set_assessment_period(self, assessment_config):
        """Test setting assessment period."""
        generator = AssessmentResultsGenerator(assessment_config)
        start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        end = datetime(2024, 1, 15, tzinfo=timezone.utc)
        generator.set_assessment_period(start, end)
        assert generator.start_time == start
        assert generator.end_time == end

    def test_generate_empty(self, assessment_config):
        """Test generating with no results."""
        generator = AssessmentResultsGenerator(assessment_config)
        results = generator.generate()

        assert isinstance(results, AssessmentResults)
        assert results.metadata.title == "Test Assessment"
        assert len(results.results) == 1
        assert results.results[0].observations is None or len(results.results[0].observations) == 0

    def test_generate_with_results(self, assessment_config, sample_check_results):
        """Test generating with check results."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        assert isinstance(results, AssessmentResults)
        assert len(results.results) == 1

        result = results.results[0]
        assert result.observations is not None
        assert len(result.observations) == 3  # One per check result

        # Should have one finding for the failed check
        assert result.findings is not None
        assert len(result.findings) == 1

    def test_generate_with_evidence(self, assessment_config, sample_evidence):
        """Test generating with evidence items."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_evidence(sample_evidence)
        results = generator.generate()

        result = results.results[0]
        assert result.observations is not None
        assert len(result.observations) == 2  # One per evidence item

    def test_generate_with_both(self, assessment_config, sample_check_results, sample_evidence):
        """Test generating with both check results and evidence."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        generator.add_evidence(sample_evidence)
        results = generator.generate()

        result = results.results[0]
        assert result.observations is not None
        assert len(result.observations) == 5  # 3 checks + 2 evidence

    def test_metadata_structure(self, assessment_config):
        """Test metadata is properly structured."""
        generator = AssessmentResultsGenerator(assessment_config)
        results = generator.generate()

        metadata = results.metadata
        assert metadata.title == "Test Assessment"
        assert metadata.oscal_version == "1.1.2"
        assert metadata.roles is not None
        assert len(metadata.roles) >= 1
        assert metadata.parties is not None
        assert len(metadata.parties) >= 1

    def test_result_properties(self, assessment_config, sample_check_results):
        """Test result contains proper properties."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        result = results.results[0]
        assert result.props is not None

        prop_names = {p.name for p in result.props}
        assert "total-checks" in prop_names
        assert "passed-checks" in prop_names
        assert "failed-checks" in prop_names

        # Verify counts
        for prop in result.props:
            if prop.name == "total-checks":
                assert prop.value == "3"
            elif prop.name == "passed-checks":
                assert prop.value == "2"
            elif prop.name == "failed-checks":
                assert prop.value == "1"

    def test_observation_structure(self, assessment_config, sample_check_results):
        """Test observation structure."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        result = results.results[0]
        obs = result.observations[0]

        assert obs.uuid is not None
        assert obs.title is not None
        assert "AUTOMATED" in obs.methods
        assert obs.collected is not None

    def test_finding_structure(self, assessment_config, sample_check_results):
        """Test finding structure for failed checks."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        result = results.results[0]
        finding = result.findings[0]

        assert finding.uuid is not None
        assert finding.title is not None
        assert finding.target is not None
        assert finding.target.status["state"] == "not-satisfied"

    def test_reviewed_controls(self, assessment_config, sample_check_results):
        """Test reviewed controls section."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        result = results.results[0]
        assert result.reviewed_controls is not None
        assert "control-selections" in result.reviewed_controls


class TestAssessmentResultsSerialization:
    """Tests for Assessment Results serialization."""

    def test_to_json(self, assessment_config, sample_check_results):
        """Test JSON serialization."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        json_str = results.to_json()
        assert json_str is not None

        # Verify it's valid JSON
        data = json.loads(json_str)
        assert "uuid" in data
        assert "metadata" in data
        assert "results" in data

    def test_to_yaml(self, assessment_config, sample_check_results):
        """Test YAML serialization."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        results = generator.generate()

        yaml_str = results.to_yaml()
        assert yaml_str is not None

        # Verify it's valid YAML
        data = yaml.safe_load(yaml_str)
        assert "uuid" in data
        assert "metadata" in data
        assert "results" in data

    def test_save_json(self, assessment_config, sample_check_results, tmp_path):
        """Test saving to JSON file."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)

        output_path = tmp_path / "assessment.json"
        result_path = generator.save(output_path, format="json")

        assert result_path.exists()
        content = result_path.read_text()
        data = json.loads(content)
        assert "assessment-results" in data

    def test_save_yaml(self, assessment_config, sample_check_results, tmp_path):
        """Test saving to YAML file."""
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)

        output_path = tmp_path / "assessment.yaml"
        result_path = generator.save(output_path, format="yaml")

        assert result_path.exists()
        content = result_path.read_text()
        data = yaml.safe_load(content)
        assert "assessment-results" in data

    def test_save_auto_extension(self, assessment_config, tmp_path):
        """Test automatic file extension."""
        generator = AssessmentResultsGenerator(assessment_config)

        json_path = generator.save(tmp_path / "test1", format="json")
        assert json_path.suffix == ".json"

        yaml_path = generator.save(tmp_path / "test2", format="yaml")
        assert yaml_path.suffix == ".yaml"

    def test_save_invalid_format(self, assessment_config, tmp_path):
        """Test invalid format raises error."""
        from attestful.core.exceptions import OSCALError

        generator = AssessmentResultsGenerator(assessment_config)

        with pytest.raises(OSCALError):
            generator.save(tmp_path / "test", format="invalid")


# =============================================================================
# AssessmentResultsLoader Tests
# =============================================================================


class TestAssessmentResultsLoader:
    """Tests for AssessmentResultsLoader."""

    def test_load_json(self, assessment_config, sample_check_results, tmp_path):
        """Test loading JSON assessment results."""
        # Generate and save
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        saved_path = generator.save(tmp_path / "assessment.json")

        # Load
        loader = AssessmentResultsLoader()
        results = loader.load(saved_path)

        assert isinstance(results, AssessmentResults)
        assert results.metadata.title == "Test Assessment"
        assert len(results.results) == 1

    def test_load_yaml(self, assessment_config, sample_check_results, tmp_path):
        """Test loading YAML assessment results."""
        # Generate and save
        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(sample_check_results)
        saved_path = generator.save(tmp_path / "assessment.yaml", format="yaml")

        # Load
        loader = AssessmentResultsLoader()
        results = loader.load(saved_path)

        assert isinstance(results, AssessmentResults)
        assert results.metadata.title == "Test Assessment"

    def test_load_caching(self, assessment_config, tmp_path):
        """Test results caching."""
        generator = AssessmentResultsGenerator(assessment_config)
        saved_path = generator.save(tmp_path / "assessment.json")

        loader = AssessmentResultsLoader()

        results1 = loader.load(saved_path)
        results2 = loader.load(saved_path)

        # Should be the same cached object
        assert results1 is results2

    def test_load_no_cache(self, assessment_config, tmp_path):
        """Test loading without cache."""
        generator = AssessmentResultsGenerator(assessment_config)
        saved_path = generator.save(tmp_path / "assessment.json")

        loader = AssessmentResultsLoader()

        results1 = loader.load(saved_path, use_cache=True)
        results2 = loader.load(saved_path, use_cache=False)

        # Should be different objects
        assert results1 is not results2

    def test_load_nonexistent_file(self):
        """Test loading nonexistent file."""
        from attestful.core.exceptions import OSCALError

        loader = AssessmentResultsLoader()

        with pytest.raises(OSCALError):
            loader.load("/nonexistent/path.json")

    def test_clear_cache(self, assessment_config, tmp_path):
        """Test cache clearing."""
        generator = AssessmentResultsGenerator(assessment_config)
        saved_path = generator.save(tmp_path / "assessment.json")

        loader = AssessmentResultsLoader()
        loader.load(saved_path)

        assert len(loader._cache) > 0

        loader.clear_cache()
        assert len(loader._cache) == 0


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_assessment_from_scan(self, sample_check_results):
        """Test create_assessment_from_scan function."""
        results = create_assessment_from_scan(
            title="Quick Assessment",
            check_results=sample_check_results,
        )

        assert isinstance(results, AssessmentResults)
        assert results.metadata.title == "Quick Assessment"
        assert len(results.results) == 1

    def test_create_assessment_with_evidence(self, sample_check_results, sample_evidence):
        """Test create_assessment_from_scan with evidence."""
        results = create_assessment_from_scan(
            title="Assessment with Evidence",
            check_results=sample_check_results,
            evidence=sample_evidence,
        )

        result = results.results[0]
        assert result.observations is not None
        assert len(result.observations) == 5  # 3 checks + 2 evidence

    def test_create_assessment_with_config_kwargs(self, sample_check_results):
        """Test create_assessment_from_scan with config kwargs."""
        results = create_assessment_from_scan(
            title="Custom Assessment",
            check_results=sample_check_results,
            organization_name="Custom Org",
            version="2.0.0",
        )

        assert results.metadata.version == "2.0.0"

    def test_get_assessment_summary_empty(self, assessment_config):
        """Test summary with empty results."""
        generator = AssessmentResultsGenerator(assessment_config)
        results = generator.generate()

        summary = get_assessment_summary(results)

        assert summary["total_findings"] == 0
        assert summary["total_observations"] == 0

    def test_get_assessment_summary_with_results(self, sample_check_results):
        """Test summary with results."""
        results = create_assessment_from_scan(
            title="Test",
            check_results=sample_check_results,
        )

        summary = get_assessment_summary(results)

        assert summary["title"] == "Test"
        assert summary["total_findings"] == 1
        assert summary["total_observations"] == 3
        assert summary["passed_checks"] == 2
        assert summary["failed_checks"] == 1
        assert summary["pass_rate"] == pytest.approx(66.67, rel=0.1)
        assert summary["status"] == "complete"


# =============================================================================
# Edge Cases
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases."""

    def test_check_without_check_object(self, assessment_config):
        """Test handling check result without check object."""
        result = CheckResult(
            check=None,
            check_id="orphan-check",
            resource_id="resource-1",
            resource_type="unknown",
            passed=False,
            status=CheckStatus.FAIL,
            severity=Severity.MEDIUM,
            message="Check failed",
            evaluated_at=datetime.now(timezone.utc),
        )

        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results([result])
        results = generator.generate()

        assert len(results.results[0].observations) == 1
        assert len(results.results[0].findings) == 1

    def test_evidence_without_id(self, assessment_config):
        """Test handling evidence without ID."""
        evidence = Evidence(
            id=None,
            evidence_type="test",
            platform="test",
            collected_at=datetime.now(timezone.utc),
            raw_data={},
        )

        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_evidence([evidence])
        results = generator.generate()

        obs = results.results[0].observations[0]
        # Should not have relevant_evidence when no ID
        assert obs.relevant_evidence is None

    def test_all_passing_checks(self, assessment_config, sample_check):
        """Test with all passing checks - no findings."""
        results = [
            CheckResult(
                check=sample_check,
                check_id=sample_check.id,
                resource_id=f"resource-{i}",
                resource_type="s3_bucket",
                passed=True,
                status=CheckStatus.PASS,
                severity=Severity.HIGH,
                message="Passed",
                evaluated_at=datetime.now(timezone.utc),
            )
            for i in range(5)
        ]

        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(results)
        assessment = generator.generate()

        result = assessment.results[0]
        assert len(result.observations) == 5
        # No findings for passing checks
        assert result.findings is None or len(result.findings) == 0

    def test_all_failing_checks(self, assessment_config, sample_check):
        """Test with all failing checks."""
        results = [
            CheckResult(
                check=sample_check,
                check_id=sample_check.id,
                resource_id=f"resource-{i}",
                resource_type="s3_bucket",
                passed=False,
                status=CheckStatus.FAIL,
                severity=Severity.HIGH,
                message="Failed",
                evaluated_at=datetime.now(timezone.utc),
            )
            for i in range(5)
        ]

        generator = AssessmentResultsGenerator(assessment_config)
        generator.add_check_results(results)
        assessment = generator.generate()

        result = assessment.results[0]
        assert len(result.observations) == 5
        assert len(result.findings) == 5

    def test_multiple_add_calls(self, assessment_config, sample_check_results, sample_evidence):
        """Test multiple add calls accumulate."""
        generator = AssessmentResultsGenerator(assessment_config)

        generator.add_check_results(sample_check_results[:1])
        generator.add_check_results(sample_check_results[1:])
        generator.add_evidence(sample_evidence[:1])
        generator.add_evidence(sample_evidence[1:])

        assert len(generator.check_results) == 3
        assert len(generator.evidence_items) == 2
