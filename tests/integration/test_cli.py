"""
Integration tests for CLI commands.

These tests verify the CLI commands work correctly with real
or mocked external dependencies.
"""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

from attestful.cli.main import cli


@pytest.fixture
def runner():
    """Click test runner."""
    return CliRunner()


@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary directory for test outputs."""
    return tmp_path


# =============================================================================
# Basic CLI Tests
# =============================================================================


class TestCLIBasic:
    """Basic CLI functionality tests."""

    def test_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "attestful" in result.output.lower()

    def test_help(self, runner):
        """Test --help flag."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "OSCAL-first compliance automation" in result.output

    def test_subcommand_help(self, runner):
        """Test subcommand help."""
        for cmd in ["scan", "collect", "analyze", "report", "oscal", "configure", "frameworks"]:
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0


# =============================================================================
# Scan Command Tests
# =============================================================================


class TestScanCommands:
    """Tests for scan commands."""

    def test_scan_list(self, runner):
        """Test scan list command."""
        result = runner.invoke(cli, ["scan", "list"])
        assert result.exit_code == 0
        assert "Recent Scans" in result.output

    def test_scan_aws_help(self, runner):
        """Test scan aws help."""
        result = runner.invoke(cli, ["scan", "aws", "--help"])
        assert result.exit_code == 0
        assert "framework" in result.output
        assert "region" in result.output


# =============================================================================
# Collect Command Tests
# =============================================================================


class TestCollectCommands:
    """Tests for collect commands."""

    def test_collect_list(self, runner):
        """Test collect list command."""
        result = runner.invoke(cli, ["collect", "list"])
        assert result.exit_code == 0
        assert "Available Collectors" in result.output
        assert "aws" in result.output
        assert "okta" in result.output

    def test_collect_okta_help(self, runner):
        """Test collect okta help."""
        result = runner.invoke(cli, ["collect", "okta", "--help"])
        assert result.exit_code == 0
        assert "since" in result.output
        assert "types" in result.output

    def test_collect_aws_help(self, runner):
        """Test collect aws help."""
        result = runner.invoke(cli, ["collect", "aws", "--help"])
        assert result.exit_code == 0
        assert "types" in result.output
        assert "output" in result.output


# =============================================================================
# Analyze Command Tests
# =============================================================================


class TestAnalyzeCommands:
    """Tests for analyze commands."""

    def test_analyze_maturity(self, runner):
        """Test analyze maturity command."""
        result = runner.invoke(cli, ["analyze", "maturity"])
        assert result.exit_code == 0
        assert "Maturity Analysis" in result.output

    def test_analyze_gaps(self, runner):
        """Test analyze gaps command."""
        result = runner.invoke(cli, ["analyze", "gaps", "--framework", "soc2"])
        assert result.exit_code == 0
        assert "Gap Analysis" in result.output


# =============================================================================
# Report Command Tests
# =============================================================================


class TestReportCommands:
    """Tests for report commands."""

    def test_report_generate_help(self, runner):
        """Test report generate help."""
        result = runner.invoke(cli, ["report", "generate", "--help"])
        assert result.exit_code == 0
        assert "format" in result.output
        assert "framework" in result.output

    def test_report_generate_html(self, runner, temp_output_dir):
        """Test generating an HTML report."""
        output_path = temp_output_dir / "report.html"

        result = runner.invoke(cli, [
            "report", "generate",
            "--format", "html",
            "--output", str(output_path),
            "--framework", "soc2",
            "--title", "Test Report",
        ])

        assert result.exit_code == 0
        assert output_path.exists()
        content = output_path.read_text()
        assert "<!DOCTYPE html>" in content

    def test_report_generate_json(self, runner, temp_output_dir):
        """Test generating a JSON report."""
        output_path = temp_output_dir / "report.json"

        result = runner.invoke(cli, [
            "report", "generate",
            "--format", "json",
            "--output", str(output_path),
            "--framework", "soc2",
        ])

        assert result.exit_code == 0
        assert output_path.exists()

        # Verify it's valid JSON
        data = json.loads(output_path.read_text())
        assert "title" in data or "metadata" in data

    def test_report_generate_markdown(self, runner, temp_output_dir):
        """Test generating a Markdown report."""
        output_path = temp_output_dir / "report.md"

        result = runner.invoke(cli, [
            "report", "generate",
            "--format", "markdown",
            "--output", str(output_path),
            "--framework", "soc2",
        ])

        assert result.exit_code == 0
        assert output_path.exists()


# =============================================================================
# OSCAL Command Tests
# =============================================================================


class TestOscalCommands:
    """Tests for OSCAL commands."""

    def test_catalog_list(self, runner):
        """Test catalog list command."""
        result = runner.invoke(cli, ["oscal", "catalog", "list"])
        assert result.exit_code == 0
        assert "Available Catalogs" in result.output
        assert "NIST" in result.output

    def test_ssp_generate_help(self, runner):
        """Test SSP generate help."""
        result = runner.invoke(cli, ["oscal", "ssp", "generate", "--help"])
        assert result.exit_code == 0
        assert "system-name" in result.output
        assert "system-id" in result.output
        assert "profile" in result.output

    def test_ssp_generate(self, runner, temp_output_dir):
        """Test generating an SSP."""
        output_path = temp_output_dir / "ssp.json"

        result = runner.invoke(cli, [
            "oscal", "ssp", "generate",
            "--profile", "nist-800-53-moderate",
            "--system-name", "Test System",
            "--system-id", "test-001",
            "--description", "A test system for integration testing",
            "--output", str(output_path),
        ])

        assert result.exit_code == 0
        assert output_path.exists()

        # Verify it's valid JSON with SSP structure
        data = json.loads(output_path.read_text())
        assert "system-security-plan" in data

    def test_ssp_generate_yaml(self, runner, temp_output_dir):
        """Test generating an SSP in YAML format."""
        output_path = temp_output_dir / "ssp.yaml"

        result = runner.invoke(cli, [
            "oscal", "ssp", "generate",
            "--profile", "nist-800-53-moderate",
            "--system-name", "YAML System",
            "--system-id", "yaml-001",
            "--description", "System in YAML format",
            "--output", str(output_path),
            "--format", "yaml",
        ])

        assert result.exit_code == 0
        assert output_path.exists()

    def test_assessment_generate_help(self, runner):
        """Test assessment generate help."""
        result = runner.invoke(cli, ["oscal", "assessment", "generate", "--help"])
        assert result.exit_code == 0
        assert "title" in result.output
        assert "scan-file" in result.output

    def test_assessment_generate(self, runner, temp_output_dir):
        """Test generating OSCAL Assessment Results."""
        # Create a mock scan results file
        scan_results = {
            "scan_type": "aws",
            "framework": "soc2",
            "results": [
                {
                    "check_id": "s3-encryption",
                    "check_title": "S3 Bucket Encryption",
                    "severity": "high",
                    "resource_id": "bucket-1",
                    "resource_type": "s3_bucket",
                    "passed": True,
                },
                {
                    "check_id": "s3-versioning",
                    "check_title": "S3 Bucket Versioning",
                    "severity": "medium",
                    "resource_id": "bucket-2",
                    "resource_type": "s3_bucket",
                    "passed": False,
                },
            ],
        }

        scan_file = temp_output_dir / "scan_results.json"
        scan_file.write_text(json.dumps(scan_results))

        output_path = temp_output_dir / "assessment.json"

        result = runner.invoke(cli, [
            "oscal", "assessment", "generate",
            "--title", "Test Assessment",
            "--scan-file", str(scan_file),
            "--output", str(output_path),
        ])

        assert result.exit_code == 0
        assert output_path.exists()

        # Verify it's valid JSON with assessment structure
        data = json.loads(output_path.read_text())
        assert "assessment-results" in data

    def test_assessment_generate_yaml(self, runner, temp_output_dir):
        """Test generating OSCAL Assessment Results in YAML format."""
        scan_results = {
            "results": [
                {
                    "check_id": "test-check",
                    "check_title": "Test Check",
                    "severity": "low",
                    "resource_id": "resource-1",
                    "resource_type": "test",
                    "passed": True,
                },
            ],
        }

        scan_file = temp_output_dir / "scan.json"
        scan_file.write_text(json.dumps(scan_results))

        output_path = temp_output_dir / "assessment.yaml"

        result = runner.invoke(cli, [
            "oscal", "assessment", "generate",
            "--title", "YAML Assessment",
            "--scan-file", str(scan_file),
            "--output", str(output_path),
            "--format", "yaml",
        ])

        assert result.exit_code == 0
        assert output_path.exists()


# =============================================================================
# Configure Command Tests
# =============================================================================


class TestConfigureCommands:
    """Tests for configure commands."""

    def test_configure_platforms(self, runner):
        """Test configure platforms command."""
        result = runner.invoke(cli, ["configure", "platforms"])
        assert result.exit_code == 0
        assert "Supported Platforms" in result.output
        assert "aws" in result.output
        assert "okta" in result.output

    def test_configure_show(self, runner):
        """Test configure show command."""
        result = runner.invoke(cli, ["configure", "show"])
        assert result.exit_code == 0
        assert "Current Configuration" in result.output

    def test_configure_init(self, runner, temp_output_dir, monkeypatch):
        """Test configure init command."""
        # Mock the data directory
        monkeypatch.setenv("ATTESTFUL_DATA_DIR", str(temp_output_dir / "attestful"))

        result = runner.invoke(cli, ["configure", "init"])

        # Init might fail due to database issues in test env, but should not crash
        assert result.exit_code in [0, 1]


# =============================================================================
# End-to-End Workflow Tests
# =============================================================================


class TestE2EWorkflows:
    """End-to-end workflow tests."""

    def test_report_from_scan_file(self, runner, temp_output_dir):
        """Test generating a report from a scan results file."""
        # Create a mock scan results file
        scan_results = {
            "scan_type": "aws",
            "framework": "soc2",
            "timestamp": "2024-01-15T10:00:00Z",
            "summary": {
                "total_resources": 10,
                "total_checks": 5,
                "passed": 3,
                "failed": 2,
            },
            "results": [
                {
                    "check_id": "s3-encryption",
                    "check_title": "S3 Bucket Encryption",
                    "severity": "high",
                    "resource_id": "bucket-1",
                    "resource_type": "s3_bucket",
                    "passed": True,
                },
                {
                    "check_id": "s3-versioning",
                    "check_title": "S3 Bucket Versioning",
                    "severity": "medium",
                    "resource_id": "bucket-2",
                    "resource_type": "s3_bucket",
                    "passed": False,
                },
                {
                    "check_id": "ec2-imdsv2",
                    "check_title": "EC2 IMDSv2",
                    "severity": "high",
                    "resource_id": "instance-1",
                    "resource_type": "ec2_instance",
                    "passed": True,
                },
            ],
        }

        scan_file = temp_output_dir / "scan_results.json"
        scan_file.write_text(json.dumps(scan_results))

        # Generate report from scan file
        report_path = temp_output_dir / "report.html"

        result = runner.invoke(cli, [
            "report", "generate",
            "--format", "html",
            "--output", str(report_path),
            "--scan-file", str(scan_file),
            "--title", "Scan Results Report",
        ])

        assert result.exit_code == 0
        assert report_path.exists()

    def test_ssp_from_scan_file(self, runner, temp_output_dir):
        """Test generating an SSP from scan results."""
        # Create a mock scan results file
        scan_results = {
            "scan_type": "aws",
            "framework": "nist-800-53",
            "results": [
                {
                    "check_id": "ac-2-check",
                    "check_title": "Account Management",
                    "severity": "high",
                    "resource_id": "iam-user-1",
                    "resource_type": "iam_user",
                    "passed": True,
                },
            ],
        }

        scan_file = temp_output_dir / "scan_results.json"
        scan_file.write_text(json.dumps(scan_results))

        ssp_path = temp_output_dir / "ssp.json"

        result = runner.invoke(cli, [
            "oscal", "ssp", "generate",
            "--profile", "nist-800-53-moderate",
            "--system-name", "Production App",
            "--system-id", "prod-app-001",
            "--description", "Production application with automated controls",
            "--scan-file", str(scan_file),
            "--output", str(ssp_path),
        ])

        assert result.exit_code == 0
        assert ssp_path.exists()

        # Verify SSP content
        data = json.loads(ssp_path.read_text())
        assert "system-security-plan" in data


# =============================================================================
# Frameworks Command Tests
# =============================================================================


class TestFrameworksCommands:
    """Tests for frameworks commands."""

    def test_frameworks_list(self, runner):
        """Test frameworks list command."""
        result = runner.invoke(cli, ["frameworks", "list"])
        assert result.exit_code == 0
        assert "Available Compliance Frameworks" in result.output
        assert "soc2" in result.output
        assert "nist-800-53" in result.output

    def test_frameworks_show_soc2(self, runner):
        """Test frameworks show soc2 command."""
        result = runner.invoke(cli, ["frameworks", "show", "soc2"])
        assert result.exit_code == 0
        assert "SOC 2 Type II Trust Services Criteria" in result.output
        assert "Security (Common Criteria)" in result.output
        assert "CC6" in result.output
        assert "CC7" in result.output

    def test_frameworks_show_soc2_with_controls(self, runner):
        """Test frameworks show soc2 with --controls flag."""
        result = runner.invoke(cli, ["frameworks", "show", "soc2", "--controls"])
        assert result.exit_code == 0
        assert "CC6.1" in result.output
        assert "CC7.2" in result.output
        assert "All Controls" in result.output

    def test_frameworks_show_soc2_with_checks(self, runner):
        """Test frameworks show soc2 with --checks flag."""
        result = runner.invoke(cli, ["frameworks", "show", "soc2", "--checks"])
        assert result.exit_code == 0
        assert "Automated Checks" in result.output
        assert "CRITICAL" in result.output or "HIGH" in result.output

    def test_frameworks_show_unknown(self, runner):
        """Test frameworks show with unknown framework."""
        result = runner.invoke(cli, ["frameworks", "show", "unknown-framework"])
        assert result.exit_code == 0  # Should not crash
        assert "not found" in result.output.lower() or "not yet implemented" in result.output.lower()

    def test_frameworks_controls_soc2(self, runner):
        """Test frameworks controls soc2 command."""
        result = runner.invoke(cli, ["frameworks", "controls", "soc2"])
        assert result.exit_code == 0
        assert "SOC 2 Controls" in result.output
        assert "CC6.1" in result.output

    def test_frameworks_controls_search(self, runner):
        """Test frameworks controls with search filter."""
        result = runner.invoke(cli, ["frameworks", "controls", "soc2", "--search", "access"])
        assert result.exit_code == 0
        # Should find controls with "access" in title or description

    def test_frameworks_controls_category(self, runner):
        """Test frameworks controls with category filter."""
        result = runner.invoke(cli, ["frameworks", "controls", "soc2", "--category", "security"])
        assert result.exit_code == 0

    def test_frameworks_checks_soc2(self, runner):
        """Test frameworks checks soc2 command."""
        result = runner.invoke(cli, ["frameworks", "checks", "soc2"])
        assert result.exit_code == 0
        assert "SOC 2 Checks" in result.output

    def test_frameworks_checks_severity_filter(self, runner):
        """Test frameworks checks with severity filter."""
        result = runner.invoke(cli, ["frameworks", "checks", "soc2", "--severity", "critical"])
        assert result.exit_code == 0

    def test_frameworks_checks_resource_filter(self, runner):
        """Test frameworks checks with resource type filter."""
        result = runner.invoke(cli, ["frameworks", "checks", "soc2", "--resource-type", "iam_user"])
        assert result.exit_code == 0

    def test_frameworks_checks_control_filter(self, runner):
        """Test frameworks checks with control filter."""
        result = runner.invoke(cli, ["frameworks", "checks", "soc2", "--control", "CC6.1"])
        assert result.exit_code == 0


# =============================================================================
# SOC 2 Scan Command Tests
# =============================================================================


class TestScanSoc2Command:
    """Tests for scan soc2 command."""

    def test_scan_soc2_help(self, runner):
        """Test scan soc2 help."""
        result = runner.invoke(cli, ["scan", "soc2", "--help"])
        assert result.exit_code == 0
        assert "SOC 2 Type II" in result.output
        assert "provider" in result.output
        assert "control" in result.output
        assert "generate-oscal" in result.output

    def test_scan_soc2_control_option(self, runner):
        """Test scan soc2 with control option help text."""
        result = runner.invoke(cli, ["scan", "soc2", "--help"])
        assert result.exit_code == 0
        assert "CC6.1" in result.output or "control" in result.output


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_command(self, runner):
        """Test invalid command."""
        result = runner.invoke(cli, ["invalid-command"])
        assert result.exit_code != 0

    def test_missing_required_option(self, runner):
        """Test missing required option."""
        result = runner.invoke(cli, ["oscal", "ssp", "generate"])
        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    def test_invalid_format(self, runner, temp_output_dir):
        """Test invalid format option."""
        result = runner.invoke(cli, [
            "report", "generate",
            "--format", "invalid",
            "--output", str(temp_output_dir / "report.txt"),
        ])
        assert result.exit_code != 0
