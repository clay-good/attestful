"""
Unit tests for ISO 27001:2022 framework.
"""

import pytest

from attestful.frameworks.iso_27001 import (
    ISO_27001_CONTROLS,
    ISO_27001_FRAMEWORK_ID,
    ISO_27001_VERSION,
    ISO27001Control,
    ISO27001Framework,
    DOMAIN_ORGANIZATIONAL,
    DOMAIN_PEOPLE,
    DOMAIN_PHYSICAL,
    DOMAIN_TECHNOLOGICAL,
    create_iso_27001_evaluator,
    get_iso_27001_aws_checks,
    get_iso_27001_framework,
    get_controls_by_domain,
    get_control_count_by_domain,
)


# =============================================================================
# Framework Constants Tests
# =============================================================================


class TestISO27001Constants:
    """Tests for ISO 27001 constants."""

    def test_framework_id(self):
        """Test framework ID."""
        assert ISO_27001_FRAMEWORK_ID == "iso-27001"

    def test_version(self):
        """Test version string."""
        assert ISO_27001_VERSION == "2022"

    def test_domain_constants(self):
        """Test domain constants."""
        assert DOMAIN_ORGANIZATIONAL == "A.5"
        assert DOMAIN_PEOPLE == "A.6"
        assert DOMAIN_PHYSICAL == "A.7"
        assert DOMAIN_TECHNOLOGICAL == "A.8"


# =============================================================================
# Control Definition Tests
# =============================================================================


class TestISO27001Control:
    """Tests for ISO27001Control dataclass."""

    def test_create_control(self):
        """Test creating a control."""
        control = ISO27001Control(
            id="A.5.1",
            title="Policies for information security",
            description="Test description",
            domain="A.5",
        )

        assert control.id == "A.5.1"
        assert control.title == "Policies for information security"
        assert control.domain == "A.5"

    def test_default_values(self):
        """Test default values."""
        control = ISO27001Control(
            id="A.5.1",
            title="Test",
            description="Test",
            domain="A.5",
        )

        assert control.objective == ""
        assert control.attributes == ["preventive"]
        assert control.nist_mappings == []
        assert control.soc2_mappings == []

    def test_control_with_mappings(self):
        """Test control with cross-framework mappings."""
        control = ISO27001Control(
            id="A.5.15",
            title="Access control",
            description="Test",
            domain="A.5",
            nist_mappings=["AC-1", "AC-2", "AC-3"],
            soc2_mappings=["CC6.1", "CC6.2"],
        )

        assert len(control.nist_mappings) == 3
        assert "AC-1" in control.nist_mappings
        assert len(control.soc2_mappings) == 2
        assert "CC6.1" in control.soc2_mappings


# =============================================================================
# Control Library Tests
# =============================================================================


class TestISO27001Controls:
    """Tests for the ISO 27001 control library."""

    def test_total_control_count(self):
        """Test that all 93 controls are defined."""
        assert len(ISO_27001_CONTROLS) == 93

    def test_organizational_controls_exist(self):
        """Test A.5 Organizational controls exist."""
        organizational = [c for c in ISO_27001_CONTROLS.values() if c.domain == "A.5"]
        assert len(organizational) == 37

    def test_people_controls_exist(self):
        """Test A.6 People controls exist."""
        people = [c for c in ISO_27001_CONTROLS.values() if c.domain == "A.6"]
        assert len(people) == 8

    def test_physical_controls_exist(self):
        """Test A.7 Physical controls exist."""
        physical = [c for c in ISO_27001_CONTROLS.values() if c.domain == "A.7"]
        assert len(physical) == 14

    def test_technological_controls_exist(self):
        """Test A.8 Technological controls exist."""
        technological = [c for c in ISO_27001_CONTROLS.values() if c.domain == "A.8"]
        assert len(technological) == 34

    def test_specific_controls_exist(self):
        """Test specific controls exist."""
        assert "A.5.1" in ISO_27001_CONTROLS
        assert "A.5.15" in ISO_27001_CONTROLS
        assert "A.6.3" in ISO_27001_CONTROLS
        assert "A.7.1" in ISO_27001_CONTROLS
        assert "A.8.24" in ISO_27001_CONTROLS

    def test_control_has_required_fields(self):
        """Test that controls have required fields."""
        for control_id, control in ISO_27001_CONTROLS.items():
            assert control.id == control_id
            assert control.title
            assert control.description
            assert control.domain


# =============================================================================
# Framework Tests
# =============================================================================


class TestISO27001Framework:
    """Tests for ISO27001Framework class."""

    def test_framework_creation(self):
        """Test creating a framework."""
        framework = ISO27001Framework()

        assert framework.version == ISO_27001_VERSION
        assert framework.controls == {}
        assert framework.check_mappings == {}

    def test_get_control(self):
        """Test getting a control."""
        framework = ISO27001Framework(controls=ISO_27001_CONTROLS)

        control = framework.get_control("A.5.15")
        assert control is not None
        assert control.id == "A.5.15"

    def test_get_nonexistent_control(self):
        """Test getting a non-existent control."""
        framework = ISO27001Framework(controls=ISO_27001_CONTROLS)

        control = framework.get_control("A.99.99")
        assert control is None

    def test_get_checks_for_control(self):
        """Test getting checks for a control."""
        framework = ISO27001Framework(
            controls=ISO_27001_CONTROLS,
            check_mappings={"A.5.15": ["check-1", "check-2"]},
        )

        checks = framework.get_checks_for_control("A.5.15")
        assert len(checks) == 2
        assert "check-1" in checks

    def test_get_checks_for_unmapped_control(self):
        """Test getting checks for an unmapped control."""
        framework = ISO27001Framework(controls=ISO_27001_CONTROLS)

        checks = framework.get_checks_for_control("A.5.99")
        assert checks == []

    def test_get_controls_by_domain(self):
        """Test getting controls by domain."""
        framework = ISO27001Framework(controls=ISO_27001_CONTROLS)

        org_controls = framework.get_controls_by_domain("A.5")
        assert len(org_controls) == 37

        tech_controls = framework.get_controls_by_domain("A.8")
        assert len(tech_controls) == 34

    def test_get_statement_of_applicability(self):
        """Test generating Statement of Applicability template."""
        framework = ISO27001Framework(controls=ISO_27001_CONTROLS)

        soa = framework.get_statement_of_applicability()
        assert len(soa) == 93

        # Check structure of SoA entry
        assert "A.5.1" in soa
        entry = soa["A.5.1"]
        assert "title" in entry
        assert "domain" in entry
        assert "applicable" in entry
        assert "justification" in entry
        assert "implementation_status" in entry
        assert "evidence" in entry


# =============================================================================
# AWS Checks Tests
# =============================================================================


class TestISO27001AWSChecks:
    """Tests for ISO 27001 AWS checks."""

    def test_checks_returned(self):
        """Test that checks are returned."""
        checks = get_iso_27001_aws_checks()
        assert len(checks) > 0

    def test_check_count(self):
        """Test the number of checks."""
        checks = get_iso_27001_aws_checks()
        assert len(checks) == 20

    def test_check_has_required_fields(self):
        """Test that checks have required fields."""
        checks = get_iso_27001_aws_checks()

        for check in checks:
            assert check.id
            assert check.title
            assert check.description
            assert check.severity
            assert check.resource_types
            assert check.condition

    def test_checks_have_framework_mappings(self):
        """Test that checks have ISO 27001 framework mappings."""
        checks = get_iso_27001_aws_checks()

        for check in checks:
            assert "iso-27001" in check.frameworks
            assert len(check.frameworks["iso-27001"]) > 0

    def test_check_severities_valid(self):
        """Test that check severities are valid."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        checks = get_iso_27001_aws_checks()

        for check in checks:
            assert check.severity in valid_severities

    def test_mfa_check_exists(self):
        """Test IAM MFA check exists."""
        checks = get_iso_27001_aws_checks()
        check_ids = [c.id for c in checks]

        assert "iso-27001-aws-a5-15-1" in check_ids

    def test_cloudtrail_checks_exist(self):
        """Test CloudTrail checks exist."""
        checks = get_iso_27001_aws_checks()
        check_ids = [c.id for c in checks]

        assert "iso-27001-aws-a8-15-1" in check_ids
        assert "iso-27001-aws-a8-15-2" in check_ids

    def test_encryption_checks_exist(self):
        """Test encryption checks exist."""
        checks = get_iso_27001_aws_checks()
        check_ids = [c.id for c in checks]

        assert "iso-27001-aws-a8-24-1" in check_ids  # S3
        assert "iso-27001-aws-a8-24-2" in check_ids  # EBS
        assert "iso-27001-aws-a8-24-3" in check_ids  # RDS


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateISO27001Evaluator:
    """Tests for create_iso_27001_evaluator function."""

    def test_create_evaluator(self):
        """Test creating an evaluator."""
        evaluator = create_iso_27001_evaluator()

        assert evaluator is not None
        assert len(evaluator.list_checks()) > 0

    def test_evaluator_has_checks(self):
        """Test that evaluator has checks registered."""
        evaluator = create_iso_27001_evaluator()
        checks = evaluator.list_checks()

        assert len(checks) == 20

    def test_evaluator_has_all_checks(self):
        """Test that evaluator has all ISO 27001 AWS checks registered."""
        evaluator = create_iso_27001_evaluator()
        expected_checks = get_iso_27001_aws_checks()

        assert len(evaluator.list_checks()) == len(expected_checks)


class TestGetISO27001Framework:
    """Tests for get_iso_27001_framework function."""

    def test_get_framework(self):
        """Test getting the framework."""
        framework = get_iso_27001_framework()

        assert isinstance(framework, ISO27001Framework)
        assert framework.version == ISO_27001_VERSION

    def test_framework_has_controls(self):
        """Test that framework has controls."""
        framework = get_iso_27001_framework()

        assert len(framework.controls) == 93

    def test_framework_has_check_mappings(self):
        """Test that framework has check mappings."""
        framework = get_iso_27001_framework()

        assert len(framework.check_mappings) > 0

    def test_check_mappings_have_valid_format(self):
        """Test that check mappings have valid control ID format."""
        import re

        framework = get_iso_27001_framework()

        # ISO 27001 control IDs follow pattern like: A.5.1, A.8.24
        control_id_pattern = re.compile(r"^A\.\d+\.\d+$")

        for control_id in framework.check_mappings.keys():
            assert control_id_pattern.match(control_id), f"Invalid control ID format: {control_id}"


# =============================================================================
# Domain Helper Function Tests
# =============================================================================


class TestDomainHelperFunctions:
    """Tests for domain helper functions."""

    def test_get_controls_by_domain(self):
        """Test getting controls by domain."""
        org_controls = get_controls_by_domain("A.5")
        assert len(org_controls) == 37

        people_controls = get_controls_by_domain("A.6")
        assert len(people_controls) == 8

    def test_get_control_count_by_domain(self):
        """Test getting control count by domain."""
        counts = get_control_count_by_domain()

        assert counts["A.5"] == 37
        assert counts["A.6"] == 8
        assert counts["A.7"] == 14
        assert counts["A.8"] == 34

        # Total should be 93
        total = sum(counts.values())
        assert total == 93


# =============================================================================
# Control Mapping Tests
# =============================================================================


class TestControlCheckMapping:
    """Tests for control-to-check mapping."""

    def test_all_checks_mapped_to_framework(self):
        """Test that all checks are mapped to at least one control."""
        framework = get_iso_27001_framework()
        all_checks = get_iso_27001_aws_checks()

        # Get all check IDs from mappings
        mapped_check_ids = set()
        for check_ids in framework.check_mappings.values():
            mapped_check_ids.update(check_ids)

        # All checks should be mapped
        for check in all_checks:
            assert check.id in mapped_check_ids, f"Check {check.id} not mapped to any control"

    def test_access_control_has_checks(self):
        """Test that A.5.15 control has checks mapped."""
        framework = get_iso_27001_framework()

        checks = framework.get_checks_for_control("A.5.15")
        assert len(checks) > 0

    def test_logging_control_has_checks(self):
        """Test that A.8.15 control has checks mapped."""
        framework = get_iso_27001_framework()

        checks = framework.get_checks_for_control("A.8.15")
        assert len(checks) > 0

    def test_cryptography_control_has_checks(self):
        """Test that A.8.24 control has checks mapped."""
        framework = get_iso_27001_framework()

        checks = framework.get_checks_for_control("A.8.24")
        assert len(checks) > 0


# =============================================================================
# Cross-Framework Mapping Tests
# =============================================================================


class TestCrossFrameworkMappings:
    """Tests for cross-framework control mappings."""

    def test_controls_have_nist_mappings(self):
        """Test that many controls have NIST 800-53 mappings."""
        controls_with_nist = [
            c for c in ISO_27001_CONTROLS.values() if c.nist_mappings
        ]
        # Most ISO controls should map to NIST
        assert len(controls_with_nist) > 80

    def test_controls_have_soc2_mappings(self):
        """Test that many controls have SOC 2 mappings."""
        controls_with_soc2 = [
            c for c in ISO_27001_CONTROLS.values() if c.soc2_mappings
        ]
        # Many ISO controls should map to SOC 2
        assert len(controls_with_soc2) > 50

    def test_access_control_mappings(self):
        """Test A.5.15 Access control has expected mappings."""
        control = ISO_27001_CONTROLS["A.5.15"]

        assert "AC-1" in control.nist_mappings
        assert "AC-2" in control.nist_mappings
        assert "CC6.1" in control.soc2_mappings
