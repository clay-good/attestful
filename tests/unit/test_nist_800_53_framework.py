"""
Unit tests for NIST 800-53 framework.
"""

import pytest

from attestful.frameworks.nist_800_53 import (
    NIST_800_53_CONTROLS,
    NIST_800_53_FRAMEWORK_ID,
    NIST_800_53_VERSION,
    NIST80053Control,
    NIST80053Framework,
    FEDRAMP_LOW,
    FEDRAMP_MODERATE,
    FEDRAMP_HIGH,
    FAMILY_AC,
    FAMILY_AU,
    FAMILY_CM,
    FAMILY_IA,
    FAMILY_SC,
    FAMILY_SI,
    create_nist_800_53_evaluator,
    get_nist_800_53_aws_checks,
    get_nist_800_53_framework,
    get_fedramp_baseline_controls,
)


# =============================================================================
# Framework Constants Tests
# =============================================================================


class TestNIST80053Constants:
    """Tests for NIST 800-53 constants."""

    def test_framework_id(self):
        """Test framework ID."""
        assert NIST_800_53_FRAMEWORK_ID == "nist-800-53"

    def test_version(self):
        """Test version string."""
        assert NIST_800_53_VERSION == "5.1.1"

    def test_fedramp_baselines(self):
        """Test FedRAMP baseline constants."""
        assert FEDRAMP_LOW == "fedramp-low"
        assert FEDRAMP_MODERATE == "fedramp-moderate"
        assert FEDRAMP_HIGH == "fedramp-high"

    def test_control_families(self):
        """Test control family constants."""
        assert FAMILY_AC == "AC"
        assert FAMILY_AU == "AU"
        assert FAMILY_CM == "CM"
        assert FAMILY_IA == "IA"
        assert FAMILY_SC == "SC"
        assert FAMILY_SI == "SI"


# =============================================================================
# Control Definition Tests
# =============================================================================


class TestNIST80053Control:
    """Tests for NIST80053Control dataclass."""

    def test_create_control(self):
        """Test creating a control."""
        control = NIST80053Control(
            id="AC-1",
            title="Policy and Procedures",
            description="Access control policy.",
            family="AC",
        )

        assert control.id == "AC-1"
        assert control.title == "Policy and Procedures"
        assert control.family == "AC"

    def test_default_values(self):
        """Test default values."""
        control = NIST80053Control(
            id="AC-1",
            title="Test",
            description="Test",
            family="AC",
        )

        assert control.priority == "P1"
        assert "low" in control.baseline_impact
        assert "moderate" in control.baseline_impact
        assert "high" in control.baseline_impact
        assert control.enhancements == []

    def test_control_with_enhancements(self):
        """Test control with enhancements."""
        control = NIST80053Control(
            id="AC-2",
            title="Account Management",
            description="Manage accounts.",
            family="AC",
            enhancements=["AC-2(1)", "AC-2(2)"],
        )

        assert len(control.enhancements) == 2
        assert "AC-2(1)" in control.enhancements


# =============================================================================
# Control Library Tests
# =============================================================================


class TestNIST80053Controls:
    """Tests for the NIST 800-53 control library."""

    def test_controls_exist(self):
        """Test that controls are defined."""
        assert len(NIST_800_53_CONTROLS) > 0

    def test_ac_controls_exist(self):
        """Test Access Control family controls exist."""
        assert "AC-1" in NIST_800_53_CONTROLS
        assert "AC-2" in NIST_800_53_CONTROLS
        assert "AC-3" in NIST_800_53_CONTROLS
        assert "AC-6" in NIST_800_53_CONTROLS

    def test_au_controls_exist(self):
        """Test Audit family controls exist."""
        assert "AU-1" in NIST_800_53_CONTROLS
        assert "AU-2" in NIST_800_53_CONTROLS
        assert "AU-3" in NIST_800_53_CONTROLS
        assert "AU-9" in NIST_800_53_CONTROLS

    def test_cm_controls_exist(self):
        """Test Configuration Management family controls exist."""
        assert "CM-1" in NIST_800_53_CONTROLS
        assert "CM-2" in NIST_800_53_CONTROLS
        assert "CM-6" in NIST_800_53_CONTROLS
        assert "CM-7" in NIST_800_53_CONTROLS

    def test_ia_controls_exist(self):
        """Test Identification and Authentication family controls exist."""
        assert "IA-1" in NIST_800_53_CONTROLS
        assert "IA-2" in NIST_800_53_CONTROLS
        assert "IA-4" in NIST_800_53_CONTROLS
        assert "IA-5" in NIST_800_53_CONTROLS

    def test_sc_controls_exist(self):
        """Test System and Communications Protection family controls exist."""
        assert "SC-1" in NIST_800_53_CONTROLS
        assert "SC-7" in NIST_800_53_CONTROLS
        assert "SC-13" in NIST_800_53_CONTROLS

    def test_si_controls_exist(self):
        """Test System and Information Integrity family controls exist."""
        assert "SI-1" in NIST_800_53_CONTROLS
        assert "SI-2" in NIST_800_53_CONTROLS
        assert "SI-4" in NIST_800_53_CONTROLS

    def test_control_has_required_fields(self):
        """Test that controls have required fields."""
        for control_id, control in NIST_800_53_CONTROLS.items():
            assert control.id == control_id
            assert control.title
            assert control.description
            assert control.family


# =============================================================================
# Framework Tests
# =============================================================================


class TestNIST80053Framework:
    """Tests for NIST80053Framework class."""

    def test_framework_creation(self):
        """Test creating a framework."""
        framework = NIST80053Framework()

        assert framework.version == NIST_800_53_VERSION
        assert framework.controls == {}
        assert framework.check_mappings == {}

    def test_get_control(self):
        """Test getting a control."""
        framework = NIST80053Framework(controls=NIST_800_53_CONTROLS)

        control = framework.get_control("AC-2")
        assert control is not None
        assert control.id == "AC-2"

    def test_get_nonexistent_control(self):
        """Test getting a non-existent control."""
        framework = NIST80053Framework(controls=NIST_800_53_CONTROLS)

        control = framework.get_control("XX-99")
        assert control is None

    def test_get_checks_for_control(self):
        """Test getting checks for a control."""
        framework = NIST80053Framework(
            controls=NIST_800_53_CONTROLS,
            check_mappings={"AC-2": ["check-1", "check-2"]},
        )

        checks = framework.get_checks_for_control("AC-2")
        assert len(checks) == 2
        assert "check-1" in checks

    def test_get_checks_for_unmapped_control(self):
        """Test getting checks for an unmapped control."""
        framework = NIST80053Framework(controls=NIST_800_53_CONTROLS)

        checks = framework.get_checks_for_control("AC-99")
        assert checks == []

    def test_get_controls_for_baseline(self):
        """Test getting controls for a FedRAMP baseline."""
        framework = NIST80053Framework(controls=NIST_800_53_CONTROLS)

        low_controls = framework.get_controls_for_baseline("fedramp-low")
        assert len(low_controls) > 0

        moderate_controls = framework.get_controls_for_baseline("fedramp-moderate")
        assert len(moderate_controls) >= len(low_controls)


# =============================================================================
# AWS Checks Tests
# =============================================================================


class TestNIST80053AWSChecks:
    """Tests for NIST 800-53 AWS checks."""

    def test_checks_returned(self):
        """Test that checks are returned."""
        checks = get_nist_800_53_aws_checks()
        assert len(checks) > 0

    def test_check_has_required_fields(self):
        """Test that checks have required fields."""
        checks = get_nist_800_53_aws_checks()

        for check in checks:
            assert check.id
            assert check.title
            assert check.description
            assert check.severity
            assert check.resource_types
            assert check.condition

    def test_checks_have_framework_mappings(self):
        """Test that checks have NIST 800-53 framework mappings."""
        checks = get_nist_800_53_aws_checks()

        for check in checks:
            assert "nist-800-53" in check.frameworks
            assert len(check.frameworks["nist-800-53"]) > 0

    def test_check_severities_valid(self):
        """Test that check severities are valid."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        checks = get_nist_800_53_aws_checks()

        for check in checks:
            assert check.severity in valid_severities

    def test_mfa_check_exists(self):
        """Test IAM MFA check exists."""
        checks = get_nist_800_53_aws_checks()
        check_ids = [c.id for c in checks]

        assert "nist-800-53-aws-ac-2-1" in check_ids

    def test_cloudtrail_checks_exist(self):
        """Test CloudTrail checks exist."""
        checks = get_nist_800_53_aws_checks()
        check_ids = [c.id for c in checks]

        assert "nist-800-53-aws-au-2-1" in check_ids
        assert "nist-800-53-aws-au-9-1" in check_ids

    def test_encryption_checks_exist(self):
        """Test encryption checks exist."""
        checks = get_nist_800_53_aws_checks()
        check_ids = [c.id for c in checks]

        assert "nist-800-53-aws-sc-13-1" in check_ids  # S3
        assert "nist-800-53-aws-sc-13-2" in check_ids  # EBS
        assert "nist-800-53-aws-sc-13-3" in check_ids  # RDS


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateNIST80053Evaluator:
    """Tests for create_nist_800_53_evaluator function."""

    def test_create_evaluator(self):
        """Test creating an evaluator."""
        evaluator = create_nist_800_53_evaluator()

        assert evaluator is not None
        assert len(evaluator.list_checks()) > 0

    def test_evaluator_has_checks(self):
        """Test that evaluator has checks registered."""
        evaluator = create_nist_800_53_evaluator()
        checks = evaluator.list_checks()

        assert len(checks) > 0

    def test_evaluator_has_all_checks(self):
        """Test that evaluator has all NIST 800-53 AWS checks registered."""
        evaluator = create_nist_800_53_evaluator()
        expected_checks = get_nist_800_53_aws_checks()

        # Evaluator may have additional checks beyond just AWS
        assert len(evaluator.list_checks()) >= len(expected_checks)


class TestGetNIST80053Framework:
    """Tests for get_nist_800_53_framework function."""

    def test_get_framework(self):
        """Test getting the framework."""
        framework = get_nist_800_53_framework()

        assert isinstance(framework, NIST80053Framework)
        assert framework.version == NIST_800_53_VERSION

    def test_framework_has_controls(self):
        """Test that framework has controls."""
        framework = get_nist_800_53_framework()

        assert len(framework.controls) > 0

    def test_framework_has_check_mappings(self):
        """Test that framework has check mappings."""
        framework = get_nist_800_53_framework()

        assert len(framework.check_mappings) > 0

    def test_check_mappings_have_valid_format(self):
        """Test that check mappings have valid control ID format."""
        import re
        framework = get_nist_800_53_framework()

        # NIST 800-53 control IDs follow pattern like: AC-1, AU-2, SC-7(3), etc.
        control_id_pattern = re.compile(r"^[A-Z]{2}-\d+(\(\d+\))?$")

        for control_id in framework.check_mappings.keys():
            assert control_id_pattern.match(control_id), f"Invalid control ID format: {control_id}"


class TestGetFedRAMPBaselineControls:
    """Tests for get_fedramp_baseline_controls function."""

    def test_get_low_baseline(self):
        """Test getting FedRAMP Low baseline controls."""
        controls = get_fedramp_baseline_controls("fedramp-low")

        assert len(controls) > 0
        assert "AC-1" in controls

    def test_get_moderate_baseline(self):
        """Test getting FedRAMP Moderate baseline controls."""
        controls = get_fedramp_baseline_controls("fedramp-moderate")

        assert len(controls) > 0
        assert "AC-4" in controls  # Only in moderate/high

    def test_get_high_baseline(self):
        """Test getting FedRAMP High baseline controls."""
        controls = get_fedramp_baseline_controls("fedramp-high")

        assert len(controls) > 0

    def test_moderate_has_more_than_low(self):
        """Test that Moderate baseline has at least as many controls as Low."""
        low_controls = get_fedramp_baseline_controls("fedramp-low")
        moderate_controls = get_fedramp_baseline_controls("fedramp-moderate")

        assert len(moderate_controls) >= len(low_controls)


# =============================================================================
# Control Mapping Tests
# =============================================================================


class TestControlCheckMapping:
    """Tests for control-to-check mapping."""

    def test_all_checks_mapped_to_framework(self):
        """Test that all checks are mapped to at least one control."""
        framework = get_nist_800_53_framework()
        all_checks = get_nist_800_53_aws_checks()

        # Get all check IDs from mappings
        mapped_check_ids = set()
        for check_ids in framework.check_mappings.values():
            mapped_check_ids.update(check_ids)

        # All checks should be mapped
        for check in all_checks:
            assert check.id in mapped_check_ids, f"Check {check.id} not mapped to any control"

    def test_ac2_has_checks(self):
        """Test that AC-2 control has checks mapped."""
        framework = get_nist_800_53_framework()

        checks = framework.get_checks_for_control("AC-2")
        assert len(checks) > 0

    def test_au2_has_checks(self):
        """Test that AU-2 control has checks mapped."""
        framework = get_nist_800_53_framework()

        checks = framework.get_checks_for_control("AU-2")
        assert len(checks) > 0

    def test_sc13_has_checks(self):
        """Test that SC-13 control has checks mapped."""
        framework = get_nist_800_53_framework()

        checks = framework.get_checks_for_control("SC-13")
        assert len(checks) > 0
