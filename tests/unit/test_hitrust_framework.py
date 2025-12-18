"""
Unit tests for HITRUST CSF framework.
"""

import pytest

from attestful.frameworks.hitrust import (
    HITRUST_CONTROLS,
    HITRUST_FRAMEWORK_ID,
    HITRUST_VERSION,
    HITRUSTControl,
    HITRUSTFramework,
    HITRUSTMaturityScore,
    CATEGORY_ISMP,
    CATEGORY_ACCESS_CONTROL,
    CATEGORY_HR_SECURITY,
    CATEGORY_RISK_MANAGEMENT,
    CATEGORY_SECURITY_POLICY,
    CATEGORY_ORG_SECURITY,
    CATEGORY_COMPLIANCE,
    CATEGORY_ASSET_MANAGEMENT,
    CATEGORY_PHYSICAL_SECURITY,
    CATEGORY_OPERATIONS,
    CATEGORY_SDLC,
    CATEGORY_INCIDENT_MANAGEMENT,
    CATEGORY_BCM,
    CATEGORY_PRIVACY,
    MATURITY_POLICY,
    MATURITY_PROCEDURE,
    MATURITY_IMPLEMENTED,
    MATURITY_MEASURED,
    MATURITY_MANAGED,
    create_hitrust_evaluator,
    get_hitrust_aws_checks,
    get_hitrust_framework,
    get_controls_by_category,
    get_hipaa_mapped_controls,
    get_control_count_by_category,
)


# =============================================================================
# Framework Constants Tests
# =============================================================================


class TestHITRUSTConstants:
    """Tests for HITRUST constants."""

    def test_framework_id(self):
        """Test framework ID."""
        assert HITRUST_FRAMEWORK_ID == "hitrust"

    def test_version(self):
        """Test version string."""
        assert HITRUST_VERSION == "11.0"

    def test_category_constants(self):
        """Test category constants."""
        assert CATEGORY_ISMP == "00"
        assert CATEGORY_ACCESS_CONTROL == "01"
        assert CATEGORY_HR_SECURITY == "02"
        assert CATEGORY_RISK_MANAGEMENT == "03"
        assert CATEGORY_SECURITY_POLICY == "04"
        assert CATEGORY_ORG_SECURITY == "05"
        assert CATEGORY_COMPLIANCE == "06"
        assert CATEGORY_ASSET_MANAGEMENT == "07"
        assert CATEGORY_PHYSICAL_SECURITY == "08"
        assert CATEGORY_OPERATIONS == "09"
        assert CATEGORY_SDLC == "10"
        assert CATEGORY_INCIDENT_MANAGEMENT == "11"
        assert CATEGORY_BCM == "12"
        assert CATEGORY_PRIVACY == "13"

    def test_maturity_level_constants(self):
        """Test maturity level constants."""
        assert MATURITY_POLICY == 1
        assert MATURITY_PROCEDURE == 2
        assert MATURITY_IMPLEMENTED == 3
        assert MATURITY_MEASURED == 4
        assert MATURITY_MANAGED == 5


# =============================================================================
# Control Definition Tests
# =============================================================================


class TestHITRUSTControl:
    """Tests for HITRUSTControl dataclass."""

    def test_create_control(self):
        """Test creating a control."""
        control = HITRUSTControl(
            id="01.a",
            title="Access Control Policy",
            description="Test description",
            category="01",
        )

        assert control.id == "01.a"
        assert control.title == "Access Control Policy"
        assert control.category == "01"

    def test_default_values(self):
        """Test default values."""
        control = HITRUSTControl(
            id="01.a",
            title="Test",
            description="Test",
            category="01",
        )

        assert control.objective == ""
        assert control.implementation_requirement == ""
        assert control.nist_mappings == []
        assert control.iso_mappings == []
        assert control.hipaa_mappings == []
        assert control.pci_mappings == []

    def test_control_with_mappings(self):
        """Test control with cross-framework mappings."""
        control = HITRUSTControl(
            id="01.a",
            title="Access Control Policy",
            description="Test",
            category="01",
            nist_mappings=["AC-1", "AC-2"],
            iso_mappings=["A.5.15"],
            hipaa_mappings=["164.312(a)(1)"],
            pci_mappings=["7.1"],
        )

        assert len(control.nist_mappings) == 2
        assert "AC-1" in control.nist_mappings
        assert len(control.iso_mappings) == 1
        assert "A.5.15" in control.iso_mappings
        assert len(control.hipaa_mappings) == 1
        assert "164.312(a)(1)" in control.hipaa_mappings
        assert len(control.pci_mappings) == 1
        assert "7.1" in control.pci_mappings


# =============================================================================
# Maturity Score Tests
# =============================================================================


class TestHITRUSTMaturityScore:
    """Tests for HITRUSTMaturityScore dataclass."""

    def test_create_score(self):
        """Test creating a maturity score."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=90,
            procedure_score=85,
            implemented_score=80,
            measured_score=70,
            managed_score=60,
        )

        assert score.control_id == "01.a"
        assert score.policy_score == 90

    def test_default_values(self):
        """Test default values."""
        score = HITRUSTMaturityScore(control_id="01.a")

        assert score.policy_score == 0
        assert score.procedure_score == 0
        assert score.implemented_score == 0
        assert score.measured_score == 0
        assert score.managed_score == 0

    def test_overall_level_0(self):
        """Test overall level 0 (no maturity)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=50,
        )
        assert score.overall_level == 0

    def test_overall_level_1(self):
        """Test overall level 1 (policy only)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=85,
            procedure_score=50,
        )
        assert score.overall_level == 1

    def test_overall_level_2(self):
        """Test overall level 2 (policy + procedure)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=85,
            procedure_score=85,
            implemented_score=50,
        )
        assert score.overall_level == 2

    def test_overall_level_3(self):
        """Test overall level 3 (implemented)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=85,
            procedure_score=85,
            implemented_score=85,
            measured_score=50,
        )
        assert score.overall_level == 3

    def test_overall_level_4(self):
        """Test overall level 4 (measured)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=85,
            procedure_score=85,
            implemented_score=85,
            measured_score=85,
            managed_score=50,
        )
        assert score.overall_level == 4

    def test_overall_level_5(self):
        """Test overall level 5 (fully managed)."""
        score = HITRUSTMaturityScore(
            control_id="01.a",
            policy_score=85,
            procedure_score=85,
            implemented_score=85,
            measured_score=85,
            managed_score=85,
        )
        assert score.overall_level == 5


# =============================================================================
# Control Library Tests
# =============================================================================


class TestHITRUSTControls:
    """Tests for the HITRUST control library."""

    def test_total_control_count(self):
        """Test that controls are defined."""
        assert len(HITRUST_CONTROLS) >= 75

    def test_access_control_category_exists(self):
        """Test Category 01 Access Control controls exist."""
        access_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "01"]
        assert len(access_controls) >= 25

    def test_operations_category_exists(self):
        """Test Category 09 Operations controls exist."""
        ops_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "09"]
        assert len(ops_controls) >= 30

    def test_sdlc_category_exists(self):
        """Test Category 10 SDLC controls exist."""
        sdlc_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "10"]
        assert len(sdlc_controls) >= 15

    def test_incident_management_category_exists(self):
        """Test Category 11 Incident Management controls exist."""
        incident_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "11"]
        assert len(incident_controls) >= 5

    def test_specific_controls_exist(self):
        """Test specific controls exist."""
        assert "01.a" in HITRUST_CONTROLS
        assert "01.q" in HITRUST_CONTROLS
        assert "09.aa" in HITRUST_CONTROLS
        assert "10.f" in HITRUST_CONTROLS
        assert "11.c" in HITRUST_CONTROLS

    def test_control_has_required_fields(self):
        """Test that controls have required fields."""
        for control_id, control in HITRUST_CONTROLS.items():
            assert control.id == control_id
            assert control.title
            assert control.description
            assert control.category


# =============================================================================
# Framework Tests
# =============================================================================


class TestHITRUSTFramework:
    """Tests for HITRUSTFramework class."""

    def test_framework_creation(self):
        """Test creating a framework."""
        framework = HITRUSTFramework()

        assert framework.version == HITRUST_VERSION
        assert framework.controls == {}
        assert framework.check_mappings == {}

    def test_get_control(self):
        """Test getting a control."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        control = framework.get_control("01.a")
        assert control is not None
        assert control.id == "01.a"

    def test_get_nonexistent_control(self):
        """Test getting a non-existent control."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        control = framework.get_control("99.z")
        assert control is None

    def test_get_checks_for_control(self):
        """Test getting checks for a control."""
        framework = HITRUSTFramework(
            controls=HITRUST_CONTROLS,
            check_mappings={"01.q": ["check-1", "check-2"]},
        )

        checks = framework.get_checks_for_control("01.q")
        assert len(checks) == 2
        assert "check-1" in checks

    def test_get_checks_for_unmapped_control(self):
        """Test getting checks for an unmapped control."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        checks = framework.get_checks_for_control("01.a")
        assert checks == []

    def test_get_controls_by_category(self):
        """Test getting controls by category."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        access_controls = framework.get_controls_by_category("01")
        assert len(access_controls) >= 25

        ops_controls = framework.get_controls_by_category("09")
        assert len(ops_controls) >= 30

    def test_get_controls_mapped_to_hipaa(self):
        """Test getting HIPAA-mapped controls."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        hipaa_controls = framework.get_controls_mapped_to_hipaa()
        assert len(hipaa_controls) > 50

    def test_calculate_category_score(self):
        """Test calculating category score."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        # Test with empty maturity scores
        score = framework.calculate_category_score("01", {})
        assert score == 0.0

        # Test with some maturity scores
        maturity_scores = {
            "01.a": HITRUSTMaturityScore(
                control_id="01.a",
                policy_score=90,
                procedure_score=90,
                implemented_score=90,
                measured_score=90,
                managed_score=90,
            ),
        }
        score = framework.calculate_category_score("01", maturity_scores)
        assert score > 0


# =============================================================================
# AWS Checks Tests
# =============================================================================


class TestHITRUSTAWSChecks:
    """Tests for HITRUST AWS checks."""

    def test_checks_returned(self):
        """Test that checks are returned."""
        checks = get_hitrust_aws_checks()
        assert len(checks) > 0

    def test_check_count(self):
        """Test the number of checks."""
        checks = get_hitrust_aws_checks()
        assert len(checks) == 20

    def test_check_has_required_fields(self):
        """Test that checks have required fields."""
        checks = get_hitrust_aws_checks()

        for check in checks:
            assert check.id
            assert check.title
            assert check.description
            assert check.severity
            assert check.resource_types
            assert check.condition

    def test_checks_have_framework_mappings(self):
        """Test that checks have HITRUST framework mappings."""
        checks = get_hitrust_aws_checks()

        for check in checks:
            assert "hitrust" in check.frameworks
            assert len(check.frameworks["hitrust"]) > 0

    def test_check_severities_valid(self):
        """Test that check severities are valid."""
        valid_severities = {"critical", "high", "medium", "low", "info"}
        checks = get_hitrust_aws_checks()

        for check in checks:
            assert check.severity in valid_severities

    def test_mfa_check_exists(self):
        """Test IAM MFA check exists."""
        checks = get_hitrust_aws_checks()
        check_ids = [c.id for c in checks]

        assert "hitrust-aws-01q-1" in check_ids

    def test_cloudtrail_checks_exist(self):
        """Test CloudTrail checks exist."""
        checks = get_hitrust_aws_checks()
        check_ids = [c.id for c in checks]

        assert "hitrust-aws-09aa-1" in check_ids
        assert "hitrust-aws-09aa-2" in check_ids

    def test_encryption_checks_exist(self):
        """Test encryption checks exist."""
        checks = get_hitrust_aws_checks()
        check_ids = [c.id for c in checks]

        assert "hitrust-aws-10f-1" in check_ids  # S3
        assert "hitrust-aws-10f-2" in check_ids  # EBS
        assert "hitrust-aws-10f-3" in check_ids  # RDS

    def test_network_security_checks_exist(self):
        """Test network security checks exist."""
        checks = get_hitrust_aws_checks()
        check_ids = [c.id for c in checks]

        assert "hitrust-aws-01m-1" in check_ids  # SSH
        assert "hitrust-aws-01m-2" in check_ids  # RDP


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateHITRUSTEvaluator:
    """Tests for create_hitrust_evaluator function."""

    def test_create_evaluator(self):
        """Test creating an evaluator."""
        evaluator = create_hitrust_evaluator()

        assert evaluator is not None
        assert len(evaluator.list_checks()) > 0

    def test_evaluator_has_checks(self):
        """Test that evaluator has checks registered."""
        evaluator = create_hitrust_evaluator()
        checks = evaluator.list_checks()

        assert len(checks) == 20

    def test_evaluator_has_all_checks(self):
        """Test that evaluator has all HITRUST AWS checks registered."""
        evaluator = create_hitrust_evaluator()
        expected_checks = get_hitrust_aws_checks()

        assert len(evaluator.list_checks()) == len(expected_checks)


class TestGetHITRUSTFramework:
    """Tests for get_hitrust_framework function."""

    def test_get_framework(self):
        """Test getting the framework."""
        framework = get_hitrust_framework()

        assert isinstance(framework, HITRUSTFramework)
        assert framework.version == HITRUST_VERSION

    def test_framework_has_controls(self):
        """Test that framework has controls."""
        framework = get_hitrust_framework()

        assert len(framework.controls) >= 75

    def test_framework_has_check_mappings(self):
        """Test that framework has check mappings."""
        framework = get_hitrust_framework()

        assert len(framework.check_mappings) > 0

    def test_check_mappings_have_valid_format(self):
        """Test that check mappings have valid control ID format."""
        import re

        framework = get_hitrust_framework()

        # HITRUST control IDs follow pattern like: 01.a, 09.aa, 10.f
        control_id_pattern = re.compile(r"^\d{2}\.[a-z]+$")

        for control_id in framework.check_mappings.keys():
            assert control_id_pattern.match(control_id), f"Invalid control ID format: {control_id}"


# =============================================================================
# Category Helper Function Tests
# =============================================================================


class TestCategoryHelperFunctions:
    """Tests for category helper functions."""

    def test_get_controls_by_category(self):
        """Test getting controls by category."""
        access_controls = get_controls_by_category("01")
        assert len(access_controls) >= 25

        ops_controls = get_controls_by_category("09")
        assert len(ops_controls) >= 30

    def test_get_control_count_by_category(self):
        """Test getting control count by category."""
        counts = get_control_count_by_category()

        assert counts["01"] >= 25  # Access Control
        assert counts["09"] >= 30  # Operations
        assert counts["10"] >= 15  # SDLC
        assert counts["11"] >= 5   # Incident Management

    def test_get_hipaa_mapped_controls(self):
        """Test getting HIPAA mapped controls."""
        hipaa_controls = get_hipaa_mapped_controls()

        # Most HITRUST controls should map to HIPAA
        assert len(hipaa_controls) > 50


# =============================================================================
# Control Mapping Tests
# =============================================================================


class TestControlCheckMapping:
    """Tests for control-to-check mapping."""

    def test_all_checks_mapped_to_framework(self):
        """Test that all checks are mapped to at least one control."""
        framework = get_hitrust_framework()
        all_checks = get_hitrust_aws_checks()

        # Get all check IDs from mappings
        mapped_check_ids = set()
        for check_ids in framework.check_mappings.values():
            mapped_check_ids.update(check_ids)

        # All checks should be mapped
        for check in all_checks:
            assert check.id in mapped_check_ids, f"Check {check.id} not mapped to any control"

    def test_access_control_has_checks(self):
        """Test that 01.q control has checks mapped."""
        framework = get_hitrust_framework()

        checks = framework.get_checks_for_control("01.q")
        assert len(checks) > 0

    def test_logging_control_has_checks(self):
        """Test that 09.aa control has checks mapped."""
        framework = get_hitrust_framework()

        checks = framework.get_checks_for_control("09.aa")
        assert len(checks) > 0

    def test_cryptography_control_has_checks(self):
        """Test that 10.f control has checks mapped."""
        framework = get_hitrust_framework()

        checks = framework.get_checks_for_control("10.f")
        assert len(checks) > 0


# =============================================================================
# Cross-Framework Mapping Tests
# =============================================================================


class TestCrossFrameworkMappings:
    """Tests for cross-framework control mappings."""

    def test_controls_have_nist_mappings(self):
        """Test that many controls have NIST 800-53 mappings."""
        controls_with_nist = [
            c for c in HITRUST_CONTROLS.values() if c.nist_mappings
        ]
        # Most HITRUST controls should map to NIST
        assert len(controls_with_nist) > 60

    def test_controls_have_iso_mappings(self):
        """Test that many controls have ISO 27001 mappings."""
        controls_with_iso = [
            c for c in HITRUST_CONTROLS.values() if c.iso_mappings
        ]
        # Many HITRUST controls should map to ISO
        assert len(controls_with_iso) > 50

    def test_controls_have_hipaa_mappings(self):
        """Test that many controls have HIPAA mappings."""
        controls_with_hipaa = [
            c for c in HITRUST_CONTROLS.values() if c.hipaa_mappings
        ]
        # Most HITRUST controls should map to HIPAA
        assert len(controls_with_hipaa) > 50

    def test_access_control_mappings(self):
        """Test 01.a Access Control Policy has expected mappings."""
        control = HITRUST_CONTROLS["01.a"]

        assert "AC-1" in control.nist_mappings
        assert "A.5.15" in control.iso_mappings
        assert "164.312(a)(1)" in control.hipaa_mappings

    def test_user_authentication_mappings(self):
        """Test 01.q User Authentication has expected mappings."""
        control = HITRUST_CONTROLS["01.q"]

        assert "IA-2" in control.nist_mappings
        assert "164.312(d)" in control.hipaa_mappings
