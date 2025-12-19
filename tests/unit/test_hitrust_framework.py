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
    HITRUSTControlScore,
    HITRUSTMaturityCalculator,
    CATEGORY_ISMP,
    CATEGORY_ACCESS_CONTROL,
    CATEGORY_HR_SECURITY,
    CATEGORY_RISK_MANAGEMENT,
    CATEGORY_SECURITY_POLICY,
    CATEGORY_ORG_SECURITY,
    CATEGORY_COMPLIANCE,
    CATEGORY_ASSET_MGMT,
    CATEGORY_PHYSICAL,
    CATEGORY_OPERATIONS,
    CATEGORY_SDLC,
    CATEGORY_INCIDENT,
    CATEGORY_BCM,
    CATEGORY_PRIVACY,
    MATURITY_POLICY,
    MATURITY_PROCEDURE,
    MATURITY_IMPLEMENTED,
    MATURITY_MEASURED,
    MATURITY_MANAGED,
    get_controls_by_category,
    get_controls_by_hipaa_mapping,
    get_control_count_by_category,
    get_all_hitrust_checks,
    get_hitrust_checks_for_control,
)


# =============================================================================
# Framework Constants Tests
# =============================================================================


class TestHITRUSTConstants:
    """Tests for HITRUST constants."""

    def test_framework_id(self):
        """Test framework ID."""
        assert HITRUST_FRAMEWORK_ID == "hitrust-csf"

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
        assert CATEGORY_ASSET_MGMT == "07"
        assert CATEGORY_PHYSICAL == "08"
        assert CATEGORY_OPERATIONS == "09"
        assert CATEGORY_SDLC == "10"
        assert CATEGORY_INCIDENT == "11"
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

        assert control.control_reference == ""
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


class TestHITRUSTControlScore:
    """Tests for HITRUSTControlScore dataclass."""

    def test_create_score(self):
        """Test creating a control score."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            policy_score=90,
            procedure_score=85,
            implemented_score=80,
            measured_score=70,
            managed_score=60,
        )

        assert score.control_id == "01.a"
        assert score.control_title == "Access Control Policy"
        assert score.category == "01"
        assert score.policy_score == 90

    def test_default_values(self):
        """Test default values."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
        )

        assert score.policy_score == 0.0
        assert score.procedure_score == 0.0
        assert score.implemented_score == 0.0
        assert score.measured_score == 0.0
        assert score.managed_score == 0.0
        assert score.overall_level == 0
        assert score.evidence_count == 0
        assert score.explanation == ""

    def test_overall_level_stored(self):
        """Test overall level is stored correctly."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            policy_score=85,
            overall_level=1,
        )
        assert score.overall_level == 1

    def test_automation_rate_calculation(self):
        """Test automation rate calculation."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            automated_checks_passed=8,
            automated_checks_total=10,
        )
        assert score.automation_rate == 80.0

    def test_automation_rate_zero_total(self):
        """Test automation rate with zero total checks."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            automated_checks_passed=0,
            automated_checks_total=0,
        )
        assert score.automation_rate == 0.0

    def test_level_name_property(self):
        """Test level name property."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            overall_level=3,
        )
        assert "Implemented" in score.level_name or score.level_name == "Level 3"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        score = HITRUSTControlScore(
            control_id="01.a",
            control_title="Access Control Policy",
            category="01",
            policy_score=85,
            procedure_score=80,
            overall_level=2,
        )
        result = score.to_dict()
        assert result["control_id"] == "01.a"
        assert result["control_title"] == "Access Control Policy"
        assert result["overall_level"] == 2
        assert "scores" in result


# =============================================================================
# Control Library Tests
# =============================================================================


class TestHITRUSTControls:
    """Tests for the HITRUST control library."""

    def test_total_control_count(self):
        """Test that controls are defined."""
        # 121 controls across 14 categories
        assert len(HITRUST_CONTROLS) >= 100

    def test_access_control_category_exists(self):
        """Test Category 01 Access Control controls exist."""
        access_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "01"]
        assert len(access_controls) >= 10

    def test_operations_category_exists(self):
        """Test Category 09 Operations controls exist."""
        ops_controls = [c for c in HITRUST_CONTROLS.values() if c.category == "09"]
        assert len(ops_controls) >= 20

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
        assert "01.b" in HITRUST_CONTROLS
        assert "09.a" in HITRUST_CONTROLS
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
        assert len(access_controls) >= 10

        ops_controls = framework.get_controls_by_category("09")
        assert len(ops_controls) >= 20

    def test_get_controls_by_maturity_level(self):
        """Test getting controls by maturity level."""
        framework = HITRUSTFramework(controls=HITRUST_CONTROLS)

        # Get controls at level 3 (Implemented) or below
        controls = framework.get_controls_by_maturity_level(MATURITY_IMPLEMENTED)
        assert len(controls) > 0


# =============================================================================
# Category Helper Function Tests
# =============================================================================


class TestCategoryHelperFunctions:
    """Tests for category helper functions."""

    def test_get_controls_by_category(self):
        """Test getting controls by category."""
        access_controls = get_controls_by_category("01")
        assert len(access_controls) >= 10

        ops_controls = get_controls_by_category("09")
        assert len(ops_controls) >= 20

    def test_get_control_count_by_category(self):
        """Test getting control count by category."""
        counts = get_control_count_by_category()

        assert counts["01"] >= 10  # Access Control
        assert counts["09"] >= 20  # Operations
        assert counts["10"] >= 15  # SDLC
        assert counts["11"] >= 5   # Incident Management

    def test_get_controls_by_hipaa_mapping(self):
        """Test getting HIPAA mapped controls."""
        hipaa_controls = get_controls_by_hipaa_mapping("164.312(a)(1)")

        # Should return controls mapped to this HIPAA requirement
        assert len(hipaa_controls) > 0


# =============================================================================
# Check Functions Tests
# =============================================================================


class TestCheckFunctions:
    """Tests for check retrieval functions."""

    def test_get_all_hitrust_checks(self):
        """Test getting all HITRUST checks."""
        checks = get_all_hitrust_checks()
        # Should return inherited checks from other frameworks
        assert isinstance(checks, list)

    def test_get_hitrust_checks_for_control(self):
        """Test getting checks for a specific control."""
        checks = get_hitrust_checks_for_control("01.a")
        # Should return a list (may be empty if no inherited checks)
        assert isinstance(checks, list)


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
        """Test 01.c Privilege Management has expected mappings."""
        control = HITRUST_CONTROLS["01.c"]

        assert "AC-6" in control.nist_mappings
        assert len(control.hipaa_mappings) > 0


# =============================================================================
# Maturity Calculator Tests
# =============================================================================


class TestHITRUSTMaturityCalculator:
    """Tests for HITRUSTMaturityCalculator class."""

    def test_calculator_creation(self):
        """Test creating a maturity calculator."""
        calculator = HITRUSTMaturityCalculator()
        assert calculator is not None

    def test_calculator_with_config(self):
        """Test creating a maturity calculator with config."""
        from attestful.frameworks.hitrust import HITRUSTMaturityConfig

        config = HITRUSTMaturityConfig()
        calculator = HITRUSTMaturityCalculator(config=config)
        assert calculator is not None
        assert calculator.config == config
