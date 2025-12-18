"""
Unit tests for cross-framework control mapping (crosswalk).
"""

import pytest

from attestful.analysis.crosswalk import (
    Framework,
    MappingStrength,
    ControlMapping,
    CrosswalkResult,
    FrameworkCrosswalk,
    get_crosswalk,
    find_equivalent_controls,
    get_control_coverage_map,
)


# =============================================================================
# Framework Enum Tests
# =============================================================================


class TestFrameworkEnum:
    """Tests for Framework enumeration."""

    def test_all_frameworks_defined(self):
        """Test all supported frameworks are defined."""
        assert Framework.NIST_800_53.value == "nist-800-53"
        assert Framework.SOC2.value == "soc2"
        assert Framework.ISO_27001.value == "iso-27001"
        assert Framework.HITRUST.value == "hitrust"

    def test_framework_count(self):
        """Test number of frameworks."""
        assert len(Framework) == 4


# =============================================================================
# MappingStrength Tests
# =============================================================================


class TestMappingStrength:
    """Tests for MappingStrength enumeration."""

    def test_all_strengths_defined(self):
        """Test all mapping strengths are defined."""
        assert MappingStrength.EXACT.value == "exact"
        assert MappingStrength.STRONG.value == "strong"
        assert MappingStrength.PARTIAL.value == "partial"
        assert MappingStrength.RELATED.value == "related"

    def test_strength_count(self):
        """Test number of strength levels."""
        assert len(MappingStrength) == 4


# =============================================================================
# ControlMapping Tests
# =============================================================================


class TestControlMapping:
    """Tests for ControlMapping dataclass."""

    def test_create_mapping(self):
        """Test creating a control mapping."""
        mapping = ControlMapping(
            source_framework=Framework.NIST_800_53,
            source_control="AC-2",
            target_framework=Framework.SOC2,
            target_control="CC6.1",
            strength=MappingStrength.STRONG,
            notes="Account management",
        )

        assert mapping.source_framework == Framework.NIST_800_53
        assert mapping.source_control == "AC-2"
        assert mapping.target_framework == Framework.SOC2
        assert mapping.target_control == "CC6.1"
        assert mapping.strength == MappingStrength.STRONG

    def test_default_strength(self):
        """Test default mapping strength."""
        mapping = ControlMapping(
            source_framework=Framework.NIST_800_53,
            source_control="AC-1",
            target_framework=Framework.SOC2,
            target_control="CC6.1",
        )

        assert mapping.strength == MappingStrength.STRONG


# =============================================================================
# CrosswalkResult Tests
# =============================================================================


class TestCrosswalkResult:
    """Tests for CrosswalkResult dataclass."""

    def test_create_result(self):
        """Test creating a crosswalk result."""
        result = CrosswalkResult(
            source_framework=Framework.NIST_800_53,
            source_control="AC-2",
            mappings=[
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.SOC2,
                    target_control="CC6.1",
                ),
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.ISO_27001,
                    target_control="A.5.16",
                ),
            ],
        )

        assert result.source_control == "AC-2"
        assert len(result.mappings) == 2

    def test_get_mappings_for_framework(self):
        """Test filtering mappings by framework."""
        result = CrosswalkResult(
            source_framework=Framework.NIST_800_53,
            source_control="AC-2",
            mappings=[
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.SOC2,
                    target_control="CC6.1",
                ),
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.SOC2,
                    target_control="CC6.2",
                ),
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.ISO_27001,
                    target_control="A.5.16",
                ),
            ],
        )

        soc2_mappings = result.get_mappings_for_framework(Framework.SOC2)
        assert len(soc2_mappings) == 2

        iso_mappings = result.get_mappings_for_framework(Framework.ISO_27001)
        assert len(iso_mappings) == 1

        hitrust_mappings = result.get_mappings_for_framework(Framework.HITRUST)
        assert len(hitrust_mappings) == 0

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = CrosswalkResult(
            source_framework=Framework.NIST_800_53,
            source_control="AC-2",
            mappings=[
                ControlMapping(
                    source_framework=Framework.NIST_800_53,
                    source_control="AC-2",
                    target_framework=Framework.SOC2,
                    target_control="CC6.1",
                    strength=MappingStrength.STRONG,
                    notes="Test",
                ),
            ],
        )

        data = result.to_dict()
        assert data["source_framework"] == "nist-800-53"
        assert data["source_control"] == "AC-2"
        assert len(data["mappings"]) == 1
        assert data["mappings"][0]["target_framework"] == "soc2"


# =============================================================================
# FrameworkCrosswalk Tests
# =============================================================================


class TestFrameworkCrosswalk:
    """Tests for FrameworkCrosswalk class."""

    def test_create_crosswalk(self):
        """Test creating a crosswalk instance."""
        crosswalk = FrameworkCrosswalk()
        assert crosswalk is not None

    def test_has_builtin_mappings(self):
        """Test that crosswalk has built-in mappings."""
        crosswalk = FrameworkCrosswalk()
        all_mappings = crosswalk.get_all_mappings()
        assert len(all_mappings) > 100  # Should have many mappings

    def test_get_mappings_nist_to_soc2(self):
        """Test getting NIST to SOC 2 mappings."""
        crosswalk = FrameworkCrosswalk()
        result = crosswalk.get_mappings(Framework.NIST_800_53, "AC-2")

        assert result.source_control == "AC-2"
        soc2_mappings = result.get_mappings_for_framework(Framework.SOC2)
        assert len(soc2_mappings) > 0

    def test_get_mappings_nist_to_iso(self):
        """Test getting NIST to ISO 27001 mappings."""
        crosswalk = FrameworkCrosswalk()
        result = crosswalk.get_mappings(Framework.NIST_800_53, "AC-2")

        iso_mappings = result.get_mappings_for_framework(Framework.ISO_27001)
        assert len(iso_mappings) > 0

    def test_get_mappings_nist_to_hitrust(self):
        """Test getting NIST to HITRUST mappings."""
        crosswalk = FrameworkCrosswalk()
        result = crosswalk.get_mappings(Framework.NIST_800_53, "AC-2")

        hitrust_mappings = result.get_mappings_for_framework(Framework.HITRUST)
        assert len(hitrust_mappings) > 0

    def test_get_mappings_soc2_to_iso(self):
        """Test getting SOC 2 to ISO 27001 mappings."""
        crosswalk = FrameworkCrosswalk()
        result = crosswalk.get_mappings(Framework.SOC2, "CC6.1")

        iso_mappings = result.get_mappings_for_framework(Framework.ISO_27001)
        assert len(iso_mappings) > 0

    def test_get_mappings_iso_to_hitrust(self):
        """Test getting ISO 27001 to HITRUST mappings."""
        crosswalk = FrameworkCrosswalk()
        result = crosswalk.get_mappings(Framework.ISO_27001, "A.5.15")

        hitrust_mappings = result.get_mappings_for_framework(Framework.HITRUST)
        assert len(hitrust_mappings) > 0

    def test_bidirectional_mappings(self):
        """Test that mappings are bidirectional."""
        crosswalk = FrameworkCrosswalk()

        # NIST -> SOC 2
        nist_result = crosswalk.get_mappings(Framework.NIST_800_53, "AC-2")
        soc2_controls = [
            m.target_control
            for m in nist_result.get_mappings_for_framework(Framework.SOC2)
        ]

        # SOC 2 -> NIST (should have reverse mapping)
        for soc2_control in soc2_controls:
            soc2_result = crosswalk.get_mappings(Framework.SOC2, soc2_control)
            nist_controls = [
                m.target_control
                for m in soc2_result.get_mappings_for_framework(Framework.NIST_800_53)
            ]
            # AC-2 should be in the reverse mapping
            assert "AC-2" in nist_controls

    def test_get_equivalent_controls(self):
        """Test getting equivalent controls."""
        crosswalk = FrameworkCrosswalk()

        equivalents = crosswalk.get_equivalent_controls(
            Framework.NIST_800_53, "AC-2",
            Framework.SOC2,
        )

        assert len(equivalents) > 0
        assert "CC6.1" in equivalents

    def test_get_equivalent_controls_with_min_strength(self):
        """Test filtering by minimum strength."""
        crosswalk = FrameworkCrosswalk()

        # Get all with partial or better
        partial_or_better = crosswalk.get_equivalent_controls(
            Framework.NIST_800_53, "AC-2",
            Framework.SOC2,
            min_strength=MappingStrength.PARTIAL,
        )

        # Get only strong or exact
        strong_or_better = crosswalk.get_equivalent_controls(
            Framework.NIST_800_53, "AC-2",
            Framework.SOC2,
            min_strength=MappingStrength.STRONG,
        )

        # Strong/exact should be subset of partial/better
        assert len(strong_or_better) <= len(partial_or_better)

    def test_has_equivalent(self):
        """Test checking for equivalent existence."""
        crosswalk = FrameworkCrosswalk()

        assert crosswalk.has_equivalent(
            Framework.NIST_800_53, "AC-2",
            Framework.SOC2,
        )

        # Test with non-existent control
        assert not crosswalk.has_equivalent(
            Framework.NIST_800_53, "XX-99",
            Framework.SOC2,
        )

    def test_get_coverage_analysis(self):
        """Test coverage analysis across frameworks."""
        crosswalk = FrameworkCrosswalk()

        covered = {
            Framework.NIST_800_53: {"AC-2", "AC-3", "AU-2"},
            Framework.SOC2: {"CC6.1"},
        }

        analysis = crosswalk.get_coverage_analysis(covered)

        assert Framework.NIST_800_53 in analysis
        assert Framework.SOC2 in analysis
        assert "direct_coverage" in analysis[Framework.NIST_800_53]
        assert "inherited_coverage" in analysis[Framework.SOC2]

    def test_get_multi_framework_gaps(self):
        """Test identifying multi-framework gaps."""
        crosswalk = FrameworkCrosswalk()

        # If AC-2 fails in NIST, equivalent controls fail in other frameworks
        failed = {
            Framework.NIST_800_53: {"AC-2"},
            Framework.SOC2: {"CC6.1"},  # CC6.1 maps to AC-2
        }

        gaps = crosswalk.get_multi_framework_gaps(failed)

        # Should find the correlation
        assert len(gaps) > 0

    def test_get_mapping_statistics(self):
        """Test getting mapping statistics."""
        crosswalk = FrameworkCrosswalk()
        stats = crosswalk.get_mapping_statistics()

        assert "total_mappings" in stats
        assert stats["total_mappings"] > 100
        assert "by_source_framework" in stats
        assert "by_strength" in stats
        assert "framework_pairs" in stats


# =============================================================================
# Specific Mapping Tests
# =============================================================================


class TestSpecificMappings:
    """Tests for specific control mappings."""

    def test_access_control_mappings(self):
        """Test access control mappings across frameworks."""
        crosswalk = FrameworkCrosswalk()

        # NIST AC-2 -> SOC 2 CC6.1
        result = crosswalk.get_mappings(Framework.NIST_800_53, "AC-2")
        soc2 = result.get_mappings_for_framework(Framework.SOC2)
        soc2_controls = [m.target_control for m in soc2]
        assert "CC6.1" in soc2_controls

        # NIST AC-2 -> ISO A.5.16
        iso = result.get_mappings_for_framework(Framework.ISO_27001)
        iso_controls = [m.target_control for m in iso]
        assert "A.5.16" in iso_controls

        # NIST AC-2 -> HITRUST 01.b
        hitrust = result.get_mappings_for_framework(Framework.HITRUST)
        hitrust_controls = [m.target_control for m in hitrust]
        assert "01.b" in hitrust_controls

    def test_audit_logging_mappings(self):
        """Test audit logging mappings across frameworks."""
        crosswalk = FrameworkCrosswalk()

        # NIST AU-2 -> SOC 2 CC7.2
        result = crosswalk.get_mappings(Framework.NIST_800_53, "AU-2")
        soc2 = result.get_mappings_for_framework(Framework.SOC2)
        soc2_controls = [m.target_control for m in soc2]
        assert "CC7.2" in soc2_controls

        # NIST AU-2 -> ISO A.8.15
        iso = result.get_mappings_for_framework(Framework.ISO_27001)
        iso_controls = [m.target_control for m in iso]
        assert "A.8.15" in iso_controls

        # NIST AU-2 -> HITRUST 09.aa
        hitrust = result.get_mappings_for_framework(Framework.HITRUST)
        hitrust_controls = [m.target_control for m in hitrust]
        assert "09.aa" in hitrust_controls

    def test_change_management_mappings(self):
        """Test change management mappings across frameworks."""
        crosswalk = FrameworkCrosswalk()

        # NIST CM-3 -> SOC 2 CC8.1
        result = crosswalk.get_mappings(Framework.NIST_800_53, "CM-3")
        soc2 = result.get_mappings_for_framework(Framework.SOC2)
        soc2_controls = [m.target_control for m in soc2]
        assert "CC8.1" in soc2_controls

        # NIST CM-3 -> ISO A.8.32
        iso = result.get_mappings_for_framework(Framework.ISO_27001)
        iso_controls = [m.target_control for m in iso]
        assert "A.8.32" in iso_controls

    def test_cryptography_mappings(self):
        """Test cryptography mappings across frameworks."""
        crosswalk = FrameworkCrosswalk()

        # NIST SC-13 -> ISO A.8.24
        result = crosswalk.get_mappings(Framework.NIST_800_53, "SC-13")
        iso = result.get_mappings_for_framework(Framework.ISO_27001)
        iso_controls = [m.target_control for m in iso]
        assert "A.8.24" in iso_controls

        # NIST SC-13 -> HITRUST 10.f
        hitrust = result.get_mappings_for_framework(Framework.HITRUST)
        hitrust_controls = [m.target_control for m in hitrust]
        assert "10.f" in hitrust_controls

    def test_incident_response_mappings(self):
        """Test incident response mappings across frameworks."""
        crosswalk = FrameworkCrosswalk()

        # NIST IR-4 -> SOC 2 CC7.4
        result = crosswalk.get_mappings(Framework.NIST_800_53, "IR-4")
        soc2 = result.get_mappings_for_framework(Framework.SOC2)
        soc2_controls = [m.target_control for m in soc2]
        assert "CC7.4" in soc2_controls

        # NIST IR-4 -> ISO A.5.26
        iso = result.get_mappings_for_framework(Framework.ISO_27001)
        iso_controls = [m.target_control for m in iso]
        assert "A.5.26" in iso_controls


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_get_crosswalk(self):
        """Test get_crosswalk factory function."""
        crosswalk = get_crosswalk()
        assert isinstance(crosswalk, FrameworkCrosswalk)

    def test_find_equivalent_controls(self):
        """Test find_equivalent_controls function."""
        equivalents = find_equivalent_controls(
            "AC-2", "nist-800-53", "soc2"
        )

        assert isinstance(equivalents, list)
        assert "CC6.1" in equivalents

    def test_find_equivalent_controls_invalid_framework(self):
        """Test with invalid framework."""
        equivalents = find_equivalent_controls(
            "AC-2", "invalid", "soc2"
        )

        assert equivalents == []

    def test_get_control_coverage_map(self):
        """Test get_control_coverage_map function."""
        coverage = get_control_coverage_map("AC-2", "nist-800-53")

        assert isinstance(coverage, dict)
        assert "soc2" in coverage
        assert "iso-27001" in coverage
        assert "hitrust" in coverage

    def test_get_control_coverage_map_invalid_framework(self):
        """Test with invalid framework."""
        coverage = get_control_coverage_map("AC-2", "invalid")

        assert coverage == {}


# =============================================================================
# Integration Tests
# =============================================================================


class TestCrosswalkIntegration:
    """Integration tests for crosswalk with frameworks."""

    def test_all_nist_controls_have_some_mappings(self):
        """Test that common NIST controls have mappings."""
        crosswalk = FrameworkCrosswalk()

        # Key NIST control families that should have mappings
        key_controls = [
            "AC-1", "AC-2", "AC-3",
            "AU-2", "AU-6",
            "CM-3",
            "IA-2", "IA-5",
            "IR-4",
            "SC-7", "SC-13",
        ]

        for control_id in key_controls:
            result = crosswalk.get_mappings(Framework.NIST_800_53, control_id)
            assert len(result.mappings) > 0, f"No mappings found for {control_id}"

    def test_soc2_controls_have_mappings(self):
        """Test that SOC 2 controls have mappings."""
        crosswalk = FrameworkCrosswalk()

        # Key SOC 2 controls
        key_controls = ["CC6.1", "CC6.6", "CC7.2", "CC8.1"]

        for control_id in key_controls:
            result = crosswalk.get_mappings(Framework.SOC2, control_id)
            assert len(result.mappings) > 0, f"No mappings found for {control_id}"

    def test_iso_controls_have_mappings(self):
        """Test that ISO 27001 controls have mappings."""
        crosswalk = FrameworkCrosswalk()

        # Key ISO controls
        key_controls = ["A.5.15", "A.8.15", "A.8.24", "A.8.32"]

        for control_id in key_controls:
            result = crosswalk.get_mappings(Framework.ISO_27001, control_id)
            assert len(result.mappings) > 0, f"No mappings found for {control_id}"

    def test_hitrust_controls_have_mappings(self):
        """Test that HITRUST controls have mappings."""
        crosswalk = FrameworkCrosswalk()

        # Key HITRUST controls
        key_controls = ["01.a", "01.q", "09.aa", "10.f"]

        for control_id in key_controls:
            result = crosswalk.get_mappings(Framework.HITRUST, control_id)
            assert len(result.mappings) > 0, f"No mappings found for {control_id}"
