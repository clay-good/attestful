"""
Unit tests for OSCAL Catalog loader and indexer.

Tests cover:
- Catalog loading from JSON, YAML, and string formats
- CatalogIndex functionality including control lookup
- Parameter resolution
- Edge cases and error handling
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from attestful.oscal.catalog import CatalogIndex, CatalogLoader, resolve_parameters
from attestful.oscal.models import (
    Catalog,
    Control,
    Group,
    Metadata,
    Parameter,
    Part,
    Property,
)
from attestful.core.exceptions import CatalogError


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_metadata() -> Metadata:
    """Create sample metadata for testing."""
    return Metadata(
        title="Test Catalog",
        last_modified=datetime.now(),
        version="1.0.0",
        oscal_version="1.1.2",
    )


@pytest.fixture
def sample_control() -> Control:
    """Create a sample control for testing."""
    return Control(
        id="AC-1",
        title="Access Control Policy and Procedures",
        props=[
            Property(name="label", value="AC-1"),
            Property(name="sort-id", value="ac-01"),
        ],
        params=[
            Parameter(
                id="ac-1_prm_1",
                label="organization-defined personnel or roles",
            ),
        ],
        parts=[
            Part(
                id="ac-1_smt",
                name="statement",
                prose="The organization {{ insert: param, ac-1_prm_1 }} develops access control policy.",
            ),
        ],
    )


@pytest.fixture
def sample_control_with_enhancements() -> Control:
    """Create a control with enhancements (nested controls)."""
    return Control(
        id="AC-2",
        title="Account Management",
        controls=[
            Control(
                id="AC-2(1)",
                title="Automated System Account Management",
            ),
            Control(
                id="AC-2(2)",
                title="Automated Temporary and Emergency Account Management",
            ),
        ],
    )


@pytest.fixture
def sample_group() -> Group:
    """Create a sample group with controls."""
    return Group(
        id="ac",
        title="Access Control",
        controls=[
            Control(id="AC-1", title="Access Control Policy"),
            Control(id="AC-2", title="Account Management"),
        ],
    )


@pytest.fixture
def sample_catalog(sample_metadata: Metadata) -> Catalog:
    """Create a sample catalog for testing."""
    return Catalog(
        uuid=uuid4(),
        metadata=sample_metadata,
        params=[
            Parameter(id="global-param-1", label="Global Parameter"),
        ],
        groups=[
            Group(
                id="ac",
                title="Access Control",
                params=[
                    Parameter(id="ac-group-param", label="AC Group Parameter"),
                ],
                controls=[
                    Control(
                        id="AC-1",
                        title="Access Control Policy",
                        params=[
                            Parameter(id="ac-1_prm_1", label="AC-1 Param 1"),
                        ],
                        props=[
                            Property(name="label", value="AC-1"),
                        ],
                    ),
                    Control(
                        id="AC-2",
                        title="Account Management",
                        controls=[
                            Control(id="AC-2(1)", title="Automated Management"),
                            Control(id="AC-2(2)", title="Temporary Accounts"),
                        ],
                    ),
                ],
            ),
            Group(
                id="au",
                title="Audit and Accountability",
                controls=[
                    Control(id="AU-1", title="Audit Policy"),
                ],
            ),
        ],
    )


@pytest.fixture
def catalog_json(sample_catalog: Catalog) -> str:
    """Create catalog JSON string."""
    return sample_catalog.to_json()


@pytest.fixture
def catalog_yaml(sample_catalog: Catalog) -> str:
    """Create catalog YAML string."""
    return sample_catalog.to_yaml()


@pytest.fixture
def catalog_file_json(sample_catalog: Catalog, tmp_path: Path) -> Path:
    """Create a temporary JSON catalog file."""
    file_path = tmp_path / "catalog.json"
    file_path.write_text(sample_catalog.to_json())
    return file_path


@pytest.fixture
def catalog_file_yaml(sample_catalog: Catalog, tmp_path: Path) -> Path:
    """Create a temporary YAML catalog file."""
    file_path = tmp_path / "catalog.yaml"
    file_path.write_text(sample_catalog.to_yaml())
    return file_path


# =============================================================================
# CatalogLoader Tests
# =============================================================================


class TestCatalogLoader:
    """Tests for CatalogLoader class."""

    def test_load_json_file(self, catalog_file_json: Path) -> None:
        """Test loading a catalog from a JSON file."""
        loader = CatalogLoader()
        catalog = loader.load(catalog_file_json)

        assert catalog is not None
        assert catalog.metadata.title == "Test Catalog"
        assert catalog.groups is not None
        assert len(catalog.groups) == 2

    def test_load_yaml_file(self, catalog_file_yaml: Path) -> None:
        """Test loading a catalog from a YAML file."""
        loader = CatalogLoader()
        catalog = loader.load(catalog_file_yaml)

        assert catalog is not None
        assert catalog.metadata.title == "Test Catalog"

    def test_load_with_cache(self, catalog_file_json: Path) -> None:
        """Test that catalog caching works."""
        loader = CatalogLoader()

        # First load
        catalog1 = loader.load(catalog_file_json, use_cache=True)

        # Second load should return cached version
        catalog2 = loader.load(catalog_file_json, use_cache=True)

        assert catalog1 is catalog2

    def test_load_without_cache(self, catalog_file_json: Path) -> None:
        """Test loading without cache returns new instance."""
        loader = CatalogLoader()

        catalog1 = loader.load(catalog_file_json, use_cache=False)
        catalog2 = loader.load(catalog_file_json, use_cache=False)

        # Should be different instances (equal content but different objects)
        assert catalog1 is not catalog2

    def test_load_nonexistent_file(self) -> None:
        """Test that loading a nonexistent file raises CatalogError."""
        loader = CatalogLoader()

        with pytest.raises(CatalogError) as exc_info:
            loader.load("/nonexistent/path/catalog.json")

        assert "not found" in str(exc_info.value).lower()

    def test_load_invalid_json(self, tmp_path: Path) -> None:
        """Test that loading invalid JSON raises CatalogError."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("{ invalid json }")

        loader = CatalogLoader()

        with pytest.raises(CatalogError):
            loader.load(invalid_file)

    def test_load_from_string_json(self, catalog_json: str) -> None:
        """Test loading catalog from JSON string."""
        loader = CatalogLoader()
        catalog = loader.load_from_string(catalog_json, format="json")

        assert catalog is not None
        assert catalog.metadata.title == "Test Catalog"

    def test_load_from_string_yaml(self, catalog_yaml: str) -> None:
        """Test loading catalog from YAML string."""
        loader = CatalogLoader()
        catalog = loader.load_from_string(catalog_yaml, format="yaml")

        assert catalog is not None
        assert catalog.metadata.title == "Test Catalog"

    def test_load_wrapped_catalog(self, sample_catalog: Catalog, tmp_path: Path) -> None:
        """Test loading a catalog wrapped in a 'catalog' key."""
        wrapped_data = {"catalog": json.loads(sample_catalog.to_json())}
        file_path = tmp_path / "wrapped.json"
        file_path.write_text(json.dumps(wrapped_data))

        loader = CatalogLoader()
        catalog = loader.load(file_path)

        assert catalog.metadata.title == "Test Catalog"

    def test_clear_cache(self, catalog_file_json: Path) -> None:
        """Test clearing the catalog cache."""
        loader = CatalogLoader()

        # Load and cache
        catalog1 = loader.load(catalog_file_json, use_cache=True)

        # Clear cache
        loader.clear_cache()

        # Load again - should be new instance
        catalog2 = loader.load(catalog_file_json, use_cache=True)

        assert catalog1 is not catalog2

    def test_create_index(self, sample_catalog: Catalog) -> None:
        """Test creating an index from a catalog."""
        loader = CatalogLoader()
        index = loader.create_index(sample_catalog)

        assert isinstance(index, CatalogIndex)
        assert index.control_count > 0

    def test_load_xml_not_implemented(self, tmp_path: Path) -> None:
        """Test that XML loading raises appropriate error."""
        xml_file = tmp_path / "catalog.xml"
        xml_file.write_text("<catalog></catalog>")

        loader = CatalogLoader()

        with pytest.raises(CatalogError) as exc_info:
            loader.load(xml_file)

        assert "xml" in str(exc_info.value).lower()


# =============================================================================
# CatalogIndex Tests
# =============================================================================


class TestCatalogIndex:
    """Tests for CatalogIndex class."""

    def test_index_creation(self, sample_catalog: Catalog) -> None:
        """Test that index is created correctly."""
        index = CatalogIndex(sample_catalog)

        # Should have indexed all controls
        assert index.control_count > 0
        assert index.group_count == 2

    def test_get_control(self, sample_catalog: Catalog) -> None:
        """Test getting a control by ID."""
        index = CatalogIndex(sample_catalog)

        control = index.get_control("AC-1")
        assert control is not None
        assert control.id == "AC-1"
        assert control.title == "Access Control Policy"

    def test_get_control_not_found(self, sample_catalog: Catalog) -> None:
        """Test getting a nonexistent control returns None."""
        index = CatalogIndex(sample_catalog)

        control = index.get_control("NONEXISTENT")
        assert control is None

    def test_get_control_enhancement(self, sample_catalog: Catalog) -> None:
        """Test getting a control enhancement."""
        index = CatalogIndex(sample_catalog)

        enhancement = index.get_control("AC-2(1)")
        assert enhancement is not None
        assert enhancement.id == "AC-2(1)"
        assert enhancement.title == "Automated Management"

    def test_get_control_with_path(self, sample_catalog: Catalog) -> None:
        """Test getting a control with its path."""
        index = CatalogIndex(sample_catalog)

        control, path = index.get_control_with_path("AC-2(1)")

        assert control is not None
        assert control.id == "AC-2(1)"
        # Path should include group and parent control
        assert "ac" in path
        assert "AC-2" in path

    def test_get_control_with_path_not_found(self, sample_catalog: Catalog) -> None:
        """Test getting path for nonexistent control."""
        index = CatalogIndex(sample_catalog)

        control, path = index.get_control_with_path("NONEXISTENT")

        assert control is None
        assert path == []

    def test_get_enhancements(self, sample_catalog: Catalog) -> None:
        """Test getting control enhancements."""
        index = CatalogIndex(sample_catalog)

        enhancements = index.get_enhancements("AC-2")

        assert len(enhancements) == 2
        assert any(e.id == "AC-2(1)" for e in enhancements)
        assert any(e.id == "AC-2(2)" for e in enhancements)

    def test_get_enhancements_none(self, sample_catalog: Catalog) -> None:
        """Test getting enhancements for control without any."""
        index = CatalogIndex(sample_catalog)

        enhancements = index.get_enhancements("AC-1")
        assert enhancements == []

    def test_get_parent_control(self, sample_catalog: Catalog) -> None:
        """Test getting parent control of an enhancement."""
        index = CatalogIndex(sample_catalog)

        parent = index.get_parent_control("AC-2(1)")

        assert parent is not None
        assert parent.id == "AC-2"

    def test_get_parent_control_none(self, sample_catalog: Catalog) -> None:
        """Test getting parent of top-level control."""
        index = CatalogIndex(sample_catalog)

        parent = index.get_parent_control("AC-1")
        assert parent is None

    def test_get_group(self, sample_catalog: Catalog) -> None:
        """Test getting the group containing a control."""
        index = CatalogIndex(sample_catalog)

        group = index.get_group("AC-1")

        assert group is not None
        assert group.id == "ac"
        assert group.title == "Access Control"

    def test_get_parameter(self, sample_catalog: Catalog) -> None:
        """Test getting a parameter by ID."""
        index = CatalogIndex(sample_catalog)

        # Global parameter
        global_param = index.get_parameter("global-param-1")
        assert global_param is not None
        assert global_param.label == "Global Parameter"

        # Group parameter
        group_param = index.get_parameter("ac-group-param")
        assert group_param is not None

        # Control parameter
        control_param = index.get_parameter("ac-1_prm_1")
        assert control_param is not None

    def test_list_all_controls(self, sample_catalog: Catalog) -> None:
        """Test listing all controls."""
        index = CatalogIndex(sample_catalog)

        controls = index.list_all_controls()

        # Should include AC-1, AC-2, AC-2(1), AC-2(2), AU-1
        assert len(controls) == 5
        control_ids = [c.id for c in controls]
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AC-2(1)" in control_ids
        assert "AU-1" in control_ids

    def test_list_control_ids(self, sample_catalog: Catalog) -> None:
        """Test listing all control IDs."""
        index = CatalogIndex(sample_catalog)

        control_ids = index.list_control_ids()

        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AC-2(1)" in control_ids

    def test_list_groups(self, sample_catalog: Catalog) -> None:
        """Test listing all groups."""
        index = CatalogIndex(sample_catalog)

        groups = index.list_groups()

        assert len(groups) == 2
        group_ids = [g.id for g in groups]
        assert "ac" in group_ids
        assert "au" in group_ids

    def test_search_controls_by_title(self, sample_catalog: Catalog) -> None:
        """Test searching controls by title."""
        index = CatalogIndex(sample_catalog)

        results = index.search_controls(title_contains="access")

        # Should find AC-1 (Access Control Policy)
        assert len(results) >= 1
        assert any(c.id == "AC-1" for c in results)

    def test_search_controls_by_title_case_insensitive(
        self, sample_catalog: Catalog
    ) -> None:
        """Test that title search is case-insensitive."""
        index = CatalogIndex(sample_catalog)

        results_upper = index.search_controls(title_contains="ACCESS")
        results_lower = index.search_controls(title_contains="access")

        assert len(results_upper) == len(results_lower)

    def test_search_controls_by_property(self, sample_catalog: Catalog) -> None:
        """Test searching controls by property."""
        index = CatalogIndex(sample_catalog)

        results = index.search_controls(has_property="label")

        assert len(results) >= 1
        assert any(c.id == "AC-1" for c in results)

    def test_search_controls_by_group(self, sample_catalog: Catalog) -> None:
        """Test searching controls by group."""
        index = CatalogIndex(sample_catalog)

        results = index.search_controls(in_group="ac")

        # Should find AC-1 and AC-2
        control_ids = [c.id for c in results]
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AU-1" not in control_ids

    def test_search_controls_combined_filters(self, sample_catalog: Catalog) -> None:
        """Test searching with multiple filters."""
        index = CatalogIndex(sample_catalog)

        results = index.search_controls(
            title_contains="policy",
            in_group="ac",
        )

        assert len(results) >= 1
        assert any(c.id == "AC-1" for c in results)

    def test_search_controls_no_matches(self, sample_catalog: Catalog) -> None:
        """Test searching with no matches."""
        index = CatalogIndex(sample_catalog)

        results = index.search_controls(title_contains="nonexistent")

        assert results == []


# =============================================================================
# Parameter Resolution Tests
# =============================================================================


class TestParameterResolution:
    """Tests for parameter resolution functionality."""

    def test_resolve_single_parameter(self) -> None:
        """Test resolving a single parameter."""
        text = "The {{ insert: param, ac-1_prm_1 }} shall develop policy."
        parameters = {"ac-1_prm_1": "organization"}

        result = resolve_parameters(text, parameters)

        assert result == "The organization shall develop policy."

    def test_resolve_multiple_parameters(self) -> None:
        """Test resolving multiple parameters in text."""
        text = (
            "The {{ insert: param, param-1 }} and {{ insert: param, param-2 }} "
            "shall comply."
        )
        parameters = {"param-1": "CISO", "param-2": "Security Team"}

        result = resolve_parameters(text, parameters)

        assert result == "The CISO and Security Team shall comply."

    def test_resolve_missing_parameter(self) -> None:
        """Test that missing parameters are replaced with placeholder."""
        text = "The {{ insert: param, missing-param }} shall comply."
        parameters = {}

        result = resolve_parameters(text, parameters)

        assert result == "The [missing-param] shall comply."

    def test_resolve_no_parameters(self) -> None:
        """Test text with no parameters is unchanged."""
        text = "This is regular text with no parameters."
        parameters = {}

        result = resolve_parameters(text, parameters)

        assert result == text

    def test_resolve_parameter_variations(self) -> None:
        """Test parameter resolution with whitespace variations."""
        # Various whitespace patterns
        texts = [
            "{{ insert: param, test }}",
            "{{insert: param, test}}",
            "{{  insert:  param,  test  }}",
        ]
        parameters = {"test": "VALUE"}

        for text in texts:
            result = resolve_parameters(text, parameters)
            assert result == "VALUE"


# =============================================================================
# Edge Cases and Error Handling
# =============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_catalog(self, sample_metadata: Metadata) -> None:
        """Test indexing an empty catalog."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
        )

        index = CatalogIndex(catalog)

        assert index.control_count == 0
        assert index.group_count == 0
        assert index.list_all_controls() == []

    def test_catalog_with_only_top_level_controls(
        self, sample_metadata: Metadata
    ) -> None:
        """Test catalog with controls outside groups."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
            controls=[
                Control(id="C-1", title="Control 1"),
                Control(id="C-2", title="Control 2"),
            ],
        )

        index = CatalogIndex(catalog)

        assert index.control_count == 2
        assert index.group_count == 0
        assert index.get_control("C-1") is not None

    def test_nested_groups(self, sample_metadata: Metadata) -> None:
        """Test catalog with nested groups."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
            groups=[
                Group(
                    id="parent",
                    title="Parent Group",
                    groups=[
                        Group(
                            id="child",
                            title="Child Group",
                            controls=[
                                Control(id="C-1", title="Nested Control"),
                            ],
                        ),
                    ],
                ),
            ],
        )

        index = CatalogIndex(catalog)

        # Should index both groups
        assert index.group_count == 2
        # Should find the nested control
        assert index.get_control("C-1") is not None

    def test_deeply_nested_enhancements(self, sample_metadata: Metadata) -> None:
        """Test controls with deeply nested enhancements."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
            controls=[
                Control(
                    id="AC-2",
                    title="Account Management",
                    controls=[
                        Control(
                            id="AC-2(1)",
                            title="Enhancement 1",
                            controls=[
                                Control(id="AC-2(1)(a)", title="Sub-enhancement"),
                            ],
                        ),
                    ],
                ),
            ],
        )

        index = CatalogIndex(catalog)

        # Should find all levels
        assert index.get_control("AC-2") is not None
        assert index.get_control("AC-2(1)") is not None
        assert index.get_control("AC-2(1)(a)") is not None

        # Should track parent relationships
        parent_of_sub = index.get_parent_control("AC-2(1)(a)")
        assert parent_of_sub is not None
        assert parent_of_sub.id == "AC-2(1)"

    def test_unicode_in_catalog(self, sample_metadata: Metadata) -> None:
        """Test catalog with unicode characters."""
        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
            controls=[
                Control(id="C-1", title="Control with unicode: \u00e9\u00e8\u00ea"),
            ],
        )

        index = CatalogIndex(catalog)

        control = index.get_control("C-1")
        assert control is not None
        assert "\u00e9" in control.title

    def test_large_catalog_performance(self, sample_metadata: Metadata) -> None:
        """Test indexing a large catalog performs acceptably."""
        # Create catalog with many controls
        controls = [
            Control(id=f"CTRL-{i}", title=f"Control {i}")
            for i in range(1000)
        ]

        catalog = Catalog(
            uuid=uuid4(),
            metadata=sample_metadata,
            controls=controls,
        )

        # Should complete quickly
        index = CatalogIndex(catalog)

        assert index.control_count == 1000

        # Lookups should be fast (O(1))
        control = index.get_control("CTRL-500")
        assert control is not None


# =============================================================================
# Round-Trip Tests
# =============================================================================


class TestRoundTrip:
    """Tests for JSON/YAML serialization round-trips."""

    def test_json_round_trip(self, sample_catalog: Catalog) -> None:
        """Test that JSON serialization round-trips correctly."""
        json_str = sample_catalog.to_json()
        loaded = Catalog.from_json(json_str)

        assert loaded.metadata.title == sample_catalog.metadata.title
        assert loaded.uuid == sample_catalog.uuid

    def test_yaml_round_trip(self, sample_catalog: Catalog) -> None:
        """Test that YAML serialization round-trips correctly."""
        yaml_str = sample_catalog.to_yaml()
        loaded = Catalog.from_yaml(yaml_str)

        assert loaded.metadata.title == sample_catalog.metadata.title

    def test_catalog_file_round_trip(
        self, sample_catalog: Catalog, tmp_path: Path
    ) -> None:
        """Test writing and reading catalog file."""
        # Write to file
        file_path = tmp_path / "catalog.json"
        file_path.write_text(sample_catalog.to_json())

        # Read back
        loader = CatalogLoader()
        loaded = loader.load(file_path)

        # Verify
        assert loaded.metadata.title == sample_catalog.metadata.title
        assert len(loaded.groups or []) == len(sample_catalog.groups or [])
