"""
Unit tests for OSCAL Profile loading and resolution.
"""

import json
import pytest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from attestful.oscal.profile import (
    ProfileLoader,
    ProfileResolver,
    ResolvedCatalog,
    create_profile,
    get_profile_summary,
)
from attestful.oscal.catalog import CatalogLoader, CatalogIndex
from attestful.oscal.models import (
    Profile,
    Catalog,
    Control,
    Group,
    Parameter,
    Part,
    Property,
    Import,
    Merge,
    Modify,
    SetParameter,
    Alter,
    SelectControlById,
    Metadata,
)
from attestful.core.exceptions import ProfileError


# =============================================================================
# Sample Data Fixtures
# =============================================================================


@pytest.fixture
def sample_catalog_data():
    """Create sample OSCAL catalog data."""
    return {
        "uuid": str(uuid4()),
        "metadata": {
            "title": "Test Catalog",
            "last-modified": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "oscal-version": "1.1.2",
        },
        "groups": [
            {
                "id": "ac",
                "title": "Access Control",
                "controls": [
                    {
                        "id": "AC-1",
                        "title": "Policy and Procedures",
                        "params": [
                            {
                                "id": "ac-1_prm_1",
                                "label": "organization-defined frequency",
                            },
                            {
                                "id": "ac-1_prm_2",
                                "label": "organization-defined events",
                            },
                        ],
                        "parts": [
                            {
                                "id": "ac-1_smt",
                                "name": "statement",
                                "prose": "The organization develops access control policy.",
                            },
                        ],
                        "props": [
                            {"name": "label", "value": "AC-1"},
                        ],
                    },
                    {
                        "id": "AC-2",
                        "title": "Account Management",
                        "params": [
                            {
                                "id": "ac-2_prm_1",
                                "label": "organization-defined account types",
                            },
                        ],
                        "parts": [
                            {
                                "id": "ac-2_smt",
                                "name": "statement",
                                "prose": "Manage accounts {{ insert: param, ac-2_prm_1 }}.",
                            },
                        ],
                        "controls": [
                            {
                                "id": "AC-2(1)",
                                "title": "Automated Account Management",
                                "parts": [
                                    {
                                        "id": "ac-2.1_smt",
                                        "name": "statement",
                                        "prose": "Use automated mechanisms.",
                                    },
                                ],
                            },
                            {
                                "id": "AC-2(2)",
                                "title": "Automated Temporary Accounts",
                                "parts": [
                                    {
                                        "id": "ac-2.2_smt",
                                        "name": "statement",
                                        "prose": "Automatically remove temporary accounts.",
                                    },
                                ],
                            },
                        ],
                    },
                    {
                        "id": "AC-3",
                        "title": "Access Enforcement",
                        "parts": [
                            {
                                "id": "ac-3_smt",
                                "name": "statement",
                                "prose": "Enforce approved authorizations.",
                            },
                        ],
                    },
                ],
            },
            {
                "id": "sc",
                "title": "System and Communications Protection",
                "controls": [
                    {
                        "id": "SC-1",
                        "title": "Policy and Procedures",
                        "parts": [
                            {
                                "id": "sc-1_smt",
                                "name": "statement",
                                "prose": "System and communications protection policy.",
                            },
                        ],
                    },
                    {
                        "id": "SC-8",
                        "title": "Transmission Confidentiality",
                        "parts": [
                            {
                                "id": "sc-8_smt",
                                "name": "statement",
                                "prose": "Protect transmission confidentiality.",
                            },
                        ],
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_catalog(sample_catalog_data):
    """Create a sample Catalog object."""
    return Catalog.model_validate(sample_catalog_data)


@pytest.fixture
def sample_catalog_file(temp_dir, sample_catalog_data):
    """Create a sample catalog file."""
    catalog_path = temp_dir / "catalog.json"
    catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))
    return catalog_path


@pytest.fixture
def sample_profile_data(sample_catalog_file):
    """Create sample OSCAL profile data."""
    return {
        "uuid": str(uuid4()),
        "metadata": {
            "title": "Test Profile",
            "last-modified": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0",
            "oscal-version": "1.1.2",
        },
        "imports": [
            {
                "href": str(sample_catalog_file),
                "include-controls": [
                    {"with-ids": ["AC-1", "AC-2", "AC-3"]},
                ],
            },
        ],
        "modify": {
            "set-parameters": [
                {
                    "param-id": "ac-1_prm_1",
                    "values": ["annually"],
                },
            ],
        },
    }


@pytest.fixture
def sample_profile(sample_profile_data):
    """Create a sample Profile object."""
    return Profile.model_validate(sample_profile_data)


@pytest.fixture
def sample_profile_file(temp_dir, sample_profile_data):
    """Create a sample profile file."""
    profile_path = temp_dir / "profile.json"
    profile_path.write_text(json.dumps({"profile": sample_profile_data}))
    return profile_path


# =============================================================================
# ProfileLoader Tests
# =============================================================================


class TestProfileLoader:
    """Tests for ProfileLoader class."""

    def test_load_json_profile(self, sample_profile_file):
        """Test loading a profile from JSON file."""
        loader = ProfileLoader()
        profile = loader.load(sample_profile_file)

        assert isinstance(profile, Profile)
        assert profile.metadata.title == "Test Profile"
        assert len(profile.imports) == 1

    def test_load_yaml_profile(self, temp_dir, sample_catalog_file):
        """Test loading a profile from YAML file."""
        import yaml

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "YAML Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(sample_catalog_file),
                        "include-all": {},
                    },
                ],
            }
        }

        profile_path = temp_dir / "profile.yaml"
        profile_path.write_text(yaml.dump(profile_data))

        loader = ProfileLoader()
        profile = loader.load(profile_path)

        assert profile.metadata.title == "YAML Profile"

    def test_load_nonexistent_file(self):
        """Test loading non-existent file raises error."""
        loader = ProfileLoader()

        with pytest.raises(ProfileError) as exc_info:
            loader.load("/nonexistent/path/profile.json")

        assert "not found" in str(exc_info.value).lower()

    def test_load_with_cache(self, sample_profile_file):
        """Test that profiles are cached."""
        loader = ProfileLoader()

        profile1 = loader.load(sample_profile_file)
        profile2 = loader.load(sample_profile_file)

        assert profile1 is profile2

    def test_load_without_cache(self, sample_profile_file):
        """Test loading without cache."""
        loader = ProfileLoader()

        profile1 = loader.load(sample_profile_file, use_cache=False)
        profile2 = loader.load(sample_profile_file, use_cache=False)

        assert profile1 is not profile2

    def test_clear_cache(self, sample_profile_file):
        """Test clearing the cache."""
        loader = ProfileLoader()

        profile1 = loader.load(sample_profile_file)
        loader.clear_cache()
        profile2 = loader.load(sample_profile_file)

        assert profile1 is not profile2

    def test_load_from_string_json(self, sample_profile_data):
        """Test loading profile from JSON string."""
        loader = ProfileLoader()
        json_str = json.dumps({"profile": sample_profile_data})

        profile = loader.load_from_string(json_str, format="json")

        assert isinstance(profile, Profile)
        assert profile.metadata.title == "Test Profile"

    def test_load_from_string_yaml(self, sample_catalog_file):
        """Test loading profile from YAML string."""
        import yaml

        loader = ProfileLoader()
        yaml_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "String Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {"href": str(sample_catalog_file), "include-all": {}},
                ],
            }
        }

        profile = loader.load_from_string(yaml.dump(yaml_data), format="yaml")

        assert profile.metadata.title == "String Profile"


# =============================================================================
# ProfileResolver Tests
# =============================================================================


class TestProfileResolverBasic:
    """Basic tests for ProfileResolver."""

    def test_resolver_creation(self):
        """Test creating a resolver."""
        resolver = ProfileResolver()

        assert resolver.catalog_loader is not None
        assert resolver.profile_loader is not None

    def test_resolve_basic_profile(self, sample_profile_file, sample_catalog_file):
        """Test resolving a basic profile."""
        resolver = ProfileResolver(base_path=sample_profile_file.parent)
        profile_loader = ProfileLoader()
        profile = profile_loader.load(sample_profile_file)

        resolved = resolver.resolve(profile)

        assert isinstance(resolved, ResolvedCatalog)
        assert resolved.control_count > 0

    def test_resolve_from_file(self, sample_profile_file):
        """Test resolving directly from file."""
        resolver = ProfileResolver()

        resolved = resolver.resolve_from_file(sample_profile_file)

        assert isinstance(resolved, ResolvedCatalog)


class TestProfileResolverImports:
    """Tests for profile import handling."""

    def test_include_specific_controls(self, temp_dir, sample_catalog_data):
        """Test including specific controls by ID."""
        # Create catalog
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        # Create profile selecting only AC-1 and AC-2
        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Selective Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [
                            {"with-ids": ["AC-1", "AC-2"]},
                        ],
                    },
                ],
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control_ids = resolved.list_control_ids()
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AC-3" not in control_ids
        assert "SC-1" not in control_ids

    def test_include_with_child_controls(self, temp_dir, sample_catalog_data):
        """Test including controls with child controls."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Child Controls Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [
                            {"with-ids": ["AC-2"], "with-child-controls": "yes"},
                        ],
                    },
                ],
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control_ids = resolved.list_control_ids()
        assert "AC-2" in control_ids
        assert "AC-2(1)" in control_ids
        assert "AC-2(2)" in control_ids

    def test_include_all_controls(self, temp_dir, sample_catalog_data):
        """Test including all controls."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "All Controls Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-all": {},
                    },
                ],
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        # Should have all controls from catalog
        control_ids = resolved.list_control_ids()
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "AC-3" in control_ids
        assert "SC-1" in control_ids
        assert "SC-8" in control_ids

    def test_exclude_controls(self, temp_dir, sample_catalog_data):
        """Test excluding specific controls."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Exclude Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-all": {},
                        "exclude-controls": [
                            {"with-ids": ["SC-1", "SC-8"]},
                        ],
                    },
                ],
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control_ids = resolved.list_control_ids()
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        assert "SC-1" not in control_ids
        assert "SC-8" not in control_ids


class TestProfileResolverModifications:
    """Tests for profile modification handling."""

    def test_set_parameter_value(self, temp_dir, sample_catalog_data):
        """Test setting parameter values."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Parameter Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [{"with-ids": ["AC-1"]}],
                    },
                ],
                "modify": {
                    "set-parameters": [
                        {
                            "param-id": "ac-1_prm_1",
                            "values": ["annually"],
                        },
                        {
                            "param-id": "ac-1_prm_2",
                            "values": ["significant changes"],
                        },
                    ],
                },
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        assert resolved.resolved_parameters.get("ac-1_prm_1") == "annually"
        assert resolved.resolved_parameters.get("ac-1_prm_2") == "significant changes"

    def test_alter_control_add_part(self, temp_dir, sample_catalog_data):
        """Test adding parts to a control via alteration."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Alter Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [{"with-ids": ["AC-1"]}],
                    },
                ],
                "modify": {
                    "alters": [
                        {
                            "control-id": "AC-1",
                            "adds": [
                                {
                                    "position": "ending",
                                    "parts": [
                                        {
                                            "id": "ac-1_org",
                                            "name": "guidance",
                                            "prose": "Organization-specific guidance.",
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control = resolved.get_control("AC-1")
        assert control is not None
        part_ids = [p.id for p in control.parts if p.id]
        assert "ac-1_org" in part_ids

    def test_alter_control_add_property(self, temp_dir, sample_catalog_data):
        """Test adding properties to a control."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Property Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [{"with-ids": ["AC-1"]}],
                    },
                ],
                "modify": {
                    "alters": [
                        {
                            "control-id": "AC-1",
                            "adds": [
                                {
                                    "props": [
                                        {"name": "priority", "value": "P1"},
                                    ],
                                },
                            ],
                        },
                    ],
                },
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control = resolved.get_control("AC-1")
        assert control is not None
        assert any(p.name == "priority" and p.value == "P1" for p in control.props)

    def test_alter_control_remove_part(self, temp_dir, sample_catalog_data):
        """Test removing parts from a control."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Remove Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [{"with-ids": ["AC-1"]}],
                    },
                ],
                "modify": {
                    "alters": [
                        {
                            "control-id": "AC-1",
                            "removes": [
                                {"by-id": "ac-1_smt"},
                            ],
                        },
                    ],
                },
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        control = resolved.get_control("AC-1")
        assert control is not None
        part_ids = [p.id for p in (control.parts or []) if p.id]
        assert "ac-1_smt" not in part_ids


class TestProfileResolverMerge:
    """Tests for profile merge handling."""

    def test_merge_flat(self, temp_dir, sample_catalog_data):
        """Test flat merge option."""
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Flat Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-all": {},
                    },
                ],
                "merge": {
                    "flat": {},
                },
            }
        }

        profile_path = temp_dir / "profile.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile_path)

        # Should have controls directly without group hierarchy
        assert resolved.control_count > 0


class TestProfileResolverCaching:
    """Tests for profile resolver caching."""

    def test_resolution_caching(self, sample_profile_file):
        """Test that resolved catalogs are cached."""
        resolver = ProfileResolver()

        resolved1 = resolver.resolve_from_file(sample_profile_file)
        resolved2 = resolver.resolve_from_file(sample_profile_file)

        # Should be same object due to caching
        assert resolved1 is resolved2

    def test_clear_cache(self, sample_profile_file):
        """Test clearing resolver cache."""
        resolver = ProfileResolver()

        resolved1 = resolver.resolve_from_file(sample_profile_file)
        resolver.clear_cache()
        resolved2 = resolver.resolve_from_file(sample_profile_file)

        assert resolved1 is not resolved2


# =============================================================================
# ResolvedCatalog Tests
# =============================================================================


class TestResolvedCatalog:
    """Tests for ResolvedCatalog class."""

    def test_get_control(self, sample_profile_file):
        """Test getting a control from resolved catalog."""
        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(sample_profile_file)

        control = resolved.get_control("AC-1")

        assert control is not None
        assert control.id == "AC-1"

    def test_get_nonexistent_control(self, sample_profile_file):
        """Test getting a non-existent control returns None."""
        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(sample_profile_file)

        control = resolved.get_control("NONEXISTENT")

        assert control is None

    def test_list_control_ids(self, sample_profile_file):
        """Test listing control IDs."""
        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(sample_profile_file)

        ids = resolved.list_control_ids()

        assert isinstance(ids, list)
        assert len(ids) > 0

    def test_control_count(self, sample_profile_file):
        """Test control count property."""
        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(sample_profile_file)

        count = resolved.control_count

        assert count > 0
        assert count == len(resolved.list_control_ids())

    def test_index_property(self, sample_profile_file):
        """Test that index property returns CatalogIndex."""
        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(sample_profile_file)

        # Access index multiple times
        index1 = resolved.index
        index2 = resolved.index

        # Should return same index object
        assert index1 is index2
        assert isinstance(index1, CatalogIndex)


# =============================================================================
# create_profile Function Tests
# =============================================================================


class TestCreateProfile:
    """Tests for create_profile convenience function."""

    def test_basic_profile_creation(self, sample_catalog_file):
        """Test creating a basic profile."""
        profile = create_profile(
            title="Custom Profile",
            imports=[
                {
                    "href": str(sample_catalog_file),
                    "include-all": {},
                },
            ],
        )

        assert isinstance(profile, Profile)
        assert profile.metadata.title == "Custom Profile"
        assert len(profile.imports) == 1

    def test_profile_with_modifications(self, sample_catalog_file):
        """Test creating a profile with modifications."""
        profile = create_profile(
            title="Modified Profile",
            imports=[
                {
                    "href": str(sample_catalog_file),
                    "include-controls": [{"with-ids": ["AC-1"]}],
                },
            ],
            modify={
                "set-parameters": [
                    {"param-id": "ac-1_prm_1", "values": ["monthly"]},
                ],
            },
        )

        assert profile.modify is not None
        assert len(profile.modify.set_parameters) == 1

    def test_profile_with_merge(self, sample_catalog_file):
        """Test creating a profile with merge settings."""
        profile = create_profile(
            title="Merged Profile",
            imports=[
                {"href": str(sample_catalog_file), "include-all": {}},
            ],
            merge={"flat": {}},
        )

        assert profile.merge is not None
        assert profile.merge.flat is not None

    def test_profile_version(self, sample_catalog_file):
        """Test setting profile version."""
        profile = create_profile(
            title="Versioned Profile",
            imports=[{"href": str(sample_catalog_file), "include-all": {}}],
            version="2.0.0",
        )

        assert profile.metadata.version == "2.0.0"


# =============================================================================
# get_profile_summary Function Tests
# =============================================================================


class TestGetProfileSummary:
    """Tests for get_profile_summary function."""

    def test_basic_summary(self, sample_profile_file):
        """Test getting basic profile summary."""
        loader = ProfileLoader()
        profile = loader.load(sample_profile_file)

        summary = get_profile_summary(profile)

        assert "uuid" in summary
        assert "title" in summary
        assert "version" in summary
        assert "imports" in summary
        assert "modifications" in summary

    def test_summary_import_details(self, sample_catalog_file):
        """Test that summary includes import details."""
        profile = create_profile(
            title="Summary Test",
            imports=[
                {
                    "href": str(sample_catalog_file),
                    "include-controls": [
                        {"with-ids": ["AC-1", "AC-2", "AC-3"]},
                    ],
                },
            ],
        )

        summary = get_profile_summary(profile)

        assert len(summary["imports"]) == 1
        assert summary["imports"][0]["control_selections"] == 3
        assert summary["imports"][0]["include_all"] is False

    def test_summary_modification_counts(self, sample_catalog_file):
        """Test that summary includes modification counts."""
        profile = create_profile(
            title="Modification Summary",
            imports=[
                {"href": str(sample_catalog_file), "include-all": {}},
            ],
            modify={
                "set-parameters": [
                    {"param-id": "param-1", "values": ["value1"]},
                    {"param-id": "param-2", "values": ["value2"]},
                ],
                "alters": [
                    {"control-id": "AC-1", "adds": []},
                ],
            },
        )

        summary = get_profile_summary(profile)

        assert summary["modifications"]["parameter_settings"] == 2
        assert summary["modifications"]["alterations"] == 1


# =============================================================================
# Profile Chaining Tests
# =============================================================================


class TestProfileChaining:
    """Tests for profile chaining (profile importing profile)."""

    def test_chained_profile_resolution(self, temp_dir, sample_catalog_data):
        """Test resolving a profile that imports another profile."""
        # Create base catalog
        catalog_path = temp_dir / "catalog.json"
        catalog_path.write_text(json.dumps({"catalog": sample_catalog_data}))

        # Create first profile (selects some controls)
        profile1_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Base Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(catalog_path),
                        "include-controls": [
                            {"with-ids": ["AC-1", "AC-2", "AC-3", "SC-1"]},
                        ],
                    },
                ],
            }
        }

        profile1_path = temp_dir / "profile1.json"
        profile1_path.write_text(json.dumps(profile1_data))

        # Create second profile that imports first profile
        profile2_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Derived Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": str(profile1_path),
                        "include-controls": [
                            {"with-ids": ["AC-1", "AC-2"]},  # Only subset
                        ],
                    },
                ],
            }
        }

        profile2_path = temp_dir / "profile2.json"
        profile2_path.write_text(json.dumps(profile2_data))

        resolver = ProfileResolver()
        resolved = resolver.resolve_from_file(profile2_path)

        control_ids = resolved.list_control_ids()
        assert "AC-1" in control_ids
        assert "AC-2" in control_ids
        # These should not be in derived profile
        assert "AC-3" not in control_ids
        assert "SC-1" not in control_ids


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestProfileErrorHandling:
    """Tests for error handling in profile operations."""

    def test_invalid_href(self, temp_dir):
        """Test handling of invalid href."""
        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "Invalid Href Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": "/nonexistent/catalog.json",
                        "include-all": {},
                    },
                ],
            }
        }

        profile_path = temp_dir / "invalid_href.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()

        with pytest.raises(Exception):
            resolver.resolve_from_file(profile_path)

    def test_unsupported_href_scheme(self, temp_dir):
        """Test handling of unsupported href scheme."""
        profile_data = {
            "profile": {
                "uuid": str(uuid4()),
                "metadata": {
                    "title": "HTTP Href Profile",
                    "last-modified": datetime.now(timezone.utc).isoformat(),
                    "version": "1.0.0",
                    "oscal-version": "1.1.2",
                },
                "imports": [
                    {
                        "href": "https://example.com/catalog.json",
                        "include-all": {},
                    },
                ],
            }
        }

        profile_path = temp_dir / "http_href.json"
        profile_path.write_text(json.dumps(profile_data))

        resolver = ProfileResolver()

        with pytest.raises(ProfileError) as exc_info:
            resolver.resolve_from_file(profile_path)

        assert "scheme" in str(exc_info.value).lower()

    def test_malformed_profile(self, temp_dir):
        """Test handling of malformed profile."""
        profile_path = temp_dir / "malformed.json"
        profile_path.write_text('{"profile": {"not": "valid"}}')

        loader = ProfileLoader()

        with pytest.raises(Exception):
            loader.load(profile_path)
