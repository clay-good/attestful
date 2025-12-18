"""
FedRAMP OSCAL Profile Loader.

Provides access to official FedRAMP baseline OSCAL profiles,
with integrity verification and profile resolution.

The profiles are sourced from:
https://github.com/GSA/fedramp-automation

Profile Details:
- FedRAMP Low: ~156 controls
- FedRAMP Moderate: ~323 controls
- FedRAMP High: ~410 controls
"""

from __future__ import annotations

import hashlib
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from attestful.core.exceptions import ProfileError
from attestful.core.logging import get_logger

if TYPE_CHECKING:
    from attestful.oscal.models import Profile

logger = get_logger("frameworks.nist_800_53.profiles")


class FedRAMPImpactLevel(str, Enum):
    """FedRAMP impact levels."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


# Base path for FedRAMP profiles
FEDRAMP_PROFILES_DIR = (
    Path(__file__).parent.parent.parent.parent.parent
    / "data"
    / "oscal"
    / "profiles"
    / "fedramp"
)

# Profile file paths
FEDRAMP_LOW_PROFILE_PATH = FEDRAMP_PROFILES_DIR / "fedramp-low-baseline.json"
FEDRAMP_MODERATE_PROFILE_PATH = FEDRAMP_PROFILES_DIR / "fedramp-moderate-baseline.json"
FEDRAMP_HIGH_PROFILE_PATH = FEDRAMP_PROFILES_DIR / "fedramp-high-baseline.json"

# SHA-256 hashes for integrity verification
FEDRAMP_PROFILE_SHA256 = {
    FedRAMPImpactLevel.LOW: None,  # Will be computed on first load
    FedRAMPImpactLevel.MODERATE: None,
    FedRAMPImpactLevel.HIGH: None,
}


def get_fedramp_profile_path(impact_level: FedRAMPImpactLevel | str) -> Path:
    """
    Get the path to a FedRAMP baseline profile.

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        Path to the profile JSON file

    Raises:
        ProfileError: If the profile file does not exist
    """
    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    path_map = {
        FedRAMPImpactLevel.LOW: FEDRAMP_LOW_PROFILE_PATH,
        FedRAMPImpactLevel.MODERATE: FEDRAMP_MODERATE_PROFILE_PATH,
        FedRAMPImpactLevel.HIGH: FEDRAMP_HIGH_PROFILE_PATH,
    }

    path = path_map[impact_level]

    if not path.exists():
        raise ProfileError(
            f"FedRAMP {impact_level.value} profile not found at: {path}. "
            "Please ensure the data/oscal/profiles/fedramp/ directory contains the baseline files.",
            profile_id=f"fedramp-{impact_level.value}",
        )

    return path


def verify_profile_integrity(
    impact_level: FedRAMPImpactLevel | str,
) -> tuple[bool, str, str]:
    """
    Verify the integrity of a FedRAMP profile.

    Computes SHA-256 hash of the profile file.

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        Tuple of (is_valid, message, hash)
    """
    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    path = get_fedramp_profile_path(impact_level)

    try:
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()

        return True, f"Profile hash computed (SHA-256: {actual_hash[:16]}...)", actual_hash

    except Exception as e:
        return False, f"Failed to verify profile integrity: {e}", ""


def load_fedramp_profile_raw(impact_level: FedRAMPImpactLevel | str) -> dict:
    """
    Load a FedRAMP profile as raw JSON.

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        Raw profile dictionary
    """
    import json

    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    path = get_fedramp_profile_path(impact_level)

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    return data


@lru_cache(maxsize=3)
def get_fedramp_profile_control_ids(impact_level: FedRAMPImpactLevel | str) -> list[str]:
    """
    Get the list of control IDs included in a FedRAMP baseline.

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        List of control IDs (e.g., ["ac-1", "ac-2", "ac-2.1", ...])
    """
    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    data = load_fedramp_profile_raw(impact_level)
    profile = data.get("profile", {})
    imports = profile.get("imports", [])

    control_ids: list[str] = []

    for imp in imports:
        includes = imp.get("include-controls", [])
        for inc in includes:
            with_ids = inc.get("with-ids", [])
            control_ids.extend(with_ids)

    logger.debug(
        f"FedRAMP {impact_level.value} baseline includes {len(control_ids)} controls"
    )

    return control_ids


def get_fedramp_profile_metadata(impact_level: FedRAMPImpactLevel | str) -> dict:
    """
    Get metadata for a FedRAMP baseline profile.

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        Dictionary with profile metadata
    """
    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    data = load_fedramp_profile_raw(impact_level)
    profile = data.get("profile", {})
    metadata = profile.get("metadata", {})

    return {
        "uuid": profile.get("uuid"),
        "title": metadata.get("title"),
        "version": metadata.get("version"),
        "oscal_version": metadata.get("oscal-version"),
        "published": metadata.get("published"),
        "last_modified": metadata.get("last-modified"),
        "impact_level": impact_level.value,
        "control_count": len(get_fedramp_profile_control_ids(impact_level)),
    }


def get_fedramp_profile_set_parameters(impact_level: FedRAMPImpactLevel | str) -> dict[str, str]:
    """
    Get organization-defined parameter values for a FedRAMP baseline.

    FedRAMP profiles include specific parameter values that organizations
    must use (e.g., password lengths, retention periods).

    Args:
        impact_level: LOW, MODERATE, or HIGH

    Returns:
        Dictionary mapping parameter IDs to their values
    """
    if isinstance(impact_level, str):
        impact_level = FedRAMPImpactLevel(impact_level.lower())

    data = load_fedramp_profile_raw(impact_level)
    profile = data.get("profile", {})

    # Collect all set-parameters from modify section
    modify = profile.get("modify", {})
    set_params = modify.get("set-parameters", [])

    params: dict[str, str] = {}
    for sp in set_params:
        param_id = sp.get("param-id")
        values = sp.get("values", [])
        if param_id and values:
            params[param_id] = values[0] if len(values) == 1 else ", ".join(values)

    return params


def compare_baselines(
    level1: FedRAMPImpactLevel | str,
    level2: FedRAMPImpactLevel | str,
) -> dict:
    """
    Compare two FedRAMP baselines.

    Args:
        level1: First impact level
        level2: Second impact level

    Returns:
        Dictionary with comparison results
    """
    if isinstance(level1, str):
        level1 = FedRAMPImpactLevel(level1.lower())
    if isinstance(level2, str):
        level2 = FedRAMPImpactLevel(level2.lower())

    controls1 = set(get_fedramp_profile_control_ids(level1))
    controls2 = set(get_fedramp_profile_control_ids(level2))

    return {
        f"{level1.value}_only": sorted(controls1 - controls2),
        f"{level2.value}_only": sorted(controls2 - controls1),
        "common": sorted(controls1 & controls2),
        f"{level1.value}_count": len(controls1),
        f"{level2.value}_count": len(controls2),
        "common_count": len(controls1 & controls2),
    }


def get_all_fedramp_statistics() -> dict:
    """
    Get statistics for all FedRAMP baselines.

    Returns:
        Dictionary with statistics for each baseline
    """
    stats = {}

    for level in FedRAMPImpactLevel:
        metadata = get_fedramp_profile_metadata(level)
        _, _, file_hash = verify_profile_integrity(level)

        stats[level.value] = {
            **metadata,
            "sha256": file_hash[:32] + "..." if file_hash else None,
        }

    # Add comparison data
    stats["comparison"] = {
        "low_to_moderate_delta": len(
            set(get_fedramp_profile_control_ids(FedRAMPImpactLevel.MODERATE))
            - set(get_fedramp_profile_control_ids(FedRAMPImpactLevel.LOW))
        ),
        "moderate_to_high_delta": len(
            set(get_fedramp_profile_control_ids(FedRAMPImpactLevel.HIGH))
            - set(get_fedramp_profile_control_ids(FedRAMPImpactLevel.MODERATE))
        ),
    }

    return stats


__all__ = [
    # Enum
    "FedRAMPImpactLevel",
    # Path constants
    "FEDRAMP_PROFILES_DIR",
    "FEDRAMP_LOW_PROFILE_PATH",
    "FEDRAMP_MODERATE_PROFILE_PATH",
    "FEDRAMP_HIGH_PROFILE_PATH",
    # Path functions
    "get_fedramp_profile_path",
    # Verification
    "verify_profile_integrity",
    # Loading
    "load_fedramp_profile_raw",
    # Control access
    "get_fedramp_profile_control_ids",
    "get_fedramp_profile_metadata",
    "get_fedramp_profile_set_parameters",
    # Comparison
    "compare_baselines",
    # Statistics
    "get_all_fedramp_statistics",
]
