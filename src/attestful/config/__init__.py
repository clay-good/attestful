"""
Configuration and credentials management for Attestful.

Provides settings management, encrypted credential storage,
and environment variable support.
"""

from attestful.config.settings import Settings, get_settings
from attestful.config.credentials import (
    CredentialStore,
    Credential,
    get_credential_store,
)

__all__ = [
    "Settings",
    "get_settings",
    "CredentialStore",
    "Credential",
    "get_credential_store",
]
