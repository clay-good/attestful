"""
Settings management for Attestful.

Uses Pydantic Settings for environment variable support
and configuration file loading.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings with environment variable support.

    Settings can be configured via:
    - Environment variables (prefixed with ATTESTFUL_)
    - Configuration file (YAML or JSON)
    - Direct instantiation

    Environment variables take precedence over config file values.
    """

    model_config = SettingsConfigDict(
        env_prefix="ATTESTFUL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application settings
    app_name: str = "Attestful"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False

    # Data directories
    data_dir: Path = Field(
        default_factory=lambda: Path.home() / ".attestful"
    )
    evidence_dir: Path | None = None
    cache_dir: Path | None = None

    # Database settings
    database_url: str = Field(
        default="sqlite:///attestful.db",
        description="SQLAlchemy database URL",
    )
    database_echo: bool = False

    # Logging settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["text", "json"] = "text"
    log_file: Path | None = None

    # Security settings
    encryption_key_file: Path | None = None
    secret_key: str | None = Field(
        default=None,
        description="Secret key for credential encryption (auto-generated if not set)",
    )

    # Collector settings
    collector_timeout: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Default timeout for collectors in seconds",
    )
    collector_retry_attempts: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Number of retry attempts for failed collector operations",
    )
    collector_rate_limit: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        description="Minimum seconds between API calls",
    )

    # AWS settings
    aws_profile: str | None = None
    aws_region: str | None = None
    aws_regions: list[str] = Field(default_factory=list)
    aws_assume_role_arn: str | None = None

    # Azure settings
    azure_subscription_id: str | None = None
    azure_tenant_id: str | None = None
    azure_client_id: str | None = None

    # GCP settings
    gcp_project_id: str | None = None
    gcp_credentials_file: Path | None = None

    # Report settings
    report_output_dir: Path | None = None
    report_default_format: Literal["html", "pdf", "json", "oscal"] = "html"
    report_company_name: str | None = None
    report_company_logo: Path | None = None

    # API settings (for enterprise features)
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_workers: int = 4
    api_cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    # OSCAL settings
    oscal_catalog_dir: Path | None = None
    oscal_profile_dir: Path | None = None
    oscal_cache_catalogs: bool = True

    @field_validator("data_dir", "evidence_dir", "cache_dir", "log_file",
                     "report_output_dir", "oscal_catalog_dir", "oscal_profile_dir",
                     "gcp_credentials_file", "report_company_logo", "encryption_key_file",
                     mode="before")
    @classmethod
    def expand_path(cls, v: str | Path | None) -> Path | None:
        """Expand ~ and environment variables in paths."""
        if v is None:
            return None
        if isinstance(v, str):
            v = os.path.expanduser(os.path.expandvars(v))
        return Path(v)

    @field_validator("aws_regions", mode="before")
    @classmethod
    def parse_regions(cls, v: Any) -> list[str]:
        """Parse comma-separated regions from environment variable."""
        if isinstance(v, str):
            return [r.strip() for r in v.split(",") if r.strip()]
        return v or []

    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        """Parse comma-separated CORS origins from environment variable."""
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v or ["*"]

    @property
    def effective_evidence_dir(self) -> Path:
        """Get the evidence directory, defaulting to data_dir/evidence."""
        if self.evidence_dir:
            return self.evidence_dir
        return self.data_dir / "evidence"

    @property
    def effective_cache_dir(self) -> Path:
        """Get the cache directory, defaulting to data_dir/cache."""
        if self.cache_dir:
            return self.cache_dir
        return self.data_dir / "cache"

    @property
    def effective_oscal_catalog_dir(self) -> Path:
        """Get the OSCAL catalog directory."""
        if self.oscal_catalog_dir:
            return self.oscal_catalog_dir
        return self.data_dir / "oscal" / "catalogs"

    @property
    def effective_oscal_profile_dir(self) -> Path:
        """Get the OSCAL profile directory."""
        if self.oscal_profile_dir:
            return self.oscal_profile_dir
        return self.data_dir / "oscal" / "profiles"

    @property
    def credentials_file(self) -> Path:
        """Get the encrypted credentials file path."""
        return self.data_dir / "credentials.enc"

    @property
    def effective_encryption_key_file(self) -> Path:
        """Get the encryption key file path."""
        if self.encryption_key_file:
            return self.encryption_key_file
        return self.data_dir / ".key"

    def ensure_directories(self) -> None:
        """Create all necessary directories if they don't exist."""
        directories = [
            self.data_dir,
            self.effective_evidence_dir,
            self.effective_cache_dir,
            self.effective_oscal_catalog_dir,
            self.effective_oscal_profile_dir,
        ]

        if self.report_output_dir:
            directories.append(self.report_output_dir)

        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)

    def to_dict(self, *, exclude_secrets: bool = True) -> dict[str, Any]:
        """
        Export settings to a dictionary.

        Args:
            exclude_secrets: If True, exclude sensitive values.

        Returns:
            Dictionary of settings.
        """
        data = self.model_dump()

        # Convert Path objects to strings
        for key, value in data.items():
            if isinstance(value, Path):
                data[key] = str(value)

        if exclude_secrets:
            secret_keys = {"secret_key", "database_url"}
            for key in secret_keys:
                if key in data and data[key]:
                    data[key] = "***"

        return data


@lru_cache
def get_settings() -> Settings:
    """
    Get the application settings singleton.

    Returns:
        Settings instance (cached).
    """
    return Settings()


def load_settings_from_file(config_path: Path) -> Settings:
    """
    Load settings from a YAML or JSON configuration file.

    Args:
        config_path: Path to configuration file.

    Returns:
        Settings instance.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        ValueError: If config file format is not supported.
    """
    import json

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    suffix = config_path.suffix.lower()
    content = config_path.read_text()

    if suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(content)
        except ImportError:
            raise ImportError("PyYAML is required to load YAML config files")
    elif suffix == ".json":
        data = json.loads(content)
    else:
        raise ValueError(f"Unsupported config file format: {suffix}")

    return Settings(**data)
