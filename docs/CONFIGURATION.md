# Configuration Reference

This document provides a comprehensive reference for all Attestful configuration options.

## Table of Contents

- [Configuration File](#configuration-file)
- [Configuration Options](#configuration-options)
  - [General Settings](#general-settings)
  - [Database Settings](#database-settings)
  - [Storage Settings](#storage-settings)
  - [Logging Settings](#logging-settings)
  - [Security Settings](#security-settings)
  - [API Settings](#api-settings)
  - [Dashboard Settings](#dashboard-settings)
- [Platform-Specific Settings](#platform-specific-settings)
  - [AWS Settings](#aws-settings)
  - [Azure Settings](#azure-settings)
  - [GCP Settings](#gcp-settings)
  - [Okta Settings](#okta-settings)
  - [GitHub Settings](#github-settings)
- [Environment Variable Overrides](#environment-variable-overrides)
- [Configuration Precedence](#configuration-precedence)

## Configuration File

Attestful uses a YAML configuration file located at:

- **Default**: `~/.attestful/config.yaml`
- **Custom**: Set via `ATTESTFUL_CONFIG` environment variable or `--config` flag

### Example Configuration File

```yaml
# Attestful Configuration
# ~/.attestful/config.yaml

general:
  data_dir: ~/.attestful
  log_level: INFO
  output_format: rich

database:
  type: sqlite
  path: ~/.attestful/attestful.db

storage:
  evidence_dir: ~/.attestful/evidence
  retention_days: 365
  compression: true

logging:
  level: INFO
  file: ~/.attestful/logs/attestful.log
  max_size_mb: 100
  backup_count: 5

security:
  credential_encryption: true
  audit_logging: true

platforms:
  aws:
    default_region: us-east-1
    assume_role: null
  okta:
    domain: your-domain.okta.com
  github:
    enterprise_url: null
```

## Configuration Options

### General Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `general.data_dir` | string | `~/.attestful` | Base directory for all Attestful data |
| `general.log_level` | string | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |
| `general.output_format` | string | `rich` | CLI output format: rich, plain, json |
| `general.timezone` | string | `UTC` | Timezone for timestamps |
| `general.parallel_workers` | int | `4` | Number of parallel workers for collection |

```yaml
general:
  data_dir: /opt/attestful/data
  log_level: DEBUG
  output_format: rich
  timezone: America/New_York
  parallel_workers: 8
```

### Database Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `database.type` | string | `sqlite` | Database type: sqlite, postgresql |
| `database.path` | string | `~/.attestful/attestful.db` | Path for SQLite database |
| `database.url` | string | null | PostgreSQL connection URL |
| `database.pool_size` | int | `5` | Connection pool size (PostgreSQL) |
| `database.max_overflow` | int | `10` | Max overflow connections |

#### SQLite Configuration

```yaml
database:
  type: sqlite
  path: ~/.attestful/attestful.db
```

#### PostgreSQL Configuration

```yaml
database:
  type: postgresql
  url: postgresql://user:password@localhost:5432/attestful
  pool_size: 10
  max_overflow: 20
```

### Storage Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage.evidence_dir` | string | `~/.attestful/evidence` | Directory for evidence files |
| `storage.retention_days` | int | `365` | Days to retain evidence |
| `storage.compression` | bool | `true` | Compress evidence files |
| `storage.hash_algorithm` | string | `sha256` | Hash algorithm for integrity |
| `storage.max_file_size_mb` | int | `100` | Maximum evidence file size |

```yaml
storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 730  # 2 years
  compression: true
  hash_algorithm: sha256
  max_file_size_mb: 200
```

### Logging Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `logging.level` | string | `INFO` | Log level |
| `logging.file` | string | null | Log file path (null for stdout only) |
| `logging.max_size_mb` | int | `100` | Max log file size before rotation |
| `logging.backup_count` | int | `5` | Number of backup log files |
| `logging.format` | string | `standard` | Log format: standard, json |

```yaml
logging:
  level: INFO
  file: /var/log/attestful/attestful.log
  max_size_mb: 100
  backup_count: 10
  format: json  # For log aggregation systems
```

### Security Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `security.credential_encryption` | bool | `true` | Encrypt stored credentials |
| `security.encryption_algorithm` | string | `AES-256-GCM` | Encryption algorithm |
| `security.key_derivation` | string | `PBKDF2` | Key derivation function |
| `security.key_iterations` | int | `100000` | PBKDF2 iterations |
| `security.audit_logging` | bool | `true` | Enable audit logging |
| `security.audit_file` | string | `~/.attestful/audit.log` | Audit log file path |

```yaml
security:
  credential_encryption: true
  encryption_algorithm: AES-256-GCM
  key_derivation: PBKDF2
  key_iterations: 200000
  audit_logging: true
  audit_file: /var/log/attestful/audit.log
```

### API Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api.enabled` | bool | `false` | Enable REST API server |
| `api.host` | string | `127.0.0.1` | API server bind address |
| `api.port` | int | `8000` | API server port |
| `api.workers` | int | `4` | Number of API workers |
| `api.cors_origins` | list | `[]` | Allowed CORS origins |
| `api.rate_limit` | int | `100` | Requests per minute per client |
| `api.auth_enabled` | bool | `true` | Enable API authentication |
| `api.jwt_secret` | string | null | JWT signing secret |
| `api.jwt_expiry_hours` | int | `24` | JWT token expiry |

```yaml
api:
  enabled: true
  host: 0.0.0.0
  port: 8000
  workers: 8
  cors_origins:
    - https://dashboard.example.com
  rate_limit: 100
  auth_enabled: true
  jwt_expiry_hours: 8
```

### Dashboard Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dashboard.enabled` | bool | `false` | Enable dashboard |
| `dashboard.host` | string | `127.0.0.1` | Dashboard bind address |
| `dashboard.port` | int | `8050` | Dashboard port |
| `dashboard.debug` | bool | `false` | Enable debug mode |
| `dashboard.theme` | string | `light` | Dashboard theme: light, dark |

```yaml
dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8050
  debug: false
  theme: dark
```

## Platform-Specific Settings

### AWS Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.aws.default_region` | string | `us-east-1` | Default AWS region |
| `platforms.aws.regions` | list | `[]` | Regions to scan (empty = all) |
| `platforms.aws.assume_role` | string | null | IAM role ARN to assume |
| `platforms.aws.external_id` | string | null | External ID for role assumption |
| `platforms.aws.session_name` | string | `attestful` | Session name for assumed role |
| `platforms.aws.profile` | string | null | AWS CLI profile to use |
| `platforms.aws.timeout` | int | `60` | API request timeout (seconds) |
| `platforms.aws.max_retries` | int | `3` | Maximum API retries |

```yaml
platforms:
  aws:
    default_region: us-east-1
    regions:
      - us-east-1
      - us-west-2
      - eu-west-1
    assume_role: arn:aws:iam::123456789012:role/AttestfulReadOnly
    external_id: attestful-audit
    session_name: attestful-scan
    timeout: 120
    max_retries: 5
```

### Azure Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.azure.subscription_id` | string | null | Default subscription ID |
| `platforms.azure.tenant_id` | string | null | Azure AD tenant ID |
| `platforms.azure.client_id` | string | null | Service principal client ID |
| `platforms.azure.use_cli_auth` | bool | `true` | Use Azure CLI authentication |
| `platforms.azure.timeout` | int | `60` | API request timeout |

```yaml
platforms:
  azure:
    subscription_id: 12345678-1234-1234-1234-123456789012
    tenant_id: 87654321-4321-4321-4321-210987654321
    use_cli_auth: true
    timeout: 120
```

### GCP Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.gcp.project_id` | string | null | Default GCP project ID |
| `platforms.gcp.projects` | list | `[]` | Projects to scan |
| `platforms.gcp.credentials_file` | string | null | Service account key file |
| `platforms.gcp.use_adc` | bool | `true` | Use Application Default Credentials |
| `platforms.gcp.timeout` | int | `60` | API request timeout |

```yaml
platforms:
  gcp:
    project_id: my-project-123
    projects:
      - my-project-123
      - other-project-456
    use_adc: true
    timeout: 120
```

### Okta Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.okta.domain` | string | required | Okta domain (e.g., company.okta.com) |
| `platforms.okta.api_token` | string | required | Okta API token (store as secret) |
| `platforms.okta.timeout` | int | `30` | API request timeout |
| `platforms.okta.page_size` | int | `200` | Items per page for pagination |
| `platforms.okta.rate_limit_buffer` | int | `10` | Buffer for rate limit (%) |

```yaml
platforms:
  okta:
    domain: company.okta.com
    # api_token should be stored as a secret, not in config
    timeout: 60
    page_size: 200
    rate_limit_buffer: 20
```

### GitHub Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `platforms.github.token` | string | required | GitHub personal access token |
| `platforms.github.enterprise_url` | string | null | GitHub Enterprise URL |
| `platforms.github.organizations` | list | `[]` | Organizations to scan |
| `platforms.github.include_archived` | bool | `false` | Include archived repositories |
| `platforms.github.timeout` | int | `30` | API request timeout |

```yaml
platforms:
  github:
    # token should be stored as a secret
    enterprise_url: https://github.mycompany.com
    organizations:
      - myorg
      - other-org
    include_archived: false
    timeout: 60
```

## Environment Variable Overrides

All configuration options can be overridden using environment variables. The naming convention is:

```
ATTESTFUL_<SECTION>_<OPTION>=value
```

### Examples

```bash
# General settings
export ATTESTFUL_GENERAL_DATA_DIR=/opt/attestful
export ATTESTFUL_GENERAL_LOG_LEVEL=DEBUG

# Database settings
export ATTESTFUL_DATABASE_TYPE=postgresql
export ATTESTFUL_DATABASE_URL=postgresql://user:pass@localhost/attestful

# Storage settings
export ATTESTFUL_STORAGE_EVIDENCE_DIR=/var/attestful/evidence
export ATTESTFUL_STORAGE_RETENTION_DAYS=730

# Platform settings
export ATTESTFUL_PLATFORMS_AWS_DEFAULT_REGION=us-west-2
export ATTESTFUL_PLATFORMS_OKTA_DOMAIN=company.okta.com

# Secrets (recommended for sensitive values)
export ATTESTFUL_PLATFORMS_OKTA_API_TOKEN=your-token
export ATTESTFUL_PLATFORMS_GITHUB_TOKEN=ghp_xxx
export ATTESTFUL_API_JWT_SECRET=your-jwt-secret
```

### Nested Configuration

For nested options, use double underscores:

```bash
export ATTESTFUL_PLATFORMS__AWS__DEFAULT_REGION=us-east-1
export ATTESTFUL_PLATFORMS__OKTA__DOMAIN=company.okta.com
```

## Configuration Precedence

Configuration values are resolved in the following order (later sources override earlier):

1. **Default values** - Built-in defaults
2. **Configuration file** - `~/.attestful/config.yaml` or custom path
3. **Environment variables** - `ATTESTFUL_*` variables
4. **Command-line arguments** - `--option value` flags

### Example

```yaml
# config.yaml
general:
  log_level: INFO
```

```bash
# Environment variable (overrides config file)
export ATTESTFUL_GENERAL_LOG_LEVEL=WARNING

# Command line (overrides environment variable)
attestful scan aws --log-level DEBUG
```

In this example, the effective log level would be `DEBUG`.

## Validating Configuration

### Check Current Configuration

```bash
# Show current configuration
attestful configure show

# Show configuration with secrets masked
attestful configure show --mask-secrets

# Validate configuration
attestful configure validate
```

### Test Platform Connectivity

```bash
# Test AWS connectivity
attestful scan aws --dry-run

# Test Okta connectivity
attestful collect okta --dry-run

# Test all platforms
attestful configure test
```

## Configuration Examples

### Minimal Production Configuration

```yaml
general:
  data_dir: /var/attestful
  log_level: INFO

database:
  type: postgresql
  url: ${ATTESTFUL_DATABASE_URL}

storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 365

platforms:
  aws:
    assume_role: arn:aws:iam::123456789012:role/AttestfulReadOnly
```

### Air-Gapped Environment

```yaml
general:
  data_dir: /opt/attestful
  log_level: INFO
  parallel_workers: 2  # Limited resources

database:
  type: sqlite
  path: /opt/attestful/attestful.db

storage:
  evidence_dir: /opt/attestful/evidence
  retention_days: 730
  compression: true

security:
  credential_encryption: true
  audit_logging: true
  audit_file: /var/log/attestful/audit.log

# No external platforms configured - use evidence ferry
```

### Enterprise with API and Dashboard

```yaml
general:
  data_dir: /var/attestful
  log_level: INFO
  parallel_workers: 16

database:
  type: postgresql
  url: ${DATABASE_URL}
  pool_size: 20

storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 1095  # 3 years

api:
  enabled: true
  host: 0.0.0.0
  port: 8000
  workers: 8
  auth_enabled: true
  cors_origins:
    - https://compliance.example.com

dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8050
  theme: dark

platforms:
  aws:
    regions:
      - us-east-1
      - us-west-2
      - eu-west-1
    assume_role: arn:aws:iam::123456789012:role/AttestfulReadOnly
  okta:
    domain: company.okta.com
  github:
    organizations:
      - mycompany
```
