# CLI Reference

This document provides a comprehensive reference for all Attestful CLI commands, options, and usage examples.

## Table of Contents

- [Global Options](#global-options)
- [Commands](#commands)
  - [scan](#scan)
  - [collect](#collect)
  - [analyze](#analyze)
  - [report](#report)
  - [oscal](#oscal)
  - [frameworks](#frameworks)
  - [configure](#configure)
- [Common Workflows](#common-workflows)
- [Exit Codes](#exit-codes)

## Global Options

These options are available for all commands:

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--version` | `-V` | Show version |
| `--config` | `-c` | Path to config file |
| `--log-level` | `-l` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `--output-format` | `-f` | Output format (rich, plain, json) |
| `--quiet` | `-q` | Suppress non-essential output |
| `--verbose` | `-v` | Increase verbosity |

```bash
# Examples
attestful --version
attestful --config /path/to/config.yaml scan aws
attestful --log-level DEBUG collect okta
attestful --output-format json scan aws
```

---

## Commands

### scan

Run compliance scans against cloud resources.

#### scan aws

Scan AWS resources for compliance.

```bash
attestful scan aws [OPTIONS]
```

| Option | Short | Type | Default | Description |
|--------|-------|------|---------|-------------|
| `--framework` | `-F` | string | all | Framework to scan against |
| `--region` | `-r` | string | default | AWS region(s) to scan |
| `--all-regions` | | flag | false | Scan all regions |
| `--profile` | `-p` | string | default | AWS profile to use |
| `--role` | | string | none | IAM role ARN to assume |
| `--severity` | `-s` | string | all | Minimum severity (critical, high, medium, low) |
| `--resource-type` | `-t` | string | all | Resource type(s) to scan |
| `--output` | `-o` | path | stdout | Output file path |
| `--format` | | string | json | Output format (json, yaml, html) |
| `--dry-run` | | flag | false | Validate without scanning |

**Examples:**

```bash
# Basic scan
attestful scan aws

# Scan specific framework
attestful scan aws --framework soc2

# Scan multiple regions
attestful scan aws --region us-east-1 --region eu-west-1

# Scan with role assumption
attestful scan aws --role arn:aws:iam::123456789012:role/AuditRole

# Filter by severity
attestful scan aws --severity high

# Save to file
attestful scan aws --output results.json
```

#### scan azure

Scan Azure resources for compliance.

```bash
attestful scan azure [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--subscription` | string | Azure subscription ID |
| `--framework` | string | Framework to scan |
| `--resource-group` | string | Resource group to scan |

#### scan gcp

Scan GCP resources for compliance.

```bash
attestful scan gcp [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--project` | string | GCP project ID |
| `--framework` | string | Framework to scan |

#### scan kubernetes

Scan Kubernetes clusters for compliance.

```bash
attestful scan kubernetes [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--namespace` | `-n` | string | Namespace(s) to scan |
| `--exclude-namespace` | | string | Namespace(s) to exclude |
| `--kubeconfig` | | path | Path to kubeconfig |
| `--context` | | string | Kubernetes context |
| `--in-cluster` | | flag | Use in-cluster config |
| `--framework` | `-F` | string | Framework to scan |
| `--severity` | `-s` | string | Minimum severity |

**Examples:**

```bash
# Scan default namespace
attestful scan kubernetes

# Scan specific namespaces
attestful scan kubernetes -n production -n staging

# Use specific context
attestful scan kubernetes --context my-cluster
```

#### scan soc2

Run SOC 2-specific compliance scan.

```bash
attestful scan soc2 [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--provider` | string | Cloud provider (aws, azure, gcp) |
| `--control` | string | Specific control(s) to check |
| `--generate-oscal` | flag | Generate OSCAL assessment |

#### scan list

List recent scans.

```bash
attestful scan list [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--limit` | int | Number of scans to show |
| `--status` | string | Filter by status |

---

### collect

Collect evidence from platforms.

#### collect list

List available collectors and their status.

```bash
attestful collect list
```

#### collect aws

Collect AWS evidence.

```bash
attestful collect aws [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--types` | `-t` | string | Evidence type(s) to collect |
| `--since` | | date | Collect data after this date |
| `--region` | `-r` | string | AWS region(s) |
| `--output` | `-o` | path | Output file |

**Available Evidence Types:**
- `account_info`
- `iam_credential_report`
- `password_policy`
- `cloudtrail_status`
- `guardduty_status`
- `config_status`
- `securityhub_findings`

**Examples:**

```bash
# Collect all evidence
attestful collect aws

# Collect specific types
attestful collect aws --types iam_credential_report,password_policy

# Collect recent data
attestful collect aws --since 2024-01-01
```

#### collect okta

Collect Okta evidence.

```bash
attestful collect okta [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--types` | `-t` | string | Evidence type(s) |
| `--since` | | date | Collect after date |
| `--output` | `-o` | path | Output file |

**Available Evidence Types:**
- `users`
- `mfa_factors`
- `groups`
- `applications`
- `policies`
- `system_log`

#### collect github

Collect GitHub evidence.

```bash
attestful collect github [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--org` | string | GitHub organization |
| `--types` | string | Evidence type(s) |
| `--include-archived` | flag | Include archived repos |

**Available Evidence Types:**
- `repositories`
- `branch_protection`
- `security_alerts`
- `audit_logs`
- `collaborators`

#### collect kubernetes

Collect Kubernetes evidence.

```bash
attestful collect kubernetes [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--namespace` | string | Namespace(s) |
| `--types` | string | Evidence type(s) |
| `--kubeconfig` | path | Kubeconfig path |
| `--context` | string | Kubernetes context |

**Available Evidence Types:**
- `cluster_info`
- `rbac_config`
- `network_policies`
- `pod_security`
- `resource_quotas`

#### collect all

Collect from all configured platforms.

```bash
attestful collect all [OPTIONS]
```

---

### analyze

Analyze compliance data and generate insights.

#### analyze maturity

Calculate compliance maturity scores.

```bash
attestful analyze maturity [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--framework` | `-F` | string | Framework for analysis |
| `--output` | `-o` | path | Output file |
| `--format` | | string | Output format |

**Examples:**

```bash
# NIST CSF maturity analysis
attestful analyze maturity --framework nist-csf-2

# Export to JSON
attestful analyze maturity --framework nist-csf-2 --format json -o maturity.json
```

#### analyze gaps

Identify compliance gaps.

```bash
attestful analyze gaps [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--framework` | `-F` | string | Framework for analysis |
| `--severity` | `-s` | string | Minimum gap severity |
| `--output` | `-o` | path | Output file |

**Examples:**

```bash
# SOC 2 gap analysis
attestful analyze gaps --framework soc2

# High severity gaps only
attestful analyze gaps --framework soc2 --severity high
```

#### analyze crosswalk

Cross-framework control mapping.

```bash
attestful analyze crosswalk [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--source` | string | Source framework (required) |
| `--target` | string | Target framework |
| `--control` | string | Specific control ID |
| `--strength` | string | Mapping strength filter |
| `--stats` | flag | Show mapping statistics |
| `--format` | string | Output format |

**Examples:**

```bash
# Map NIST 800-53 to SOC 2
attestful analyze crosswalk --source nist-800-53 --target soc2

# Map specific control
attestful analyze crosswalk --source nist-800-53 --control AC-2

# Show statistics
attestful analyze crosswalk --source nist-800-53 --stats
```

#### analyze trends

Analyze compliance trends over time.

```bash
attestful analyze trends [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--framework` | string | Framework for analysis |
| `--period` | string | Time period (30d, 90d, 1y) |
| `--metric` | string | Metric to track |

---

### report

Generate compliance reports.

#### report generate

Generate a compliance report.

```bash
attestful report generate [OPTIONS]
```

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--format` | `-f` | string | Output format (html, pdf, json, markdown) |
| `--output` | `-o` | path | Output file path |
| `--framework` | `-F` | string | Framework for report |
| `--template` | | string | Report template |
| `--title` | | string | Report title |
| `--scan-file` | | path | Scan results file |
| `--include-evidence` | | flag | Include evidence details |

**Examples:**

```bash
# Generate HTML report
attestful report generate --format html --output report.html

# SOC 2 report
attestful report generate --framework soc2 --format html -o soc2-report.html

# Executive summary
attestful report generate --template executive --format html -o exec-summary.html

# From scan results file
attestful report generate --scan-file results.json --format html -o report.html
```

#### report templates

List available report templates.

```bash
attestful report templates
```

---

### oscal

OSCAL document management.

#### oscal catalog list

List available OSCAL catalogs.

```bash
attestful oscal catalog list
```

#### oscal catalog show

Show catalog details.

```bash
attestful oscal catalog show <catalog-id>
```

#### oscal ssp generate

Generate an OSCAL System Security Plan.

```bash
attestful oscal ssp generate [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--profile` | string | OSCAL profile (required) |
| `--system-name` | string | System name (required) |
| `--system-id` | string | System identifier (required) |
| `--description` | string | System description |
| `--output` | path | Output file path |
| `--format` | string | Output format (json, yaml) |
| `--scan-file` | path | Include scan results |

**Examples:**

```bash
# Generate SSP
attestful oscal ssp generate \
  --profile nist-800-53-moderate \
  --system-name "Production App" \
  --system-id "prod-001" \
  --output ssp.json

# With scan results
attestful oscal ssp generate \
  --profile fedramp-moderate \
  --system-name "Cloud Service" \
  --system-id "cloud-001" \
  --scan-file results.json \
  --output ssp.json
```

#### oscal assessment generate

Generate OSCAL Assessment Results.

```bash
attestful oscal assessment generate [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--title` | string | Assessment title (required) |
| `--scan-file` | path | Scan results file (required) |
| `--output` | path | Output file path |
| `--format` | string | Output format |

**Examples:**

```bash
# Generate assessment results
attestful oscal assessment generate \
  --title "Q1 2024 Assessment" \
  --scan-file results.json \
  --output assessment.json
```

#### oscal validate

Validate an OSCAL document.

```bash
attestful oscal validate <file>
```

---

### frameworks

Manage compliance frameworks.

#### frameworks list

List supported frameworks.

```bash
attestful frameworks list
```

#### frameworks show

Show framework details.

```bash
attestful frameworks show <framework> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--controls` | flag | Show all controls |
| `--checks` | flag | Show automated checks |

**Examples:**

```bash
# Show SOC 2 overview
attestful frameworks show soc2

# Show all controls
attestful frameworks show soc2 --controls

# Show automated checks
attestful frameworks show soc2 --checks
```

#### frameworks controls

List framework controls.

```bash
attestful frameworks controls <framework> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--search` | string | Search in title/description |
| `--category` | string | Filter by category |

#### frameworks checks

List framework checks.

```bash
attestful frameworks checks <framework> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--severity` | string | Filter by severity |
| `--resource-type` | string | Filter by resource type |
| `--control` | string | Filter by control |

#### frameworks load

Load a custom framework.

```bash
attestful frameworks load <file>
```

---

### configure

Manage Attestful configuration.

#### configure init

Initialize Attestful configuration.

```bash
attestful configure init [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--data-dir` | path | Data directory path |
| `--force` | flag | Overwrite existing config |

#### configure show

Show current configuration.

```bash
attestful configure show [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--mask-secrets` | flag | Mask sensitive values |

#### configure set

Set a configuration value.

```bash
attestful configure set <key> <value> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--secret` | flag | Store as encrypted secret |

**Examples:**

```bash
# Set Okta domain
attestful configure set okta.domain company.okta.com

# Set API token as secret
attestful configure set okta.api_token your-token --secret
```

#### configure get

Get a configuration value.

```bash
attestful configure get <key>
```

#### configure validate

Validate configuration.

```bash
attestful configure validate
```

#### configure platforms

List supported platforms and their configuration status.

```bash
attestful configure platforms
```

#### configure test

Test platform connectivity.

```bash
attestful configure test [platform]
```

---

## Common Workflows

### Initial Setup

```bash
# Initialize Attestful
attestful configure init

# Configure AWS
# (uses AWS CLI credentials)

# Configure Okta
attestful configure set okta.domain company.okta.com
attestful configure set okta.api_token your-token --secret

# Verify configuration
attestful configure validate
```

### Daily Compliance Check

```bash
# Run SOC 2 scan
attestful scan aws --framework soc2 --output daily-scan.json

# Generate quick report
attestful report generate --scan-file daily-scan.json --format html -o daily-report.html
```

### Weekly Evidence Collection

```bash
# Collect from all platforms
attestful collect all

# Calculate maturity
attestful analyze maturity --framework nist-csf-2

# Generate weekly report
attestful report generate --framework nist-csf-2 --format html -o weekly-report.html
```

### Audit Preparation

```bash
# Full scan against audit framework
attestful scan aws --framework soc2 --all-regions -o audit-scan.json

# Collect all evidence
attestful collect all

# Generate comprehensive report
attestful report generate \
  --framework soc2 \
  --scan-file audit-scan.json \
  --include-evidence \
  --format html \
  -o audit-report.html

# Generate OSCAL assessment
attestful oscal assessment generate \
  --title "SOC 2 Type II Assessment" \
  --scan-file audit-scan.json \
  -o assessment.json
```

### FedRAMP Authorization Package

```bash
# Generate SSP
attestful oscal ssp generate \
  --profile fedramp-moderate \
  --system-name "My Cloud Service" \
  --system-id "FED-001" \
  -o ssp.json

# Run scan
attestful scan aws --framework fedramp --baseline moderate -o scan.json

# Generate assessment results
attestful oscal assessment generate \
  --title "Initial Assessment" \
  --scan-file scan.json \
  -o sar.json
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Authentication error |
| 4 | Scan/collection failed |
| 5 | Validation error |
| 10 | Compliance failures found (for CI/CD) |
