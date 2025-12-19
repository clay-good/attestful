# Getting Started with Attestful

This guide will help you install Attestful, configure it for your environment, and run your first compliance scan and evidence collection.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Using pip](#using-pip)
  - [Using Docker](#using-docker)
  - [Manual Installation](#manual-installation)
- [First-Time Configuration](#first-time-configuration)
- [Running Your First Scan](#running-your-first-scan)
- [Running Your First Evidence Collection](#running-your-first-evidence-collection)
- [Viewing Results](#viewing-results)
- [Next Steps](#next-steps)

## Prerequisites

Before installing Attestful, ensure you have:

### System Requirements

- **Operating System**: Linux, macOS, or Windows (WSL2 recommended)
- **Python**: 3.11 or higher
- **Memory**: 4 GB RAM minimum (8 GB recommended)
- **Disk Space**: 1 GB for installation, additional space for evidence storage

### Cloud Provider Access (for scanning)

For AWS scanning:
- AWS CLI configured with credentials
- IAM permissions for read-only access to resources
- Recommended: Use a dedicated read-only IAM role

For Azure scanning:
- Azure CLI configured with credentials
- Reader role on target subscriptions

For GCP scanning:
- gcloud CLI configured
- Viewer role on target projects

### Platform Access (for evidence collection)

Each platform requires specific credentials:
- **Okta**: API token with read access
- **GitHub**: Personal access token or GitHub App
- **Jira**: API token
- **Slack**: Bot token with appropriate scopes

## Installation

### Using pip

The simplest way to install Attestful is via pip:

```bash
# Install the base package
pip install attestful

# Install with optional features
pip install attestful[pdf]        # PDF report generation
pip install attestful[enterprise] # API server and dashboard
pip install attestful[all]        # All optional features
```

Verify the installation:

```bash
attestful --version
```

### Using Docker

For containerized deployments:

```bash
# Pull the latest image
docker pull ghcr.io/attestful/attestful:latest

# Run a scan
docker run --rm \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/output:/output \
  ghcr.io/attestful/attestful:latest \
  scan aws --output /output/results.json

# Run with environment variables
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION \
  ghcr.io/attestful/attestful:latest \
  scan aws
```

### Manual Installation

For development or air-gapped environments:

```bash
# Clone the repository
git clone https://github.com/clay-good/attestful.git
cd attestful

# Install with Poetry
poetry install

# Or install with pip in editable mode
pip install -e .

# Verify installation
poetry run attestful --version
```

## First-Time Configuration

### Initialize Attestful

Run the initialization command to set up the data directory and configuration:

```bash
attestful configure init
```

This creates:
- `~/.attestful/` - Default data directory
- `~/.attestful/config.yaml` - Configuration file
- `~/.attestful/credentials/` - Encrypted credential storage
- `~/.attestful/evidence/` - Evidence storage directory

### Configure Cloud Credentials

#### AWS Configuration

Attestful uses your existing AWS credentials. Ensure you have one of:

1. **AWS CLI configured**:
   ```bash
   aws configure
   ```

2. **Environment variables**:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"
   ```

3. **IAM Role** (when running on EC2/ECS):
   No configuration needed; credentials are automatic.

#### Azure Configuration

```bash
# Login to Azure
az login

# Set default subscription
az account set --subscription "your-subscription-id"
```

#### GCP Configuration

```bash
# Login to GCP
gcloud auth application-default login

# Set default project
gcloud config set project your-project-id
```

### Configure Platform Credentials

Store credentials securely using the Attestful credential store:

```bash
# Configure Okta
attestful configure set okta.domain "your-domain.okta.com"
attestful configure set okta.api_token "your-api-token" --secret

# Configure GitHub
attestful configure set github.token "ghp_your_token" --secret

# Configure Jira
attestful configure set jira.url "https://your-domain.atlassian.net"
attestful configure set jira.email "your-email@example.com"
attestful configure set jira.api_token "your-api-token" --secret
```

### Verify Configuration

Check your current configuration:

```bash
attestful configure show
```

Verify platform connectivity:

```bash
# Test AWS connectivity
attestful scan aws --dry-run

# Test Okta connectivity
attestful collect okta --dry-run
```

## Running Your First Scan

### Quick Scan

Run a quick compliance scan of your AWS environment:

```bash
attestful scan aws
```

This will:
1. Discover AWS resources in the default region
2. Evaluate them against built-in compliance checks
3. Display results in the terminal

### Scan with Framework Filter

Scan against a specific compliance framework:

```bash
# SOC 2 compliance scan
attestful scan aws --framework soc2

# NIST 800-53 compliance scan
attestful scan aws --framework nist-800-53

# Multiple frameworks
attestful scan aws --framework soc2 --framework nist-800-53
```

### Scan Specific Regions

```bash
# Single region
attestful scan aws --region us-east-1

# Multiple regions
attestful scan aws --region us-east-1 --region us-west-2

# All regions
attestful scan aws --all-regions
```

### Save Scan Results

```bash
# Save to JSON
attestful scan aws --output results.json

# Save to specific format
attestful scan aws --output report.html --format html
```

### Example Output

```
Attestful AWS Compliance Scan
=============================

Scanning region: us-east-1
Discovering resources...
  - S3 Buckets: 15
  - EC2 Instances: 8
  - IAM Users: 12
  - RDS Instances: 3

Running compliance checks...
  Framework: SOC 2

Results Summary
---------------
Total Resources: 38
Total Checks: 156
Passed: 142 (91.0%)
Failed: 14 (9.0%)

Critical Findings: 2
High Findings: 5
Medium Findings: 7

Top Issues:
  1. [CRITICAL] S3 bucket 'public-data' has public access enabled
  2. [CRITICAL] IAM user 'legacy-service' has no MFA enabled
  3. [HIGH] EC2 instance 'i-abc123' uses IMDSv1
  ...

Full report saved to: results.json
```

## Running Your First Evidence Collection

### Collect Evidence from Okta

```bash
# Collect all evidence types
attestful collect okta

# Collect specific evidence types
attestful collect okta --types users,mfa_factors,policies

# Collect with date filter
attestful collect okta --since 2024-01-01
```

### Collect Evidence from AWS

```bash
# Collect AWS configuration evidence
attestful collect aws --types iam_credential_report,password_policy,cloudtrail_status
```

### Collect from Multiple Platforms

```bash
# Collect from all configured platforms
attestful collect all

# Collect from specific platforms
attestful collect okta github jira
```

### View Collection Status

```bash
# List recent collections
attestful collect list

# View collection details
attestful collect show <collection-id>
```

### Example Collection Output

```
Attestful Evidence Collection
=============================

Platform: Okta
Evidence Types: users, mfa_factors, groups, policies

Collecting evidence...
  [✓] Users: 156 records
  [✓] MFA Factors: 312 records (2 per user avg)
  [✓] Groups: 24 records
  [✓] Policies: 8 records

Collection Summary
------------------
Total Evidence Items: 4
Total Records: 500
Collection Time: 12.3s

Evidence stored at: ~/.attestful/evidence/okta/2024-01-15/

Collection ID: col_abc123def456
```

## Viewing Results

### Analyze Compliance Maturity

```bash
# Calculate maturity score
attestful analyze maturity

# Maturity for specific framework
attestful analyze maturity --framework nist-csf-2
```

### Generate Reports

```bash
# Generate HTML report
attestful report generate --format html --output compliance-report.html

# Generate executive summary
attestful report generate --format html --template executive --output exec-summary.html

# Generate OSCAL assessment results
attestful oscal assessment generate --title "Q1 Assessment" --output assessment.json
```

### Gap Analysis

```bash
# Identify compliance gaps
attestful analyze gaps --framework soc2

# Cross-framework mapping
attestful analyze crosswalk --source nist-800-53 --target soc2
```

### View in Dashboard (Enterprise)

If you have the enterprise features installed:

```bash
# Start the dashboard
attestful dashboard serve

# Access at http://localhost:8050
```

## Next Steps

Now that you've completed your first scan and collection:

### 1. Set Up Scheduled Collections

Create a cron job or scheduled task to collect evidence regularly:

```bash
# Example cron entry (daily at 2 AM)
0 2 * * * /usr/local/bin/attestful collect all >> /var/log/attestful/collection.log 2>&1
```

### 2. Configure Additional Platforms

Add more evidence sources:

```bash
# View available platforms
attestful collect list

# Configure additional platforms
attestful configure set slack.token "xoxb-your-token" --secret
attestful configure set datadog.api_key "your-api-key" --secret
```

### 3. Customize Checks

Create custom compliance checks:

```yaml
# custom-checks.yaml
checks:
  - id: custom-s3-naming
    title: S3 Bucket Naming Convention
    description: Buckets must follow naming convention
    severity: low
    resource_types:
      - s3_bucket
    condition:
      path: raw_data.Name
      operator: matches
      value: "^(prod|dev|staging)-[a-z0-9-]+$"
    frameworks:
      internal:
        - SEC-001
```

Load custom checks:

```bash
attestful scan aws --checks custom-checks.yaml
```

### 4. Generate OSCAL Documents

Create OSCAL System Security Plans:

```bash
attestful oscal ssp generate \
  --profile nist-800-53-moderate \
  --system-name "Production Application" \
  --system-id "prod-app-001" \
  --output ssp.json
```

### 5. Explore the Documentation

- [Configuration Reference](CONFIGURATION.md) - All configuration options
- [Collector Reference](COLLECTORS.md) - Platform-specific details
- [Framework Reference](FRAMEWORKS.md) - Supported compliance frameworks
- [CLI Reference](CLI.md) - Complete command reference
- [OSCAL Guide](OSCAL.md) - Working with OSCAL documents

### 6. Get Help

```bash
# General help
attestful --help

# Command-specific help
attestful scan --help
attestful scan aws --help

# List available frameworks
attestful frameworks list

# List available collectors
attestful collect list
```

For additional support:
- GitHub Issues: https://github.com/clay-good/attestful/issues
