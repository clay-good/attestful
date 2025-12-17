# Attestful

**OSCAL-first compliance automation platform. Open-source alternative to Vanta.**

[![CI](https://github.com/attestful/attestful/actions/workflows/ci.yml/badge.svg)](https://github.com/attestful/attestful/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## What is Attestful?

Attestful is a **self-hosted, air-gap capable** compliance automation platform that uses [OSCAL](https://pages.nist.gov/OSCAL/) (Open Security Controls Assessment Language) as its foundation. It combines:

- **Automated compliance checking** with 200+ checks across AWS, Azure, GCP, Kubernetes, and Docker
- **Evidence collection** from 13+ platforms (Okta, Jamf, Snowflake, Datadog, GitLab, etc.)
- **Multi-framework support** for NIST CSF 2.0, NIST 800-53/FedRAMP, SOC 2, ISO 27001, and HITRUST
- **Cross-framework mapping** to reduce duplicate compliance work

## Why Attestful?

| Feature | Attestful | Vanta | Drata |
|---------|-----------|-------|-------|
| Open Source | ✅ | ❌ | ❌ |
| Self-Hosted | ✅ | ❌ | ❌ |
| Air-Gap Capable | ✅ | ❌ | ❌ |
| OSCAL Native | ✅ | ❌ | ❌ |
| FedRAMP Ready | ✅ | ❌ | ❌ |
| Automated Remediation | ✅ | ⚠️ | ⚠️ |

## Quick Start

### Installation

```bash
# Install with pip
pip install attestful

# Or with Poetry (recommended)
poetry add attestful

# Or with all optional dependencies
pip install attestful[all]
```

### First Scan

```bash
# Initialize Attestful
attestful configure init

# Configure AWS credentials
attestful configure credentials --platform aws

# Run a compliance scan
attestful scan aws --framework soc2

# View results
attestful report generate --format html --output report.html
```

### First Evidence Collection

```bash
# Configure Okta credentials
attestful configure credentials --platform okta

# Collect evidence
attestful collect okta

# Analyze maturity
attestful analyze maturity --framework nist-csf

# View gaps
attestful analyze gaps
```

## Supported Frameworks

### NIST CSF 2.0
- 106 subcategories across 6 functions
- Evidence-based maturity scoring (0-4)
- 38 API-collectible evidence types

### NIST 800-53 / FedRAMP
- Full Rev 5 catalog (1000+ controls)
- FedRAMP Low, Moderate, and High baselines
- OSCAL-native for FedRAMP authorization

### SOC 2 Type II
- All 5 Trust Services Criteria
- 90%+ automation for Common Criteria
- Audit-ready evidence packages

### ISO 27001
- ISO 27001:2022 Annex A controls
- Statement of Applicability generator
- Certification audit support

### HITRUST
- HITRUST CSF controls
- 5-level maturity scoring
- MyCSF integration ready

## Supported Platforms

### Cloud Infrastructure
- **AWS** - EC2, S3, IAM, VPC, CloudTrail, and more
- **Azure** - VMs, Storage, AD, NSGs, and more
- **GCP** - Compute, Storage, IAM, and more
- **Kubernetes** - Pods, Services, NetworkPolicies
- **Docker** - Containers, Images, Networks

### SaaS Platforms
- **Okta** - Users, MFA, policies, audit logs
- **Jamf** - Devices, MDM, compliance
- **Google Workspace** - Users, Drive, audit logs
- **Snowflake** - Users, roles, access history
- **Datadog** - Monitors, security signals
- **GitLab** - Projects, pipelines, security scans
- **Jira** - Issues, workflows, audit logs
- **Zendesk** - Tickets, users, security
- **Zoom** - Users, meetings, security
- **Notion** - Pages, permissions
- **Slab** - Posts, topics
- **SpotDraft** - Contracts, approvals

## Key Features

### Compliance as Code

All compliance checks are defined in version-controlled YAML:

```yaml
id: soc2-cc6.1-001
name: Ensure MFA enabled for all IAM users
severity: critical
resource_types: [aws_iam_user]
condition: |
  resource.get('raw', {}).get('mfa_enabled') == True
remediation: |
  Enable MFA for all IAM users via AWS Console or CLI
```

### OSCAL Integration

Generate OSCAL documents for FedRAMP and other machine-readable compliance:

```bash
# Generate System Security Plan
attestful oscal ssp generate --profile fedramp-moderate

# Export assessment results
attestful oscal assessment export --scan-id latest

# Generate POA&M
attestful oscal poam generate
```

### Automated Remediation

Fix compliance issues automatically with 33+ remediation actions:

```bash
# Preview remediation plan
attestful remediate plan --scan-id abc123

# Apply remediations (with dry-run)
attestful remediate apply --dry-run

# Apply remediations
attestful remediate apply
```

### Air-Gap Support

Deploy in disconnected environments:

```bash
# Export evidence bundle
attestful collect export --output evidence-bundle.attestful

# Import on air-gapped system
attestful collect import --input evidence-bundle.attestful

# Analyze offline
attestful analyze maturity
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI / API / Dashboard                     │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                       OSCAL Layer                            │
│   Catalog → Profile → Component → SSP → Assessment          │
└─────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Resource Checks │  │    Evidence     │  │    Analysis     │
│   (Compliy)     │  │   (Nisify)      │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  Unified Collector Layer                     │
│        Infrastructure + Platform Collectors                  │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     Storage Layer                            │
│           Database + File-based Evidence                     │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [OSCAL Guide](docs/OSCAL.md) - Working with OSCAL documents
- [Instructions](instructions.txt) - Complete implementation guide

## Development

```bash
# Clone the repository
git clone https://github.com/attestful/attestful.git
cd attestful

# Install dependencies
make install-dev

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

Attestful is licensed under the [Apache License 2.0](LICENSE).

## Acknowledgments

Attestful was created by merging two projects:
- **Compliy** - Multi-cloud compliance checker
- **Nisify** - NIST CSF 2.0 evidence aggregator

Special thanks to:
- [NIST OSCAL Team](https://pages.nist.gov/OSCAL/) for the OSCAL standard
- [FedRAMP Automation Team](https://github.com/GSA/fedramp-automation) for OSCAL content
