# Attestful

**Prove your compliance posture with automated evidence and clear visualization.**

## What is Attestful?

Attestful is a **focused, open-source tool** that does ONE thing extremely well:

- **Automated evidence collection** from 30+ platforms (cloud, SaaS, infrastructure)
- **Clear compliance visualization** showing percentage completion per framework
- **OSCAL-native exports** for interoperability with other compliance tools
- **Self-hosted/air-gapped deployment** for government and defense organizations

**Attestful is NOT a full GRC platform.** It does NOT compete with Vanta, Drata, or enterprise GRC suites. Organizations needing full GRC capabilities should pair Attestful with a dedicated GRC platform and use Attestful's OSCAL exports for evidence transfer.

## What Attestful Does NOT Include (Intentionally)

- ❌ Third-Party Risk Management (TPRM) or vendor questionnaires
- ❌ Trust Center or public compliance page hosting
- ❌ AI questionnaire automation
- ❌ Policy management or policy templates
- ❌ Risk register or risk management workflows
- ❌ Audit workflow management or auditor portals
- ❌ Employee compliance tracking or onboarding
- ❌ Security awareness training
- ❌ User access reviews or access certification campaigns

These features are intentionally out of scope to keep Attestful simple and focused.

## Core Principles

| Principle | Description |
|-----------|-------------|
| **Evidence-First** | Primary function is collecting evidence from as many sources as possible |
| **Clear Visualization** | Leadership sees "We are 90% SOC 2 compliant" at a glance |
| **OSCAL-First** | All evidence and assessments use OSCAL format for interoperability |
| **Self-hosted/Air-gapped** | Works entirely offline - critical for government/defense |
| **Simple and Focused** | Do evidence collection and visualization extremely well |
| **Open-source** | Free forever for core functionality |

## Target Users

- **Government/defense contractors** needing self-hosted compliance tools
- **Startups** wanting simple compliance visibility without SaaS costs
- **Air-gapped environments** (classified networks, OT/ICS)
- **Teams with existing GRC platforms** that need better evidence collection

## Supported Frameworks

| Framework | Status | Description |
|-----------|--------|-------------|
| **NIST CSF 2.0** | ✅ | 106 subcategories, evidence-based maturity scoring |
| **NIST 800-53 / FedRAMP** | ✅ | Full Rev 5 catalog, OSCAL-native for FedRAMP authorization |
| **SOC 2 Type II** | ✅ | All 5 Trust Services Criteria, 90%+ automation |
| **ISO 27001** | ✅ | ISO 27001:2022 Annex A controls |
| **HITRUST** | ✅ | HITRUST CSF with 5-level maturity scoring |

## Supported Platforms (30+)

### Cloud Infrastructure
- **AWS** - EC2, S3, IAM, VPC, CloudTrail, Secrets Manager, and more
- **Azure** - VMs, Storage, AD, Key Vault, NSGs, and more
- **GCP** - Compute, Storage, IAM, and more
- **Kubernetes** - Pods, Services, NetworkPolicies, RBAC
- **Docker** - Containers, Images, Networks, Swarm

### Identity & Access
- **Okta** - Users, MFA, policies, audit logs
- **Google Workspace** - Users, Drive, audit logs
- **Microsoft 365** - Users, groups, compliance settings
- **1Password** - Vaults, users, access policies

### Secrets Management
- **AWS Secrets Manager** - Secrets, rotation, access logs
- **Azure Key Vault** - Keys, secrets, certificates
- **HashiCorp Vault** - Secrets engines, policies, audit

### DevOps & Source Control
- **GitHub** - Repos, workflows, security alerts
- **GitLab** - Projects, pipelines, security scans
- **Terraform Cloud** - Workspaces, runs, policy checks

### Collaboration & Productivity
- **Slack** - Users, channels, apps, DLP settings
- **Notion** - Pages, permissions
- **Confluence** - Spaces, pages, permissions
- **Zoom** - Users, meetings, security settings

### Project Management
- **Jira** - Issues, workflows, audit logs
- **Linear** - Issues, teams, integrations
- **Asana** - Projects, tasks, permissions
- **Monday** - Boards, users, permissions
- **Shortcut** - Stories, iterations

### Other Platforms
- **Jamf** - Devices, MDM, compliance
- **Datadog** - Monitors, security signals
- **PagerDuty** - Incidents, services, escalations
- **Snowflake** - Users, roles, access history
- **Zendesk** - Tickets, users, security
- **Slab** - Posts, topics
- **SpotDraft** - Contracts, approvals

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

### First Evidence Collection

```bash
# Initialize Attestful
attestful configure init

# Configure platform credentials
attestful configure credentials --platform okta
attestful configure credentials --platform aws

# Collect evidence from all configured platforms
attestful collect --all

# View compliance dashboard
attestful dashboard
```

### View Compliance Status

```bash
# Analyze compliance by framework
attestful analyze maturity --framework nist-csf
attestful analyze maturity --framework soc2

# Generate compliance report
attestful report generate --format html --output compliance-report.html

# Export to OSCAL
attestful oscal assessment export --format json
```

## Dashboard

Attestful includes a simple, monochrome dashboard designed for clarity:

- **Large compliance percentage** - See "90% SOC 2" at a glance
- **Framework selector** - Switch between NIST CSF, SOC 2, ISO 27001, etc.
- **Category breakdown** - Drill into specific control areas
- **Evidence status** - See which platforms are connected and collecting
- **Light/dark mode** - Toggle based on preference

The dashboard is designed for leadership who need to understand compliance posture without technical details.

## Air-Gap Support

Attestful is designed for disconnected environments:

```bash
# Export evidence bundle for transfer
attestful collect export --output evidence-bundle.attestful

# Import on air-gapped system
attestful collect import --input evidence-bundle.attestful

# Generate static HTML dashboard for offline viewing
attestful dashboard export --output dashboard.html

# Analyze offline
attestful analyze maturity
```

## OSCAL Integration

Attestful uses [OSCAL](https://pages.nist.gov/OSCAL/) (Open Security Controls Assessment Language) as its native format:

```bash
# Export assessment results in OSCAL format
attestful oscal assessment export --format json

# Generate System Security Plan
attestful oscal ssp generate --profile fedramp-moderate

# Generate POA&M for failed controls
attestful oscal poam generate
```

OSCAL exports work with any OSCAL-compatible tool, including FedRAMP authorization systems.

## Development

```bash
# Clone the repository
git clone https://github.com/clay-good/attestful.git
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

## Documentation

For detailed documentation, see the [docs/](docs/) directory:

- [Getting Started](docs/GETTING_STARTED.md) - Installation and first steps
- [CLI Reference](docs/CLI.md) - Command-line interface
- [Collectors](docs/COLLECTORS.md) - Platform integrations
- [Frameworks](docs/FRAMEWORKS.md) - Supported compliance frameworks
- [OSCAL Guide](docs/OSCAL.md) - Working with OSCAL documents
- [Architecture](docs/ARCHITECTURE.md) - System design and components
- [Configuration](docs/CONFIGURATION.md) - Configuration options
- [Deployment](docs/DEPLOYMENT.md) - Docker and Kubernetes deployment
- [Air-Gap Deployment](docs/AIR_GAP.md) - Offline deployment guide
