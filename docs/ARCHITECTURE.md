# Attestful Architecture

This document describes the architecture of Attestful, an OSCAL-first compliance automation platform.

## Overview

Attestful combines two distinct compliance approaches into a unified platform:

1. **Resource-based compliance checking** (from Compliy): Evaluates cloud infrastructure resources against defined checks
2. **Evidence-based compliance verification** (from Nisify): Collects evidence artifacts from platforms to prove control implementation

Both approaches feed into the OSCAL layer, which provides a standardized format for all compliance data.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI / API / Dashboard                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OSCAL Layer                                     │
│  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌─────┐  ┌────────────┐        │
│  │ Catalog  │  │ Profile  │  │ Component │  │ SSP │  │ Assessment │        │
│  └──────────┘  └──────────┘  └───────────┘  └─────┘  └────────────┘        │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        │                               │                               │
        ▼                               ▼                               ▼
┌───────────────────┐    ┌─────────────────────────┐    ┌───────────────────┐
│ Resource Checking │    │   Evidence Collection   │    │     Analysis      │
│    (Compliy)      │    │       (Nisify)          │    │                   │
├───────────────────┤    ├─────────────────────────┤    ├───────────────────┤
│ - Scanner         │    │ - Platform Collectors   │    │ - Maturity Calc   │
│ - Evaluator       │    │ - Evidence Storage      │    │ - Gap Analysis    │
│ - Remediation     │    │ - Mapping Engine        │    │ - Trend Tracker   │
└───────────────────┘    └─────────────────────────┘    └───────────────────┘
        │                               │                               │
        └───────────────────────────────┼───────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Unified Collector Layer                              │
│  ┌─────────────────────────────┐    ┌─────────────────────────────────┐    │
│  │   Infrastructure Collectors  │    │     Platform Collectors         │    │
│  │   (AWS, Azure, GCP, K8s)    │    │   (Okta, Jamf, Snowflake...)    │    │
│  └─────────────────────────────┘    └─────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Storage Layer                                   │
│  ┌──────────────────────┐         ┌───────────────────────────────────┐    │
│  │   Database (SQLite/  │         │   File Storage (Evidence Files)   │    │
│  │   PostgreSQL)        │         │   SHA-256 Integrity Verification  │    │
│  └──────────────────────┘         └───────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. OSCAL Layer (`src/attestful/oscal/`)

The OSCAL layer is the heart of Attestful, providing standardized data models for all compliance information.

#### Catalog (`catalog.py`)
- Loads and parses OSCAL catalog files (controls definitions)
- Supports NIST 800-53, SOC 2, ISO 27001, and custom catalogs
- Provides fast control lookup via indexing
- Handles parameter resolution in control prose

#### Profile (`profile.py`)
- Manages control selections and customizations
- Resolves profile imports and modifications
- Supports profile inheritance for organizational customization
- Generates tailored catalogs from baselines

#### Component (`component.py`)
- Defines reusable control implementations
- Maps automated checks to control statements
- Links evidence types to control requirements
- Supports component composition

#### SSP (`ssp.py`)
- Generates System Security Plans
- Combines profiles with component implementations
- Manages responsibility matrices
- Supports SSP diffing and validation

#### Assessment (`assessment.py`)
- Converts scan results to OSCAL format
- Maps maturity scores to findings
- Generates POA&M documents
- Tracks assessment history

### 2. Collector Layer (`src/attestful/collectors/`)

#### Base Collector (`base.py`)

The unified collector base class supports dual-mode operation:

```
┌─────────────────────────────────────────────────────────────────┐
│                      BaseCollector                              │
├─────────────────────────────────────────────────────────────────┤
│  + collect_resources() -> List[Resource]   # Checking mode      │
│  + collect_evidence() -> CollectionResult  # Evidence mode      │
│  - _rate_limit()                           # Common utilities    │
│  - _with_retry()                                                │
│  - _handle_errors()                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┴───────────────────┐
          │                                       │
          ▼                                       ▼
┌─────────────────────┐               ┌─────────────────────┐
│ InfrastructureMode  │               │   EvidenceMode      │
│                     │               │                     │
│ - EC2 instances     │               │ - MFA status        │
│ - S3 buckets        │               │ - Audit logs        │
│ - IAM policies      │               │ - Policy documents  │
│ - Security groups   │               │ - User inventories  │
└─────────────────────┘               └─────────────────────┘
```

#### Infrastructure Collectors (`cloud/`)
- **AWSCollector**: EC2, S3, IAM, VPC, CloudTrail, etc.
- **AzureCollector**: VMs, Storage, AD, NSGs, etc.
- **GCPCollector**: Compute, Storage, IAM, etc.
- **KubernetesCollector**: Pods, Services, NetworkPolicies, etc.
- **DockerCollector**: Containers, Images, Networks

#### Platform Collectors (`platforms/`)
- **OktaCollector**: Users, groups, MFA, policies
- **JamfCollector**: Devices, MDM, compliance
- **GoogleWorkspaceCollector**: Users, Drive, audit logs
- **SnowflakeCollector**: Users, roles, access history
- **DatadogCollector**: Monitors, logs, security signals
- **GitLabCollector**: Projects, pipelines, security scans
- **JiraCollector**: Issues, workflows, audit logs
- **ZendeskCollector**: Tickets, users, security settings
- **ZoomCollector**: Users, meetings, security settings
- **NotionCollector**: Pages, permissions, audit logs
- **SlabCollector**: Posts, topics, settings
- **SpotDraftCollector**: Contracts, approvals, signatures

### 3. Scanner & Evaluator (`src/attestful/scanner/`, `src/attestful/evaluator/`)

The scanning engine evaluates resources against defined checks.

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Scanner    │────▶│   Evaluator  │────▶│   Results    │
│              │     │              │     │              │
│ - Orchestrate│     │ - Parse cond │     │ - Pass/Fail  │
│ - Collect    │     │ - Evaluate   │     │ - Evidence   │
│ - Filter     │     │ - JMESPath   │     │ - Severity   │
└──────────────┘     └──────────────┘     └──────────────┘
```

#### Check Definition Format (YAML)
```yaml
id: soc2-cc6.1-001
name: Ensure MFA enabled for all IAM users
severity: critical
resource_types: [aws_iam_user]
condition: |
  resource.get('raw', {}).get('mfa_enabled') == True
remediation: |
  1. Sign in to AWS Console
  2. Navigate to IAM > Users
  3. Enable MFA for each user
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html
```

#### Condition Evaluation
- Python expressions with restricted scope
- JMESPath queries for complex JSON traversal
- Built-in functions: `any()`, `all()`, `len()`, type conversions

### 4. Storage Layer (`src/attestful/storage/`)

#### Database Schema

```
┌─────────────────────┐     ┌─────────────────────┐
│   attestful_scans   │     │ attestful_evidence  │
├─────────────────────┤     ├─────────────────────┤
│ id                  │     │ id                  │
│ provider            │     │ collection_run_id   │
│ framework           │     │ platform            │
│ status              │     │ evidence_type       │
│ started_at          │     │ file_path           │
│ completed_at        │     │ file_hash           │
│ summary_json        │     │ collected_at        │
└─────────────────────┘     └─────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────┐     ┌─────────────────────┐
│ attestful_results   │     │ attestful_maturity  │
├─────────────────────┤     ├─────────────────────┤
│ id                  │     │ id                  │
│ scan_id             │     │ snapshot_date       │
│ check_id            │     │ framework           │
│ resource_id         │     │ control_id          │
│ status              │     │ maturity_level      │
│ evidence_json       │     │ score               │
└─────────────────────┘     └─────────────────────┘
```

#### File-Based Evidence Storage

```
evidence/
├── 2024/
│   ├── 01/
│   │   ├── 15/
│   │   │   ├── okta/
│   │   │   │   ├── users/
│   │   │   │   │   └── a1b2c3d4.json
│   │   │   │   └── mfa_status/
│   │   │   │       └── e5f6g7h8.json
│   │   │   └── aws/
│   │   │       └── security_findings/
│   │   │           └── i9j0k1l2.json
```

Features:
- SHA-256 hashing for integrity verification
- Zstandard compression for large files
- Retention policies with archival
- Tamper detection via checksum chain

### 5. Analysis Layer (`src/attestful/analysis/`)

#### Maturity Calculator
- Implements NIST-style maturity levels (0-4)
- Calculates scores based on evidence presence, freshness, and completeness
- Supports weighted evidence types
- Generates roll-up scores (subcategory → category → function → overall)

#### Gap Analyzer
- Identifies missing controls between frameworks
- Calculates control equivalency scores
- Generates prioritized remediation lists
- Supports cross-framework compliance

#### Trend Tracker
- Stores historical maturity snapshots
- Calculates improvement trajectories
- Identifies regression patterns
- Generates compliance trend reports

### 6. Frameworks Layer (`src/attestful/frameworks/`)

Each framework implementation provides:
- OSCAL catalog for the framework's controls
- Control-to-check mappings
- Evidence type mappings
- Framework-specific reporting templates
- Cross-framework mappings

```
frameworks/
├── nist_csf/           # NIST CSF 2.0
│   ├── catalog.py      # 106 subcategories
│   ├── mapping.py      # Evidence mappings
│   └── calculator.py   # Maturity scoring
├── nist_800_53/        # NIST 800-53 / FedRAMP
│   ├── catalog.py      # 1000+ controls
│   └── fedramp.py      # FedRAMP baselines
├── soc2/               # SOC 2 Type II
│   ├── catalog.py      # Trust Services Criteria
│   └── checks.py       # 200+ automated checks
├── iso27001/           # ISO 27001:2022
│   └── catalog.py      # Annex A controls
└── hitrust/            # HITRUST CSF
    └── catalog.py      # HITRUST controls
```

### 7. Remediation Layer (`src/attestful/remediation/`)

Automated remediation actions (33+ actions):

| Provider   | Actions |
|------------|---------|
| AWS        | 8 (S3 encryption, CloudTrail, IAM policies) |
| Azure      | 6 (Storage encryption, NSG rules, SQL TDE) |
| GCP        | 6 (Storage versioning, firewall, OS Login) |
| Kubernetes | 4 (Pod security, resource limits, network policies) |

Features:
- Dry-run mode for safe testing
- Rollback support for failed actions
- Risk-level classification
- Audit logging of all actions

## Data Flow

### Compliance Scan Flow

```
1. User initiates scan
   │
   ▼
2. Scanner identifies target resources
   │
   ▼
3. Collector gathers resources from cloud provider
   │
   ▼
4. Evaluator runs checks against resources
   │
   ▼
5. Results stored in database
   │
   ▼
6. Results converted to OSCAL Assessment Results
   │
   ▼
7. Reports generated (HTML, PDF, OSCAL)
```

### Evidence Collection Flow

```
1. User initiates collection
   │
   ▼
2. Collector connects to platform (Okta, etc.)
   │
   ▼
3. Evidence gathered via API calls
   │
   ▼
4. Evidence stored in filesystem with hash
   │
   ▼
5. Mapping engine links evidence to controls
   │
   ▼
6. Maturity calculator computes scores
   │
   ▼
7. Results converted to OSCAL observations
```

## Air-Gap Architecture

For disconnected environments, Attestful supports an "evidence ferry" pattern:

```
┌────────────────────────────────────────────────────────────────┐
│                    Connected Network                            │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│  │   Okta      │    │    AWS      │    │   GitLab    │        │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘        │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│  ┌──────────────────────────────────────────────────┐          │
│  │           Attestful Collection Agent              │          │
│  └──────────────────────────────────────────────────┘          │
│                            │                                    │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────┐          │
│  │        Signed Evidence Bundle (.attestful)        │          │
│  └──────────────────────────────────────────────────┘          │
└────────────────────────────────────────────────────────────────┘
                             │
                        USB Transfer
                             │
                             ▼
┌────────────────────────────────────────────────────────────────┐
│                    Air-Gapped Network                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────┐          │
│  │        Import & Verify Signed Bundle              │          │
│  └──────────────────────────────────────────────────┘          │
│                            │                                    │
│                            ▼                                    │
│  ┌──────────────────────────────────────────────────┐          │
│  │           Attestful Analysis Server               │          │
│  │                                                   │          │
│  │  - Maturity scoring                              │          │
│  │  - Gap analysis                                  │          │
│  │  - Report generation                             │          │
│  │  - OSCAL SSP generation                          │          │
│  └──────────────────────────────────────────────────┘          │
└────────────────────────────────────────────────────────────────┘
```

## Security Architecture

### Credential Management
- Fernet symmetric encryption for stored credentials
- PBKDF2-SHA256 key derivation (600k iterations)
- OS keychain integration where available
- Environment variable support for automation

### Audit Logging
- All administrative actions logged
- Checksum chain for tamper detection
- Configurable retention periods
- Export for SIEM integration

### RBAC (Enterprise)
- Four roles: admin, analyst, auditor, viewer
- API key authentication with SHA-256 hashing
- Rate limiting (configurable)
- TLS/mTLS support

## Extensibility

### Adding a New Collector

1. Create a new file in `src/attestful/collectors/platforms/`
2. Inherit from `BaseCollector`
3. Implement `collect_resources()` and/or `collect_evidence()`
4. Register in the collector registry
5. Add tests with mocked API responses

### Adding a New Framework

1. Create a new directory in `src/attestful/frameworks/`
2. Create an OSCAL catalog for the framework
3. Create profiles for common baselines
4. Map controls to existing checks
5. Add framework-specific reporting templates

### Adding a New Check

1. Add a new entry to the appropriate YAML file in `data/standards/`
2. Define the condition using Python/JMESPath syntax
3. Specify resource types and severity
4. Add remediation guidance
5. Test against sample resources

## Performance Considerations

- **Parallel collection**: Collectors use async I/O for concurrent API calls
- **Caching**: OSCAL catalogs cached after first load
- **Batch operations**: Database operations batched for bulk inserts
- **Incremental collection**: Only collect evidence changed since last run
- **Compression**: Large evidence files compressed with zstandard
