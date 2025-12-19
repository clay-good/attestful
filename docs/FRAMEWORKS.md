# Framework Reference

This document provides detailed information about all compliance frameworks supported by Attestful, including control mappings, automation coverage, and framework-specific features.

## Table of Contents

- [Overview](#overview)
- [Supported Frameworks](#supported-frameworks)
  - [NIST CSF 2.0](#nist-csf-20)
  - [NIST 800-53 Rev 5](#nist-800-53-rev-5)
  - [FedRAMP](#fedramp)
  - [SOC 2 Type II](#soc-2-type-ii)
  - [ISO 27001](#iso-27001)
  - [HITRUST CSF](#hitrust-csf)
- [Cross-Framework Mappings](#cross-framework-mappings)
- [Automation Coverage](#automation-coverage)
- [Custom Frameworks](#custom-frameworks)

## Overview

Attestful uses OSCAL (Open Security Controls Assessment Language) as the foundation for all compliance frameworks. This enables:

- **Standardized data format** for controls and assessments
- **Cross-framework mapping** to reduce duplicate effort
- **Machine-readable** compliance documentation
- **Interoperability** with other OSCAL-compatible tools

### Framework Selection

Choose frameworks based on your compliance requirements:

| Framework | Best For |
|-----------|----------|
| NIST CSF 2.0 | General cybersecurity posture, initial assessments |
| NIST 800-53 | Federal systems, FedRAMP preparation |
| FedRAMP | Cloud services for federal agencies |
| SOC 2 | SaaS companies, customer trust |
| ISO 27001 | International compliance, enterprise |
| HITRUST | Healthcare, multi-framework compliance |

---

## Supported Frameworks

### NIST CSF 2.0

The NIST Cybersecurity Framework 2.0 is a voluntary framework for managing cybersecurity risk.

#### Framework Structure

| Function | ID | Categories |
|----------|-----|------------|
| **Govern** | GV | Organizational Context, Risk Management Strategy, Roles & Responsibilities, Policy, Oversight, Cybersecurity Supply Chain Risk Management |
| **Identify** | ID | Asset Management, Business Environment, Governance, Risk Assessment, Risk Management Strategy, Supply Chain Risk Management |
| **Protect** | PR | Identity Management & Access Control, Awareness & Training, Data Security, Information Protection Processes, Maintenance, Protective Technology |
| **Detect** | DE | Anomalies & Events, Security Continuous Monitoring, Detection Processes |
| **Respond** | RS | Response Planning, Communications, Analysis, Mitigation, Improvements |
| **Recover** | RC | Recovery Planning, Improvements, Communications |

#### Maturity Levels

Attestful calculates maturity scores based on NIST methodology:

| Level | Score Range | Description |
|-------|-------------|-------------|
| Initial | 0-24 | Ad hoc, reactive processes |
| Developing | 25-49 | Some processes defined but not consistent |
| Defined | 50-69 | Documented and standardized processes |
| Managed | 70-89 | Measured and controlled processes |
| Optimizing | 90-100 | Continuous improvement focus |

#### Evidence Mappings

| Evidence Type | CSF Categories |
|---------------|----------------|
| `iam_credential_report` | PR.AA, GV.RR |
| `password_policy` | PR.AA, GV.PO |
| `cloudtrail_status` | DE.CM, GV.OV |
| `guardduty_status` | DE.CM, DE.AE |
| `config_status` | DE.CM, ID.AM |
| `securityhub_findings` | DE.AE, RS.AN |
| `mfa_factors` | PR.AA |
| `system_log` | DE.CM, DE.AE |

#### Usage

```bash
# Calculate CSF maturity
attestful analyze maturity --framework nist-csf-2

# Generate CSF report
attestful report generate --framework nist-csf-2 --format html

# View CSF controls
attestful frameworks show nist-csf-2 --controls
```

---

### NIST 800-53 Rev 5

NIST Special Publication 800-53 Revision 5 provides security and privacy controls for federal information systems.

#### Control Families

| Family ID | Name | Controls |
|-----------|------|----------|
| AC | Access Control | 25 |
| AT | Awareness and Training | 6 |
| AU | Audit and Accountability | 16 |
| CA | Assessment, Authorization, and Monitoring | 9 |
| CM | Configuration Management | 14 |
| CP | Contingency Planning | 13 |
| IA | Identification and Authentication | 12 |
| IR | Incident Response | 10 |
| MA | Maintenance | 7 |
| MP | Media Protection | 8 |
| PE | Physical and Environmental Protection | 23 |
| PL | Planning | 11 |
| PM | Program Management | 32 |
| PS | Personnel Security | 9 |
| PT | PII Processing and Transparency | 8 |
| RA | Risk Assessment | 10 |
| SA | System and Services Acquisition | 23 |
| SC | System and Communications Protection | 51 |
| SI | System and Information Integrity | 23 |
| SR | Supply Chain Risk Management | 12 |

#### Baselines

| Baseline | Control Count | Description |
|----------|---------------|-------------|
| Low | ~130 | Minimal security requirements |
| Moderate | ~325 | Most common federal baseline |
| High | ~420 | Maximum security requirements |

#### Automated Checks

Attestful provides automated checks for many 800-53 controls:

| Control | Check | Automation |
|---------|-------|------------|
| AC-2 | Account Management | User inventory, disabled account detection |
| AC-3 | Access Enforcement | IAM policy analysis |
| AC-6 | Least Privilege | Over-permissioned role detection |
| AU-2 | Audit Events | CloudTrail/audit log configuration |
| AU-3 | Content of Audit Records | Log content verification |
| CM-2 | Baseline Configuration | Configuration drift detection |
| IA-2 | Identification and Authentication | MFA enforcement |
| IA-5 | Authenticator Management | Password policy compliance |
| SC-7 | Boundary Protection | Security group analysis |
| SC-8 | Transmission Confidentiality | Encryption in transit |
| SC-28 | Protection of Information at Rest | Encryption at rest |
| SI-2 | Flaw Remediation | Vulnerability scanning |
| SI-4 | Information System Monitoring | GuardDuty/monitoring status |

#### Usage

```bash
# Scan against 800-53 Moderate baseline
attestful scan aws --framework nist-800-53 --baseline moderate

# Generate OSCAL assessment results
attestful oscal assessment generate --framework nist-800-53 --output ar.json

# View control details
attestful frameworks controls nist-800-53 --control AC-2
```

---

### FedRAMP

The Federal Risk and Authorization Management Program (FedRAMP) provides a standardized approach for cloud services.

#### Impact Levels

| Level | Description | Based On |
|-------|-------------|----------|
| Low | Low-impact systems | NIST 800-53 Low + FedRAMP additions |
| Moderate | Most common level | NIST 800-53 Moderate + FedRAMP additions |
| High | High-security systems | NIST 800-53 High + FedRAMP additions |

#### FedRAMP-Specific Controls

FedRAMP adds controls and parameters to the NIST 800-53 baseline:

| Area | Requirements |
|------|--------------|
| Continuous Monitoring | Monthly vulnerability scanning, annual penetration testing |
| Incident Response | 1-hour notification for high-impact incidents |
| Data Location | US-based data centers required |
| Personnel | US persons for privileged access |
| Encryption | FIPS 140-2 validated encryption |

#### Usage

```bash
# Scan for FedRAMP Moderate
attestful scan aws --framework fedramp --baseline moderate

# Generate FedRAMP SSP
attestful oscal ssp generate --profile fedramp-moderate --output ssp.json

# Check FedRAMP-specific requirements
attestful frameworks show fedramp --checks
```

---

### SOC 2 Type II

SOC 2 (System and Organization Controls 2) Type II reports on controls relevant to security, availability, processing integrity, confidentiality, and privacy.

#### Trust Services Criteria

| Category | ID | Description |
|----------|-----|-------------|
| **Common Criteria (Security)** | CC | Required for all SOC 2 reports |
| **Availability** | A | System availability commitments |
| **Processing Integrity** | PI | System processing accuracy |
| **Confidentiality** | C | Confidential information protection |
| **Privacy** | P | Personal information handling |

#### Common Criteria Controls

| Control ID | Title | Automation Rate |
|------------|-------|-----------------|
| CC1.1 | COSO Principle 1 | Evidence-based |
| CC1.2 | COSO Principle 2 | Evidence-based |
| CC2.1 | Information Communication | Evidence-based |
| CC3.1 | Risk Assessment | Automated |
| CC4.1 | Monitoring Activities | Automated |
| CC5.1 | Control Activities | Automated |
| CC6.1 | Logical and Physical Access | Automated |
| CC6.2 | Authentication | Automated |
| CC6.3 | Access Removal | Automated |
| CC6.6 | Encryption in Transit | Automated |
| CC6.7 | Transmission Security | Automated |
| CC7.1 | Vulnerability Management | Automated |
| CC7.2 | Security Monitoring | Automated |
| CC7.3 | Incident Response | Evidence-based |
| CC7.4 | Incident Analysis | Evidence-based |
| CC8.1 | Change Management | Evidence-based |
| CC9.1 | Risk Mitigation | Evidence-based |
| CC9.2 | Vendor Management | Evidence-based |

#### Automation Coverage

Attestful automates approximately **90%** of SOC 2 Common Criteria evidence collection:

| Automated | Evidence-Based | Total |
|-----------|----------------|-------|
| 45 checks | 5 manual | 50 controls |

#### Usage

```bash
# Run SOC 2 compliance scan
attestful scan aws --framework soc2

# SOC 2 maturity analysis
attestful analyze maturity --framework soc2

# Generate SOC 2 report
attestful report generate --framework soc2 --format html

# View SOC 2 controls
attestful frameworks show soc2 --controls
```

---

### ISO 27001

ISO/IEC 27001 is an international standard for information security management systems (ISMS).

#### Annex A Controls

ISO 27001:2022 includes 93 controls in 4 categories:

| Category | Controls | Description |
|----------|----------|-------------|
| Organizational (A.5) | 37 | Policies, roles, asset management |
| People (A.6) | 8 | Screening, awareness, responsibilities |
| Physical (A.7) | 14 | Secure areas, equipment, clear desk |
| Technological (A.8) | 34 | Access control, cryptography, operations |

#### Key Controls

| Control | Title | Automation |
|---------|-------|------------|
| A.5.1 | Policies for information security | Evidence-based |
| A.5.15 | Access control | Automated |
| A.5.17 | Authentication information | Automated |
| A.8.2 | Privileged access rights | Automated |
| A.8.3 | Information access restriction | Automated |
| A.8.5 | Secure authentication | Automated |
| A.8.9 | Configuration management | Automated |
| A.8.15 | Logging | Automated |
| A.8.16 | Monitoring activities | Automated |
| A.8.24 | Use of cryptography | Automated |

#### Statement of Applicability

Attestful helps generate a Statement of Applicability (SoA):

```bash
# Generate SoA
attestful frameworks soa iso-27001 --output soa.xlsx
```

#### Usage

```bash
# Scan against ISO 27001
attestful scan aws --framework iso-27001

# Gap analysis
attestful analyze gaps --framework iso-27001

# Generate ISO 27001 report
attestful report generate --framework iso-27001 --format html
```

---

### HITRUST CSF

The HITRUST Common Security Framework (CSF) is a comprehensive framework combining multiple standards, particularly popular in healthcare.

#### Control Categories

| Domain | ID | Description |
|--------|-----|-------------|
| Information Protection Program | 0 | Security program management |
| Endpoint Protection | 1 | Device security |
| Portable Media Security | 2 | Removable media |
| Mobile Device Security | 3 | Mobile device management |
| Wireless Security | 4 | Wireless networks |
| Configuration Management | 5 | System configuration |
| Vulnerability Management | 6 | Vulnerability handling |
| Network Protection | 7 | Network security |
| Transmission Protection | 8 | Data in transit |
| Password Management | 9 | Password policies |
| Access Control | 10 | Access management |
| Audit Logging | 11 | Logging and monitoring |
| Education & Awareness | 12 | Security training |
| Third Party Assurance | 13 | Vendor management |
| Incident Management | 14 | Incident response |
| Business Continuity | 15 | BC/DR |
| Risk Management | 16 | Risk processes |
| Physical Security | 17 | Physical controls |
| Data Protection | 18 | Data security |
| Privacy | 19 | Privacy practices |

#### Maturity Levels

HITRUST uses a 5-level maturity model:

| Level | Name | Description |
|-------|------|-------------|
| 1 | Policy | Policy exists |
| 2 | Procedure | Procedures documented |
| 3 | Implemented | Controls implemented |
| 4 | Measured | Metrics tracked |
| 5 | Managed | Continuous improvement |

#### Inheritance from Other Frameworks

HITRUST maps to multiple frameworks:

| Source Framework | Mapped Controls |
|-----------------|-----------------|
| NIST 800-53 | ~200 |
| ISO 27001 | ~80 |
| HIPAA | ~45 |
| PCI DSS | ~60 |
| SOC 2 | ~50 |

#### Usage

```bash
# Scan against HITRUST
attestful scan aws --framework hitrust

# HITRUST maturity analysis
attestful analyze maturity --framework hitrust

# View HITRUST controls
attestful frameworks show hitrust --controls
```

---

## Cross-Framework Mappings

Attestful provides bidirectional mappings between frameworks, reducing duplicate compliance effort.

### Mapping Strengths

| Strength | Description |
|----------|-------------|
| Strong | Direct 1:1 control mapping |
| Moderate | Similar intent, partial overlap |
| Weak | Related concepts only |

### Common Mappings

#### Access Control

| NIST 800-53 | SOC 2 | ISO 27001 | HITRUST |
|-------------|-------|-----------|---------|
| AC-2 | CC6.1, CC6.2 | A.5.15 | 10.a |
| AC-3 | CC6.1 | A.5.15 | 10.b |
| AC-6 | CC6.1, CC6.3 | A.8.2 | 10.c |
| IA-2 | CC6.1 | A.5.17 | 09.a |
| IA-5 | CC6.1 | A.5.17 | 09.b |

#### Audit and Monitoring

| NIST 800-53 | SOC 2 | ISO 27001 | HITRUST |
|-------------|-------|-----------|---------|
| AU-2 | CC7.2 | A.8.15 | 11.a |
| AU-3 | CC7.2 | A.8.15 | 11.b |
| AU-6 | CC7.2 | A.8.16 | 11.c |
| SI-4 | CC7.2 | A.8.16 | 11.d |

### Using Cross-Framework Mappings

```bash
# View mappings from NIST 800-53 to SOC 2
attestful analyze crosswalk --source nist-800-53 --target soc2

# View mappings for specific control
attestful analyze crosswalk --source nist-800-53 --control AC-2

# Export all mappings
attestful analyze crosswalk --source nist-800-53 --format json --output mappings.json
```

---

## Automation Coverage

Attestful provides varying levels of automation for each framework:

### Coverage Summary

| Framework | Automated | Evidence-Based | Manual | Total |
|-----------|-----------|----------------|--------|-------|
| NIST CSF 2.0 | 60% | 30% | 10% | 108 categories |
| NIST 800-53 | 45% | 35% | 20% | 1,000+ controls |
| FedRAMP Moderate | 50% | 35% | 15% | 325 controls |
| SOC 2 | 90% | 8% | 2% | 50 controls |
| ISO 27001 | 55% | 30% | 15% | 93 controls |
| HITRUST | 50% | 35% | 15% | 700+ requirements |

### Automation Types

| Type | Description | Examples |
|------|-------------|----------|
| **Automated** | Full automated assessment | S3 encryption check, MFA enforcement |
| **Evidence-Based** | Automated evidence collection, manual review | Policy documents, training records |
| **Manual** | Requires human input | Risk acceptance decisions, physical security |

---

## Custom Frameworks

Attestful supports creating custom frameworks for internal compliance requirements.

### Creating Custom Frameworks

```yaml
# custom-framework.yaml
framework:
  id: internal-security
  title: Internal Security Policy
  version: 1.0.0

controls:
  - id: INT-001
    title: Password Requirements
    description: All systems must enforce strong passwords
    category: Access Control
    checks:
      - password_policy
      - mfa_enabled

  - id: INT-002
    title: Data Encryption
    description: All data must be encrypted at rest
    category: Data Protection
    checks:
      - s3_encryption
      - rds_encryption
      - ebs_encryption

  - id: INT-003
    title: Logging
    description: All systems must have logging enabled
    category: Monitoring
    checks:
      - cloudtrail_enabled
      - vpc_flow_logs
```

### Loading Custom Frameworks

```bash
# Load custom framework
attestful frameworks load custom-framework.yaml

# Scan against custom framework
attestful scan aws --framework internal-security

# Generate custom framework report
attestful report generate --framework internal-security
```

### Mapping Custom Controls

```yaml
# Map custom controls to standard frameworks
mappings:
  INT-001:
    nist-800-53:
      - IA-5
    soc2:
      - CC6.1
    iso-27001:
      - A.5.17
```
