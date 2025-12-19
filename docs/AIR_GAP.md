# Air-Gap Deployment Guide

This document provides comprehensive instructions for deploying and operating Attestful in air-gapped (disconnected) environments.

## Table of Contents

- [Overview](#overview)
- [Pre-Deployment Preparation](#pre-deployment-preparation)
- [Creating Deployment Media](#creating-deployment-media)
- [Air-Gap Installation](#air-gap-installation)
- [Offline Configuration](#offline-configuration)
- [Evidence Ferry](#evidence-ferry)
- [Offline Updates](#offline-updates)
- [Operational Procedures](#operational-procedures)
- [Troubleshooting](#troubleshooting)

## Overview

### What is Air-Gap Deployment?

An air-gapped deployment operates without any network connectivity to external systems. This is required for:

- Classified government systems
- High-security financial environments
- Critical infrastructure
- Compliance with data sovereignty requirements

### Air-Gap Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CONNECTED NETWORK                                  │
│                                                                             │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐        │
│  │  Cloud APIs     │    │  SaaS Platforms │    │  Evidence       │        │
│  │  (AWS, Azure)   │    │  (Okta, GitHub) │    │  Sources        │        │
│  └────────┬────────┘    └────────┬────────┘    └────────┬────────┘        │
│           │                      │                      │                  │
│           └──────────────────────┼──────────────────────┘                  │
│                                  │                                          │
│                                  ▼                                          │
│                    ┌─────────────────────────┐                             │
│                    │  Attestful Collection   │                             │
│                    │  Agent (Connected)      │                             │
│                    └───────────┬─────────────┘                             │
│                                │                                            │
│                                ▼                                            │
│                    ┌─────────────────────────┐                             │
│                    │  Evidence Export        │                             │
│                    │  (Signed Bundle)        │                             │
│                    └───────────┬─────────────┘                             │
│                                │                                            │
└────────────────────────────────┼────────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    TRANSFER MEDIA       │
                    │  (USB, Optical Disc)    │
                    └────────────┬────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────────────────────┐
│                                ▼                                            │
│                           AIR-GAPPED NETWORK                                │
│                                                                             │
│                    ┌─────────────────────────┐                             │
│                    │  Evidence Import        │                             │
│                    │  (Verification)         │                             │
│                    └───────────┬─────────────┘                             │
│                                │                                            │
│                                ▼                                            │
│                    ┌─────────────────────────┐                             │
│                    │  Attestful Server       │                             │
│                    │  (Air-Gapped)           │                             │
│                    └───────────┬─────────────┘                             │
│                                │                                            │
│           ┌────────────────────┼────────────────────┐                      │
│           ▼                    ▼                    ▼                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │  Analysis       │  │  Reporting      │  │  Dashboard      │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Collection Agent | Connected | Gathers evidence from APIs |
| Evidence Ferry | Transfer | Secure evidence transport |
| Attestful Server | Air-Gapped | Analysis, reporting, storage |

---

## Pre-Deployment Preparation

### 1. Inventory Requirements

Before creating deployment media, inventory all required components:

**Software Components:**
- Attestful application package
- Python runtime and dependencies
- PostgreSQL database
- OSCAL catalogs and profiles
- Framework definitions

**Hardware Requirements:**
- Server meeting minimum specifications (see DEPLOYMENT.md)
- Transfer media (USB drives, optical media)
- Hardware security module (optional, for key management)

### 2. Download All Dependencies

On a connected system, download all required packages:

```bash
# Create offline package directory
mkdir -p /opt/attestful-offline
cd /opt/attestful-offline

# Download Attestful and all dependencies
pip download attestful -d ./packages/

# Download all optional dependencies
pip download attestful[pdf,enterprise] -d ./packages/

# Download PostgreSQL packages (Ubuntu/Debian)
apt-get download postgresql postgresql-contrib libpq5
mv *.deb ./system-packages/

# Or for RHEL/CentOS
yumdownloader postgresql-server postgresql-contrib
mv *.rpm ./system-packages/
```

### 3. Download OSCAL Content

```bash
mkdir -p data/oscal/catalogs data/oscal/profiles

# Download NIST 800-53 catalog
curl -L -o data/oscal/catalogs/nist-800-53-rev5.json \
  https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json

# Download FedRAMP profiles
curl -L -o data/oscal/profiles/fedramp-moderate.json \
  https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline_profile.json
```

### 4. Prepare Docker Images (Optional)

If using Docker:

```bash
# Pull images
docker pull attestful/attestful:1.0.0
docker pull postgres:15-alpine

# Save images
docker save attestful/attestful:1.0.0 | gzip > attestful-image.tar.gz
docker save postgres:15-alpine | gzip > postgres-image.tar.gz
```

---

## Creating Deployment Media

### 1. Create Deployment Bundle

```bash
#!/bin/bash
# create-deployment-bundle.sh

BUNDLE_DIR="/opt/attestful-bundle"
VERSION="1.0.0"
DATE=$(date +%Y%m%d)
BUNDLE_NAME="attestful-${VERSION}-airgap-${DATE}"

mkdir -p "${BUNDLE_DIR}/${BUNDLE_NAME}"
cd "${BUNDLE_DIR}/${BUNDLE_NAME}"

# Create directory structure
mkdir -p packages system-packages docker-images data scripts

# Copy Python packages
cp -r /opt/attestful-offline/packages/* packages/

# Copy system packages
cp -r /opt/attestful-offline/system-packages/* system-packages/

# Copy Docker images (if using Docker)
cp /opt/attestful-offline/*.tar.gz docker-images/

# Copy OSCAL data
cp -r /opt/attestful-offline/data/* data/

# Copy installation scripts
cp /opt/attestful-offline/scripts/* scripts/

# Create manifest
cat > MANIFEST.json << EOF
{
  "version": "${VERSION}",
  "created": "$(date -Iseconds)",
  "contents": {
    "packages": $(ls packages | wc -l),
    "system_packages": $(ls system-packages | wc -l),
    "docker_images": $(ls docker-images | wc -l),
    "oscal_catalogs": $(ls data/oscal/catalogs | wc -l),
    "oscal_profiles": $(ls data/oscal/profiles | wc -l)
  }
}
EOF

# Create checksums
find . -type f -exec sha256sum {} \; > SHA256SUMS

# Create bundle archive
cd ..
tar -czvf "${BUNDLE_NAME}.tar.gz" "${BUNDLE_NAME}"

# Sign the bundle (GPG)
gpg --detach-sign --armor "${BUNDLE_NAME}.tar.gz"

echo "Bundle created: ${BUNDLE_NAME}.tar.gz"
echo "Signature: ${BUNDLE_NAME}.tar.gz.asc"
```

### 2. Verify Bundle Integrity

```bash
# On the connected system, before transfer
cd /opt/attestful-bundle
sha256sum -c SHA256SUMS
gpg --verify attestful-1.0.0-airgap-*.tar.gz.asc
```

### 3. Prepare Transfer Media

#### USB Drive

```bash
# Format USB drive (WARNING: destroys all data)
sudo mkfs.ext4 -L ATTESTFUL /dev/sdX1

# Mount and copy
sudo mount /dev/sdX1 /mnt/usb
sudo cp attestful-*.tar.gz attestful-*.tar.gz.asc /mnt/usb/
sudo umount /mnt/usb
```

#### Optical Media (for high-security environments)

```bash
# Create ISO image
mkisofs -o attestful-bundle.iso -R -J attestful-*/

# Burn to disc
cdrecord -v dev=/dev/sr0 attestful-bundle.iso
```

---

## Air-Gap Installation

### 1. Transfer and Verify

On the air-gapped system:

```bash
# Mount transfer media
sudo mount /dev/sdX1 /mnt/transfer

# Copy and verify
cp /mnt/transfer/attestful-*.tar.gz /opt/
cp /mnt/transfer/attestful-*.tar.gz.asc /opt/

# Import GPG key (must be done offline with key on media)
gpg --import /mnt/transfer/attestful-signing-key.asc

# Verify signature
gpg --verify /opt/attestful-*.tar.gz.asc

# Extract bundle
cd /opt
tar -xzvf attestful-*.tar.gz
cd attestful-*
```

### 2. Install System Dependencies

```bash
# Ubuntu/Debian
cd system-packages
sudo dpkg -i *.deb

# RHEL/CentOS
cd system-packages
sudo rpm -ivh *.rpm
```

### 3. Install Python Packages

```bash
# Create virtual environment
python3.11 -m venv /opt/attestful/venv

# Install from local packages (no network)
/opt/attestful/venv/bin/pip install --no-index --find-links=./packages attestful
```

### 4. Load Docker Images (Optional)

```bash
# Load images
gunzip -c docker-images/attestful-image.tar.gz | docker load
gunzip -c docker-images/postgres-image.tar.gz | docker load

# Verify
docker images | grep attestful
```

### 5. Install OSCAL Content

```bash
# Create data directory
mkdir -p /var/attestful/data/oscal

# Copy OSCAL content
cp -r data/oscal/* /var/attestful/data/oscal/

# Set ownership
chown -R attestful:attestful /var/attestful/data
```

---

## Offline Configuration

### 1. Configure for Air-Gap Operation

```yaml
# /etc/attestful/config.yaml

general:
  data_dir: /var/attestful
  log_level: INFO
  # Disable all network features
  offline_mode: true

database:
  type: sqlite  # Or local PostgreSQL
  path: /var/attestful/attestful.db

storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 730  # 2 years
  compression: true

# Disable external APIs
api:
  enabled: true
  host: 127.0.0.1  # Local only
  port: 8000

# Use local OSCAL content only
oscal:
  catalogs_dir: /var/attestful/data/oscal/catalogs
  profiles_dir: /var/attestful/data/oscal/profiles
  offline_only: true

# Disable network collectors
collectors:
  enabled: false  # Evidence comes via ferry

# Security settings for air-gap
security:
  credential_encryption: true
  audit_logging: true
  # Use local key storage
  key_storage: file
  key_path: /var/attestful/keys
```

### 2. Initialize Air-Gap System

```bash
# Initialize database and configuration
/opt/attestful/venv/bin/attestful configure init --offline

# Verify OSCAL catalogs loaded
/opt/attestful/venv/bin/attestful oscal catalog list

# Check system status
/opt/attestful/venv/bin/attestful health
```

---

## Evidence Ferry

The Evidence Ferry securely transfers collected evidence from connected systems to air-gapped systems.

### 1. Export Evidence (Connected System)

```bash
# Collect evidence from platforms
attestful collect all

# Export evidence bundle
attestful ferry export \
  --since 2024-01-01 \
  --output /tmp/evidence-export.atf \
  --sign

# The export creates a signed, encrypted bundle
# Output: evidence-export.atf (encrypted bundle)
#         evidence-export.atf.sig (detached signature)
```

### 2. Bundle Format

The evidence bundle contains:

```
evidence-export.atf
├── manifest.json         # Bundle metadata
├── evidence/             # Evidence files
│   ├── aws/
│   ├── okta/
│   └── github/
├── resources/            # Collected resources
├── checksums.sha256     # File integrity checksums
└── signature.gpg        # Digital signature
```

### 3. Transfer Evidence

```bash
# Copy to transfer media
cp /tmp/evidence-export.atf* /mnt/usb/incoming/

# Optionally encrypt for transport
gpg --encrypt --recipient security-team@example.com \
  evidence-export.atf
```

### 4. Import Evidence (Air-Gapped System)

```bash
# Mount transfer media
sudo mount /dev/sdX1 /mnt/transfer

# Verify signature
attestful ferry verify /mnt/transfer/incoming/evidence-export.atf

# Import evidence
attestful ferry import \
  --input /mnt/transfer/incoming/evidence-export.atf \
  --verify

# Check imported evidence
attestful evidence list --since 2024-01-01
```

### 5. Run Analysis on Imported Evidence

```bash
# Run scans against imported resources
attestful scan --source imported --framework soc2

# Calculate maturity scores
attestful analyze maturity --framework nist-csf-2

# Generate reports
attestful report generate --format html --output compliance-report.html
```

---

## Offline Updates

### 1. Create Update Bundle

On a connected system:

```bash
# Download new version
pip download attestful==1.1.0 -d ./update-packages/

# Download new OSCAL content
./scripts/download-oscal-updates.sh

# Create update bundle
./scripts/create-update-bundle.sh 1.1.0
```

### 2. Update Bundle Structure

```
attestful-update-1.1.0/
├── MANIFEST.json
├── CHANGELOG.md
├── packages/            # Updated Python packages
├── migrations/          # Database migrations
├── oscal-updates/       # Updated OSCAL content
├── install.sh          # Update script
└── SHA256SUMS
```

### 3. Apply Update

```bash
# Stop services
sudo systemctl stop attestful

# Backup current installation
attestful backup create --output /var/attestful/backups/pre-update.tar.gz

# Apply update
cd /opt/attestful-update-1.1.0
sudo ./install.sh

# Run migrations
attestful db migrate

# Verify update
attestful --version

# Start services
sudo systemctl start attestful
```

### 4. Rollback If Needed

```bash
# Stop services
sudo systemctl stop attestful

# Restore from backup
attestful backup restore --input /var/attestful/backups/pre-update.tar.gz

# Start services
sudo systemctl start attestful
```

---

## Operational Procedures

### Daily Operations

1. **Import Latest Evidence:**
```bash
attestful ferry import --input /mnt/transfer/daily-evidence.atf
```

2. **Run Compliance Scans:**
```bash
attestful scan --source imported --framework all
```

3. **Generate Daily Report:**
```bash
attestful report generate --format html --output daily-report.html
```

### Weekly Operations

1. **Full Analysis:**
```bash
attestful analyze maturity --framework nist-csf-2
attestful analyze gaps --framework soc2
```

2. **Export Reports:**
```bash
# Prepare reports for transfer out
attestful report generate --format pdf --output weekly-report.pdf
cp weekly-report.pdf /mnt/transfer/outgoing/
```

### Monthly Operations

1. **Database Maintenance:**
```bash
attestful db vacuum
attestful db analyze
```

2. **Evidence Retention:**
```bash
attestful storage cleanup --older-than 365d --dry-run
attestful storage cleanup --older-than 365d
```

3. **Audit Log Review:**
```bash
attestful audit export --since 30d --output audit-log.json
```

---

## Troubleshooting

### Common Issues

#### Evidence Import Fails

```
Error: Signature verification failed
```

**Solution:**
1. Verify GPG key is imported
2. Check bundle wasn't modified during transfer
3. Re-export evidence on connected system

```bash
# Check imported keys
gpg --list-keys

# Import key if missing
gpg --import /mnt/transfer/keys/attestful-signing.asc
```

#### Database Migration Errors

```
Error: Migration xyz failed
```

**Solution:**
1. Restore from backup
2. Check migration compatibility
3. Contact support with error details

```bash
attestful backup restore --input /var/attestful/backups/latest.tar.gz
attestful db status
```

#### Missing OSCAL Catalog

```
Error: Catalog 'nist-800-53-rev5' not found
```

**Solution:**
1. Verify OSCAL content was installed
2. Check catalog directory configuration

```bash
ls /var/attestful/data/oscal/catalogs/
attestful oscal catalog list
```

### Diagnostic Commands

```bash
# Full system check
attestful diagnose

# Check database
attestful db status

# Verify OSCAL content
attestful oscal validate-all

# Check storage
attestful storage status

# Review logs
journalctl -u attestful --since "1 hour ago"
```

### Log Locations

| Log | Location |
|-----|----------|
| Application | /var/log/attestful/attestful.log |
| Audit | /var/log/attestful/audit.log |
| Database | /var/log/postgresql/postgresql-*.log |

---

## Security Considerations

### Transfer Media Security

1. **Use write-once media** (optical discs) for updates
2. **Encrypt sensitive exports** before transfer
3. **Maintain chain of custody** documentation
4. **Sanitize media** after use

### Key Management

1. Store signing keys on HSM or secure token
2. Rotate keys according to security policy
3. Maintain offline key backup

### Audit Trail

1. All imports are logged with source and verification status
2. All exports include manifest with timestamps
3. Maintain transfer logs for compliance

### Incident Response

1. **Compromised Media:**
   - Do not import
   - Quarantine media
   - Investigate source

2. **Failed Verification:**
   - Re-export from source
   - Check key validity
   - Review transfer process
