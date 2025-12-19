# Backup and Recovery Procedures

This document provides comprehensive procedures for backing up and recovering Attestful data, configurations, and evidence.

## Table of Contents

- [Overview](#overview)
- [Backup Strategy](#backup-strategy)
- [Database Backup](#database-backup)
- [Evidence Backup](#evidence-backup)
- [Configuration Backup](#configuration-backup)
- [Full System Backup](#full-system-backup)
- [Recovery Procedures](#recovery-procedures)
- [Disaster Recovery](#disaster-recovery)
- [Testing and Validation](#testing-and-validation)
- [Automation](#automation)

## Overview

### What to Back Up

| Component | Priority | Frequency | Method |
|-----------|----------|-----------|--------|
| Database | Critical | Daily | pg_dump / SQLite copy |
| Evidence Files | Critical | Daily | File system / S3 sync |
| Configuration | High | On change | File copy |
| OSCAL Content | Medium | On update | File copy |
| Encryption Keys | Critical | On creation | Secure offline |
| Audit Logs | High | Daily | Log rotation / archive |

### Backup Locations

- **Local**: Fast recovery, limited protection
- **Remote**: Disaster protection, slower recovery
- **Offline**: Maximum protection, manual process

---

## Backup Strategy

### Retention Policy

| Backup Type | Retention |
|-------------|-----------|
| Daily | 30 days |
| Weekly | 12 weeks |
| Monthly | 12 months |
| Annual | 7 years (compliance) |

### Backup Schedule

| Time | Action |
|------|--------|
| 02:00 Daily | Incremental database backup |
| 03:00 Daily | Evidence sync |
| 04:00 Weekly (Sunday) | Full database backup |
| 05:00 Monthly (1st) | Full system backup |

---

## Database Backup

### PostgreSQL Backup

#### Full Backup

```bash
#!/bin/bash
# backup-database-full.sh

BACKUP_DIR="/var/attestful/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/attestful_full_${DATE}.sql.gz"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

# Full database dump with compression
pg_dump -h localhost -U attestful -d attestful \
  --format=custom \
  --compress=9 \
  --file="${BACKUP_FILE}"

# Verify backup
pg_restore --list "${BACKUP_FILE}" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Backup successful: ${BACKUP_FILE}"
    # Generate checksum
    sha256sum "${BACKUP_FILE}" > "${BACKUP_FILE}.sha256"
else
    echo "Backup verification failed!"
    exit 1
fi

# Cleanup old backups (keep 30 days)
find "${BACKUP_DIR}" -name "attestful_full_*.sql.gz" -mtime +30 -delete
```

#### Incremental Backup (WAL Archiving)

1. **Enable WAL archiving in postgresql.conf:**

```
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/attestful/backups/wal/%f'
```

2. **Create base backup:**

```bash
pg_basebackup -h localhost -U attestful -D /var/attestful/backups/base \
  --format=tar --gzip --checkpoint=fast
```

3. **Archive WAL files:**

```bash
#!/bin/bash
# archive-wal.sh
WAL_DIR="/var/attestful/backups/wal"
ARCHIVE_DIR="/var/attestful/backups/wal-archive"

# Move completed WAL files to archive
find "${WAL_DIR}" -name "*.ready" -exec mv {} "${ARCHIVE_DIR}/" \;
```

### SQLite Backup

```bash
#!/bin/bash
# backup-sqlite.sh

DB_PATH="/var/attestful/attestful.db"
BACKUP_DIR="/var/attestful/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/attestful_${DATE}.db"

mkdir -p "${BACKUP_DIR}"

# Use SQLite backup API (safe for concurrent access)
sqlite3 "${DB_PATH}" ".backup '${BACKUP_FILE}'"

# Compress
gzip "${BACKUP_FILE}"

# Verify
sqlite3 "${BACKUP_FILE}.gz" "PRAGMA integrity_check;" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Backup successful: ${BACKUP_FILE}.gz"
    sha256sum "${BACKUP_FILE}.gz" > "${BACKUP_FILE}.gz.sha256"
else
    echo "Backup verification failed!"
    exit 1
fi
```

### Using Attestful CLI

```bash
# Create database backup
attestful backup database --output /var/attestful/backups/db-backup.sql.gz

# Verify backup
attestful backup verify --input /var/attestful/backups/db-backup.sql.gz
```

---

## Evidence Backup

### Local Evidence Backup

```bash
#!/bin/bash
# backup-evidence.sh

EVIDENCE_DIR="/var/attestful/evidence"
BACKUP_DIR="/var/attestful/backups/evidence"
DATE=$(date +%Y%m%d)

mkdir -p "${BACKUP_DIR}"

# Create tarball with integrity file
cd "${EVIDENCE_DIR}"
tar -czvf "${BACKUP_DIR}/evidence_${DATE}.tar.gz" \
  --newer-mtime="1 day ago" \
  .

# Generate manifest
find . -type f -newer-mtime "1 day ago" -exec sha256sum {} \; \
  > "${BACKUP_DIR}/evidence_${DATE}.manifest"

echo "Evidence backup complete: ${BACKUP_DIR}/evidence_${DATE}.tar.gz"
```

### S3 Sync

```bash
#!/bin/bash
# sync-evidence-s3.sh

EVIDENCE_DIR="/var/attestful/evidence"
S3_BUCKET="s3://attestful-backups/evidence"

# Sync to S3 with server-side encryption
aws s3 sync "${EVIDENCE_DIR}" "${S3_BUCKET}" \
  --sse AES256 \
  --exclude "*.tmp" \
  --delete

# Verify sync
aws s3 ls "${S3_BUCKET}" --recursive | wc -l
```

### Evidence Integrity Verification

```bash
#!/bin/bash
# verify-evidence.sh

EVIDENCE_DIR="/var/attestful/evidence"
MANIFEST="${EVIDENCE_DIR}/.integrity-manifest"

# Generate current checksums
find "${EVIDENCE_DIR}" -type f -name "*.json.gz" -exec sha256sum {} \; \
  | sort > /tmp/current-manifest

# Compare with stored manifest
if [ -f "${MANIFEST}" ]; then
    diff "${MANIFEST}" /tmp/current-manifest
    if [ $? -eq 0 ]; then
        echo "Evidence integrity verified"
    else
        echo "WARNING: Evidence integrity mismatch!"
        exit 1
    fi
fi
```

### Using Attestful CLI

```bash
# Backup evidence
attestful backup evidence --output /var/attestful/backups/evidence-backup.tar.gz

# Backup specific time range
attestful backup evidence \
  --since 2024-01-01 \
  --until 2024-01-31 \
  --output /var/attestful/backups/evidence-2024-01.tar.gz
```

---

## Configuration Backup

### Configuration Files

```bash
#!/bin/bash
# backup-config.sh

CONFIG_DIR="/etc/attestful"
BACKUP_DIR="/var/attestful/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "${BACKUP_DIR}"

# Backup configuration (excluding secrets)
tar -czvf "${BACKUP_DIR}/config_${DATE}.tar.gz" \
  --exclude="*.key" \
  --exclude="*secret*" \
  "${CONFIG_DIR}"

# Backup secrets separately (encrypted)
tar -cvf - "${CONFIG_DIR}"/*.key "${CONFIG_DIR}"/*secret* 2>/dev/null | \
  gpg --encrypt --recipient backup@example.com \
  > "${BACKUP_DIR}/secrets_${DATE}.tar.gpg"

echo "Configuration backup complete"
```

### Encryption Keys

```bash
#!/bin/bash
# backup-keys.sh

KEY_DIR="/var/attestful/keys"
BACKUP_DIR="/var/attestful/backups/keys"

# Keys should be backed up offline and encrypted
tar -cvf - "${KEY_DIR}" | \
  gpg --symmetric --cipher-algo AES256 \
  > "${BACKUP_DIR}/keys_$(date +%Y%m%d).tar.gpg"

echo "Keys backed up. Store offline securely!"
echo "IMPORTANT: Test key restoration before removing originals"
```

### Using Attestful CLI

```bash
# Export configuration (sanitized)
attestful configure export --output /var/attestful/backups/config-export.yaml

# Export with secrets (encrypted)
attestful configure export \
  --include-secrets \
  --encrypt \
  --output /var/attestful/backups/config-full.yaml.enc
```

---

## Full System Backup

### Complete Backup Script

```bash
#!/bin/bash
# full-backup.sh

set -e

BACKUP_BASE="/var/attestful/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_BASE}/full/${DATE}"

echo "Starting full backup: ${DATE}"

mkdir -p "${BACKUP_DIR}"

# 1. Stop services (optional - for consistency)
# systemctl stop attestful

# 2. Database backup
echo "Backing up database..."
pg_dump -h localhost -U attestful -d attestful \
  --format=custom --compress=9 \
  --file="${BACKUP_DIR}/database.dump"

# 3. Evidence backup
echo "Backing up evidence..."
tar -czvf "${BACKUP_DIR}/evidence.tar.gz" \
  /var/attestful/evidence

# 4. Configuration backup
echo "Backing up configuration..."
tar -czvf "${BACKUP_DIR}/config.tar.gz" \
  /etc/attestful \
  --exclude="*.key"

# 5. OSCAL content backup
echo "Backing up OSCAL content..."
tar -czvf "${BACKUP_DIR}/oscal.tar.gz" \
  /var/attestful/data/oscal

# 6. Keys backup (encrypted)
echo "Backing up keys..."
tar -cvf - /var/attestful/keys | \
  gpg --encrypt --recipient backup@example.com \
  > "${BACKUP_DIR}/keys.tar.gpg"

# 7. Restart services
# systemctl start attestful

# 8. Create manifest
echo "Creating manifest..."
cat > "${BACKUP_DIR}/MANIFEST.json" << EOF
{
  "date": "${DATE}",
  "type": "full",
  "components": {
    "database": "database.dump",
    "evidence": "evidence.tar.gz",
    "config": "config.tar.gz",
    "oscal": "oscal.tar.gz",
    "keys": "keys.tar.gpg"
  }
}
EOF

# 9. Generate checksums
echo "Generating checksums..."
cd "${BACKUP_DIR}"
sha256sum * > SHA256SUMS

# 10. Create final archive
echo "Creating final archive..."
cd "${BACKUP_BASE}/full"
tar -cvf "${DATE}.tar" "${DATE}"
gzip "${DATE}.tar"

# Cleanup temporary directory
rm -rf "${DATE}"

echo "Full backup complete: ${BACKUP_BASE}/full/${DATE}.tar.gz"
```

### Using Attestful CLI

```bash
# Full system backup
attestful backup create \
  --type full \
  --output /var/attestful/backups/full-backup.tar.gz

# List available backups
attestful backup list

# Show backup details
attestful backup info --input /var/attestful/backups/full-backup.tar.gz
```

---

## Recovery Procedures

### Database Recovery

#### PostgreSQL Recovery

```bash
#!/bin/bash
# restore-database.sh

BACKUP_FILE=$1

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: restore-database.sh <backup-file>"
    exit 1
fi

# Verify backup
pg_restore --list "${BACKUP_FILE}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Invalid backup file!"
    exit 1
fi

# Stop application
systemctl stop attestful

# Drop and recreate database
sudo -u postgres psql << EOF
DROP DATABASE IF EXISTS attestful;
CREATE DATABASE attestful OWNER attestful;
EOF

# Restore
pg_restore -h localhost -U attestful -d attestful \
  --clean --if-exists \
  "${BACKUP_FILE}"

# Restart application
systemctl start attestful

echo "Database restored successfully"
```

#### Point-in-Time Recovery (PITR)

```bash
#!/bin/bash
# pitr-recovery.sh

RECOVERY_TARGET=$1  # e.g., "2024-01-15 14:30:00"

# Stop PostgreSQL
systemctl stop postgresql

# Remove current data
rm -rf /var/lib/postgresql/14/main/*

# Restore base backup
tar -xzf /var/attestful/backups/base/base.tar.gz \
  -C /var/lib/postgresql/14/main

# Create recovery configuration
cat > /var/lib/postgresql/14/main/recovery.signal << EOF
EOF

cat >> /var/lib/postgresql/14/main/postgresql.auto.conf << EOF
restore_command = 'cp /var/attestful/backups/wal-archive/%f %p'
recovery_target_time = '${RECOVERY_TARGET}'
recovery_target_action = 'promote'
EOF

# Start PostgreSQL (recovery mode)
systemctl start postgresql

echo "PITR recovery initiated. Target: ${RECOVERY_TARGET}"
```

### Evidence Recovery

```bash
#!/bin/bash
# restore-evidence.sh

BACKUP_FILE=$1
TARGET_DIR="/var/attestful/evidence"

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: restore-evidence.sh <backup-file>"
    exit 1
fi

# Verify checksum if available
if [ -f "${BACKUP_FILE}.sha256" ]; then
    sha256sum -c "${BACKUP_FILE}.sha256"
    if [ $? -ne 0 ]; then
        echo "Checksum verification failed!"
        exit 1
    fi
fi

# Create target directory
mkdir -p "${TARGET_DIR}"

# Extract
tar -xzvf "${BACKUP_FILE}" -C "${TARGET_DIR}"

# Verify integrity
attestful storage verify

echo "Evidence restored successfully"
```

### Configuration Recovery

```bash
#!/bin/bash
# restore-config.sh

CONFIG_BACKUP=$1
SECRETS_BACKUP=$2

# Restore configuration
tar -xzvf "${CONFIG_BACKUP}" -C /

# Restore secrets (requires GPG key)
gpg --decrypt "${SECRETS_BACKUP}" | tar -xvf - -C /

# Validate configuration
attestful configure validate

echo "Configuration restored successfully"
```

### Full System Recovery

```bash
#!/bin/bash
# full-restore.sh

BACKUP_FILE=$1

if [ -z "${BACKUP_FILE}" ]; then
    echo "Usage: full-restore.sh <backup-archive>"
    exit 1
fi

echo "Starting full system restore..."

# Extract backup archive
RESTORE_DIR="/tmp/attestful-restore-$$"
mkdir -p "${RESTORE_DIR}"
tar -xzf "${BACKUP_FILE}" -C "${RESTORE_DIR}"
cd "${RESTORE_DIR}"/*

# Verify checksums
sha256sum -c SHA256SUMS
if [ $? -ne 0 ]; then
    echo "Checksum verification failed!"
    exit 1
fi

# Stop services
systemctl stop attestful

# 1. Restore database
echo "Restoring database..."
pg_restore -h localhost -U attestful -d attestful \
  --clean --if-exists \
  database.dump

# 2. Restore evidence
echo "Restoring evidence..."
tar -xzf evidence.tar.gz -C /

# 3. Restore configuration
echo "Restoring configuration..."
tar -xzf config.tar.gz -C /

# 4. Restore OSCAL content
echo "Restoring OSCAL content..."
tar -xzf oscal.tar.gz -C /

# 5. Restore keys (requires GPG key)
echo "Restoring keys..."
gpg --decrypt keys.tar.gpg | tar -xvf - -C /

# Cleanup
rm -rf "${RESTORE_DIR}"

# Start services
systemctl start attestful

# Verify
attestful health

echo "Full system restore complete"
```

### Using Attestful CLI

```bash
# Restore from backup
attestful backup restore --input /var/attestful/backups/full-backup.tar.gz

# Restore specific components
attestful backup restore \
  --input /var/attestful/backups/full-backup.tar.gz \
  --components database,evidence

# Dry run (validate only)
attestful backup restore \
  --input /var/attestful/backups/full-backup.tar.gz \
  --dry-run
```

---

## Disaster Recovery

### Recovery Time Objectives (RTO)

| Scenario | Target RTO | Method |
|----------|------------|--------|
| Database corruption | 1 hour | Local backup restore |
| Server failure | 4 hours | Remote backup restore |
| Data center failure | 24 hours | Cross-region restore |

### Recovery Point Objectives (RPO)

| Data Type | Target RPO | Backup Frequency |
|-----------|------------|------------------|
| Database | 1 hour | Hourly WAL archive |
| Evidence | 24 hours | Daily sync |
| Configuration | 0 (on change) | Immediate |

### Disaster Recovery Runbook

1. **Assess the Situation**
   - Identify scope of failure
   - Determine data loss window
   - Select appropriate backup

2. **Prepare Recovery Environment**
   - Provision new server if needed
   - Install base system
   - Configure network

3. **Execute Recovery**
   ```bash
   # Download backup from remote storage
   aws s3 cp s3://attestful-dr-backups/latest.tar.gz /tmp/

   # Run full restore
   attestful backup restore --input /tmp/latest.tar.gz
   ```

4. **Validate Recovery**
   ```bash
   # Check system health
   attestful health

   # Verify data integrity
   attestful storage verify
   attestful db check
   ```

5. **Resume Operations**
   - Update DNS if needed
   - Notify stakeholders
   - Document incident

---

## Testing and Validation

### Backup Testing

```bash
#!/bin/bash
# test-backup.sh

BACKUP_FILE=$1
TEST_DIR="/tmp/backup-test-$$"

echo "Testing backup: ${BACKUP_FILE}"

# Create isolated test environment
mkdir -p "${TEST_DIR}"

# For database backups
if [[ "${BACKUP_FILE}" == *.dump ]]; then
    # Create test database
    createdb -h localhost -U postgres attestful_test

    # Restore
    pg_restore -h localhost -U postgres -d attestful_test "${BACKUP_FILE}"

    # Verify
    psql -h localhost -U postgres -d attestful_test \
      -c "SELECT COUNT(*) FROM attestful_scans;"

    # Cleanup
    dropdb -h localhost -U postgres attestful_test
fi

# For evidence backups
if [[ "${BACKUP_FILE}" == *.tar.gz ]]; then
    tar -tzf "${BACKUP_FILE}" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Archive integrity: OK"
    else
        echo "Archive integrity: FAILED"
        exit 1
    fi
fi

rm -rf "${TEST_DIR}"
echo "Backup test complete"
```

### Monthly DR Test

```bash
#!/bin/bash
# monthly-dr-test.sh

echo "Starting monthly DR test..."

# 1. Create test environment
docker-compose -f docker-compose-dr-test.yml up -d

# 2. Download latest backup
aws s3 cp s3://attestful-backups/latest/full.tar.gz /tmp/

# 3. Restore in test environment
docker exec attestful-dr-test attestful backup restore \
  --input /tmp/full.tar.gz

# 4. Run validation tests
docker exec attestful-dr-test attestful health
docker exec attestful-dr-test attestful db check
docker exec attestful-dr-test attestful scan aws --dry-run

# 5. Document results
echo "DR test completed at $(date)" >> /var/log/dr-tests.log

# 6. Cleanup
docker-compose -f docker-compose-dr-test.yml down -v
```

---

## Automation

### Cron Configuration

```cron
# /etc/cron.d/attestful-backup

# Daily incremental backup at 2 AM
0 2 * * * attestful /opt/attestful/scripts/backup-incremental.sh

# Weekly full backup on Sunday at 3 AM
0 3 * * 0 attestful /opt/attestful/scripts/backup-full.sh

# Monthly offsite sync on 1st at 4 AM
0 4 1 * * attestful /opt/attestful/scripts/sync-offsite.sh

# Daily backup verification at 5 AM
0 5 * * * attestful /opt/attestful/scripts/verify-backups.sh
```

### Systemd Timer

```ini
# /etc/systemd/system/attestful-backup.timer
[Unit]
Description=Daily Attestful Backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target

# /etc/systemd/system/attestful-backup.service
[Unit]
Description=Attestful Backup Service

[Service]
Type=oneshot
User=attestful
ExecStart=/opt/attestful/scripts/backup-full.sh
```

### Monitoring and Alerting

```bash
#!/bin/bash
# check-backup-age.sh

MAX_AGE_HOURS=25
BACKUP_DIR="/var/attestful/backups"

# Find most recent backup
LATEST=$(find "${BACKUP_DIR}" -name "*.tar.gz" -type f -printf '%T+ %p\n' | sort -r | head -1)
LATEST_FILE=$(echo "${LATEST}" | cut -d' ' -f2)
LATEST_TIME=$(echo "${LATEST}" | cut -d' ' -f1)

# Calculate age in hours
AGE_SECONDS=$(( $(date +%s) - $(date -d "${LATEST_TIME}" +%s) ))
AGE_HOURS=$(( AGE_SECONDS / 3600 ))

if [ ${AGE_HOURS} -gt ${MAX_AGE_HOURS} ]; then
    echo "CRITICAL: Backup is ${AGE_HOURS} hours old!"
    # Send alert
    curl -X POST "https://alerts.example.com/webhook" \
      -d "{\"message\": \"Backup is ${AGE_HOURS} hours old\"}"
    exit 2
else
    echo "OK: Latest backup is ${AGE_HOURS} hours old"
    exit 0
fi
```
