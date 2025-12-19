# Security Hardening Guide

This document provides comprehensive security hardening procedures for Attestful deployments, covering system security, network security, access control, and audit logging.

## Table of Contents

- [Overview](#overview)
- [System Security](#system-security)
- [Network Security](#network-security)
- [Access Control](#access-control)
- [Credential Management](#credential-management)
- [Encryption](#encryption)
- [Audit Logging](#audit-logging)
- [Container Security](#container-security)
- [Kubernetes Security](#kubernetes-security)
- [Compliance Considerations](#compliance-considerations)
- [Security Checklist](#security-checklist)

## Overview

### Security Model

Attestful follows a defense-in-depth approach:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NETWORK PERIMETER                                  │
│                    (Firewall, WAF, DDoS Protection)                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRANSPORT LAYER                                    │
│                         (TLS 1.3, mTLS)                                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                           APPLICATION LAYER                                  │
│            (Authentication, Authorization, Input Validation)                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
┌─────────────────────────────────────────────────────────────────────────────┐
│                              DATA LAYER                                      │
│              (Encryption at Rest, Access Controls)                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | Authentication, RBAC, MFA |
| Data breach | Encryption, access controls |
| Man-in-the-middle | TLS, certificate pinning |
| Injection attacks | Input validation, parameterized queries |
| Credential theft | Encryption, secure storage, rotation |
| Insider threats | Audit logging, least privilege |

---

## System Security

### Operating System Hardening

#### Disable Unnecessary Services

```bash
# Disable unused services
sudo systemctl disable --now cups bluetooth avahi-daemon

# Remove unnecessary packages
sudo apt-get autoremove --purge
```

#### Configure Firewall

```bash
# UFW configuration
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (restricted)
sudo ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTPS
sudo ufw allow 443/tcp

# Allow Attestful API (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 8000

sudo ufw enable
```

#### Kernel Hardening

```bash
# /etc/sysctl.d/99-attestful-hardening.conf

# Network security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1

# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
```

Apply changes:

```bash
sudo sysctl -p /etc/sysctl.d/99-attestful-hardening.conf
```

#### File System Security

```bash
# Secure mount options in /etc/fstab
/dev/sda1  /var/attestful  ext4  nodev,nosuid,noexec  0  2

# Set proper permissions
sudo chmod 750 /var/attestful
sudo chmod 600 /etc/attestful/config.yaml
sudo chmod 700 /var/attestful/keys

# Set ownership
sudo chown -R attestful:attestful /var/attestful
sudo chown root:attestful /etc/attestful
```

### Service Account

```bash
# Create dedicated service account
sudo useradd -r -s /usr/sbin/nologin -d /opt/attestful attestful

# Set account restrictions
sudo usermod -L attestful  # Lock password
sudo chage -E 0 attestful  # No password aging
```

### Systemd Hardening

```ini
# /etc/systemd/system/attestful.service
[Service]
# Run as non-root
User=attestful
Group=attestful

# Restrict capabilities
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# File system restrictions
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes

# Read-write paths
ReadWritePaths=/var/attestful /var/log/attestful

# Network restrictions (if not needed)
# PrivateNetwork=yes

# Memory restrictions
MemoryDenyWriteExecute=yes

# System call filtering
SystemCallFilter=@system-service
SystemCallArchitectures=native
```

---

## Network Security

### TLS Configuration

#### Generate Certificates

```bash
# Generate CA (for internal use)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=Attestful CA"

# Generate server certificate
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr \
  -subj "/CN=attestful.example.com"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt

# Set permissions
chmod 600 server.key
chown attestful:attestful server.key server.crt
```

#### Nginx TLS Configuration

```nginx
# /etc/nginx/conf.d/attestful-ssl.conf

ssl_certificate /etc/ssl/certs/attestful.crt;
ssl_certificate_key /etc/ssl/private/attestful.key;

# Modern TLS configuration
ssl_protocols TLSv1.3 TLSv1.2;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/ssl/certs/ca-chain.crt;

# Session configuration
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;

# DH parameters
ssl_dhparam /etc/ssl/certs/dhparam.pem;
```

Generate DH parameters:

```bash
openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096
```

### Mutual TLS (mTLS)

For API authentication:

```nginx
# Client certificate authentication
ssl_client_certificate /etc/ssl/certs/client-ca.crt;
ssl_verify_client optional;

location /api/ {
    if ($ssl_client_verify != SUCCESS) {
        return 403;
    }
    proxy_pass http://attestful_api;
}
```

### Rate Limiting

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=100r/m;
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;

# Apply to endpoints
location /api/v1/auth {
    limit_req zone=auth_limit burst=5 nodelay;
    proxy_pass http://attestful_api;
}

location /api/ {
    limit_req zone=api_limit burst=50 nodelay;
    proxy_pass http://attestful_api;
}
```

### Security Headers

```nginx
# Security headers
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

---

## Access Control

### Role-Based Access Control (RBAC)

```yaml
# config.yaml - RBAC configuration
security:
  rbac:
    enabled: true
    default_role: viewer

roles:
  admin:
    description: Full system access
    permissions:
      - "*"

  analyst:
    description: Run scans and view results
    permissions:
      - "scan:*"
      - "collect:*"
      - "report:read"
      - "evidence:read"
      - "framework:read"

  viewer:
    description: Read-only access
    permissions:
      - "scan:read"
      - "report:read"
      - "evidence:read"
      - "framework:read"

  operator:
    description: Manage system operations
    permissions:
      - "scan:*"
      - "collect:*"
      - "config:read"
      - "backup:*"
```

### User Management

```bash
# Create user with role
attestful user create --email analyst@example.com --role analyst

# Update user role
attestful user update --email analyst@example.com --role admin

# Disable user
attestful user disable --email analyst@example.com

# List users
attestful user list
```

### API Key Management

```bash
# Create API key with limited scope
attestful api-key create \
  --name "CI/CD Pipeline" \
  --role analyst \
  --expires-in 90d \
  --allowed-ips "10.0.0.0/8"

# Rotate API key
attestful api-key rotate --name "CI/CD Pipeline"

# Revoke API key
attestful api-key revoke --name "CI/CD Pipeline"
```

### Multi-Factor Authentication

```yaml
# config.yaml - MFA configuration
security:
  mfa:
    enabled: true
    required_for_roles:
      - admin
      - operator
    methods:
      - totp
      - webauthn
```

---

## Credential Management

### Encryption at Rest

```yaml
# config.yaml - Credential encryption
security:
  credential_encryption: true
  encryption_algorithm: AES-256-GCM
  key_derivation: PBKDF2
  key_iterations: 100000

  # Key storage options
  key_storage: file  # or 'hsm', 'vault'
  key_path: /var/attestful/keys/master.key
```

### External Secret Managers

#### AWS Secrets Manager

```yaml
# config.yaml
credentials:
  backend: aws_secrets_manager
  aws:
    region: us-east-1
    secrets_prefix: "attestful/"
```

```bash
# Store platform credentials
aws secretsmanager create-secret \
  --name attestful/okta \
  --secret-string '{"api_token": "xxx", "domain": "company.okta.com"}'
```

#### HashiCorp Vault

```yaml
# config.yaml
credentials:
  backend: vault
  vault:
    address: https://vault.example.com:8200
    auth_method: kubernetes  # or 'token', 'approle'
    secrets_path: secret/data/attestful
```

#### 1Password

```yaml
# config.yaml
credentials:
  backend: onepassword
  onepassword:
    vault: "Production"
    connect_host: http://op-connect:8080
    connect_token_file: /var/attestful/secrets/op-token
```

### Credential Rotation

```bash
# Rotate all credentials
attestful credentials rotate --all

# Rotate specific platform
attestful credentials rotate --platform okta

# Check credential age
attestful credentials check-age
```

### Secure Credential Handling

```python
# Never log credentials
import logging
logging.getLogger("attestful.collectors").addFilter(
    lambda record: not any(
        secret in str(record.msg)
        for secret in ["api_token", "password", "secret"]
    )
)

# Mask credentials in error messages
class SafeConfig:
    def __repr__(self):
        return f"Config(domain={self.domain}, api_token=***)"
```

---

## Encryption

### Data at Rest

#### Database Encryption

```yaml
# PostgreSQL with TDE (Transparent Data Encryption)
database:
  type: postgresql
  url: postgresql://user:pass@localhost/attestful
  ssl_mode: verify-full
  ssl_cert: /etc/ssl/certs/postgres-client.crt
  ssl_key: /etc/ssl/private/postgres-client.key
```

#### Evidence Encryption

```yaml
# config.yaml
storage:
  encryption:
    enabled: true
    algorithm: AES-256-GCM
    key_provider: vault  # or 'file', 'kms'
```

### Data in Transit

All network communication uses TLS 1.3:

```yaml
# config.yaml
api:
  tls:
    enabled: true
    cert_file: /etc/ssl/certs/attestful.crt
    key_file: /etc/ssl/private/attestful.key
    min_version: "1.3"
```

### Key Management

```bash
# Generate new encryption key
attestful keys generate --type master --output /var/attestful/keys/

# Rotate encryption keys
attestful keys rotate

# Export key backup (encrypted)
attestful keys export --encrypt --output /var/attestful/backups/keys.enc
```

---

## Audit Logging

### Configuration

```yaml
# config.yaml
security:
  audit_logging: true
  audit_file: /var/log/attestful/audit.log
  audit_format: json

  # What to log
  audit_events:
    - authentication
    - authorization
    - configuration_change
    - scan_execution
    - evidence_access
    - report_generation
    - user_management
    - credential_access

  # Integrity protection
  audit_signing: true
  audit_chain: true  # Hash chain for tamper detection
```

### Audit Log Format

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "event_id": "evt_abc123",
  "event_type": "authentication",
  "action": "login_success",
  "actor": {
    "user_id": "usr_xyz789",
    "email": "analyst@example.com",
    "ip_address": "10.0.1.50",
    "user_agent": "Mozilla/5.0..."
  },
  "resource": {
    "type": "session",
    "id": "sess_def456"
  },
  "metadata": {
    "mfa_used": true,
    "auth_method": "totp"
  },
  "chain_hash": "sha256:abc123...",
  "signature": "..."
}
```

### Log Rotation

```bash
# /etc/logrotate.d/attestful
/var/log/attestful/*.log {
    daily
    rotate 365
    compress
    delaycompress
    missingok
    notifempty
    create 0640 attestful attestful
    postrotate
        systemctl reload attestful
    endscript
}
```

### Log Forwarding

```yaml
# config.yaml - Forward to SIEM
logging:
  siem:
    enabled: true
    type: syslog
    host: siem.example.com
    port: 514
    protocol: tcp
    format: cef
```

### Audit Log Review

```bash
# Search audit logs
attestful audit search --event-type authentication --since "7 days ago"

# Verify audit log integrity
attestful audit verify --file /var/log/attestful/audit.log

# Export for compliance
attestful audit export --since "1 month ago" --format csv --output audit-report.csv
```

---

## Container Security

### Docker Security

#### Secure Dockerfile

```dockerfile
# Use minimal base image
FROM python:3.11-slim-bookworm AS base

# Run as non-root
RUN useradd -r -s /bin/false attestful
USER attestful

# No secrets in image
# Use runtime secrets mounting

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD attestful health || exit 1

# Read-only root filesystem
# Mount /tmp and /var/attestful as writable volumes
```

#### Docker Compose Security

```yaml
version: '3.8'
services:
  attestful:
    image: attestful/attestful:1.0.0
    user: "1000:1000"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:noexec,nosuid,size=100M
    volumes:
      - data:/var/attestful:rw
    secrets:
      - db_password
      - api_key
```

#### Container Scanning

```bash
# Scan image with Trivy
trivy image attestful/attestful:1.0.0

# Scan with Snyk
snyk container test attestful/attestful:1.0.0
```

---

## Kubernetes Security

### Pod Security

```yaml
# pod-security.yaml
apiVersion: v1
kind: Pod
metadata:
  name: attestful
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: attestful
      image: attestful/attestful:1.0.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "2"
          memory: "4Gi"
        requests:
          cpu: "500m"
          memory: "1Gi"
```

### Network Policies

```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: attestful-network-policy
  namespace: attestful
spec:
  podSelector:
    matchLabels:
      app: attestful
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress
        - podSelector:
            matchLabels:
              app: nginx
      ports:
        - protocol: TCP
          port: 8000
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    # Allow outbound to cloud APIs
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
```

### Secrets Management

```yaml
# Use external secrets operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: attestful-secrets
  namespace: attestful
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: attestful-secrets
  data:
    - secretKey: database-url
      remoteRef:
        key: attestful/database
        property: url
```

---

## Compliance Considerations

### SOC 2 Requirements

| Control | Implementation |
|---------|----------------|
| CC6.1 | RBAC, MFA, access logging |
| CC6.6 | TLS 1.3, encryption at rest |
| CC6.7 | Rate limiting, input validation |
| CC7.2 | Audit logging, monitoring |

### FedRAMP Requirements

| Control | Implementation |
|---------|----------------|
| AC-2 | User management, RBAC |
| AU-2 | Comprehensive audit logging |
| SC-8 | TLS, mTLS |
| SC-28 | AES-256 encryption at rest |

### HIPAA Requirements

| Requirement | Implementation |
|-------------|----------------|
| Access controls | RBAC, MFA |
| Audit controls | Immutable audit logs |
| Transmission security | TLS 1.3 |
| Encryption | AES-256-GCM |

---

## Security Checklist

### Pre-Production Checklist

- [ ] Operating system hardened
- [ ] Firewall configured
- [ ] TLS 1.3 enabled
- [ ] Security headers configured
- [ ] RBAC enabled
- [ ] MFA required for privileged users
- [ ] Credentials encrypted
- [ ] Audit logging enabled
- [ ] Log forwarding configured
- [ ] Backup encryption enabled
- [ ] Container security applied
- [ ] Network policies in place
- [ ] Secrets management configured
- [ ] Security scanning integrated

### Regular Security Tasks

#### Daily
- [ ] Review authentication failures
- [ ] Check for security alerts

#### Weekly
- [ ] Review audit logs
- [ ] Check credential expiration
- [ ] Review access patterns

#### Monthly
- [ ] Rotate API keys
- [ ] Review user access
- [ ] Security patch review

#### Quarterly
- [ ] Penetration testing
- [ ] Credential rotation
- [ ] Security configuration review
- [ ] Disaster recovery test

### Security Verification

```bash
# Run security checks
attestful security audit

# Check configuration
attestful security check-config

# Verify encryption
attestful security verify-encryption

# Test authentication
attestful security test-auth

# Generate security report
attestful security report --output security-report.html
```
