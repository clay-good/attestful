# Deployment Guide

This document provides comprehensive instructions for deploying Attestful in production environments.

## Table of Contents

- [System Requirements](#system-requirements)
- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Manual Installation](#manual-installation)
- [Database Setup](#database-setup)
- [Storage Configuration](#storage-configuration)
- [Reverse Proxy Setup](#reverse-proxy-setup)
- [High Availability](#high-availability)
- [Verification](#verification)
- [Monitoring](#monitoring)

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 2 cores |
| Memory | 4 GB RAM |
| Storage | 20 GB SSD |
| OS | Linux (Ubuntu 20.04+, RHEL 8+, Debian 11+) |
| Python | 3.11 or higher |

### Recommended Production Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 4+ cores |
| Memory | 8+ GB RAM |
| Storage | 100+ GB SSD (depends on evidence retention) |
| Database | PostgreSQL 14+ (external) |
| Network | 100 Mbps+ |

### Network Requirements

| Direction | Port | Purpose |
|-----------|------|---------|
| Outbound | 443 | Cloud provider APIs (AWS, Azure, GCP) |
| Outbound | 443 | SaaS platform APIs (Okta, GitHub, etc.) |
| Inbound | 8000 | API server (optional) |
| Inbound | 8050 | Dashboard (optional) |

---

## Deployment Options

| Option | Use Case | Complexity |
|--------|----------|------------|
| Docker Compose | Small teams, single server | Low |
| Kubernetes | Enterprise, high availability | Medium |
| Manual | Air-gapped, custom requirements | High |

---

## Docker Deployment

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

### Quick Start

1. **Create deployment directory:**

```bash
mkdir -p /opt/attestful
cd /opt/attestful
```

2. **Create docker-compose.yml:**

```yaml
version: '3.8'

services:
  attestful:
    image: attestful/attestful:latest
    container_name: attestful
    restart: unless-stopped
    ports:
      - "8000:8000"  # API
      - "8050:8050"  # Dashboard
    volumes:
      - ./data:/var/attestful
      - ./config:/etc/attestful
    environment:
      - ATTESTFUL_GENERAL_DATA_DIR=/var/attestful
      - ATTESTFUL_DATABASE_TYPE=postgresql
      - ATTESTFUL_DATABASE_URL=postgresql://attestful:password@postgres:5432/attestful
      - ATTESTFUL_API_ENABLED=true
      - ATTESTFUL_DASHBOARD_ENABLED=true
    depends_on:
      - postgres
    healthcheck:
      test: ["CMD", "attestful", "health"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: attestful-db
    restart: unless-stopped
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_USER=attestful
      - POSTGRES_PASSWORD=password  # Change in production!
      - POSTGRES_DB=attestful
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U attestful"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

3. **Create configuration file:**

```bash
mkdir -p config
cat > config/config.yaml << 'EOF'
general:
  data_dir: /var/attestful
  log_level: INFO

security:
  credential_encryption: true
  audit_logging: true

api:
  enabled: true
  host: 0.0.0.0
  port: 8000

dashboard:
  enabled: true
  host: 0.0.0.0
  port: 8050
EOF
```

4. **Start the services:**

```bash
docker-compose up -d
```

5. **Initialize the database:**

```bash
docker-compose exec attestful attestful configure init
```

6. **Verify deployment:**

```bash
docker-compose exec attestful attestful health
```

### Production Docker Configuration

For production deployments, use these additional settings:

```yaml
version: '3.8'

services:
  attestful:
    image: attestful/attestful:1.0.0  # Pin version
    restart: always
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"
    secrets:
      - db_password
      - jwt_secret
      - okta_api_token
    environment:
      - ATTESTFUL_DATABASE_URL=postgresql://attestful:${DB_PASSWORD}@postgres:5432/attestful
      - ATTESTFUL_API_JWT_SECRET_FILE=/run/secrets/jwt_secret

secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
  okta_api_token:
    file: ./secrets/okta_api_token.txt
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.25+
- Helm 3.0+
- kubectl configured

### Using Helm

1. **Add the Attestful Helm repository:**

```bash
helm repo add attestful https://clay-good.github.io/attestful
helm repo update
```

2. **Create values file:**

```yaml
# values.yaml
replicaCount: 2

image:
  repository: attestful/attestful
  tag: "1.0.0"
  pullPolicy: IfNotPresent

resources:
  limits:
    cpu: 2000m
    memory: 4Gi
  requests:
    cpu: 500m
    memory: 1Gi

persistence:
  enabled: true
  storageClass: standard
  size: 100Gi

postgresql:
  enabled: true
  auth:
    postgresPassword: changeme
    database: attestful

api:
  enabled: true
  service:
    type: ClusterIP
    port: 8000

dashboard:
  enabled: true
  service:
    type: ClusterIP
    port: 8050

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: attestful.example.com
      paths:
        - path: /api
          pathType: Prefix
          service: api
        - path: /
          pathType: Prefix
          service: dashboard
  tls:
    - secretName: attestful-tls
      hosts:
        - attestful.example.com

config:
  general:
    logLevel: INFO
  security:
    credentialEncryption: true
    auditLogging: true

secrets:
  create: true
  jwtSecret: ""  # Auto-generated if empty
  # Reference existing secrets for platform credentials
  platformSecrets:
    okta:
      existingSecret: okta-credentials
      apiTokenKey: api-token
```

3. **Install the chart:**

```bash
helm install attestful attestful/attestful \
  --namespace attestful \
  --create-namespace \
  --values values.yaml
```

4. **Verify installation:**

```bash
kubectl get pods -n attestful
kubectl logs -n attestful -l app=attestful
```

### Manual Kubernetes Manifests

For environments without Helm, use raw manifests:

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: attestful
---
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: attestful-config
  namespace: attestful
data:
  config.yaml: |
    general:
      data_dir: /var/attestful
      log_level: INFO
    api:
      enabled: true
      host: 0.0.0.0
      port: 8000
---
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: attestful-secrets
  namespace: attestful
type: Opaque
stringData:
  database-url: postgresql://user:pass@postgres:5432/attestful
  jwt-secret: your-jwt-secret
---
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: attestful
  namespace: attestful
spec:
  replicas: 2
  selector:
    matchLabels:
      app: attestful
  template:
    metadata:
      labels:
        app: attestful
    spec:
      containers:
        - name: attestful
          image: attestful/attestful:1.0.0
          ports:
            - containerPort: 8000
            - containerPort: 8050
          envFrom:
            - secretRef:
                name: attestful-secrets
          volumeMounts:
            - name: config
              mountPath: /etc/attestful
            - name: data
              mountPath: /var/attestful
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: 8000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            limits:
              cpu: "2"
              memory: 4Gi
            requests:
              cpu: "500m"
              memory: 1Gi
      volumes:
        - name: config
          configMap:
            name: attestful-config
        - name: data
          persistentVolumeClaim:
            claimName: attestful-data
---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: attestful
  namespace: attestful
spec:
  selector:
    app: attestful
  ports:
    - name: api
      port: 8000
      targetPort: 8000
    - name: dashboard
      port: 8050
      targetPort: 8050
```

---

## Manual Installation

### System Preparation

1. **Install system dependencies (Ubuntu/Debian):**

```bash
sudo apt-get update
sudo apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    postgresql-client \
    libpq-dev \
    build-essential \
    libffi-dev \
    libssl-dev
```

2. **Install system dependencies (RHEL/CentOS):**

```bash
sudo dnf install -y \
    python3.11 \
    python3.11-devel \
    postgresql \
    libpq-devel \
    gcc \
    libffi-devel \
    openssl-devel
```

3. **Create service user:**

```bash
sudo useradd -r -s /bin/false -d /opt/attestful attestful
sudo mkdir -p /opt/attestful /var/attestful /etc/attestful
sudo chown -R attestful:attestful /opt/attestful /var/attestful /etc/attestful
```

### Application Installation

1. **Create virtual environment:**

```bash
sudo -u attestful python3.11 -m venv /opt/attestful/venv
```

2. **Install Attestful:**

```bash
sudo -u attestful /opt/attestful/venv/bin/pip install attestful
```

3. **Create configuration:**

```bash
sudo cat > /etc/attestful/config.yaml << 'EOF'
general:
  data_dir: /var/attestful
  log_level: INFO

database:
  type: postgresql
  url: postgresql://attestful:password@localhost:5432/attestful

storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 365

security:
  credential_encryption: true
  audit_logging: true
  audit_file: /var/log/attestful/audit.log

logging:
  level: INFO
  file: /var/log/attestful/attestful.log
  max_size_mb: 100
  backup_count: 10
EOF

sudo chown attestful:attestful /etc/attestful/config.yaml
sudo chmod 600 /etc/attestful/config.yaml
```

4. **Create log directory:**

```bash
sudo mkdir -p /var/log/attestful
sudo chown attestful:attestful /var/log/attestful
```

5. **Initialize the application:**

```bash
sudo -u attestful /opt/attestful/venv/bin/attestful configure init
```

### Systemd Service

Create a systemd service file:

```bash
sudo cat > /etc/systemd/system/attestful.service << 'EOF'
[Unit]
Description=Attestful Compliance Platform
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=attestful
Group=attestful
WorkingDirectory=/opt/attestful
Environment=ATTESTFUL_CONFIG=/etc/attestful/config.yaml
ExecStart=/opt/attestful/venv/bin/attestful api serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/attestful /var/log/attestful

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable attestful
sudo systemctl start attestful
```

Check service status:

```bash
sudo systemctl status attestful
sudo journalctl -u attestful -f
```

---

## Database Setup

### PostgreSQL Setup

1. **Install PostgreSQL:**

```bash
# Ubuntu/Debian
sudo apt-get install -y postgresql postgresql-contrib

# RHEL/CentOS
sudo dnf install -y postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
```

2. **Configure PostgreSQL:**

```bash
sudo -u postgres psql << 'EOF'
CREATE USER attestful WITH PASSWORD 'secure-password-here';
CREATE DATABASE attestful OWNER attestful;
GRANT ALL PRIVILEGES ON DATABASE attestful TO attestful;
\q
EOF
```

3. **Configure authentication (pg_hba.conf):**

```
# Allow local connections
local   attestful   attestful                           scram-sha-256
# Allow network connections (adjust IP range)
host    attestful   attestful   10.0.0.0/8              scram-sha-256
```

4. **Configure PostgreSQL (postgresql.conf):**

```
# Performance tuning for Attestful
shared_buffers = 256MB
effective_cache_size = 768MB
maintenance_work_mem = 64MB
work_mem = 16MB
max_connections = 100
```

5. **Restart PostgreSQL:**

```bash
sudo systemctl restart postgresql
```

### Database Migrations

Run migrations after installation or upgrade:

```bash
attestful db migrate
```

---

## Storage Configuration

### Evidence Storage

Configure evidence storage for production:

```yaml
storage:
  evidence_dir: /var/attestful/evidence
  retention_days: 365
  compression: true
  hash_algorithm: sha256
```

### S3-Compatible Storage (Optional)

For large deployments, use S3-compatible storage:

```yaml
storage:
  type: s3
  bucket: attestful-evidence
  region: us-east-1
  endpoint: null  # Use default AWS endpoint
  # Or for MinIO/compatible:
  # endpoint: https://minio.example.com
  access_key: ${AWS_ACCESS_KEY_ID}
  secret_key: ${AWS_SECRET_ACCESS_KEY}
```

---

## Reverse Proxy Setup

### Nginx Configuration

```nginx
upstream attestful_api {
    server 127.0.0.1:8000;
}

upstream attestful_dashboard {
    server 127.0.0.1:8050;
}

server {
    listen 443 ssl http2;
    server_name attestful.example.com;

    ssl_certificate /etc/ssl/certs/attestful.crt;
    ssl_certificate_key /etc/ssl/private/attestful.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;

    # API
    location /api/ {
        proxy_pass http://attestful_api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for long-running scans
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }

    # Dashboard
    location / {
        proxy_pass http://attestful_dashboard;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name attestful.example.com;
    return 301 https://$server_name$request_uri;
}
```

---

## High Availability

### Multi-Node Deployment

For high availability, deploy multiple Attestful instances:

```yaml
# docker-compose-ha.yml
version: '3.8'

services:
  attestful-1:
    image: attestful/attestful:1.0.0
    environment:
      - ATTESTFUL_DATABASE_URL=postgresql://attestful:password@postgres:5432/attestful
      - ATTESTFUL_NODE_ID=node-1

  attestful-2:
    image: attestful/attestful:1.0.0
    environment:
      - ATTESTFUL_DATABASE_URL=postgresql://attestful:password@postgres:5432/attestful
      - ATTESTFUL_NODE_ID=node-2

  haproxy:
    image: haproxy:2.8
    ports:
      - "8000:8000"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro

  postgres:
    image: postgres:15-alpine
    # ... postgresql config
```

### HAProxy Configuration

```haproxy
frontend attestful_api
    bind *:8000
    default_backend attestful_servers

backend attestful_servers
    balance roundrobin
    option httpchk GET /api/v1/health
    http-check expect status 200
    server attestful-1 attestful-1:8000 check
    server attestful-2 attestful-2:8000 check
```

---

## Verification

### Post-Deployment Checks

1. **Health check:**

```bash
curl -s http://localhost:8000/api/v1/health | jq
```

2. **Database connection:**

```bash
attestful configure validate
```

3. **Platform connectivity:**

```bash
attestful configure test aws
attestful configure test okta
```

4. **Run test scan:**

```bash
attestful scan aws --dry-run
```

### Smoke Tests

```bash
# Check API endpoints
curl -s http://localhost:8000/api/v1/frameworks | jq '.data | length'

# Check dashboard
curl -s -o /dev/null -w "%{http_code}" http://localhost:8050/

# Verify database
attestful db status
```

---

## Monitoring

### Health Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/v1/health` | Basic health check |
| `/api/v1/health/ready` | Readiness probe |
| `/api/v1/health/live` | Liveness probe |

### Prometheus Metrics

Enable metrics endpoint:

```yaml
api:
  metrics_enabled: true
  metrics_path: /metrics
```

Key metrics:

| Metric | Description |
|--------|-------------|
| `attestful_scans_total` | Total scans by status |
| `attestful_scan_duration_seconds` | Scan duration histogram |
| `attestful_collections_total` | Total collections by platform |
| `attestful_api_requests_total` | API requests by endpoint |
| `attestful_db_connections` | Active database connections |

### Logging

Configure structured logging for log aggregation:

```yaml
logging:
  level: INFO
  format: json
  file: /var/log/attestful/attestful.log
```

### Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: attestful
    rules:
      - alert: AttestfulDown
        expr: up{job="attestful"} == 0
        for: 5m
        labels:
          severity: critical

      - alert: AttestfulScansFailing
        expr: rate(attestful_scans_total{status="failed"}[1h]) > 0.5
        for: 15m
        labels:
          severity: warning

      - alert: AttestfulHighLatency
        expr: histogram_quantile(0.95, attestful_api_request_duration_seconds) > 5
        for: 10m
        labels:
          severity: warning
```
