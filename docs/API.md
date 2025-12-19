# REST API Reference

This document provides a comprehensive reference for the Attestful REST API, including endpoints, request/response formats, authentication, and rate limiting.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Common Response Formats](#common-response-formats)
- [Endpoints](#endpoints)
  - [Health](#health)
  - [Scans](#scans)
  - [Collections](#collections)
  - [Resources](#resources)
  - [Evidence](#evidence)
  - [Frameworks](#frameworks)
  - [Analysis](#analysis)
  - [Reports](#reports)
  - [OSCAL](#oscal)
  - [Remediation](#remediation)
  - [Configuration](#configuration)
- [Webhooks](#webhooks)
- [Error Handling](#error-handling)
- [SDK Examples](#sdk-examples)

## Overview

The Attestful REST API provides programmatic access to all platform functionality. The API follows REST conventions and returns JSON responses.

### Base URL

```
http://localhost:8000/api/v1
```

For production deployments:
```
https://attestful.example.com/api/v1
```

### API Versioning

The API version is included in the URL path. The current version is `v1`. When breaking changes are introduced, a new version will be released while maintaining backward compatibility for previous versions.

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | Bearer token for authentication |
| `Content-Type` | Yes* | `application/json` for POST/PUT/PATCH |
| `Accept` | No | `application/json` (default) |
| `X-Request-ID` | No | Client-generated request ID for tracing |

---

## Authentication

### JWT Authentication

Attestful uses JWT (JSON Web Tokens) for API authentication.

#### Obtaining a Token

```http
POST /api/v1/auth/token
Content-Type: application/json

{
  "username": "admin@example.com",
  "password": "your-password"
}
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 28800,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

#### Using the Token

Include the token in the `Authorization` header:

```http
GET /api/v1/scans
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### Refreshing a Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4..."
}
```

### API Key Authentication

For service-to-service communication, API keys can be used:

```http
GET /api/v1/scans
X-API-Key: atst_live_abc123def456
```

API keys are created in the dashboard or via CLI:

```bash
attestful configure api-key create --name "CI/CD Pipeline"
```

### OAuth 2.0 (Enterprise)

Enterprise deployments support OAuth 2.0 with OIDC providers:

```http
GET /api/v1/auth/oauth/authorize?provider=okta&redirect_uri=...
```

---

## Rate Limiting

API requests are rate-limited to ensure fair usage and system stability.

### Limits

| Tier | Requests/Minute | Requests/Hour |
|------|-----------------|---------------|
| Standard | 100 | 1,000 |
| Enterprise | 1,000 | 10,000 |

### Rate Limit Headers

Every response includes rate limit information:

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1704067200
```

### Rate Limit Exceeded

When rate limits are exceeded, the API returns `429 Too Many Requests`:

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded. Please retry after 60 seconds.",
    "retry_after": 60
  }
}
```

---

## Common Response Formats

### Success Response

```json
{
  "data": { ... },
  "meta": {
    "request_id": "req_abc123",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### List Response

```json
{
  "data": [ ... ],
  "meta": {
    "total": 150,
    "page": 1,
    "per_page": 20,
    "total_pages": 8
  },
  "links": {
    "self": "/api/v1/scans?page=1",
    "next": "/api/v1/scans?page=2",
    "last": "/api/v1/scans?page=8"
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "validation_error",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "provider",
        "message": "Provider must be one of: aws, azure, gcp"
      }
    ]
  }
}
```

---

## Endpoints

### Health

#### Get Health Status

```http
GET /api/v1/health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "database": "healthy",
    "storage": "healthy",
    "collectors": {
      "aws": "configured",
      "okta": "configured",
      "github": "not_configured"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### Scans

#### List Scans

```http
GET /api/v1/scans
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `per_page` | int | Items per page (default: 20, max: 100) |
| `provider` | string | Filter by provider (aws, azure, gcp, kubernetes) |
| `framework` | string | Filter by framework |
| `status` | string | Filter by status (pending, running, completed, failed) |
| `since` | datetime | Filter scans after this date |

**Response:**

```json
{
  "data": [
    {
      "id": "scan_abc123",
      "provider": "aws",
      "framework": "soc2",
      "status": "completed",
      "started_at": "2024-01-15T10:00:00Z",
      "completed_at": "2024-01-15T10:15:00Z",
      "summary": {
        "total_resources": 450,
        "total_checks": 85,
        "passed": 72,
        "failed": 10,
        "skipped": 3
      }
    }
  ],
  "meta": {
    "total": 50,
    "page": 1,
    "per_page": 20
  }
}
```

#### Create Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "provider": "aws",
  "framework": "soc2",
  "options": {
    "regions": ["us-east-1", "us-west-2"],
    "resource_types": ["s3_bucket", "ec2_instance"],
    "severity_threshold": "medium"
  }
}
```

**Response:**

```json
{
  "data": {
    "id": "scan_def456",
    "provider": "aws",
    "framework": "soc2",
    "status": "pending",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

#### Get Scan

```http
GET /api/v1/scans/{scan_id}
```

**Response:**

```json
{
  "data": {
    "id": "scan_abc123",
    "provider": "aws",
    "framework": "soc2",
    "status": "completed",
    "started_at": "2024-01-15T10:00:00Z",
    "completed_at": "2024-01-15T10:15:00Z",
    "options": {
      "regions": ["us-east-1"],
      "severity_threshold": "low"
    },
    "summary": {
      "total_resources": 450,
      "total_checks": 85,
      "passed": 72,
      "failed": 10,
      "skipped": 3,
      "by_severity": {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 1
      }
    }
  }
}
```

#### Get Scan Results

```http
GET /api/v1/scans/{scan_id}/results
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by result status (passed, failed, skipped) |
| `severity` | string | Filter by severity (critical, high, medium, low) |
| `control_id` | string | Filter by control ID |
| `resource_type` | string | Filter by resource type |

**Response:**

```json
{
  "data": [
    {
      "id": "result_xyz789",
      "check_id": "s3-encryption-check",
      "check_title": "S3 Bucket Encryption",
      "status": "failed",
      "severity": "high",
      "resource": {
        "id": "my-bucket",
        "type": "s3_bucket",
        "arn": "arn:aws:s3:::my-bucket"
      },
      "control_mappings": {
        "soc2": ["CC6.1"],
        "nist-800-53": ["SC-28"]
      },
      "remediation": "Enable default encryption on the S3 bucket"
    }
  ]
}
```

#### Cancel Scan

```http
POST /api/v1/scans/{scan_id}/cancel
```

---

### Collections

#### List Collections

```http
GET /api/v1/collections
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `platform` | string | Filter by platform |
| `status` | string | Filter by status |
| `since` | datetime | Filter after date |

**Response:**

```json
{
  "data": [
    {
      "id": "coll_abc123",
      "platform": "okta",
      "status": "completed",
      "started_at": "2024-01-15T09:00:00Z",
      "completed_at": "2024-01-15T09:05:00Z",
      "summary": {
        "evidence_types": ["users", "mfa_factors", "groups"],
        "items_collected": 1250,
        "errors": 0
      }
    }
  ]
}
```

#### Create Collection

```http
POST /api/v1/collections
Content-Type: application/json

{
  "platform": "okta",
  "evidence_types": ["users", "mfa_factors", "groups"],
  "options": {
    "since": "2024-01-01T00:00:00Z",
    "include_inactive": false
  }
}
```

#### Get Collection

```http
GET /api/v1/collections/{collection_id}
```

#### Get Collection Evidence

```http
GET /api/v1/collections/{collection_id}/evidence
```

---

### Resources

#### List Resources

```http
GET /api/v1/resources
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `provider` | string | Filter by provider |
| `type` | string | Filter by resource type |
| `region` | string | Filter by region |
| `tag` | string | Filter by tag (key:value) |
| `scan_id` | string | Filter by scan ID |

**Response:**

```json
{
  "data": [
    {
      "id": "i-abc123def456",
      "type": "ec2_instance",
      "provider": "aws",
      "region": "us-east-1",
      "name": "web-server-1",
      "tags": {
        "Environment": "production",
        "Team": "engineering"
      },
      "last_scanned": "2024-01-15T10:00:00Z",
      "compliance_status": {
        "passed": 12,
        "failed": 2,
        "skipped": 1
      }
    }
  ]
}
```

#### Get Resource

```http
GET /api/v1/resources/{resource_id}
```

#### Get Resource Compliance History

```http
GET /api/v1/resources/{resource_id}/history
```

---

### Evidence

#### List Evidence

```http
GET /api/v1/evidence
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `platform` | string | Filter by platform |
| `type` | string | Filter by evidence type |
| `control_id` | string | Filter by mapped control |
| `since` | datetime | Filter after date |

**Response:**

```json
{
  "data": [
    {
      "id": "evd_abc123",
      "platform": "okta",
      "type": "users",
      "collected_at": "2024-01-15T09:00:00Z",
      "metadata": {
        "total_count": 150,
        "active_count": 142
      },
      "control_mappings": {
        "nist-csf-2": ["PR.AA-1", "PR.AA-3"],
        "soc2": ["CC6.1", "CC6.2"]
      },
      "storage": {
        "path": "evidence/2024/01/15/okta-users-abc123.json.gz",
        "size_bytes": 45678,
        "hash": "sha256:abc123..."
      }
    }
  ]
}
```

#### Get Evidence

```http
GET /api/v1/evidence/{evidence_id}
```

#### Download Evidence

```http
GET /api/v1/evidence/{evidence_id}/download
```

Returns the raw evidence file with appropriate Content-Type header.

---

### Frameworks

#### List Frameworks

```http
GET /api/v1/frameworks
```

**Response:**

```json
{
  "data": [
    {
      "id": "soc2",
      "name": "SOC 2 Type II",
      "version": "2017",
      "description": "Trust Services Criteria",
      "controls_count": 50,
      "automation_coverage": 0.90,
      "categories": [
        {
          "id": "cc",
          "name": "Common Criteria",
          "controls_count": 45
        }
      ]
    }
  ]
}
```

#### Get Framework

```http
GET /api/v1/frameworks/{framework_id}
```

#### List Framework Controls

```http
GET /api/v1/frameworks/{framework_id}/controls
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Filter by category |
| `search` | string | Search in title/description |
| `automated` | boolean | Filter by automation status |

**Response:**

```json
{
  "data": [
    {
      "id": "CC6.1",
      "title": "Logical and Physical Access Controls",
      "description": "The entity implements...",
      "category": "cc",
      "automated": true,
      "checks": ["iam-mfa-enabled", "password-policy-check"],
      "evidence_types": ["users", "mfa_factors", "password_policy"]
    }
  ]
}
```

#### Get Framework Mappings

```http
GET /api/v1/frameworks/{framework_id}/mappings
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `target` | string | Target framework ID |
| `control_id` | string | Specific control ID |

---

### Analysis

#### Get Maturity Score

```http
GET /api/v1/analysis/maturity
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `framework` | string | Framework ID (required) |
| `as_of` | datetime | Calculate as of date |

**Response:**

```json
{
  "data": {
    "framework": "nist-csf-2",
    "overall_score": 72.5,
    "level": "Managed",
    "calculated_at": "2024-01-15T10:30:00Z",
    "by_function": {
      "govern": 68.0,
      "identify": 75.0,
      "protect": 80.0,
      "detect": 70.0,
      "respond": 65.0,
      "recover": 72.0
    },
    "trend": {
      "previous_score": 68.0,
      "change": 4.5,
      "direction": "improving"
    }
  }
}
```

#### Get Gap Analysis

```http
GET /api/v1/analysis/gaps
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `framework` | string | Framework ID (required) |
| `severity` | string | Minimum gap severity |

**Response:**

```json
{
  "data": {
    "framework": "soc2",
    "total_gaps": 15,
    "by_severity": {
      "critical": 2,
      "high": 5,
      "medium": 6,
      "low": 2
    },
    "gaps": [
      {
        "control_id": "CC6.1",
        "title": "Logical Access Controls",
        "gap_description": "MFA not enforced for all users",
        "severity": "high",
        "remediation": "Enable MFA enforcement in Okta",
        "evidence_available": false
      }
    ]
  }
}
```

#### Get Compliance Trends

```http
GET /api/v1/analysis/trends
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `framework` | string | Framework ID |
| `period` | string | Time period (30d, 90d, 1y) |
| `metric` | string | Metric to track |

---

### Reports

#### List Reports

```http
GET /api/v1/reports
```

#### Generate Report

```http
POST /api/v1/reports
Content-Type: application/json

{
  "framework": "soc2",
  "format": "html",
  "template": "executive",
  "options": {
    "include_evidence": true,
    "scan_ids": ["scan_abc123", "scan_def456"]
  }
}
```

**Response:**

```json
{
  "data": {
    "id": "rpt_abc123",
    "status": "generating",
    "framework": "soc2",
    "format": "html",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

#### Get Report

```http
GET /api/v1/reports/{report_id}
```

#### Download Report

```http
GET /api/v1/reports/{report_id}/download
```

---

### OSCAL

#### List Catalogs

```http
GET /api/v1/oscal/catalogs
```

**Response:**

```json
{
  "data": [
    {
      "id": "nist-800-53-rev5",
      "title": "NIST SP 800-53 Rev 5",
      "version": "5.0.0",
      "controls_count": 1007,
      "groups_count": 20
    }
  ]
}
```

#### Get Catalog

```http
GET /api/v1/oscal/catalogs/{catalog_id}
```

#### Search Catalog Controls

```http
GET /api/v1/oscal/catalogs/{catalog_id}/controls
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Search term |
| `group` | string | Filter by group/family |

#### List Profiles

```http
GET /api/v1/oscal/profiles
```

#### Resolve Profile

```http
GET /api/v1/oscal/profiles/{profile_id}/resolve
```

Returns the resolved catalog with all imports and modifications applied.

#### Generate SSP

```http
POST /api/v1/oscal/ssp
Content-Type: application/json

{
  "profile_id": "fedramp-moderate",
  "system_name": "Production Application",
  "system_id": "prod-001",
  "description": "Customer-facing SaaS application",
  "components": ["aws", "kubernetes"],
  "scan_ids": ["scan_abc123"]
}
```

#### Export Assessment Results

```http
POST /api/v1/oscal/assessment
Content-Type: application/json

{
  "scan_id": "scan_abc123",
  "ssp_id": "ssp-prod-001",
  "title": "Q1 2024 Assessment"
}
```

#### Generate POA&M

```http
POST /api/v1/oscal/poam
Content-Type: application/json

{
  "assessment_id": "ar_abc123",
  "ssp_id": "ssp-prod-001"
}
```

#### Validate OSCAL Document

```http
POST /api/v1/oscal/validate
Content-Type: application/json

{
  "document": { ... },
  "document_type": "catalog"
}
```

---

### Remediation

#### List Remediation Actions

```http
GET /api/v1/remediation
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status |
| `provider` | string | Filter by provider |
| `severity` | string | Filter by severity |

**Response:**

```json
{
  "data": [
    {
      "id": "rem_abc123",
      "check_id": "s3-encryption-check",
      "resource_id": "my-bucket",
      "resource_type": "s3_bucket",
      "action": "enable_s3_encryption",
      "status": "pending",
      "severity": "high",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### Create Remediation

```http
POST /api/v1/remediation
Content-Type: application/json

{
  "scan_result_id": "result_xyz789",
  "dry_run": true
}
```

#### Execute Remediation

```http
POST /api/v1/remediation/{remediation_id}/execute
Content-Type: application/json

{
  "dry_run": false,
  "approval_token": "apr_xyz789"
}
```

#### Get Remediation Status

```http
GET /api/v1/remediation/{remediation_id}
```

#### Rollback Remediation

```http
POST /api/v1/remediation/{remediation_id}/rollback
```

---

### Configuration

#### Get Configuration

```http
GET /api/v1/config
```

Returns non-sensitive configuration values.

#### Update Configuration

```http
PATCH /api/v1/config
Content-Type: application/json

{
  "general": {
    "log_level": "DEBUG"
  }
}
```

#### Test Platform Connectivity

```http
POST /api/v1/config/test/{platform}
```

**Response:**

```json
{
  "data": {
    "platform": "aws",
    "status": "connected",
    "details": {
      "account_id": "123456789012",
      "regions_available": ["us-east-1", "us-west-2"]
    }
  }
}
```

---

## Webhooks

### Configuring Webhooks

```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "url": "https://example.com/webhook",
  "events": ["scan.completed", "scan.failed", "collection.completed"],
  "secret": "your-webhook-secret"
}
```

### Webhook Events

| Event | Description |
|-------|-------------|
| `scan.started` | Scan has started |
| `scan.completed` | Scan completed successfully |
| `scan.failed` | Scan failed |
| `collection.started` | Collection has started |
| `collection.completed` | Collection completed |
| `collection.failed` | Collection failed |
| `remediation.executed` | Remediation action executed |
| `remediation.failed` | Remediation action failed |

### Webhook Payload

```json
{
  "id": "evt_abc123",
  "event": "scan.completed",
  "timestamp": "2024-01-15T10:15:00Z",
  "data": {
    "scan_id": "scan_abc123",
    "provider": "aws",
    "summary": {
      "passed": 72,
      "failed": 10
    }
  }
}
```

### Verifying Webhooks

Webhooks include an HMAC signature in the `X-Attestful-Signature` header:

```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## Error Handling

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `authentication_required` | 401 | No valid authentication provided |
| `forbidden` | 403 | Insufficient permissions |
| `not_found` | 404 | Resource not found |
| `validation_error` | 400 | Invalid request parameters |
| `rate_limit_exceeded` | 429 | Rate limit exceeded |
| `internal_error` | 500 | Internal server error |
| `service_unavailable` | 503 | Service temporarily unavailable |

### Error Response Format

```json
{
  "error": {
    "code": "validation_error",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "provider",
        "code": "invalid_choice",
        "message": "Must be one of: aws, azure, gcp, kubernetes"
      }
    ],
    "request_id": "req_abc123"
  }
}
```

---

## SDK Examples

### Python

```python
from attestful import AttestfulClient

# Initialize client
client = AttestfulClient(
    base_url="https://attestful.example.com/api/v1",
    api_key="atst_live_abc123"
)

# Run a scan
scan = client.scans.create(
    provider="aws",
    framework="soc2",
    options={"regions": ["us-east-1"]}
)

# Wait for completion
scan.wait()

# Get results
results = scan.results(status="failed", severity="high")
for result in results:
    print(f"{result.resource.id}: {result.check_title}")

# Generate report
report = client.reports.create(
    framework="soc2",
    format="html",
    scan_ids=[scan.id]
)
report.download("soc2-report.html")
```

### cURL

```bash
# Authenticate
TOKEN=$(curl -s -X POST https://attestful.example.com/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username":"admin@example.com","password":"secret"}' \
  | jq -r '.access_token')

# Create scan
SCAN_ID=$(curl -s -X POST https://attestful.example.com/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"aws","framework":"soc2"}' \
  | jq -r '.data.id')

# Check status
curl -s https://attestful.example.com/api/v1/scans/$SCAN_ID \
  -H "Authorization: Bearer $TOKEN" \
  | jq '.data.status'

# Get results
curl -s "https://attestful.example.com/api/v1/scans/$SCAN_ID/results?status=failed" \
  -H "Authorization: Bearer $TOKEN"
```

### JavaScript/TypeScript

```typescript
import { AttestfulClient } from '@attestful/sdk';

const client = new AttestfulClient({
  baseUrl: 'https://attestful.example.com/api/v1',
  apiKey: 'atst_live_abc123',
});

// Run scan
const scan = await client.scans.create({
  provider: 'aws',
  framework: 'soc2',
});

// Poll for completion
await scan.waitForCompletion();

// Get failed checks
const failures = await scan.getResults({ status: 'failed' });
console.log(`Found ${failures.length} failures`);

// Generate OSCAL assessment
const assessment = await client.oscal.createAssessment({
  scanId: scan.id,
  title: 'Q1 2024 Assessment',
});
```

---

## OpenAPI Specification

The complete OpenAPI 3.0 specification is available at:

```
GET /api/v1/openapi.json
```

Interactive API documentation (Swagger UI):

```
GET /api/v1/docs
```

Alternative documentation (ReDoc):

```
GET /api/v1/redoc
```
