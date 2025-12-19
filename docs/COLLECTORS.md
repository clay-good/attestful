# Collector Reference

This document provides detailed information about all Attestful collectors, including supported platforms, required credentials, and available evidence types.

## Table of Contents

- [Overview](#overview)
- [Cloud Infrastructure Collectors](#cloud-infrastructure-collectors)
  - [AWS Collector](#aws-collector)
  - [Azure Collector](#azure-collector)
  - [GCP Collector](#gcp-collector)
  - [Kubernetes Collector](#kubernetes-collector)
- [Identity & Access Collectors](#identity--access-collectors)
  - [Okta Collector](#okta-collector)
  - [Azure AD Collector](#azure-ad-collector)
- [Source Control Collectors](#source-control-collectors)
  - [GitHub Collector](#github-collector)
  - [GitLab Collector](#gitlab-collector)
- [Productivity & Communication Collectors](#productivity--communication-collectors)
  - [Google Workspace Collector](#google-workspace-collector)
  - [Slack Collector](#slack-collector)
  - [Zoom Collector](#zoom-collector)
- [Issue Tracking Collectors](#issue-tracking-collectors)
  - [Jira Collector](#jira-collector)
- [Monitoring & Security Collectors](#monitoring--security-collectors)
  - [Datadog Collector](#datadog-collector)
- [Endpoint Management Collectors](#endpoint-management-collectors)
  - [Jamf Collector](#jamf-collector)
- [Data Platform Collectors](#data-platform-collectors)
  - [Snowflake Collector](#snowflake-collector)
- [Documentation Collectors](#documentation-collectors)
  - [Notion Collector](#notion-collector)
  - [Slab Collector](#slab-collector)

## Overview

Attestful collectors gather evidence from various platforms for compliance assessments. Each collector supports two modes:

1. **Resource Mode**: Collects configuration data for compliance checks
2. **Evidence Mode**: Collects audit evidence for compliance documentation

### Common Options

All collectors support these options:

| Option | Description |
|--------|-------------|
| `--types` | Specific evidence types to collect |
| `--since` | Only collect data after this date |
| `--output` | Output file path |
| `--format` | Output format (json, yaml) |
| `--dry-run` | Validate configuration without collecting |

---

## Cloud Infrastructure Collectors

### AWS Collector

Collects configuration and evidence from Amazon Web Services.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Access Key ID | AWS access key | IAM Console > Users > Security Credentials |
| Secret Access Key | AWS secret key | Created with Access Key ID |
| (Optional) Role ARN | IAM role to assume | IAM Console > Roles |

#### Required IAM Permissions

Minimum required permissions (attach to IAM user or role):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
        "s3:GetBucketPublicAccessBlock",
        "s3:ListAllMyBuckets",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:GetCredentialReport",
        "iam:GenerateCredentialReport",
        "iam:ListAccessKeys",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "config:DescribeConfigurationRecorders",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "securityhub:GetFindings",
        "kms:ListKeys",
        "kms:DescribeKey"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Resource Types

| Type | Description |
|------|-------------|
| `s3_bucket` | S3 buckets and their configurations |
| `ec2_instance` | EC2 instances |
| `security_group` | VPC security groups |
| `iam_user` | IAM users |
| `iam_role` | IAM roles |
| `iam_policy` | IAM policies |
| `rds_instance` | RDS database instances |
| `rds_cluster` | RDS clusters |
| `kms_key` | KMS encryption keys |
| `lambda_function` | Lambda functions |
| `cloudtrail_trail` | CloudTrail trails |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `account_info` | AWS account information | GV.OC |
| `iam_credential_report` | IAM credential report | PR.AA, GV.RR |
| `password_policy` | IAM password policy | PR.AA, GV.PO |
| `cloudtrail_status` | CloudTrail configuration | DE.CM, GV.OV |
| `guardduty_status` | GuardDuty detector status | DE.CM, DE.AE |
| `config_status` | AWS Config recorder status | DE.CM, ID.AM |
| `securityhub_findings` | Security Hub findings | DE.AE, RS.AN |
| `s3_public_access` | S3 public access settings | PR.DS, PR.AC |
| `encryption_status` | KMS and encryption status | PR.DS |

#### Usage Examples

```bash
# Scan AWS resources
attestful scan aws

# Scan specific regions
attestful scan aws --region us-east-1 --region eu-west-1

# Scan with assumed role
attestful scan aws --role arn:aws:iam::123456789012:role/AuditRole

# Collect evidence
attestful collect aws --types iam_credential_report,password_policy,cloudtrail_status

# Collect all evidence types
attestful collect aws
```

#### Configuration

```yaml
platforms:
  aws:
    default_region: us-east-1
    regions:
      - us-east-1
      - us-west-2
    assume_role: arn:aws:iam::123456789012:role/AttestfulReadOnly
    external_id: attestful-audit
    timeout: 120
```

---

### Azure Collector

Collects configuration and evidence from Microsoft Azure.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Tenant ID | Azure AD tenant ID | Azure Portal > Azure AD > Overview |
| Subscription ID | Azure subscription | Azure Portal > Subscriptions |
| Client ID | Service principal | Azure AD > App registrations |
| Client Secret | Service principal secret | App registration > Certificates & secrets |

#### Required Permissions

Assign the **Reader** role to the service principal at the subscription level.

#### Resource Types

| Type | Description |
|------|-------------|
| `virtual_machine` | Azure VMs |
| `storage_account` | Storage accounts |
| `sql_server` | SQL servers |
| `key_vault` | Key vaults |
| `network_security_group` | NSGs |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `subscription_info` | Subscription details | GV.OC |
| `activity_logs` | Azure Activity Logs | DE.CM, DE.AE |
| `security_center_findings` | Defender findings | DE.AE, RS.AN |
| `policy_compliance` | Policy compliance status | GV.PO |

#### Usage Examples

```bash
# Scan Azure resources
attestful scan azure

# Scan specific subscription
attestful scan azure --subscription 12345678-1234-1234-1234-123456789012

# Collect evidence
attestful collect azure --types activity_logs,security_center_findings
```

---

### GCP Collector

Collects configuration and evidence from Google Cloud Platform.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Project ID | GCP project identifier | GCP Console > Project settings |
| Service Account | Service account key | IAM > Service Accounts |

#### Required Permissions

The service account needs these roles:
- `roles/viewer` - Basic read access
- `roles/securitycenter.findingsViewer` - Security findings
- `roles/logging.viewer` - Audit logs

#### Resource Types

| Type | Description |
|------|-------------|
| `compute_instance` | Compute Engine VMs |
| `storage_bucket` | Cloud Storage buckets |
| `sql_instance` | Cloud SQL instances |
| `gke_cluster` | GKE clusters |
| `iam_service_account` | Service accounts |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `project_info` | Project metadata | GV.OC |
| `audit_logs` | Cloud Audit Logs | DE.CM, DE.AE |
| `security_findings` | Security Command Center | DE.AE, RS.AN |
| `iam_policy` | IAM policy bindings | PR.AC, GV.RR |

#### Usage Examples

```bash
# Scan GCP resources
attestful scan gcp --project my-project-123

# Collect evidence
attestful collect gcp --types audit_logs,security_findings
```

---

### Kubernetes Collector

Collects configuration and evidence from Kubernetes clusters.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Kubeconfig | Kubernetes config file | `~/.kube/config` or KUBECONFIG env |
| Context | Cluster context name | `kubectl config get-contexts` |
| (Optional) Token | Service account token | `kubectl create token` |

#### Required Permissions

The service account needs these RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: attestful-reader
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets", "namespaces", "serviceaccounts"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "statefulsets", "replicasets"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["get", "list"]
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies", "poddisruptionbudgets"]
  verbs: ["get", "list"]
```

#### Resource Types

| Type | Description |
|------|-------------|
| `pod` | Kubernetes pods |
| `deployment` | Deployments |
| `service` | Services |
| `configmap` | ConfigMaps |
| `secret` | Secrets (metadata only) |
| `network_policy` | Network policies |
| `role` | RBAC roles |
| `service_account` | Service accounts |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `cluster_info` | Cluster version and config | ID.AM, GV.OC |
| `rbac_config` | RBAC roles and bindings | PR.AC, GV.RR |
| `network_policies` | Network policy rules | PR.AC, PR.DS |
| `pod_security` | Pod security configurations | PR.DS, PR.PT |
| `resource_quotas` | Resource quotas | PR.DS |

#### Usage Examples

```bash
# Scan Kubernetes cluster
attestful scan kubernetes

# Scan specific namespace
attestful scan kubernetes --namespace production

# Scan with specific context
attestful scan kubernetes --context my-cluster

# Collect evidence
attestful collect kubernetes --types cluster_info,rbac_config,network_policies
```

---

## Identity & Access Collectors

### Okta Collector

Collects identity and access management evidence from Okta.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Domain | Okta domain (company.okta.com) | Okta Admin Console URL |
| API Token | Okta API token | Security > API > Tokens |

#### Required Permissions

The API token needs these permissions:
- Read users
- Read groups
- Read applications
- Read policies
- Read system logs

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | All users with profiles | PR.AA, ID.AM |
| `mfa_factors` | MFA enrollment status | PR.AA |
| `groups` | Groups and memberships | PR.AC, GV.RR |
| `applications` | Configured applications | PR.AC, ID.AM |
| `policies` | Authentication policies | PR.AA, GV.PO |
| `system_log` | Authentication events | DE.CM, DE.AE |

#### Usage Examples

```bash
# Collect all Okta evidence
attestful collect okta

# Collect specific types
attestful collect okta --types users,mfa_factors,policies

# Collect recent events
attestful collect okta --types system_log --since 2024-01-01
```

#### Configuration

```yaml
platforms:
  okta:
    domain: company.okta.com
    timeout: 60
    page_size: 200
```

---

### Azure AD Collector

Collects identity and access management evidence from Azure Active Directory.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Tenant ID | Azure AD tenant |
| Client ID | App registration client ID |
| Client Secret | App registration secret |

#### Required Permissions

Microsoft Graph API permissions:
- `User.Read.All`
- `Group.Read.All`
- `AuditLog.Read.All`
- `Policy.Read.All`

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Azure AD users | PR.AA, ID.AM |
| `groups` | Security groups | PR.AC, GV.RR |
| `sign_in_logs` | Sign-in activity | DE.CM, DE.AE |
| `conditional_access` | CA policies | PR.AA, GV.PO |
| `mfa_status` | MFA registration | PR.AA |

---

## Source Control Collectors

### GitHub Collector

Collects source control and security evidence from GitHub.

#### Required Credentials

| Credential | Description | How to Obtain |
|------------|-------------|---------------|
| Token | Personal access token or GitHub App | Settings > Developer settings > PATs |
| (Optional) Enterprise URL | GitHub Enterprise Server URL | Your GHE server URL |

#### Required Permissions

Personal Access Token scopes:
- `repo` - Full repository access
- `read:org` - Read organization data
- `admin:org_hook` - Read webhooks (optional)

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `repositories` | Repository configurations | ID.AM, PR.DS |
| `branch_protection` | Branch protection rules | PR.DS, GV.PO |
| `security_alerts` | Dependabot and code scanning | DE.CM, DE.AE |
| `audit_logs` | Organization audit logs | DE.CM |
| `collaborators` | Repository access | PR.AC |

#### Usage Examples

```bash
# Collect from organization
attestful collect github --org mycompany

# Collect specific types
attestful collect github --types repositories,branch_protection,security_alerts
```

---

### GitLab Collector

Collects source control and security evidence from GitLab.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Token | Personal or project access token |
| URL | GitLab instance URL (for self-hosted) |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `projects` | Project configurations | ID.AM, PR.DS |
| `merge_request_approvals` | MR approval rules | PR.DS, GV.PO |
| `security_findings` | SAST/DAST findings | DE.CM, DE.AE |
| `audit_events` | Audit events | DE.CM |

---

## Productivity & Communication Collectors

### Google Workspace Collector

Collects evidence from Google Workspace (formerly G Suite).

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Service Account | Service account with domain-wide delegation |
| Admin Email | Admin user email for impersonation |

#### Required Scopes

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/admin.directory.group.readonly`
- `https://www.googleapis.com/auth/admin.reports.audit.readonly`

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Workspace users | PR.AA, ID.AM |
| `groups` | Groups and members | PR.AC |
| `admin_activity` | Admin audit logs | DE.CM |
| `login_activity` | Login audit logs | DE.CM, DE.AE |
| `drive_activity` | Drive audit logs | DE.CM |
| `mobile_devices` | Managed devices | ID.AM |

---

### Slack Collector

Collects evidence from Slack workspaces.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Bot Token | Slack bot OAuth token (xoxb-...) |

#### Required Scopes

- `users:read`
- `users:read.email`
- `team:read`
- `channels:read`

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Workspace users | PR.AA, ID.AM |
| `channels` | Channel configurations | PR.AC |
| `workspace_settings` | Workspace settings | GV.PO |

---

### Zoom Collector

Collects evidence from Zoom.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Account ID | Zoom account ID |
| Client ID | OAuth app client ID |
| Client Secret | OAuth app client secret |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Zoom users | PR.AA, ID.AM |
| `meetings` | Meeting configurations | GV.PO |
| `settings` | Account settings | GV.PO |

---

## Issue Tracking Collectors

### Jira Collector

Collects evidence from Jira.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| URL | Jira instance URL |
| Email | User email |
| API Token | Jira API token |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `projects` | Project configurations | ID.AM |
| `issues` | Security-related issues | RS.AN, RS.MI |
| `workflows` | Workflow configurations | GV.PO |
| `permissions` | Permission schemes | PR.AC |

---

## Monitoring & Security Collectors

### Datadog Collector

Collects evidence from Datadog.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| API Key | Datadog API key |
| Application Key | Datadog application key |
| Site | Datadog site (datadoghq.com, datadoghq.eu) |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `monitors` | Monitor configurations | DE.CM |
| `dashboards` | Dashboard configurations | DE.CM |
| `security_signals` | Security signals | DE.AE |
| `logs_config` | Log configuration | DE.CM |

---

## Endpoint Management Collectors

### Jamf Collector

Collects evidence from Jamf Pro.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| URL | Jamf Pro server URL |
| Username | Jamf Pro username |
| Password | Jamf Pro password |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `computers` | Managed computers | ID.AM |
| `mobile_devices` | Managed mobile devices | ID.AM |
| `policies` | Configuration policies | PR.IP |
| `profiles` | Configuration profiles | PR.IP |

---

## Data Platform Collectors

### Snowflake Collector

Collects evidence from Snowflake.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Account | Snowflake account identifier |
| Username | Snowflake username |
| Password | Snowflake password |
| Warehouse | Default warehouse |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Snowflake users | PR.AA, ID.AM |
| `roles` | Roles and grants | PR.AC |
| `access_history` | Query access history | DE.CM |
| `network_policies` | Network rules | PR.AC |

---

## Documentation Collectors

### Notion Collector

Collects evidence from Notion.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Token | Notion integration token |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Workspace users | ID.AM |
| `pages` | Security documentation | GV.PO |
| `databases` | Database configurations | ID.AM |

---

### Slab Collector

Collects evidence from Slab.

#### Required Credentials

| Credential | Description |
|------------|-------------|
| Token | Slab API token |

#### Evidence Types

| Type | Description | CSF Mapping |
|------|-------------|-------------|
| `users` | Slab users | ID.AM |
| `posts` | Security documentation | GV.PO |
| `topics` | Policy topics | GV.PO |
