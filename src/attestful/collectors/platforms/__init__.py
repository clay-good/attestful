"""
Platform collectors for SaaS and enterprise tools.

Collectors for Okta, GitHub, Jamf, Google Workspace, Snowflake, Datadog,
GitLab, Jira, Zendesk, Zoom, Notion, Slab, SpotDraft, and more.
"""

from attestful.collectors.platforms.okta import OktaCollector, OktaCollectorConfig
from attestful.collectors.platforms.github import GitHubCollector, GitHubCollectorConfig
from attestful.collectors.platforms.datadog import DatadogCollector, DatadogCollectorConfig
from attestful.collectors.platforms.gitlab import GitLabCollector, GitLabCollectorConfig
from attestful.collectors.platforms.jira import JiraCollector, JiraCollectorConfig
from attestful.collectors.platforms.zendesk import ZendeskCollector, ZendeskCollectorConfig
from attestful.collectors.platforms.zoom import ZoomCollector, ZoomCollectorConfig
from attestful.collectors.platforms.notion import NotionCollector, NotionCollectorConfig
from attestful.collectors.platforms.slack import SlackCollector, SlackCollectorConfig
from attestful.collectors.platforms.pagerduty import PagerDutyCollector, PagerDutyCollectorConfig
from attestful.collectors.platforms.terraform import TerraformCloudCollector, TerraformCloudCollectorConfig
from attestful.collectors.platforms.slab import SlabCollector, SlabCollectorConfig
from attestful.collectors.platforms.spotdraft import SpotDraftCollector, SpotDraftCollectorConfig
from attestful.collectors.platforms.jamf import JamfCollector, JamfCollectorConfig
from attestful.collectors.platforms.google_workspace import GoogleWorkspaceCollector, GoogleWorkspaceCollectorConfig
from attestful.collectors.platforms.snowflake import SnowflakeCollector, SnowflakeCollectorConfig
from attestful.collectors.platforms.microsoft365 import Microsoft365Collector, Microsoft365CollectorConfig
from attestful.collectors.platforms.onepassword import OnePasswordCollector, OnePasswordCollectorConfig
from attestful.collectors.platforms.confluence import ConfluenceCollector, ConfluenceCollectorConfig
from attestful.collectors.platforms.linear import LinearCollector, LinearCollectorConfig
from attestful.collectors.platforms.shortcut import ShortcutCollector, ShortcutCollectorConfig
from attestful.collectors.platforms.asana import AsanaCollector, AsanaCollectorConfig
from attestful.collectors.platforms.monday import MondayCollector, MondayCollectorConfig
from attestful.collectors.platforms.aws_secrets_manager import (
    AWSSecretsManagerCollector,
    SecretsManagerConfig,
)
from attestful.collectors.platforms.azure_key_vault import (
    AzureKeyVaultCollector,
    AzureKeyVaultConfig,
)
from attestful.collectors.platforms.hashicorp_vault import (
    HashiCorpVaultCollector,
    HashiCorpVaultConfig,
)

__all__ = [
    "OktaCollector",
    "OktaCollectorConfig",
    "GitHubCollector",
    "GitHubCollectorConfig",
    "DatadogCollector",
    "DatadogCollectorConfig",
    "GitLabCollector",
    "GitLabCollectorConfig",
    "JiraCollector",
    "JiraCollectorConfig",
    "ZendeskCollector",
    "ZendeskCollectorConfig",
    "ZoomCollector",
    "ZoomCollectorConfig",
    "NotionCollector",
    "NotionCollectorConfig",
    "SlackCollector",
    "SlackCollectorConfig",
    "PagerDutyCollector",
    "PagerDutyCollectorConfig",
    "TerraformCloudCollector",
    "TerraformCloudCollectorConfig",
    "SlabCollector",
    "SlabCollectorConfig",
    "SpotDraftCollector",
    "SpotDraftCollectorConfig",
    "JamfCollector",
    "JamfCollectorConfig",
    "GoogleWorkspaceCollector",
    "GoogleWorkspaceCollectorConfig",
    "SnowflakeCollector",
    "SnowflakeCollectorConfig",
    "Microsoft365Collector",
    "Microsoft365CollectorConfig",
    "OnePasswordCollector",
    "OnePasswordCollectorConfig",
    "ConfluenceCollector",
    "ConfluenceCollectorConfig",
    "LinearCollector",
    "LinearCollectorConfig",
    "ShortcutCollector",
    "ShortcutCollectorConfig",
    "AsanaCollector",
    "AsanaCollectorConfig",
    "MondayCollector",
    "MondayCollectorConfig",
    "AWSSecretsManagerCollector",
    "SecretsManagerConfig",
    "AzureKeyVaultCollector",
    "AzureKeyVaultConfig",
    "HashiCorpVaultCollector",
    "HashiCorpVaultConfig",
]
