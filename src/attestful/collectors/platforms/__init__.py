"""
Platform collectors for SaaS and enterprise tools.

Collectors for Okta, GitHub, Jamf, Google Workspace, Snowflake, Datadog,
GitLab, Jira, Zendesk, Zoom, Notion, Slab, SpotDraft, and more.
"""

from attestful.collectors.platforms.okta import OktaCollector, OktaCollectorConfig
from attestful.collectors.platforms.github import GitHubCollector, GitHubCollectorConfig

__all__ = [
    "OktaCollector",
    "OktaCollectorConfig",
    "GitHubCollector",
    "GitHubCollectorConfig",
]
