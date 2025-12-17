"""
Cloud infrastructure collectors.

Collectors for AWS, Azure, GCP, Kubernetes, and Docker.
"""

from attestful.collectors.cloud.aws import AWSCollector, AWSCollectorConfig
from attestful.collectors.cloud.azure import AzureCollector, AzureCollectorConfig

__all__ = [
    "AWSCollector",
    "AWSCollectorConfig",
    "AzureCollector",
    "AzureCollectorConfig",
]
