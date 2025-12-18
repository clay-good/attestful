"""
Cloud infrastructure collectors.

Collectors for AWS, Azure, GCP, Kubernetes, and Docker.
"""

from attestful.collectors.cloud.aws import AWSCollector, AWSCollectorConfig
from attestful.collectors.cloud.azure import AzureCollector, AzureCollectorConfig
from attestful.collectors.cloud.gcp import GCPCollector, GCPCollectorConfig

__all__ = [
    "AWSCollector",
    "AWSCollectorConfig",
    "AzureCollector",
    "AzureCollectorConfig",
    "GCPCollector",
    "GCPCollectorConfig",
]
