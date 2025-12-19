"""
Container orchestration collectors for Attestful.

Provides collectors for Kubernetes and Docker environments,
enabling compliance checking and evidence collection for containerized workloads.
"""

from attestful.collectors.containers.kubernetes import (
    KubernetesCollector,
    KubernetesCollectorConfig,
)
from attestful.collectors.containers.docker import (
    DockerCollector,
    DockerConnection,
)

__all__ = [
    "KubernetesCollector",
    "KubernetesCollectorConfig",
    "DockerCollector",
    "DockerConnection",
]
