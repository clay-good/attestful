"""
Container orchestration collectors for Attestful.

Provides collectors for Kubernetes and Docker environments,
enabling compliance checking and evidence collection for containerized workloads.
"""

from attestful.collectors.containers.kubernetes import (
    KubernetesCollector,
    KubernetesCollectorConfig,
)

__all__ = [
    "KubernetesCollector",
    "KubernetesCollectorConfig",
]
