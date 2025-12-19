"""
Kubernetes-specific remediation actions.

Provides automated remediation for Kubernetes compliance issues including:
- Pod/Deployment security context enforcement
- Resource limits and requests
- Network policies
- RBAC cleanup
"""

from __future__ import annotations

import asyncio
from typing import Any

try:
    from kubernetes import client
    from kubernetes.client.rest import ApiException

    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    client = None  # type: ignore[assignment]
    ApiException = Exception  # type: ignore[misc, assignment]

from attestful.core.logging import get_logger
from attestful.remediation.base import (
    RemediationAction,
    RemediationResult,
    RemediationStatus,
    RiskLevel,
)

logger = get_logger(__name__)


# Kubernetes Remediation Registry
K8S_REMEDIATION_REGISTRY: dict[str, type[RemediationAction]] = {}


def register_k8s_action(check_ids: list[str]) -> Any:
    """Decorator to register a Kubernetes remediation action for specific check IDs."""

    def decorator(cls: type[RemediationAction]) -> type[RemediationAction]:
        for check_id in check_ids:
            K8S_REMEDIATION_REGISTRY[check_id] = cls
        return cls

    return decorator


def get_k8s_remediation_action(
    check_id: str,
    resource_id: str,
    resource_data: dict[str, Any],
    namespace: str = "default",
    dry_run: bool = False,
    **kwargs: Any,
) -> RemediationAction | None:
    """
    Get the appropriate Kubernetes remediation action for a check ID.

    Args:
        check_id: The compliance check ID
        resource_id: The Kubernetes resource ID
        resource_data: Resource configuration data
        namespace: Kubernetes namespace
        dry_run: If True, only simulate the remediation
        **kwargs: Additional arguments for the remediation action

    Returns:
        RemediationAction instance or None if no action registered
    """
    action_cls = K8S_REMEDIATION_REGISTRY.get(check_id)
    if action_cls:
        return action_cls(
            check_id=check_id,
            resource_id=resource_id,
            resource_data=resource_data,
            namespace=namespace,
            dry_run=dry_run,
            **kwargs,
        )
    return None


@register_k8s_action(["k8s-pod-security-context", "k8s-deployment-security-context"])
class EnablePodSecurityContextAction(RemediationAction):
    """Enable security context on a Pod or Deployment."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        namespace: str = "default",
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type=resource_data.get("kind", "Pod"),
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.namespace = namespace
        self.resource_name = resource_data.get("metadata", {}).get("name", resource_id)
        self.kind = resource_data.get("kind", "Pod")

    def get_description(self) -> str:
        """Get description of this remediation."""
        return (
            f"Enable security context on {self.kind} {self.resource_name} in namespace "
            f"{self.namespace}. This will set runAsNonRoot=true, readOnlyRootFilesystem=true, "
            f"and drop all capabilities."
        )

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.MEDIUM  # Can break applications that require root or write access

    async def validate(self) -> tuple[bool, str]:
        """Validate that security context can be updated."""
        if not K8S_AVAILABLE:
            return False, "Kubernetes SDK not available"

        try:
            loop = asyncio.get_event_loop()
            # Check if resource exists and is accessible
            if self.kind == "Pod":
                api = client.CoreV1Api()
                await loop.run_in_executor(
                    None, api.read_namespaced_pod, self.resource_name, self.namespace
                )
            elif self.kind == "Deployment":
                api = client.AppsV1Api()
                await loop.run_in_executor(
                    None, api.read_namespaced_deployment, self.resource_name, self.namespace
                )
            else:
                return False, f"Unsupported resource kind: {self.kind}"

            return True, f"{self.kind} is accessible and can be updated"

        except ApiException as e:
            return False, f"Cannot access {self.kind}: {e.reason}"
        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Enable security context on the Pod/Deployment."""
        changes_made: list[str] = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would enable security context on {self.kind} {self.resource_name}",
                    changes_made=[
                        "Set runAsNonRoot: true",
                        "Set readOnlyRootFilesystem: true",
                        "Drop ALL capabilities",
                    ],
                )

            loop = asyncio.get_event_loop()

            if self.kind == "Pod":
                api = client.CoreV1Api()
                pod = await loop.run_in_executor(
                    None, api.read_namespaced_pod, self.resource_name, self.namespace
                )

                # Store original for rollback
                self.rollback_data = {
                    "kind": "Pod",
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "security_context": (
                        pod.spec.security_context.to_dict()
                        if pod.spec.security_context
                        else None
                    ),
                    "container_security_contexts": [
                        c.security_context.to_dict() if c.security_context else None
                        for c in pod.spec.containers
                    ],
                }

                # Update security context
                if not pod.spec.security_context:
                    pod.spec.security_context = client.V1PodSecurityContext()

                pod.spec.security_context.run_as_non_root = True
                pod.spec.security_context.run_as_user = 1000
                pod.spec.security_context.fs_group = 1000

                # Update container security contexts
                for container in pod.spec.containers:
                    if not container.security_context:
                        container.security_context = client.V1SecurityContext()

                    container.security_context.run_as_non_root = True
                    container.security_context.read_only_root_filesystem = True
                    container.security_context.allow_privilege_escalation = False
                    container.security_context.capabilities = client.V1Capabilities(
                        drop=["ALL"]
                    )

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_pod,
                    self.resource_name,
                    self.namespace,
                    pod,
                )

                changes_made.extend(
                    [
                        f"Set runAsNonRoot: true on Pod {self.resource_name}",
                        "Set readOnlyRootFilesystem: true on all containers",
                        "Dropped ALL capabilities from all containers",
                    ]
                )

            elif self.kind == "Deployment":
                api = client.AppsV1Api()
                deployment = await loop.run_in_executor(
                    None, api.read_namespaced_deployment, self.resource_name, self.namespace
                )

                # Store original for rollback
                self.rollback_data = {
                    "kind": "Deployment",
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "security_context": (
                        deployment.spec.template.spec.security_context.to_dict()
                        if deployment.spec.template.spec.security_context
                        else None
                    ),
                    "container_security_contexts": [
                        c.security_context.to_dict() if c.security_context else None
                        for c in deployment.spec.template.spec.containers
                    ],
                }

                # Update security context
                if not deployment.spec.template.spec.security_context:
                    deployment.spec.template.spec.security_context = (
                        client.V1PodSecurityContext()
                    )

                deployment.spec.template.spec.security_context.run_as_non_root = True
                deployment.spec.template.spec.security_context.run_as_user = 1000
                deployment.spec.template.spec.security_context.fs_group = 1000

                # Update container security contexts
                for container in deployment.spec.template.spec.containers:
                    if not container.security_context:
                        container.security_context = client.V1SecurityContext()

                    container.security_context.run_as_non_root = True
                    container.security_context.read_only_root_filesystem = True
                    container.security_context.allow_privilege_escalation = False
                    container.security_context.capabilities = client.V1Capabilities(
                        drop=["ALL"]
                    )

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_deployment,
                    self.resource_name,
                    self.namespace,
                    deployment,
                )

                changes_made.extend(
                    [
                        f"Set runAsNonRoot: true on Deployment {self.resource_name}",
                        "Set readOnlyRootFilesystem: true on all containers",
                        "Dropped ALL capabilities from all containers",
                    ]
                )

            logger.info(
                "k8s_security_context_enabled",
                extra={
                    "kind": self.kind,
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully enabled security context on {self.kind} {self.resource_name}",
                changes_made=changes_made,
            )

        except ApiException as e:
            logger.error(
                "k8s_security_context_enable_failed",
                extra={
                    "kind": self.kind,
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "error": e.reason,
                },
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to enable security context: {e.reason}",
                error=str(e),
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback security context changes."""
        if not self.rollback_data:
            return True

        try:
            loop = asyncio.get_event_loop()

            if self.rollback_data["kind"] == "Pod":
                api = client.CoreV1Api()
                pod = await loop.run_in_executor(
                    None,
                    api.read_namespaced_pod,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                )

                # Restore original security context
                if self.rollback_data["security_context"]:
                    pod.spec.security_context = client.V1PodSecurityContext(
                        **self.rollback_data["security_context"]
                    )
                else:
                    pod.spec.security_context = None

                # Restore container security contexts
                for i, container in enumerate(pod.spec.containers):
                    if i < len(self.rollback_data["container_security_contexts"]):
                        ctx = self.rollback_data["container_security_contexts"][i]
                        if ctx:
                            container.security_context = client.V1SecurityContext(**ctx)
                        else:
                            container.security_context = None

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_pod,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                    pod,
                )

            elif self.rollback_data["kind"] == "Deployment":
                api = client.AppsV1Api()
                deployment = await loop.run_in_executor(
                    None,
                    api.read_namespaced_deployment,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                )

                # Restore original security context
                if self.rollback_data["security_context"]:
                    deployment.spec.template.spec.security_context = (
                        client.V1PodSecurityContext(**self.rollback_data["security_context"])
                    )
                else:
                    deployment.spec.template.spec.security_context = None

                # Restore container security contexts
                for i, container in enumerate(deployment.spec.template.spec.containers):
                    if i < len(self.rollback_data["container_security_contexts"]):
                        ctx = self.rollback_data["container_security_contexts"][i]
                        if ctx:
                            container.security_context = client.V1SecurityContext(**ctx)
                        else:
                            container.security_context = None

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_deployment,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                    deployment,
                )

            logger.info(
                "k8s_security_context_rollback_success",
                extra={
                    "kind": self.rollback_data["kind"],
                    "name": self.rollback_data["name"],
                    "namespace": self.rollback_data["namespace"],
                },
            )

            return True

        except Exception as e:
            logger.error(
                "k8s_security_context_rollback_failed",
                extra={"error": str(e)},
            )
            return False


@register_k8s_action(["k8s-pod-resource-limits", "k8s-deployment-resource-limits"])
class AddResourceLimitsAction(RemediationAction):
    """Add resource limits and requests to a Pod or Deployment."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        namespace: str = "default",
        cpu_request: str = "100m",
        cpu_limit: str = "500m",
        memory_request: str = "128Mi",
        memory_limit: str = "512Mi",
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type=resource_data.get("kind", "Pod"),
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.namespace = namespace
        self.resource_name = resource_data.get("metadata", {}).get("name", resource_id)
        self.kind = resource_data.get("kind", "Pod")
        self.cpu_request = cpu_request
        self.cpu_limit = cpu_limit
        self.memory_request = memory_request
        self.memory_limit = memory_limit

    def get_description(self) -> str:
        """Get description of this remediation."""
        return (
            f"Add resource limits to {self.kind} {self.resource_name} in namespace "
            f"{self.namespace}. CPU: {self.cpu_request}/{self.cpu_limit}, "
            f"Memory: {self.memory_request}/{self.memory_limit}"
        )

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.LOW  # Adding resource limits is generally safe

    async def validate(self) -> tuple[bool, str]:
        """Validate that resource limits can be added."""
        if not K8S_AVAILABLE:
            return False, "Kubernetes SDK not available"

        try:
            loop = asyncio.get_event_loop()
            if self.kind == "Pod":
                api = client.CoreV1Api()
                await loop.run_in_executor(
                    None, api.read_namespaced_pod, self.resource_name, self.namespace
                )
            elif self.kind == "Deployment":
                api = client.AppsV1Api()
                await loop.run_in_executor(
                    None, api.read_namespaced_deployment, self.resource_name, self.namespace
                )
            else:
                return False, f"Unsupported resource kind: {self.kind}"

            return True, f"{self.kind} is accessible and can be updated"

        except ApiException as e:
            return False, f"Cannot access {self.kind}: {e.reason}"
        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Add resource limits to the Pod/Deployment."""
        changes_made: list[str] = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would add resource limits to {self.kind} {self.resource_name}",
                    changes_made=[
                        f"Set CPU request: {self.cpu_request}, limit: {self.cpu_limit}",
                        f"Set Memory request: {self.memory_request}, limit: {self.memory_limit}",
                    ],
                )

            loop = asyncio.get_event_loop()

            if self.kind == "Pod":
                api = client.CoreV1Api()
                pod = await loop.run_in_executor(
                    None, api.read_namespaced_pod, self.resource_name, self.namespace
                )

                # Store original for rollback
                self.rollback_data = {
                    "kind": "Pod",
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "container_resources": [
                        c.resources.to_dict() if c.resources else None
                        for c in pod.spec.containers
                    ],
                }

                # Add resource limits to all containers
                for container in pod.spec.containers:
                    if not container.resources:
                        container.resources = client.V1ResourceRequirements()

                    container.resources.requests = {
                        "cpu": self.cpu_request,
                        "memory": self.memory_request,
                    }
                    container.resources.limits = {
                        "cpu": self.cpu_limit,
                        "memory": self.memory_limit,
                    }

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_pod,
                    self.resource_name,
                    self.namespace,
                    pod,
                )

                changes_made.append(
                    f"Added resource limits to Pod {self.resource_name}: "
                    f"CPU {self.cpu_request}/{self.cpu_limit}, "
                    f"Memory {self.memory_request}/{self.memory_limit}"
                )

            elif self.kind == "Deployment":
                api = client.AppsV1Api()
                deployment = await loop.run_in_executor(
                    None, api.read_namespaced_deployment, self.resource_name, self.namespace
                )

                # Store original for rollback
                self.rollback_data = {
                    "kind": "Deployment",
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "container_resources": [
                        c.resources.to_dict() if c.resources else None
                        for c in deployment.spec.template.spec.containers
                    ],
                }

                # Add resource limits to all containers
                for container in deployment.spec.template.spec.containers:
                    if not container.resources:
                        container.resources = client.V1ResourceRequirements()

                    container.resources.requests = {
                        "cpu": self.cpu_request,
                        "memory": self.memory_request,
                    }
                    container.resources.limits = {
                        "cpu": self.cpu_limit,
                        "memory": self.memory_limit,
                    }

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_deployment,
                    self.resource_name,
                    self.namespace,
                    deployment,
                )

                changes_made.append(
                    f"Added resource limits to Deployment {self.resource_name}: "
                    f"CPU {self.cpu_request}/{self.cpu_limit}, "
                    f"Memory {self.memory_request}/{self.memory_limit}"
                )

            logger.info(
                "k8s_resource_limits_added",
                extra={
                    "kind": self.kind,
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully added resource limits to {self.kind} {self.resource_name}",
                changes_made=changes_made,
            )

        except ApiException as e:
            logger.error(
                "k8s_resource_limits_add_failed",
                extra={
                    "kind": self.kind,
                    "name": self.resource_name,
                    "namespace": self.namespace,
                    "error": e.reason,
                },
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to add resource limits: {e.reason}",
                error=str(e),
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback resource limit changes."""
        if not self.rollback_data:
            return True

        try:
            loop = asyncio.get_event_loop()

            if self.rollback_data["kind"] == "Pod":
                api = client.CoreV1Api()
                pod = await loop.run_in_executor(
                    None,
                    api.read_namespaced_pod,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                )

                # Restore original resources
                for i, container in enumerate(pod.spec.containers):
                    if i < len(self.rollback_data["container_resources"]):
                        res = self.rollback_data["container_resources"][i]
                        if res:
                            container.resources = client.V1ResourceRequirements(**res)
                        else:
                            container.resources = None

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_pod,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                    pod,
                )

            elif self.rollback_data["kind"] == "Deployment":
                api = client.AppsV1Api()
                deployment = await loop.run_in_executor(
                    None,
                    api.read_namespaced_deployment,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                )

                # Restore original resources
                for i, container in enumerate(deployment.spec.template.spec.containers):
                    if i < len(self.rollback_data["container_resources"]):
                        res = self.rollback_data["container_resources"][i]
                        if res:
                            container.resources = client.V1ResourceRequirements(**res)
                        else:
                            container.resources = None

                await loop.run_in_executor(
                    None,
                    api.patch_namespaced_deployment,
                    self.rollback_data["name"],
                    self.rollback_data["namespace"],
                    deployment,
                )

            logger.info(
                "k8s_resource_limits_rollback_success",
                extra={
                    "kind": self.rollback_data["kind"],
                    "name": self.rollback_data["name"],
                    "namespace": self.rollback_data["namespace"],
                },
            )

            return True

        except Exception as e:
            logger.error(
                "k8s_resource_limits_rollback_failed",
                extra={"error": str(e)},
            )
            return False


@register_k8s_action(["k8s-namespace-network-policy"])
class CreateDefaultDenyNetworkPolicyAction(RemediationAction):
    """Create a default deny network policy for a namespace."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        namespace: str = "default",
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="NetworkPolicy",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.namespace = namespace
        self.policy_name = f"default-deny-{namespace}"

    def get_description(self) -> str:
        """Get description of this remediation."""
        return (
            f"Create default deny network policy in namespace {self.namespace}. "
            f"This will block all ingress and egress traffic by default. "
            f"You will need to create additional policies to allow specific traffic."
        )

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.HIGH  # Can break all network communication in the namespace

    async def validate(self) -> tuple[bool, str]:
        """Validate that network policy can be created."""
        if not K8S_AVAILABLE:
            return False, "Kubernetes SDK not available"

        try:
            loop = asyncio.get_event_loop()
            # Check if namespace exists
            api = client.CoreV1Api()
            await loop.run_in_executor(None, api.read_namespace, self.namespace)

            # Check if policy already exists
            net_api = client.NetworkingV1Api()
            try:
                await loop.run_in_executor(
                    None,
                    net_api.read_namespaced_network_policy,
                    self.policy_name,
                    self.namespace,
                )
                return False, f"Network policy {self.policy_name} already exists"
            except ApiException as e:
                if e.status == 404:
                    return True, "Namespace exists and policy can be created"
                raise

        except ApiException as e:
            return False, f"Cannot access namespace: {e.reason}"
        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Create default deny network policy."""
        changes_made: list[str] = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would create default deny network policy in namespace {self.namespace}",
                    changes_made=["Create default deny ingress and egress network policy"],
                )

            loop = asyncio.get_event_loop()
            net_api = client.NetworkingV1Api()

            # Create default deny policy
            policy = client.V1NetworkPolicy(
                api_version="networking.k8s.io/v1",
                kind="NetworkPolicy",
                metadata=client.V1ObjectMeta(
                    name=self.policy_name,
                    namespace=self.namespace,
                    labels={
                        "managed-by": "attestful",
                        "policy-type": "default-deny",
                    },
                ),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(
                        match_labels={}
                    ),  # Apply to all pods
                    policy_types=["Ingress", "Egress"],
                    ingress=[],  # Deny all ingress
                    egress=[],  # Deny all egress
                ),
            )

            await loop.run_in_executor(
                None, net_api.create_namespaced_network_policy, self.namespace, policy
            )

            self.rollback_data = {
                "policy_name": self.policy_name,
                "namespace": self.namespace,
                "created": True,
            }

            changes_made.append(
                f"Created default deny network policy {self.policy_name} in namespace {self.namespace}"
            )

            logger.info(
                "k8s_network_policy_created",
                extra={
                    "policy_name": self.policy_name,
                    "namespace": self.namespace,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully created default deny network policy in namespace {self.namespace}",
                changes_made=changes_made,
            )

        except ApiException as e:
            logger.error(
                "k8s_network_policy_create_failed",
                extra={
                    "policy_name": self.policy_name,
                    "namespace": self.namespace,
                    "error": e.reason,
                },
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to create network policy: {e.reason}",
                error=str(e),
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback network policy creation."""
        if not self.rollback_data or not self.rollback_data.get("created"):
            return True

        try:
            loop = asyncio.get_event_loop()
            net_api = client.NetworkingV1Api()

            await loop.run_in_executor(
                None,
                net_api.delete_namespaced_network_policy,
                self.rollback_data["policy_name"],
                self.rollback_data["namespace"],
            )

            logger.info(
                "k8s_network_policy_rollback_success",
                extra={
                    "policy_name": self.rollback_data["policy_name"],
                    "namespace": self.rollback_data["namespace"],
                },
            )

            return True

        except Exception as e:
            logger.error(
                "k8s_network_policy_rollback_failed",
                extra={"error": str(e)},
            )
            return False


@register_k8s_action(["k8s-cluster-admin-binding"])
class RemoveClusterAdminBindingAction(RemediationAction):
    """Remove cluster-admin role binding from a service account or user."""

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_data: dict[str, Any],
        binding_name: str | None = None,
        dry_run: bool = False,
        **kwargs: Any,
    ):
        super().__init__(
            check_id=check_id,
            resource_id=resource_id,
            resource_type="ClusterRoleBinding",
            resource_data=resource_data,
            dry_run=dry_run,
        )
        self.binding_name = binding_name or resource_data.get("metadata", {}).get(
            "name", resource_id
        )

    def get_description(self) -> str:
        """Get description of this remediation."""
        return (
            f"Remove cluster-admin role binding {self.binding_name}. "
            f"This will revoke cluster-admin privileges from the associated service account or user. "
            f"Ensure the subject has appropriate alternative permissions before removing."
        )

    def get_risk_level(self) -> RiskLevel:
        """Get risk level."""
        return RiskLevel.CRITICAL  # Can break critical cluster operations

    async def validate(self) -> tuple[bool, str]:
        """Validate that cluster role binding can be removed."""
        if not K8S_AVAILABLE:
            return False, "Kubernetes SDK not available"

        try:
            loop = asyncio.get_event_loop()
            # Check if binding exists
            api = client.RbacAuthorizationV1Api()
            binding = await loop.run_in_executor(
                None, api.read_cluster_role_binding, self.binding_name
            )

            # Check if it's actually a cluster-admin binding
            if binding.role_ref.name != "cluster-admin":
                return False, f"Binding {self.binding_name} is not a cluster-admin binding"

            return True, f"Cluster-admin binding {self.binding_name} can be removed"

        except ApiException as e:
            return False, f"Cannot access cluster role binding: {e.reason}"
        except Exception as e:
            return False, f"Validation error: {e!s}"

    async def execute(self) -> RemediationResult:
        """Remove cluster-admin role binding."""
        changes_made: list[str] = []

        try:
            if self.dry_run:
                return self._create_result(
                    status=RemediationStatus.SUCCESS,
                    message=f"[DRY RUN] Would remove cluster-admin binding {self.binding_name}",
                    changes_made=[f"Delete ClusterRoleBinding {self.binding_name}"],
                )

            loop = asyncio.get_event_loop()
            api = client.RbacAuthorizationV1Api()

            # Get binding for rollback
            binding = await loop.run_in_executor(
                None, api.read_cluster_role_binding, self.binding_name
            )

            self.rollback_data = {
                "binding_name": self.binding_name,
                "binding": binding.to_dict(),
            }

            # Delete the binding
            await loop.run_in_executor(
                None, api.delete_cluster_role_binding, self.binding_name
            )

            changes_made.append(f"Removed cluster-admin binding {self.binding_name}")

            logger.info(
                "k8s_cluster_admin_binding_removed",
                extra={
                    "binding_name": self.binding_name,
                    "action_id": self.action_id,
                },
            )

            return self._create_result(
                status=RemediationStatus.SUCCESS,
                message=f"Successfully removed cluster-admin binding {self.binding_name}",
                changes_made=changes_made,
            )

        except ApiException as e:
            logger.error(
                "k8s_cluster_admin_binding_remove_failed",
                extra={
                    "binding_name": self.binding_name,
                    "error": e.reason,
                },
            )

            return self._create_result(
                status=RemediationStatus.FAILED,
                message=f"Failed to remove cluster-admin binding: {e.reason}",
                error=str(e),
            )
        except Exception as e:
            return self._create_result(
                status=RemediationStatus.FAILED,
                message="Unexpected error during remediation",
                error=str(e),
            )

    async def rollback(self) -> bool:
        """Rollback cluster role binding removal."""
        if not self.rollback_data:
            return True

        try:
            loop = asyncio.get_event_loop()
            api = client.RbacAuthorizationV1Api()

            # Recreate the binding
            binding_dict = self.rollback_data["binding"]
            binding = client.V1ClusterRoleBinding(
                api_version=binding_dict.get("api_version"),
                kind=binding_dict.get("kind"),
                metadata=client.V1ObjectMeta(**binding_dict.get("metadata", {})),
                role_ref=client.V1RoleRef(**binding_dict.get("role_ref", {})),
                subjects=[
                    client.V1Subject(**s) for s in binding_dict.get("subjects", [])
                ],
            )

            await loop.run_in_executor(None, api.create_cluster_role_binding, binding)

            logger.info(
                "k8s_cluster_admin_binding_rollback_success",
                extra={"binding_name": self.rollback_data["binding_name"]},
            )

            return True

        except Exception as e:
            logger.error(
                "k8s_cluster_admin_binding_rollback_failed",
                extra={"error": str(e)},
            )
            return False
