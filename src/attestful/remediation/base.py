"""
Base classes for automated remediation framework.

Provides the core abstractions for remediation actions including:
- Validation before execution
- Dry-run support
- Rollback capabilities
- Batch execution with concurrency control
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable
from uuid import uuid4

from attestful.core.logging import get_logger

logger = get_logger(__name__)


class RemediationStatus(str, Enum):
    """Status of a remediation action."""

    PENDING = "pending"
    VALIDATING = "validating"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"
    PARTIAL = "partial"  # Some changes made but not all


class RiskLevel(str, Enum):
    """Risk level for remediation actions."""

    LOW = "low"  # Safe, easily reversible changes
    MEDIUM = "medium"  # May affect functionality, reversible
    HIGH = "high"  # Significant impact, may affect availability
    CRITICAL = "critical"  # High risk, manual review recommended


@dataclass
class RemediationResult:
    """Result of a remediation action."""

    action_id: str
    check_id: str
    resource_id: str
    resource_type: str
    status: RemediationStatus
    message: str
    started_at: datetime
    completed_at: datetime | None = None
    error: str | None = None
    rollback_data: dict[str, Any] | None = None
    changes_made: list[str] = field(default_factory=list)
    dry_run: bool = False
    risk_level: RiskLevel = RiskLevel.LOW

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_id": self.action_id,
            "check_id": self.check_id,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "status": self.status.value,
            "message": self.message,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "changes_made": self.changes_made,
            "dry_run": self.dry_run,
            "risk_level": self.risk_level.value,
        }


class RemediationAction(ABC):
    """
    Abstract base class for remediation actions.

    All remediation actions must implement:
    - validate(): Check if remediation is safe to execute
    - execute(): Perform the actual remediation
    - rollback(): Undo changes if something goes wrong
    - get_description(): Human-readable description
    - get_risk_level(): Risk level of the action
    """

    def __init__(
        self,
        check_id: str,
        resource_id: str,
        resource_type: str,
        resource_data: dict[str, Any],
        dry_run: bool = False,
    ):
        """
        Initialize remediation action.

        Args:
            check_id: ID of the compliance check that failed
            resource_id: ID of the resource to remediate
            resource_type: Type of the resource
            resource_data: Current resource data
            dry_run: If True, only simulate the remediation
        """
        self.action_id = str(uuid4())
        self.check_id = check_id
        self.resource_id = resource_id
        self.resource_type = resource_type
        self.resource_data = resource_data
        self.dry_run = dry_run
        self.rollback_data: dict[str, Any] | None = None
        self._started_at: datetime | None = None

    @abstractmethod
    async def validate(self) -> tuple[bool, str]:
        """
        Validate that the remediation is safe to execute.

        Returns:
            Tuple of (is_valid, message)
        """
        pass

    @abstractmethod
    async def execute(self) -> RemediationResult:
        """
        Execute the remediation action.

        Returns:
            RemediationResult with status and details
        """
        pass

    @abstractmethod
    async def rollback(self) -> bool:
        """
        Rollback the remediation if something went wrong.

        Returns:
            True if rollback was successful, False otherwise
        """
        pass

    @abstractmethod
    def get_description(self) -> str:
        """
        Get a human-readable description of what this remediation will do.

        Returns:
            Description string
        """
        pass

    @abstractmethod
    def get_risk_level(self) -> RiskLevel:
        """
        Get the risk level of this remediation action.

        Returns:
            RiskLevel enum value
        """
        pass

    def _create_result(
        self,
        status: RemediationStatus,
        message: str,
        error: str | None = None,
        changes_made: list[str] | None = None,
    ) -> RemediationResult:
        """Create a remediation result."""
        return RemediationResult(
            action_id=self.action_id,
            check_id=self.check_id,
            resource_id=self.resource_id,
            resource_type=self.resource_type,
            status=status,
            message=message,
            started_at=self._started_at or datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            error=error,
            rollback_data=self.rollback_data,
            changes_made=changes_made or [],
            dry_run=self.dry_run,
            risk_level=self.get_risk_level(),
        )


@dataclass
class RemediationPlan:
    """
    A plan for remediating multiple compliance issues.

    Organizes actions by risk level and provides summary information.
    """

    actions: list[RemediationAction] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_action(self, action: RemediationAction) -> None:
        """Add an action to the plan."""
        self.actions.append(action)

    def get_actions_by_risk(self, risk_level: RiskLevel) -> list[RemediationAction]:
        """Get actions filtered by risk level."""
        return [a for a in self.actions if a.get_risk_level() == risk_level]

    def get_summary(self) -> dict[str, Any]:
        """Get plan summary."""
        by_risk = {
            "low": len(self.get_actions_by_risk(RiskLevel.LOW)),
            "medium": len(self.get_actions_by_risk(RiskLevel.MEDIUM)),
            "high": len(self.get_actions_by_risk(RiskLevel.HIGH)),
            "critical": len(self.get_actions_by_risk(RiskLevel.CRITICAL)),
        }

        by_resource_type: dict[str, int] = {}
        for action in self.actions:
            rt = action.resource_type
            by_resource_type[rt] = by_resource_type.get(rt, 0) + 1

        return {
            "total_actions": len(self.actions),
            "by_risk_level": by_risk,
            "by_resource_type": by_resource_type,
            "created_at": self.created_at.isoformat(),
        }


class RemediationEngine:
    """
    Engine for executing remediation actions with safety controls.

    Features:
    - Dry-run support
    - Approval workflow
    - Concurrent execution with limits
    - Automatic rollback on failure
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        require_approval: bool = True,
        approval_callback: Callable[[RemediationAction], bool] | None = None,
        max_risk_level: RiskLevel = RiskLevel.HIGH,
    ):
        """
        Initialize remediation engine.

        Args:
            max_concurrent: Maximum number of concurrent remediation actions
            require_approval: If True, require approval before executing
            approval_callback: Optional callback function for approval
            max_risk_level: Maximum risk level to auto-approve
        """
        self.max_concurrent = max_concurrent
        self.require_approval = require_approval
        self.approval_callback = approval_callback
        self.max_risk_level = max_risk_level
        self.results: list[RemediationResult] = []

    async def execute_action(
        self,
        action: RemediationAction,
        auto_approve: bool = False,
    ) -> RemediationResult:
        """
        Execute a single remediation action with safety checks.

        Args:
            action: The remediation action to execute
            auto_approve: If True, skip approval requirement

        Returns:
            RemediationResult
        """
        action._started_at = datetime.now(timezone.utc)

        logger.info(
            "remediation_action_starting",
            extra={
                "action_id": action.action_id,
                "check_id": action.check_id,
                "resource_id": action.resource_id,
                "dry_run": action.dry_run,
            },
        )

        try:
            # Step 1: Check risk level
            risk_level = action.get_risk_level()
            risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
            if risk_order.index(risk_level) > risk_order.index(self.max_risk_level):
                if not auto_approve:
                    logger.warning(
                        "remediation_risk_too_high",
                        extra={
                            "action_id": action.action_id,
                            "risk_level": risk_level.value,
                        },
                    )
                    return action._create_result(
                        status=RemediationStatus.SKIPPED,
                        message=f"Risk level {risk_level.value} exceeds maximum allowed {self.max_risk_level.value}",
                    )

            # Step 2: Validate the action
            is_valid, validation_message = await action.validate()
            if not is_valid:
                logger.warning(
                    "remediation_validation_failed",
                    extra={
                        "action_id": action.action_id,
                        "message": validation_message,
                    },
                )
                return action._create_result(
                    status=RemediationStatus.FAILED,
                    message=f"Validation failed: {validation_message}",
                )

            # Step 3: Check if approval is required
            if self.require_approval and not auto_approve and not action.dry_run:
                if self.approval_callback:
                    approved = self.approval_callback(action)
                    if not approved:
                        logger.info(
                            "remediation_not_approved",
                            extra={"action_id": action.action_id},
                        )
                        return action._create_result(
                            status=RemediationStatus.SKIPPED,
                            message="Remediation not approved by user",
                        )
                else:
                    logger.warning(
                        "remediation_requires_approval",
                        extra={"action_id": action.action_id},
                    )
                    return action._create_result(
                        status=RemediationStatus.SKIPPED,
                        message="Remediation requires approval but no callback provided",
                    )

            # Step 4: Execute the action
            result = await action.execute()

            # Step 5: Handle failures with rollback
            if result.status == RemediationStatus.FAILED and not action.dry_run:
                logger.warning(
                    "remediation_failed_attempting_rollback",
                    extra={"action_id": action.action_id},
                )
                rollback_success = await action.rollback()
                if rollback_success:
                    result.status = RemediationStatus.ROLLED_BACK
                    result.message += " (rolled back successfully)"
                    logger.info(
                        "remediation_rolled_back",
                        extra={"action_id": action.action_id},
                    )

            logger.info(
                "remediation_action_completed",
                extra={
                    "action_id": action.action_id,
                    "status": result.status.value,
                },
            )

            self.results.append(result)
            return result

        except Exception as e:
            logger.error(
                "remediation_action_error",
                extra={
                    "action_id": action.action_id,
                    "error": str(e),
                },
            )

            # Attempt rollback on exception
            if not action.dry_run:
                try:
                    await action.rollback()
                except Exception as rollback_error:
                    logger.error(
                        "remediation_rollback_failed",
                        extra={
                            "action_id": action.action_id,
                            "error": str(rollback_error),
                        },
                    )

            result = action._create_result(
                status=RemediationStatus.FAILED,
                message="Remediation failed with exception",
                error=str(e),
            )
            self.results.append(result)
            return result

    async def execute_batch(
        self,
        actions: list[RemediationAction],
        auto_approve: bool = False,
        stop_on_failure: bool = False,
    ) -> list[RemediationResult]:
        """
        Execute multiple remediation actions concurrently.

        Args:
            actions: List of remediation actions to execute
            auto_approve: If True, skip approval requirement
            stop_on_failure: If True, stop executing on first failure

        Returns:
            List of RemediationResults
        """
        logger.info(
            "remediation_batch_starting",
            extra={
                "action_count": len(actions),
                "auto_approve": auto_approve,
            },
        )

        if stop_on_failure:
            # Execute sequentially if we need to stop on failure
            results = []
            for action in actions:
                result = await self.execute_action(action, auto_approve=auto_approve)
                results.append(result)
                if result.status == RemediationStatus.FAILED:
                    logger.warning(
                        "remediation_batch_stopped_on_failure",
                        extra={"action_id": action.action_id},
                    )
                    # Mark remaining as skipped
                    for remaining in actions[len(results) :]:
                        results.append(
                            remaining._create_result(
                                status=RemediationStatus.SKIPPED,
                                message="Skipped due to previous failure",
                            )
                        )
                    break
            return results

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def execute_with_semaphore(action: RemediationAction) -> RemediationResult:
            async with semaphore:
                return await self.execute_action(action, auto_approve=auto_approve)

        # Execute all actions concurrently with limit
        results = await asyncio.gather(
            *[execute_with_semaphore(action) for action in actions],
            return_exceptions=True,
        )

        # Handle any exceptions that occurred
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "remediation_batch_action_exception",
                    extra={
                        "action_id": actions[i].action_id,
                        "error": str(result),
                    },
                )
                final_results.append(
                    actions[i]._create_result(
                        status=RemediationStatus.FAILED,
                        message="Exception during execution",
                        error=str(result),
                    )
                )
            else:
                final_results.append(result)

        logger.info(
            "remediation_batch_completed",
            extra={
                "total": len(final_results),
                "success": sum(1 for r in final_results if r.status == RemediationStatus.SUCCESS),
                "failed": sum(1 for r in final_results if r.status == RemediationStatus.FAILED),
                "skipped": sum(1 for r in final_results if r.status == RemediationStatus.SKIPPED),
            },
        )

        return final_results

    async def execute_plan(
        self,
        plan: RemediationPlan,
        auto_approve: bool = False,
        skip_high_risk: bool = True,
    ) -> list[RemediationResult]:
        """
        Execute a remediation plan.

        Executes actions in order of risk level (lowest first).

        Args:
            plan: The remediation plan to execute
            auto_approve: If True, skip approval requirement
            skip_high_risk: If True, skip high and critical risk actions

        Returns:
            List of RemediationResults
        """
        all_results = []

        # Execute in order of risk: low, medium, high, critical
        for risk_level in [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]:
            if skip_high_risk and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                # Mark high-risk actions as skipped
                for action in plan.get_actions_by_risk(risk_level):
                    all_results.append(
                        action._create_result(
                            status=RemediationStatus.SKIPPED,
                            message=f"Skipped due to {risk_level.value} risk level",
                        )
                    )
                continue

            actions = plan.get_actions_by_risk(risk_level)
            if actions:
                results = await self.execute_batch(actions, auto_approve=auto_approve)
                all_results.extend(results)

        return all_results

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all remediation results."""
        return {
            "total": len(self.results),
            "success": sum(1 for r in self.results if r.status == RemediationStatus.SUCCESS),
            "failed": sum(1 for r in self.results if r.status == RemediationStatus.FAILED),
            "rolled_back": sum(1 for r in self.results if r.status == RemediationStatus.ROLLED_BACK),
            "skipped": sum(1 for r in self.results if r.status == RemediationStatus.SKIPPED),
            "results": [r.to_dict() for r in self.results],
        }

    def clear_results(self) -> None:
        """Clear all stored results."""
        self.results = []
