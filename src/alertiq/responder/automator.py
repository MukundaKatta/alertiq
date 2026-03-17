"""ResponseAutomator - Executes containment actions."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime

from alertiq.models import (
    Alert,
    ContainmentAction,
    Incident,
    IncidentStatus,
    Playbook,
    PlaybookStep,
)

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of executing a containment action."""

    action: ContainmentAction
    target: str
    success: bool
    timestamp: datetime = field(default_factory=datetime.utcnow)
    message: str = ""
    dry_run: bool = True


class ResponseAutomator:
    """Executes containment actions from playbooks.

    In production, this would integrate with firewalls, IAM systems, EDR
    platforms, etc. By default, operates in dry-run mode for safety.
    """

    def __init__(self, dry_run: bool = True) -> None:
        self._dry_run = dry_run
        self._action_log: list[ActionResult] = []

    @property
    def action_log(self) -> list[ActionResult]:
        """Get the log of executed actions."""
        return list(self._action_log)

    def execute_playbook(
        self, playbook: Playbook, incident: Incident, auto_only: bool = True
    ) -> list[ActionResult]:
        """Execute the automated steps of a playbook for an incident.

        Args:
            playbook: The response playbook to execute.
            incident: The incident to respond to.
            auto_only: If True, only execute automated steps.

        Returns:
            List of ActionResult objects.
        """
        results: list[ActionResult] = []

        for step in playbook.steps:
            if auto_only and not step.automated:
                continue
            if step.containment_action is None:
                continue

            targets = self._resolve_targets(step.containment_action, incident)
            for target in targets:
                result = self._execute_action(step.containment_action, target)
                results.append(result)
                self._action_log.append(result)

        # Update incident status
        if results:
            incident.status = IncidentStatus.CONTAINING
            incident.containment_actions = list(
                {r.action for r in results if r.success}
            )

        return results

    def _execute_action(self, action: ContainmentAction, target: str) -> ActionResult:
        """Execute a single containment action against a target."""
        if self._dry_run:
            msg = f"[DRY RUN] Would execute {action.value} on {target}"
            logger.info(msg)
            return ActionResult(
                action=action, target=target, success=True, message=msg, dry_run=True
            )

        # Production implementations would call actual APIs here
        handler = self._get_handler(action)
        return handler(action, target)

    def _get_handler(self, action: ContainmentAction):
        """Get the handler function for a containment action."""
        handlers = {
            ContainmentAction.BLOCK_IP: self._block_ip,
            ContainmentAction.DISABLE_ACCOUNT: self._disable_account,
            ContainmentAction.ISOLATE_HOST: self._isolate_host,
            ContainmentAction.QUARANTINE_FILE: self._quarantine_file,
            ContainmentAction.REVOKE_SESSION: self._revoke_session,
            ContainmentAction.BLOCK_DOMAIN: self._block_domain,
        }
        return handlers.get(action, self._noop)

    def _block_ip(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Blocking IP: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Blocked IP {target}", dry_run=False)

    def _disable_account(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Disabling account: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Disabled account {target}", dry_run=False)

    def _isolate_host(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Isolating host: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Isolated host {target}", dry_run=False)

    def _quarantine_file(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Quarantining file: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Quarantined file on {target}", dry_run=False)

    def _revoke_session(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Revoking session: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Revoked sessions for {target}", dry_run=False)

    def _block_domain(self, action: ContainmentAction, target: str) -> ActionResult:
        logger.info("Blocking domain: %s", target)
        return ActionResult(action=action, target=target, success=True, message=f"Blocked domain {target}", dry_run=False)

    def _noop(self, action: ContainmentAction, target: str) -> ActionResult:
        return ActionResult(action=action, target=target, success=False, message="No handler", dry_run=False)

    def _resolve_targets(self, action: ContainmentAction, incident: Incident) -> list[str]:
        """Resolve the targets for a containment action from incident data."""
        if action == ContainmentAction.BLOCK_IP:
            return incident.affected_ips[:5]  # limit to first 5
        elif action == ContainmentAction.DISABLE_ACCOUNT:
            return incident.affected_users[:5]
        elif action == ContainmentAction.ISOLATE_HOST:
            return incident.affected_hosts[:5]
        elif action == ContainmentAction.REVOKE_SESSION:
            return incident.affected_users[:5]
        elif action in (ContainmentAction.BLOCK_DOMAIN, ContainmentAction.QUARANTINE_FILE):
            return incident.affected_hosts[:3]
        return []
