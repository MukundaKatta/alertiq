"""CorrelationRule definitions for linking related alerts into incidents."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta

from alertiq.models import Alert, AlertCategory


class CorrelationRule(ABC):
    """Base class for alert correlation rules."""

    name: str = "base_rule"
    description: str = ""

    @abstractmethod
    def matches(self, alerts: list[Alert]) -> list[list[Alert]]:
        """Find groups of alerts that match this correlation rule.

        Returns a list of alert groups, each group forming a potential incident.
        """
        ...


class SameSourceMultiType(CorrelationRule):
    """Correlates alerts from the same source IP with different alert categories.

    Indicates a single attacker performing multiple types of attacks.
    """

    name = "same_source_multi_type"
    description = "Multiple alert types from the same source IP within time window"

    def __init__(self, time_window_seconds: int = 3600, min_categories: int = 2) -> None:
        self._window = timedelta(seconds=time_window_seconds)
        self._min_categories = min_categories

    def matches(self, alerts: list[Alert]) -> list[list[Alert]]:
        # Group by source IP
        by_ip: dict[str, list[Alert]] = {}
        for alert in alerts:
            if alert.source_ip:
                by_ip.setdefault(alert.source_ip, []).append(alert)

        groups: list[list[Alert]] = []
        for ip, ip_alerts in by_ip.items():
            sorted_alerts = sorted(ip_alerts, key=lambda a: a.timestamp)
            # Check time window and category diversity
            window_group: list[Alert] = []
            for alert in sorted_alerts:
                if window_group and alert.timestamp - window_group[0].timestamp > self._window:
                    self._check_and_add(window_group, groups)
                    window_group = [alert]
                else:
                    window_group.append(alert)
            self._check_and_add(window_group, groups)

        return groups

    def _check_and_add(self, window: list[Alert], groups: list[list[Alert]]) -> None:
        categories = {a.category for a in window if a.category}
        if len(categories) >= self._min_categories:
            groups.append(list(window))


class KillChainProgression(CorrelationRule):
    """Detects kill chain progression by tracking MITRE ATT&CK tactic sequences.

    Identifies when alerts progress through the cyber kill chain stages.
    """

    name = "kill_chain_progression"
    description = "Alerts progressing through MITRE ATT&CK kill chain stages"

    # Kill chain order by tactic ID
    KILL_CHAIN_ORDER = [
        "TA0001",  # Initial Access
        "TA0002",  # Execution
        "TA0003",  # Persistence
        "TA0004",  # Privilege Escalation
        "TA0005",  # Defense Evasion
        "TA0006",  # Credential Access
        "TA0007",  # Discovery
        "TA0008",  # Lateral Movement
        "TA0009",  # Collection
        "TA0010",  # Exfiltration
        "TA0011",  # Command and Control
        "TA0040",  # Impact
    ]

    def __init__(self, time_window_seconds: int = 7200, min_stages: int = 3) -> None:
        self._window = timedelta(seconds=time_window_seconds)
        self._min_stages = min_stages
        self._tactic_order = {tid: i for i, tid in enumerate(self.KILL_CHAIN_ORDER)}

    def matches(self, alerts: list[Alert]) -> list[list[Alert]]:
        # Group by user or source IP
        by_entity: dict[str, list[Alert]] = {}
        for alert in alerts:
            key = alert.user or alert.source_ip or "unknown"
            by_entity.setdefault(key, []).append(alert)

        groups: list[list[Alert]] = []
        for entity, entity_alerts in by_entity.items():
            if entity == "unknown":
                continue
            sorted_alerts = sorted(entity_alerts, key=lambda a: a.timestamp)
            # Collect tactics seen
            tactics_seen: set[str] = set()
            chain_alerts: list[Alert] = []
            for alert in sorted_alerts:
                for tactic in alert.mitre_tactics:
                    if tactic.tactic_id in self._tactic_order:
                        tactics_seen.add(tactic.tactic_id)
                        chain_alerts.append(alert)
                        break

            if len(tactics_seen) >= self._min_stages:
                # Verify chronological progression
                if self._is_progressive(chain_alerts):
                    groups.append(chain_alerts)

        return groups

    def _is_progressive(self, alerts: list[Alert]) -> bool:
        """Check if the tactic sequence shows forward progression."""
        last_stage = -1
        progressions = 0
        for alert in alerts:
            for tactic in alert.mitre_tactics:
                stage = self._tactic_order.get(tactic.tactic_id, -1)
                if stage > last_stage:
                    progressions += 1
                    last_stage = stage
                    break
        return progressions >= 2


class RepeatedFailures(CorrelationRule):
    """Correlates repeated authentication failures targeting the same entity.

    Detects brute force and credential stuffing attacks.
    """

    name = "repeated_failures"
    description = "Repeated authentication failures targeting same user or host"

    def __init__(self, time_window_seconds: int = 600, min_failures: int = 5) -> None:
        self._window = timedelta(seconds=time_window_seconds)
        self._min_failures = min_failures

    def matches(self, alerts: list[Alert]) -> list[list[Alert]]:
        # Filter to brute force category
        bf_alerts = [
            a for a in alerts
            if a.category == AlertCategory.BRUTE_FORCE
        ]

        # Group by target user
        by_user: dict[str, list[Alert]] = {}
        for alert in bf_alerts:
            key = alert.user or alert.dest_ip or "unknown"
            if key != "unknown":
                by_user.setdefault(key, []).append(alert)

        groups: list[list[Alert]] = []
        for user, user_alerts in by_user.items():
            sorted_alerts = sorted(user_alerts, key=lambda a: a.timestamp)
            window_group: list[Alert] = []
            for alert in sorted_alerts:
                if window_group and alert.timestamp - window_group[0].timestamp > self._window:
                    if len(window_group) >= self._min_failures:
                        groups.append(list(window_group))
                    window_group = [alert]
                else:
                    window_group.append(alert)
            if len(window_group) >= self._min_failures:
                groups.append(list(window_group))

        return groups


# Registry of all built-in correlation rules
DEFAULT_RULES: list[CorrelationRule] = [
    SameSourceMultiType(),
    KillChainProgression(),
    RepeatedFailures(),
]
