"""AlertDeduplicator - Groups related alerts to reduce noise."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from alertiq.models import Alert


class AlertDeduplicator:
    """Groups related alerts using content-based deduplication keys.

    Alerts are considered duplicates if they share the same category, source IP
    or user, and occur within a configurable time window.
    """

    def __init__(self, time_window_seconds: int = 300) -> None:
        """Initialize deduplicator.

        Args:
            time_window_seconds: Window in seconds for grouping related alerts.
        """
        self._window = timedelta(seconds=time_window_seconds)

    def compute_dedup_key(self, alert: Alert) -> str:
        """Compute a deduplication key for an alert.

        Key components: category + source_ip/user + hostname.
        """
        parts = [
            str(alert.category.value) if alert.category else "unknown",
            alert.source_ip or "no_ip",
            alert.user or "no_user",
            alert.hostname or "no_host",
        ]
        return "|".join(parts)

    def deduplicate(self, alerts: list[Alert]) -> dict[str, list[Alert]]:
        """Group alerts by dedup key within the time window.

        Returns a dict mapping dedup_key -> list of grouped alerts.
        """
        # Assign dedup keys
        for alert in alerts:
            alert.dedup_key = self.compute_dedup_key(alert)

        # Group by key
        groups: dict[str, list[Alert]] = defaultdict(list)
        for alert in sorted(alerts, key=lambda a: a.timestamp):
            groups[alert.dedup_key].append(alert)

        # Apply time window: split groups that span too long
        result: dict[str, list[Alert]] = {}
        for key, group in groups.items():
            subgroups = self._split_by_window(group)
            for i, subgroup in enumerate(subgroups):
                subkey = f"{key}#{i}" if len(subgroups) > 1 else key
                for alert in subgroup:
                    alert.dedup_key = subkey
                result[subkey] = subgroup

        return result

    def _split_by_window(self, alerts: list[Alert]) -> list[list[Alert]]:
        """Split a sorted list of alerts into sub-groups by time window."""
        if not alerts:
            return []

        subgroups: list[list[Alert]] = [[alerts[0]]]
        for alert in alerts[1:]:
            if alert.timestamp - subgroups[-1][0].timestamp <= self._window:
                subgroups[-1].append(alert)
            else:
                subgroups.append([alert])
        return subgroups

    def get_representative(self, group: list[Alert]) -> Alert:
        """Select the most representative alert from a group.

        Picks the alert with the highest priority score.
        """
        return max(group, key=lambda a: a.priority_score)

    def summary(self, groups: dict[str, list[Alert]]) -> list[dict[str, object]]:
        """Produce a summary of deduplicated alert groups."""
        summaries = []
        for key, group in groups.items():
            rep = self.get_representative(group)
            summaries.append({
                "dedup_key": key,
                "count": len(group),
                "representative_alert_id": rep.alert_id,
                "category": rep.category.value if rep.category else "unknown",
                "max_severity": rep.severity.value,
                "max_priority": rep.priority_score,
                "first_seen": group[0].timestamp.isoformat(),
                "last_seen": group[-1].timestamp.isoformat(),
            })
        return summaries
