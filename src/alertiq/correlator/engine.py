"""CorrelationEngine - Links related alerts into incidents."""

from __future__ import annotations

from datetime import datetime

from alertiq.models import Alert, Incident, IncidentStatus, Severity
from alertiq.correlator.rules import CorrelationRule, DEFAULT_RULES


class CorrelationEngine:
    """Links alerts into incidents by IP, user, timeframe, and correlation rules.

    The engine applies a set of correlation rules to a batch of alerts and
    produces Incident objects grouping related alerts.
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules = rules or DEFAULT_RULES

    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        """Run all correlation rules and produce incidents.

        Args:
            alerts: List of triaged alerts to correlate.

        Returns:
            List of Incident objects, each containing correlated alerts.
        """
        incidents: list[Incident] = []
        correlated_ids: set[str] = set()

        for rule in self._rules:
            groups = rule.matches(alerts)
            for group in groups:
                # Skip alerts already correlated
                new_alerts = [a for a in group if a.alert_id not in correlated_ids]
                if len(new_alerts) < 2:
                    continue

                incident = self._build_incident(new_alerts, rule.name)
                incidents.append(incident)

                for alert in new_alerts:
                    alert.incident_id = incident.incident_id
                    correlated_ids.add(alert.alert_id)

        return incidents

    def _build_incident(self, alerts: list[Alert], rule_name: str) -> Incident:
        """Build an Incident from a group of correlated alerts."""
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

        # Collect affected entities
        hosts = list({a.hostname for a in alerts if a.hostname})
        users = list({a.user for a in alerts if a.user})
        ips = list(
            {ip for a in alerts for ip in [a.source_ip, a.dest_ip] if ip}
        )

        # Collect all MITRE tactics
        all_tactics = []
        seen_tactics: set[str] = set()
        for alert in alerts:
            for tactic in alert.mitre_tactics:
                if tactic.tactic_id not in seen_tactics:
                    all_tactics.append(tactic)
                    seen_tactics.add(tactic.tactic_id)

        # Determine incident severity from highest alert severity
        max_score = max(a.priority_score for a in alerts)
        categories = list({a.category.value for a in alerts if a.category})

        incident = Incident(
            title=f"Correlated Incident [{rule_name}]: {', '.join(categories)}",
            status=IncidentStatus.NEW,
            severity=self._score_to_severity(max_score),
            priority_score=max_score,
            alerts=sorted_alerts,
            correlation_rule=rule_name,
            affected_hosts=hosts,
            affected_users=users,
            affected_ips=ips,
            mitre_tactics=all_tactics,
        )
        return incident

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        if score >= 85:
            return Severity.CRITICAL
        if score >= 65:
            return Severity.HIGH
        if score >= 45:
            return Severity.MEDIUM
        if score >= 25:
            return Severity.LOW
        return Severity.INFO
