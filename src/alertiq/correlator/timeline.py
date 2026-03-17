"""AttackTimeline - Builds attack narrative from correlated alerts."""

from __future__ import annotations

from alertiq.models import Alert, Incident, TimelineEvent


class AttackTimeline:
    """Builds a chronological attack narrative from correlated alerts.

    Produces a sequence of TimelineEvent objects that describe the progression
    of an attack, mapping each step to MITRE ATT&CK tactics and techniques.
    """

    def build(self, incident: Incident) -> list[TimelineEvent]:
        """Build a timeline from an incident's alerts.

        Returns a sorted list of TimelineEvent objects.
        """
        events: list[TimelineEvent] = []

        for alert in sorted(incident.alerts, key=lambda a: a.timestamp):
            tactic_name = None
            technique_name = None

            if alert.mitre_tactics:
                tactic_name = alert.mitre_tactics[0].name
            if alert.mitre_techniques:
                technique_name = alert.mitre_techniques[0].name

            description = self._build_event_description(alert)

            event = TimelineEvent(
                timestamp=alert.timestamp,
                alert_id=alert.alert_id,
                description=description,
                tactic=tactic_name,
                technique=technique_name,
            )
            events.append(event)

        incident.timeline = events
        return events

    def _build_event_description(self, alert: Alert) -> str:
        """Build a human-readable description for a timeline event."""
        parts: list[str] = [alert.title]

        context_parts: list[str] = []
        if alert.source_ip:
            context_parts.append(f"src={alert.source_ip}")
        if alert.dest_ip:
            context_parts.append(f"dst={alert.dest_ip}")
        if alert.user:
            context_parts.append(f"user={alert.user}")
        if alert.hostname:
            context_parts.append(f"host={alert.hostname}")

        if context_parts:
            parts.append(f"[{', '.join(context_parts)}]")

        return " ".join(parts)

    def narrative(self, events: list[TimelineEvent]) -> str:
        """Generate a prose narrative of the attack timeline."""
        if not events:
            return "No events to narrate."

        lines: list[str] = ["Attack Timeline Narrative:", ""]
        for i, event in enumerate(events, 1):
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            tactic_info = f" ({event.tactic})" if event.tactic else ""
            technique_info = f" via {event.technique}" if event.technique else ""

            lines.append(
                f"  Step {i} [{ts}]{tactic_info}{technique_info}: {event.description}"
            )

        lines.append("")
        lines.append(f"Total events: {len(events)}")
        duration = events[-1].timestamp - events[0].timestamp
        lines.append(f"Duration: {duration}")

        return "\n".join(lines)
