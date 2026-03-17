"""Rich incident reporting for ALERTIQ."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from alertiq.models import Alert, Incident, Severity, TimelineEvent


_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class IncidentReporter:
    """Generates rich formatted incident reports."""

    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console()

    def report_alert(self, alert: Alert) -> None:
        """Print a formatted single alert report."""
        color = _SEVERITY_COLORS.get(alert.severity, "white")
        title = f"Alert: {alert.alert_id}"

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Field", style="bold cyan", width=20)
        table.add_column("Value")

        table.add_row("Title", alert.title)
        table.add_row("Source", alert.source)
        table.add_row("Timestamp", alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"))
        table.add_row("Category", alert.category.value if alert.category else "Unclassified")
        table.add_row("Severity", Text(alert.severity.value.upper(), style=color))
        table.add_row("Priority Score", f"{alert.priority_score:.1f}/100")
        if alert.source_ip:
            table.add_row("Source IP", alert.source_ip)
        if alert.dest_ip:
            table.add_row("Dest IP", alert.dest_ip)
        if alert.user:
            table.add_row("User", alert.user)
        if alert.hostname:
            table.add_row("Hostname", alert.hostname)

        if alert.mitre_tactics:
            tactics = ", ".join(f"{t.name} ({t.tactic_id})" for t in alert.mitre_tactics)
            table.add_row("MITRE Tactics", tactics)
        if alert.mitre_techniques:
            techniques = ", ".join(f"{t.name} ({t.technique_id})" for t in alert.mitre_techniques)
            table.add_row("MITRE Techniques", techniques)

        if alert.description:
            table.add_row("Description", alert.description)

        self._console.print(Panel(table, title=title, border_style=color))

    def report_incident(self, incident: Incident) -> None:
        """Print a formatted incident report with all details."""
        color = _SEVERITY_COLORS.get(incident.severity, "white")

        # Header
        self._console.print()
        self._console.print(
            Panel(
                f"[bold]{incident.title}[/bold]",
                title=f"Incident Report: {incident.incident_id}",
                subtitle=f"Status: {incident.status.value} | Severity: {incident.severity.value.upper()}",
                border_style=color,
            )
        )

        # Summary table
        summary = Table(title="Incident Summary", show_header=False, box=None, padding=(0, 2))
        summary.add_column("Field", style="bold cyan", width=20)
        summary.add_column("Value")
        summary.add_row("Created", incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
        summary.add_row("Priority Score", f"{incident.priority_score:.1f}/100")
        summary.add_row("Correlation Rule", incident.correlation_rule or "N/A")
        summary.add_row("Alert Count", str(len(incident.alerts)))
        summary.add_row("Affected Hosts", ", ".join(incident.affected_hosts) or "N/A")
        summary.add_row("Affected Users", ", ".join(incident.affected_users) or "N/A")
        summary.add_row("Affected IPs", ", ".join(incident.affected_ips) or "N/A")

        if incident.mitre_tactics:
            tactics = ", ".join(f"{t.name} ({t.tactic_id})" for t in incident.mitre_tactics)
            summary.add_row("MITRE Tactics", tactics)

        if incident.containment_actions:
            actions = ", ".join(a.value for a in incident.containment_actions)
            summary.add_row("Containment", actions)

        self._console.print(summary)
        self._console.print()

        # Alert table
        alert_table = Table(title="Correlated Alerts")
        alert_table.add_column("ID", style="cyan", width=14)
        alert_table.add_column("Time", width=20)
        alert_table.add_column("Category", width=16)
        alert_table.add_column("Severity", width=10)
        alert_table.add_column("Title", width=40)
        alert_table.add_column("Source", width=10)

        for alert in sorted(incident.alerts, key=lambda a: a.timestamp):
            sev_color = _SEVERITY_COLORS.get(alert.severity, "white")
            alert_table.add_row(
                alert.alert_id,
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                alert.category.value if alert.category else "N/A",
                Text(alert.severity.value, style=sev_color),
                alert.title[:40],
                alert.source,
            )

        self._console.print(alert_table)
        self._console.print()

    def report_timeline(self, events: list[TimelineEvent]) -> None:
        """Print an attack timeline as a tree."""
        if not events:
            self._console.print("[dim]No timeline events.[/dim]")
            return

        tree = Tree("[bold]Attack Timeline[/bold]")
        for i, event in enumerate(events, 1):
            ts = event.timestamp.strftime("%H:%M:%S")
            tactic = f" [yellow]({event.tactic})[/yellow]" if event.tactic else ""
            technique = f" via [cyan]{event.technique}[/cyan]" if event.technique else ""
            tree.add(f"[bold]{ts}[/bold]{tactic}{technique} - {event.description}")

        self._console.print(tree)
        self._console.print()

    def report_triage_summary(self, alerts: list[Alert]) -> None:
        """Print a triage summary table for a batch of alerts."""
        table = Table(title="Triage Summary")
        table.add_column("ID", style="cyan", width=14)
        table.add_column("Time", width=20)
        table.add_column("Category", width=16)
        table.add_column("Severity", width=10)
        table.add_column("Score", width=8, justify="right")
        table.add_column("Title", width=40)
        table.add_column("MITRE Tactics", width=25)

        for alert in sorted(alerts, key=lambda a: -a.priority_score):
            sev_color = _SEVERITY_COLORS.get(alert.severity, "white")
            tactics = ", ".join(t.tactic_id for t in alert.mitre_tactics[:3])
            table.add_row(
                alert.alert_id,
                alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                alert.category.value if alert.category else "N/A",
                Text(alert.severity.value, style=sev_color),
                f"{alert.priority_score:.1f}",
                alert.title[:40],
                tactics,
            )

        self._console.print(table)
        self._console.print()

    def report_dedup_summary(self, groups: list[dict[str, object]]) -> None:
        """Print deduplication summary."""
        table = Table(title="Deduplicated Alert Groups")
        table.add_column("Group Key", width=35)
        table.add_column("Count", width=6, justify="right")
        table.add_column("Category", width=16)
        table.add_column("Max Severity", width=12)
        table.add_column("Max Score", width=10, justify="right")
        table.add_column("First Seen", width=20)
        table.add_column("Last Seen", width=20)

        for group in groups:
            table.add_row(
                str(group["dedup_key"])[:35],
                str(group["count"]),
                str(group["category"]),
                str(group["max_severity"]),
                str(group["max_priority"]),
                str(group["first_seen"])[:19],
                str(group["last_seen"])[:19],
            )

        self._console.print(table)
        self._console.print()
