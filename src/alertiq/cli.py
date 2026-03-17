"""ALERTIQ CLI - Click-based command line interface."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console

from alertiq.correlator.engine import CorrelationEngine
from alertiq.correlator.timeline import AttackTimeline
from alertiq.models import Alert, AlertCategory
from alertiq.report import IncidentReporter
from alertiq.responder.automator import ResponseAutomator
from alertiq.responder.playbook import IncidentPlaybook
from alertiq.simulator import AlertSimulator
from alertiq.triage.classifier import AlertClassifier
from alertiq.triage.dedup import AlertDeduplicator
from alertiq.triage.priority import PriorityEngine

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="alertiq")
def cli() -> None:
    """ALERTIQ - AI-powered SOC Analyst for security alert triage."""
    pass


@cli.command()
@click.option("--count", "-n", default=10, help="Number of alerts to simulate.")
@click.option("--scenario", "-s", type=click.Choice(["random", "kill_chain", "brute_force_campaign", "data_breach"]), default="random", help="Attack scenario to simulate.")
@click.option("--seed", type=int, default=None, help="Random seed for reproducible output.")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file path (JSON).")
def simulate(count: int, scenario: str, seed: int | None, output: str | None) -> None:
    """Simulate security alerts for testing."""
    sim = AlertSimulator(seed=seed)

    if scenario == "random":
        alerts = sim.generate(count=count)
        console.print(f"[bold green]Generated {len(alerts)} random alerts[/bold green]")
    else:
        alerts = sim.generate_attack_scenario(scenario)
        console.print(f"[bold green]Generated {len(alerts)} alerts for '{scenario}' scenario[/bold green]")

    reporter = IncidentReporter(console)
    for alert in alerts:
        reporter.report_alert(alert)

    if output:
        data = [a.model_dump(mode="json") for a in alerts]
        with open(output, "w") as f:
            json.dump(data, f, indent=2, default=str)
        console.print(f"[green]Saved to {output}[/green]")


@cli.command()
@click.option("--input", "-i", "input_file", type=click.Path(exists=True), default=None, help="Input alerts JSON file.")
@click.option("--count", "-n", default=10, help="Number of alerts to simulate if no input.")
@click.option("--seed", type=int, default=None, help="Random seed.")
def triage(input_file: str | None, count: int, seed: int | None) -> None:
    """Triage alerts: classify, prioritize, and deduplicate."""
    alerts = _load_or_simulate(input_file, count, seed)

    classifier = AlertClassifier()
    priority = PriorityEngine()
    dedup = AlertDeduplicator()

    console.print("[bold]Classifying alerts...[/bold]")
    alerts = classifier.classify_batch(alerts)

    console.print("[bold]Scoring priorities...[/bold]")
    alerts = priority.score_batch(alerts)

    console.print("[bold]Deduplicating...[/bold]")
    groups = dedup.deduplicate(alerts)
    summaries = dedup.summary(groups)

    reporter = IncidentReporter(console)
    reporter.report_triage_summary(alerts)
    reporter.report_dedup_summary(summaries)

    console.print(f"[bold green]Triaged {len(alerts)} alerts into {len(groups)} groups[/bold green]")


@cli.command()
@click.option("--input", "-i", "input_file", type=click.Path(exists=True), default=None, help="Input alerts JSON file.")
@click.option("--count", "-n", default=20, help="Number of alerts to simulate if no input.")
@click.option("--window", "-w", default=3600, help="Correlation time window in seconds.")
@click.option("--seed", type=int, default=None, help="Random seed.")
def correlate(input_file: str | None, count: int, window: int, seed: int | None) -> None:
    """Correlate alerts into incidents."""
    alerts = _load_or_simulate(input_file, count, seed)

    # Triage first
    classifier = AlertClassifier()
    priority = PriorityEngine()
    alerts = priority.score_batch(classifier.classify_batch(alerts))

    engine = CorrelationEngine()
    incidents = engine.correlate(alerts)

    reporter = IncidentReporter(console)
    timeline_builder = AttackTimeline()

    if not incidents:
        console.print("[yellow]No correlated incidents found.[/yellow]")
        return

    for incident in incidents:
        events = timeline_builder.build(incident)
        reporter.report_incident(incident)
        reporter.report_timeline(events)

    console.print(f"[bold green]Found {len(incidents)} correlated incidents from {len(alerts)} alerts[/bold green]")


@cli.command()
@click.option("--scenario", "-s", type=click.Choice(["kill_chain", "brute_force_campaign", "data_breach"]), default="kill_chain", help="Attack scenario.")
@click.option("--auto-respond/--no-auto-respond", default=True, help="Execute automated containment.")
def run(scenario: str, auto_respond: bool) -> None:
    """Run full pipeline: simulate -> triage -> correlate -> respond -> report."""
    console.print(f"[bold]Running full ALERTIQ pipeline for '{scenario}' scenario[/bold]")
    console.print()

    # 1. Simulate
    sim = AlertSimulator(seed=42)
    alerts = sim.generate_attack_scenario(scenario)
    console.print(f"[green]1. Simulated {len(alerts)} alerts[/green]")

    # 2. Triage
    classifier = AlertClassifier()
    priority = PriorityEngine()
    alerts = priority.score_batch(classifier.classify_batch(alerts))
    console.print(f"[green]2. Triaged {len(alerts)} alerts[/green]")

    reporter = IncidentReporter(console)
    reporter.report_triage_summary(alerts)

    # 3. Correlate
    engine = CorrelationEngine()
    incidents = engine.correlate(alerts)
    console.print(f"[green]3. Correlated into {len(incidents)} incidents[/green]")

    # 4. Timeline + Report
    timeline_builder = AttackTimeline()
    playbook_mgr = IncidentPlaybook()
    automator = ResponseAutomator(dry_run=True)

    for incident in incidents:
        events = timeline_builder.build(incident)
        reporter.report_incident(incident)
        reporter.report_timeline(events)

        console.print(f"[bold]Narrative:[/bold]")
        console.print(timeline_builder.narrative(events))
        console.print()

        # 5. Respond
        if auto_respond:
            playbooks = playbook_mgr.get_playbook_for_incident(incident)
            for pb in playbooks:
                console.print(f"[bold yellow]Executing playbook: {pb.name}[/bold yellow]")
                results = automator.execute_playbook(pb, incident)
                for r in results:
                    status = "[green]OK[/green]" if r.success else "[red]FAIL[/red]"
                    console.print(f"  {status} {r.action.value} -> {r.target} ({r.message})")
                console.print()

    # If no incidents were correlated, still show individual alerts
    if not incidents:
        console.print("[yellow]No incidents correlated. Showing individual alerts:[/yellow]")
        for alert in alerts:
            reporter.report_alert(alert)

    console.print("[bold green]Pipeline complete.[/bold green]")


@cli.command("list-playbooks")
def list_playbooks() -> None:
    """List all available response playbooks."""
    playbook_mgr = IncidentPlaybook()
    playbooks = playbook_mgr.list_playbooks()

    for pb in playbooks:
        console.print(f"\n[bold]{pb.name}[/bold] ({pb.category.value})")
        console.print(f"  {pb.description}")
        console.print(f"  Severity threshold: {pb.severity_threshold.value}")
        console.print(f"  MITRE Tactics: {', '.join(pb.mitre_tactics)}")
        console.print(f"  Steps:")
        for step in pb.steps:
            auto_tag = " [auto]" if step.automated else ""
            console.print(f"    {step.step_number}. {step.action}{auto_tag}: {step.description}")


def _load_or_simulate(input_file: str | None, count: int, seed: int | None) -> list[Alert]:
    """Load alerts from file or simulate them."""
    if input_file:
        with open(input_file) as f:
            data = json.load(f)
        alerts = [Alert(**item) for item in data]
        console.print(f"[green]Loaded {len(alerts)} alerts from {input_file}[/green]")
    else:
        sim = AlertSimulator(seed=seed)
        alerts = sim.generate(count=count)
        console.print(f"[green]Simulated {len(alerts)} alerts[/green]")
    return alerts


if __name__ == "__main__":
    cli()
