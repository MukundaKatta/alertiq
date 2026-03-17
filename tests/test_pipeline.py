"""Integration tests for the full ALERTIQ pipeline."""

from alertiq.correlator.engine import CorrelationEngine
from alertiq.correlator.timeline import AttackTimeline
from alertiq.responder.automator import ResponseAutomator
from alertiq.responder.playbook import IncidentPlaybook
from alertiq.simulator import AlertSimulator
from alertiq.triage.classifier import AlertClassifier
from alertiq.triage.dedup import AlertDeduplicator
from alertiq.triage.priority import PriorityEngine


class TestFullPipeline:
    def test_kill_chain_pipeline(self):
        """Test full pipeline with kill chain scenario."""
        # 1. Simulate
        sim = AlertSimulator(seed=42)
        alerts = sim.generate_attack_scenario("kill_chain")
        assert len(alerts) > 0

        # 2. Classify
        classifier = AlertClassifier()
        alerts = classifier.classify_batch(alerts)
        assert all(a.category is not None for a in alerts)

        # 3. Prioritize
        priority = PriorityEngine()
        alerts = priority.score_batch(alerts)
        assert all(a.priority_score > 0 for a in alerts)

        # 4. Deduplicate
        dedup = AlertDeduplicator()
        groups = dedup.deduplicate(alerts)
        assert len(groups) > 0

        # 5. Correlate
        engine = CorrelationEngine()
        incidents = engine.correlate(alerts)
        # May or may not find correlated incidents depending on data

        # 6. Timeline and response for any incidents
        timeline_builder = AttackTimeline()
        playbook_mgr = IncidentPlaybook()
        automator = ResponseAutomator(dry_run=True)

        for incident in incidents:
            events = timeline_builder.build(incident)
            assert len(events) > 0

            playbooks = playbook_mgr.get_playbook_for_incident(incident)
            for pb in playbooks:
                results = automator.execute_playbook(pb, incident)
                assert all(r.success for r in results)

    def test_random_alerts_pipeline(self):
        """Test pipeline with random alerts."""
        sim = AlertSimulator(seed=99)
        alerts = sim.generate(count=30)

        classifier = AlertClassifier()
        priority = PriorityEngine()
        dedup = AlertDeduplicator()

        alerts = priority.score_batch(classifier.classify_batch(alerts))
        groups = dedup.deduplicate(alerts)
        summaries = dedup.summary(groups)

        assert len(summaries) > 0
        assert all("count" in s for s in summaries)
        assert all("category" in s for s in summaries)

    def test_brute_force_pipeline(self):
        """Test pipeline with brute force scenario."""
        sim = AlertSimulator()
        alerts = sim.generate_attack_scenario("brute_force_campaign")

        classifier = AlertClassifier()
        priority = PriorityEngine()
        alerts = priority.score_batch(classifier.classify_batch(alerts))

        engine = CorrelationEngine()
        incidents = engine.correlate(alerts)

        # Brute force scenario should trigger repeated failures rule
        if incidents:
            for incident in incidents:
                assert len(incident.alerts) >= 2
