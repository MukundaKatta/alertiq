"""Tests for correlation engine, rules, and timeline."""

from datetime import datetime, timedelta

from alertiq.correlator.engine import CorrelationEngine
from alertiq.correlator.rules import (
    KillChainProgression,
    RepeatedFailures,
    SameSourceMultiType,
)
from alertiq.correlator.timeline import AttackTimeline
from alertiq.models import Alert, AlertCategory, MITRETactic, Severity
from alertiq.triage.classifier import AlertClassifier
from alertiq.triage.priority import PriorityEngine


class TestSameSourceMultiType:
    def test_detects_multi_type_from_same_ip(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="IDS", title="Brute force", category=AlertCategory.BRUTE_FORCE, source_ip="10.0.1.1", timestamp=base_time),
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", timestamp=base_time + timedelta(minutes=10)),
            Alert(source="DLP", title="Data exfil", category=AlertCategory.DATA_EXFIL, source_ip="10.0.1.1", timestamp=base_time + timedelta(minutes=20)),
        ]
        rule = SameSourceMultiType(time_window_seconds=3600)
        groups = rule.matches(alerts)
        assert len(groups) == 1
        assert len(groups[0]) == 3

    def test_no_match_single_type(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="EDR", title="Malware 1", category=AlertCategory.MALWARE, source_ip="10.0.1.1", timestamp=base_time),
            Alert(source="EDR", title="Malware 2", category=AlertCategory.MALWARE, source_ip="10.0.1.1", timestamp=base_time + timedelta(minutes=5)),
        ]
        rule = SameSourceMultiType()
        groups = rule.matches(alerts)
        assert len(groups) == 0


class TestKillChainProgression:
    def test_detects_progression(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="Email", title="Phishing", user="jsmith", timestamp=base_time,
                  mitre_tactics=[MITRETactic(tactic_id="TA0001", name="Initial Access")]),
            Alert(source="EDR", title="Execution", user="jsmith", timestamp=base_time + timedelta(minutes=10),
                  mitre_tactics=[MITRETactic(tactic_id="TA0002", name="Execution")]),
            Alert(source="EDR", title="Persistence", user="jsmith", timestamp=base_time + timedelta(minutes=20),
                  mitre_tactics=[MITRETactic(tactic_id="TA0003", name="Persistence")]),
            Alert(source="IDS", title="Lateral Movement", user="jsmith", timestamp=base_time + timedelta(minutes=40),
                  mitre_tactics=[MITRETactic(tactic_id="TA0008", name="Lateral Movement")]),
        ]
        rule = KillChainProgression(min_stages=3)
        groups = rule.matches(alerts)
        assert len(groups) >= 1


class TestRepeatedFailures:
    def test_detects_brute_force(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="SIEM", title=f"Failed login {i}", category=AlertCategory.BRUTE_FORCE, user="admin", timestamp=base_time + timedelta(seconds=i * 10))
            for i in range(8)
        ]
        rule = RepeatedFailures(min_failures=5)
        groups = rule.matches(alerts)
        assert len(groups) == 1
        assert len(groups[0]) == 8

    def test_no_match_below_threshold(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="SIEM", title=f"Failed login {i}", category=AlertCategory.BRUTE_FORCE, user="admin", timestamp=base_time + timedelta(seconds=i * 10))
            for i in range(3)
        ]
        rule = RepeatedFailures(min_failures=5)
        groups = rule.matches(alerts)
        assert len(groups) == 0


class TestCorrelationEngine:
    def test_full_correlation(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="SIEM", title=f"Failed login {i}", category=AlertCategory.BRUTE_FORCE, source_ip="10.0.1.1", user="admin", timestamp=base_time + timedelta(seconds=i * 10))
            for i in range(6)
        ]
        # Add a different category from same IP
        alerts.append(Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", timestamp=base_time + timedelta(minutes=5)))

        engine = CorrelationEngine()
        incidents = engine.correlate(alerts)
        assert len(incidents) >= 1


class TestAttackTimeline:
    def test_build_timeline(self):
        from alertiq.models import Incident
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        incident = Incident(
            title="Test Incident",
            alerts=[
                Alert(source="EDR", title="Step 1", timestamp=base_time, mitre_tactics=[MITRETactic(tactic_id="TA0001", name="Initial Access")]),
                Alert(source="EDR", title="Step 2", timestamp=base_time + timedelta(minutes=10), mitre_tactics=[MITRETactic(tactic_id="TA0002", name="Execution")]),
            ],
        )
        timeline = AttackTimeline()
        events = timeline.build(incident)
        assert len(events) == 2
        assert events[0].tactic == "Initial Access"
        assert events[1].tactic == "Execution"

    def test_narrative(self):
        from alertiq.models import Incident
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        incident = Incident(
            title="Test",
            alerts=[
                Alert(source="EDR", title="Phishing email", timestamp=base_time, mitre_tactics=[MITRETactic(tactic_id="TA0001", name="Initial Access")]),
            ],
        )
        timeline = AttackTimeline()
        events = timeline.build(incident)
        narrative = timeline.narrative(events)
        assert "Attack Timeline Narrative" in narrative
        assert "Initial Access" in narrative
