"""Tests for PriorityEngine."""

from alertiq.models import Alert, AlertCategory, MITRETactic, Severity
from alertiq.triage.classifier import AlertClassifier
from alertiq.triage.priority import PriorityEngine


class TestPriorityEngine:
    def setup_method(self):
        self.classifier = AlertClassifier()
        self.engine = PriorityEngine()

    def test_score_malware(self):
        alert = Alert(source="EDR", title="Malware detected")
        alert = self.classifier.classify(alert)
        result = self.engine.score(alert)
        assert result.priority_score > 0
        assert result.severity in list(Severity)

    def test_score_data_exfil_high(self):
        alert = Alert(source="DLP", title="Data exfiltration detected", description="Large data transfer.")
        alert = self.classifier.classify(alert)
        result = self.engine.score(alert)
        assert result.priority_score >= 65  # data exfil base is 85 + tactic bonuses

    def test_score_with_external_ip(self):
        alert = Alert(source="IDS", title="Malware C2 beacon", source_ip="203.0.113.42")
        alert = self.classifier.classify(alert)
        result = self.engine.score(alert)
        # External IP should add bonus
        alert2 = Alert(source="IDS", title="Malware C2 beacon", source_ip="10.0.1.1")
        alert2 = self.classifier.classify(alert2)
        result2 = self.engine.score(alert2)
        assert result.priority_score > result2.priority_score

    def test_score_with_admin_user(self):
        alert = Alert(source="SIEM", title="Brute force attack", user="admin")
        alert = self.classifier.classify(alert)
        result = self.engine.score(alert)

        alert2 = Alert(source="SIEM", title="Brute force attack", user="jsmith")
        alert2 = self.classifier.classify(alert2)
        result2 = self.engine.score(alert2)
        assert result.priority_score > result2.priority_score

    def test_score_clamped_to_100(self):
        alert = Alert(
            source="EDR", title="Malware detected",
            source_ip="203.0.113.1", user="admin",
        )
        alert.category = AlertCategory.DATA_EXFIL
        alert.mitre_tactics = [
            MITRETactic(tactic_id="TA0010", name="Exfiltration"),
            MITRETactic(tactic_id="TA0040", name="Impact"),
            MITRETactic(tactic_id="TA0008", name="Lateral Movement"),
        ]
        alert.mitre_techniques = [
            # add more than 2 to trigger sophistication bonus
        ]
        result = self.engine.score(alert)
        assert result.priority_score <= 100.0

    def test_severity_mapping(self):
        engine = PriorityEngine()
        assert engine._score_to_severity(90) == Severity.CRITICAL
        assert engine._score_to_severity(70) == Severity.HIGH
        assert engine._score_to_severity(50) == Severity.MEDIUM
        assert engine._score_to_severity(30) == Severity.LOW
        assert engine._score_to_severity(10) == Severity.INFO

    def test_score_batch(self):
        alerts = [
            Alert(source="EDR", title="Malware detected"),
            Alert(source="IDS", title="SYN flood denial of service"),
        ]
        alerts = self.classifier.classify_batch(alerts)
        results = self.engine.score_batch(alerts)
        assert all(a.priority_score > 0 for a in results)
