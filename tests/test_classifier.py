"""Tests for AlertClassifier."""

from alertiq.models import Alert, AlertCategory
from alertiq.triage.classifier import AlertClassifier


class TestAlertClassifier:
    def setup_method(self):
        self.classifier = AlertClassifier()

    def test_classify_malware(self):
        alert = Alert(source="EDR", title="Malware detected: Trojan.GenericKD", description="Suspicious process execution.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.MALWARE
        assert len(result.mitre_tactics) > 0

    def test_classify_phishing(self):
        alert = Alert(source="Email Gateway", title="Phishing email detected", description="Spearphishing with attachment.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.PHISHING

    def test_classify_brute_force(self):
        alert = Alert(source="SIEM", title="Multiple failed login attempts", description="Brute force password attack detected.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.BRUTE_FORCE

    def test_classify_data_exfil(self):
        alert = Alert(source="DLP", title="Large data transfer to external host", description="Data exfiltration detected. Abnormal upload volume.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.DATA_EXFIL

    def test_classify_insider_threat(self):
        alert = Alert(source="SIEM", title="Unauthorized access to sensitive files", description="Anomalous access by non-authorized user.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.INSIDER_THREAT

    def test_classify_dos(self):
        alert = Alert(source="IDS", title="SYN flood attack detected", description="Denial of service attack on web server.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.DOS

    def test_classify_lateral_movement(self):
        alert = Alert(source="EDR", title="Pass-the-hash attack detected", description="Lateral movement via NTLM hash reuse.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.LATERAL_MOVEMENT

    def test_classify_batch(self):
        alerts = [
            Alert(source="EDR", title="Malware detected"),
            Alert(source="Email Gateway", title="Phishing email"),
            Alert(source="IDS", title="SYN flood DDoS attack"),
        ]
        results = self.classifier.classify_batch(alerts)
        assert len(results) == 3
        assert all(a.category is not None for a in results)

    def test_mitre_mapping_applied(self):
        alert = Alert(source="EDR", title="Ransomware behavior detected")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.MALWARE
        assert any(t.tactic_id == "TA0002" for t in result.mitre_tactics)

    def test_unknown_defaults_to_malware(self):
        alert = Alert(source="Unknown", title="Something happened", description="Generic event.")
        result = self.classifier.classify(alert)
        assert result.category == AlertCategory.MALWARE
