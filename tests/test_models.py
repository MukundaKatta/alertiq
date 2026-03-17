"""Tests for ALERTIQ data models."""

from alertiq.models import (
    Alert,
    AlertCategory,
    CATEGORY_MITRE_MAP,
    ContainmentAction,
    Incident,
    IncidentStatus,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    MITRETactic,
    MITRETechnique,
    Playbook,
    PlaybookStep,
    Severity,
    TimelineEvent,
)


class TestAlert:
    def test_alert_creation(self):
        alert = Alert(source="EDR", title="Test alert")
        assert alert.alert_id.startswith("ALT-")
        assert alert.source == "EDR"
        assert alert.title == "Test alert"
        assert alert.severity == Severity.MEDIUM
        assert alert.priority_score == 0.0
        assert alert.category is None

    def test_alert_with_all_fields(self):
        alert = Alert(
            source="IDS",
            title="Malware detected",
            description="Trojan found",
            category=AlertCategory.MALWARE,
            severity=Severity.HIGH,
            priority_score=75.0,
            source_ip="10.0.1.1",
            dest_ip="10.0.2.1",
            user="admin",
            hostname="SRV-01",
        )
        assert alert.category == AlertCategory.MALWARE
        assert alert.severity == Severity.HIGH
        assert alert.source_ip == "10.0.1.1"
        assert alert.user == "admin"


class TestIncident:
    def test_incident_creation(self):
        incident = Incident(title="Test incident")
        assert incident.incident_id.startswith("INC-")
        assert incident.status == IncidentStatus.NEW
        assert incident.alerts == []

    def test_incident_with_alerts(self):
        alert1 = Alert(source="EDR", title="Alert 1")
        alert2 = Alert(source="IDS", title="Alert 2")
        incident = Incident(
            title="Multi-alert incident",
            alerts=[alert1, alert2],
            affected_hosts=["SRV-01"],
            affected_users=["admin"],
        )
        assert len(incident.alerts) == 2
        assert "SRV-01" in incident.affected_hosts


class TestMITRE:
    def test_mitre_tactics_coverage(self):
        assert "TA0001" in MITRE_TACTICS
        assert "TA0008" in MITRE_TACTICS
        assert "TA0040" in MITRE_TACTICS
        assert len(MITRE_TACTICS) == 12

    def test_mitre_techniques_exist(self):
        assert "T1566" in MITRE_TECHNIQUES
        assert "T1110" in MITRE_TECHNIQUES
        assert MITRE_TECHNIQUES["T1566"].name == "Phishing"

    def test_category_mitre_map_completeness(self):
        for category in AlertCategory:
            assert category in CATEGORY_MITRE_MAP, f"Missing MITRE mapping for {category}"
            mapping = CATEGORY_MITRE_MAP[category]
            assert "tactics" in mapping
            assert "techniques" in mapping
            assert len(mapping["tactics"]) > 0
            assert len(mapping["techniques"]) > 0


class TestPlaybook:
    def test_playbook_creation(self):
        step = PlaybookStep(
            step_number=1,
            action="Block IP",
            description="Block the source IP",
            automated=True,
            containment_action=ContainmentAction.BLOCK_IP,
        )
        playbook = Playbook(
            name="Test Playbook",
            category=AlertCategory.BRUTE_FORCE,
            steps=[step],
        )
        assert playbook.name == "Test Playbook"
        assert len(playbook.steps) == 1
        assert playbook.steps[0].automated is True


class TestEnums:
    def test_all_alert_categories(self):
        expected = {"malware", "phishing", "brute_force", "data_exfil", "insider_threat", "dos", "lateral_movement"}
        actual = {c.value for c in AlertCategory}
        assert actual == expected

    def test_severity_levels(self):
        expected = {"critical", "high", "medium", "low", "info"}
        actual = {s.value for s in Severity}
        assert actual == expected

    def test_containment_actions(self):
        expected = {"block_ip", "disable_account", "isolate_host", "quarantine_file", "revoke_session", "block_domain"}
        actual = {a.value for a in ContainmentAction}
        assert actual == expected
