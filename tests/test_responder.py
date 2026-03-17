"""Tests for playbooks and response automator."""

from alertiq.models import (
    Alert,
    AlertCategory,
    ContainmentAction,
    Incident,
    IncidentStatus,
    Severity,
)
from alertiq.responder.automator import ResponseAutomator
from alertiq.responder.playbook import IncidentPlaybook, PLAYBOOK_REGISTRY


class TestIncidentPlaybook:
    def test_all_categories_have_playbooks(self):
        for category in AlertCategory:
            assert category in PLAYBOOK_REGISTRY, f"No playbook for {category}"

    def test_get_playbook(self):
        mgr = IncidentPlaybook()
        pb = mgr.get_playbook(AlertCategory.MALWARE)
        assert pb is not None
        assert pb.name == "Malware Incident Response"
        assert len(pb.steps) > 0

    def test_get_playbook_for_incident(self):
        mgr = IncidentPlaybook()
        incident = Incident(
            title="Test",
            alerts=[
                Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE),
                Alert(source="IDS", title="Brute force", category=AlertCategory.BRUTE_FORCE),
            ],
        )
        playbooks = mgr.get_playbook_for_incident(incident)
        assert len(playbooks) == 2
        names = {pb.name for pb in playbooks}
        assert "Malware Incident Response" in names
        assert "Brute Force Incident Response" in names

    def test_playbook_has_automated_steps(self):
        mgr = IncidentPlaybook()
        for category in AlertCategory:
            pb = mgr.get_playbook(category)
            auto_steps = [s for s in pb.steps if s.automated]
            assert len(auto_steps) > 0, f"No automated steps for {category}"

    def test_list_playbooks(self):
        mgr = IncidentPlaybook()
        pbs = mgr.list_playbooks()
        assert len(pbs) == len(AlertCategory)


class TestResponseAutomator:
    def test_dry_run_execution(self):
        automator = ResponseAutomator(dry_run=True)
        incident = Incident(
            title="Test",
            affected_ips=["10.0.1.1"],
            affected_users=["admin"],
            affected_hosts=["SRV-01"],
            alerts=[Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE)],
        )
        mgr = IncidentPlaybook()
        pb = mgr.get_playbook(AlertCategory.MALWARE)
        results = automator.execute_playbook(pb, incident)
        assert len(results) > 0
        assert all(r.dry_run for r in results)
        assert all(r.success for r in results)

    def test_incident_status_updated(self):
        automator = ResponseAutomator(dry_run=True)
        incident = Incident(
            title="Test",
            affected_ips=["10.0.1.1"],
            affected_users=["admin"],
            affected_hosts=["SRV-01"],
            alerts=[Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE)],
        )
        mgr = IncidentPlaybook()
        pb = mgr.get_playbook(AlertCategory.MALWARE)
        automator.execute_playbook(pb, incident)
        assert incident.status == IncidentStatus.CONTAINING

    def test_action_log_preserved(self):
        automator = ResponseAutomator(dry_run=True)
        incident = Incident(
            title="Test",
            affected_ips=["10.0.1.1", "10.0.1.2"],
            affected_hosts=["SRV-01"],
            alerts=[Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE)],
        )
        mgr = IncidentPlaybook()
        pb = mgr.get_playbook(AlertCategory.MALWARE)
        automator.execute_playbook(pb, incident)
        assert len(automator.action_log) > 0
