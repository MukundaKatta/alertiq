"""IncidentPlaybook - Response steps per alert type."""

from __future__ import annotations

from alertiq.models import (
    AlertCategory,
    ContainmentAction,
    Playbook,
    PlaybookStep,
    Severity,
)


def _malware_playbook() -> Playbook:
    return Playbook(
        name="Malware Incident Response",
        category=AlertCategory.MALWARE,
        description="Response playbook for malware infections including trojans, ransomware, and backdoors.",
        severity_threshold=Severity.MEDIUM,
        mitre_tactics=["TA0002", "TA0003", "TA0005", "TA0011"],
        steps=[
            PlaybookStep(step_number=1, action="Isolate Host", description="Immediately isolate the infected host from the network to prevent lateral spread.", automated=True, containment_action=ContainmentAction.ISOLATE_HOST),
            PlaybookStep(step_number=2, action="Quarantine File", description="Quarantine the malicious file or binary identified in the alert.", automated=True, containment_action=ContainmentAction.QUARANTINE_FILE),
            PlaybookStep(step_number=3, action="Block C2", description="Block the command-and-control domain or IP address at the firewall.", automated=True, containment_action=ContainmentAction.BLOCK_DOMAIN),
            PlaybookStep(step_number=4, action="Collect Forensic Evidence", description="Capture memory dump and disk image of the infected host for analysis."),
            PlaybookStep(step_number=5, action="Scan Related Hosts", description="Run antivirus/EDR scans on hosts that communicated with the infected system."),
            PlaybookStep(step_number=6, action="Reset Credentials", description="Reset credentials for any user accounts active on the infected host."),
            PlaybookStep(step_number=7, action="Restore and Verify", description="Reimage or restore the host from a known-good backup and verify clean state."),
        ],
    )


def _phishing_playbook() -> Playbook:
    return Playbook(
        name="Phishing Incident Response",
        category=AlertCategory.PHISHING,
        description="Response playbook for phishing attacks including spearphishing with attachments and links.",
        severity_threshold=Severity.MEDIUM,
        mitre_tactics=["TA0001"],
        steps=[
            PlaybookStep(step_number=1, action="Block Sender", description="Block the phishing sender email address and domain.", automated=True, containment_action=ContainmentAction.BLOCK_DOMAIN),
            PlaybookStep(step_number=2, action="Remove Emails", description="Search for and remove all instances of the phishing email from user mailboxes."),
            PlaybookStep(step_number=3, action="Revoke Sessions", description="Revoke active sessions for any users who clicked the phishing link.", automated=True, containment_action=ContainmentAction.REVOKE_SESSION),
            PlaybookStep(step_number=4, action="Reset Credentials", description="Force password reset for users who entered credentials on the phishing page.", automated=True, containment_action=ContainmentAction.DISABLE_ACCOUNT),
            PlaybookStep(step_number=5, action="Scan Attachments", description="Submit any attachments to sandbox for detonation analysis."),
            PlaybookStep(step_number=6, action="Notify Users", description="Send notification to affected users about the phishing campaign."),
        ],
    )


def _brute_force_playbook() -> Playbook:
    return Playbook(
        name="Brute Force Incident Response",
        category=AlertCategory.BRUTE_FORCE,
        description="Response playbook for brute force and credential stuffing attacks.",
        severity_threshold=Severity.MEDIUM,
        mitre_tactics=["TA0006"],
        steps=[
            PlaybookStep(step_number=1, action="Block Source IP", description="Block the attacking source IP address at the perimeter firewall.", automated=True, containment_action=ContainmentAction.BLOCK_IP),
            PlaybookStep(step_number=2, action="Lock Target Accounts", description="Temporarily lock accounts that were targeted by the brute force attack.", automated=True, containment_action=ContainmentAction.DISABLE_ACCOUNT),
            PlaybookStep(step_number=3, action="Review Auth Logs", description="Analyze authentication logs for successful logins from the attacker IP."),
            PlaybookStep(step_number=4, action="Check Compromised Accounts", description="Verify if any targeted accounts were successfully compromised."),
            PlaybookStep(step_number=5, action="Enforce MFA", description="Ensure multi-factor authentication is enabled for all targeted accounts."),
            PlaybookStep(step_number=6, action="Reset Passwords", description="Force password reset for any compromised or potentially compromised accounts."),
        ],
    )


def _data_exfil_playbook() -> Playbook:
    return Playbook(
        name="Data Exfiltration Incident Response",
        category=AlertCategory.DATA_EXFIL,
        description="Response playbook for data exfiltration incidents.",
        severity_threshold=Severity.HIGH,
        mitre_tactics=["TA0009", "TA0010"],
        steps=[
            PlaybookStep(step_number=1, action="Block Destination", description="Block the exfiltration destination IP/domain.", automated=True, containment_action=ContainmentAction.BLOCK_IP),
            PlaybookStep(step_number=2, action="Isolate Source Host", description="Isolate the host performing the exfiltration.", automated=True, containment_action=ContainmentAction.ISOLATE_HOST),
            PlaybookStep(step_number=3, action="Disable User Account", description="Disable the user account involved in the exfiltration.", automated=True, containment_action=ContainmentAction.DISABLE_ACCOUNT),
            PlaybookStep(step_number=4, action="Assess Data Scope", description="Determine what data was accessed and potentially exfiltrated."),
            PlaybookStep(step_number=5, action="Preserve Evidence", description="Capture network traffic logs and host forensic artifacts."),
            PlaybookStep(step_number=6, action="Legal Notification", description="Engage legal counsel for breach notification requirements."),
            PlaybookStep(step_number=7, action="Monitor for Further Activity", description="Set up enhanced monitoring for the compromised accounts and systems."),
        ],
    )


def _insider_threat_playbook() -> Playbook:
    return Playbook(
        name="Insider Threat Incident Response",
        category=AlertCategory.INSIDER_THREAT,
        description="Response playbook for insider threat incidents.",
        severity_threshold=Severity.HIGH,
        mitre_tactics=["TA0009", "TA0010", "TA0006"],
        steps=[
            PlaybookStep(step_number=1, action="Enhanced Monitoring", description="Enable enhanced monitoring and logging for the suspect user."),
            PlaybookStep(step_number=2, action="Revoke Elevated Access", description="Revoke any elevated or unnecessary access permissions.", automated=True, containment_action=ContainmentAction.REVOKE_SESSION),
            PlaybookStep(step_number=3, action="Preserve Evidence", description="Preserve all audit logs, email records, and file access logs."),
            PlaybookStep(step_number=4, action="Coordinate with HR", description="Engage HR and legal for investigation coordination."),
            PlaybookStep(step_number=5, action="Assess Data Access", description="Review all data accessed by the suspect user in the relevant timeframe."),
            PlaybookStep(step_number=6, action="Disable Account", description="Disable the user account if risk level warrants immediate action.", automated=True, containment_action=ContainmentAction.DISABLE_ACCOUNT),
        ],
    )


def _dos_playbook() -> Playbook:
    return Playbook(
        name="Denial of Service Incident Response",
        category=AlertCategory.DOS,
        description="Response playbook for denial of service attacks.",
        severity_threshold=Severity.MEDIUM,
        mitre_tactics=["TA0040"],
        steps=[
            PlaybookStep(step_number=1, action="Block Attack Source", description="Block the source IPs of the DoS attack at the network edge.", automated=True, containment_action=ContainmentAction.BLOCK_IP),
            PlaybookStep(step_number=2, action="Enable Rate Limiting", description="Enable or increase rate limiting on affected services."),
            PlaybookStep(step_number=3, action="Activate DDoS Mitigation", description="Engage cloud-based DDoS mitigation service if available."),
            PlaybookStep(step_number=4, action="Scale Resources", description="Scale infrastructure resources to absorb attack traffic."),
            PlaybookStep(step_number=5, action="Monitor Service Health", description="Continuously monitor affected service availability and performance."),
        ],
    )


def _lateral_movement_playbook() -> Playbook:
    return Playbook(
        name="Lateral Movement Incident Response",
        category=AlertCategory.LATERAL_MOVEMENT,
        description="Response playbook for lateral movement detection.",
        severity_threshold=Severity.HIGH,
        mitre_tactics=["TA0007", "TA0008"],
        steps=[
            PlaybookStep(step_number=1, action="Isolate Compromised Hosts", description="Isolate all hosts involved in the lateral movement chain.", automated=True, containment_action=ContainmentAction.ISOLATE_HOST),
            PlaybookStep(step_number=2, action="Block Internal Traffic", description="Block suspicious internal traffic patterns between affected hosts.", automated=True, containment_action=ContainmentAction.BLOCK_IP),
            PlaybookStep(step_number=3, action="Disable Compromised Accounts", description="Disable accounts used for lateral movement.", automated=True, containment_action=ContainmentAction.DISABLE_ACCOUNT),
            PlaybookStep(step_number=4, action="Audit Access Paths", description="Map all access paths the attacker used to move laterally."),
            PlaybookStep(step_number=5, action="Reset Credentials", description="Reset credentials for all accounts on compromised hosts."),
            PlaybookStep(step_number=6, action="Hunt for Persistence", description="Search all affected hosts for persistence mechanisms."),
            PlaybookStep(step_number=7, action="Segment Network", description="Review and tighten network segmentation between affected zones."),
        ],
    )


# Registry of all built-in playbooks
PLAYBOOK_REGISTRY: dict[AlertCategory, Playbook] = {
    AlertCategory.MALWARE: _malware_playbook(),
    AlertCategory.PHISHING: _phishing_playbook(),
    AlertCategory.BRUTE_FORCE: _brute_force_playbook(),
    AlertCategory.DATA_EXFIL: _data_exfil_playbook(),
    AlertCategory.INSIDER_THREAT: _insider_threat_playbook(),
    AlertCategory.DOS: _dos_playbook(),
    AlertCategory.LATERAL_MOVEMENT: _lateral_movement_playbook(),
}


class IncidentPlaybook:
    """Selects and provides response playbooks for incidents."""

    def __init__(self) -> None:
        self._registry = dict(PLAYBOOK_REGISTRY)

    def get_playbook(self, category: AlertCategory) -> Playbook | None:
        """Get the playbook for a given alert category."""
        return self._registry.get(category)

    def get_playbook_for_incident(self, incident: "Incident") -> list[Playbook]:  # noqa: F821
        """Get all applicable playbooks for an incident's alert categories."""
        from alertiq.models import Incident  # avoid circular import at module level

        categories = {a.category for a in incident.alerts if a.category}
        playbooks = []
        for cat in categories:
            pb = self.get_playbook(cat)
            if pb:
                playbooks.append(pb)
        return playbooks

    def list_playbooks(self) -> list[Playbook]:
        """List all available playbooks."""
        return list(self._registry.values())
