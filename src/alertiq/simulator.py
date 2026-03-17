"""Alert simulation engine for testing and demonstrations."""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from alertiq.models import Alert, AlertCategory


# Simulation templates
_ALERT_TEMPLATES: dict[AlertCategory, list[dict[str, str]]] = {
    AlertCategory.MALWARE: [
        {"title": "Malware detected: Trojan.GenericKD", "source": "EDR", "description": "Suspicious process execution detected. Trojan binary identified in user temp directory."},
        {"title": "Ransomware behavior detected", "source": "EDR", "description": "Process encrypting files with suspicious extension changes. Ransomware indicators present."},
        {"title": "C2 beacon callback detected", "source": "IDS", "description": "Periodic outbound connections to known C2 infrastructure. Malware beacon pattern."},
        {"title": "Malicious PowerShell execution", "source": "SIEM", "description": "Encoded PowerShell command with suspicious download cradle detected."},
        {"title": "Backdoor installation attempt", "source": "EDR", "description": "Suspicious binary dropped in startup folder. Backdoor persistence mechanism."},
    ],
    AlertCategory.PHISHING: [
        {"title": "Phishing email detected", "source": "Email Gateway", "description": "Spearphishing email with malicious attachment targeting finance department."},
        {"title": "Suspicious URL click from email", "source": "Email Gateway", "description": "User clicked suspicious link in phishing email redirecting to credential harvesting page."},
        {"title": "Spearphishing attachment opened", "source": "EDR", "description": "User opened malicious Office document with embedded macro from phishing email."},
        {"title": "Credential harvesting page accessed", "source": "Proxy", "description": "User accessed known credential harvesting page impersonating corporate login."},
    ],
    AlertCategory.BRUTE_FORCE: [
        {"title": "Multiple failed login attempts", "source": "SIEM", "description": "Excessive failed authentication attempts from single source IP. Brute force pattern."},
        {"title": "Password spraying detected", "source": "IAM", "description": "Single password tested against multiple user accounts. Password spray attack pattern."},
        {"title": "Account lockout triggered", "source": "Active Directory", "description": "Account lockout due to repeated failed login attempts. Credential stuffing suspected."},
        {"title": "SSH brute force attempt", "source": "IDS", "description": "Rapid SSH authentication failures from external IP. Brute force attack on SSH service."},
    ],
    AlertCategory.DATA_EXFIL: [
        {"title": "Large data transfer to external host", "source": "DLP", "description": "Abnormal volume of data uploaded to external cloud storage service."},
        {"title": "DNS tunneling detected", "source": "IDS", "description": "Suspicious DNS query patterns consistent with DNS tunneling data exfiltration."},
        {"title": "Sensitive file upload detected", "source": "DLP", "description": "Confidential documents uploaded to personal file sharing service."},
        {"title": "Unusual outbound data volume", "source": "SIEM", "description": "Data exfiltration alert: host sending abnormal volume of data to external IP."},
    ],
    AlertCategory.INSIDER_THREAT: [
        {"title": "Unauthorized access to sensitive data", "source": "DLP", "description": "User accessed confidential files outside normal job function. Insider threat indicator."},
        {"title": "After-hours access to critical systems", "source": "SIEM", "description": "Anomalous off-hours access to production database by non-operations user."},
        {"title": "Privilege abuse detected", "source": "IAM", "description": "User escalated privileges without authorization. Privilege misuse detected."},
        {"title": "Policy violation: USB data copy", "source": "DLP", "description": "Unauthorized bulk copy of files to removable USB media detected."},
    ],
    AlertCategory.DOS: [
        {"title": "SYN flood attack detected", "source": "IDS", "description": "High volume SYN flood targeting web server. Denial of service attack."},
        {"title": "Traffic spike on web server", "source": "WAF", "description": "Abnormal request surge causing service degradation. DDoS indicators present."},
        {"title": "UDP flood detected", "source": "IDS", "description": "UDP flood attack saturating network bandwidth. DoS attack in progress."},
    ],
    AlertCategory.LATERAL_MOVEMENT: [
        {"title": "RDP connection from unusual source", "source": "SIEM", "description": "Remote Desktop connection from non-standard internal host. Lateral movement indicator."},
        {"title": "Pass-the-hash attack detected", "source": "EDR", "description": "NTLM authentication with pass-the-hash technique detected. Lateral movement in progress."},
        {"title": "Internal port scan detected", "source": "IDS", "description": "Internal host scanning multiple systems on common service ports. East-west scanning activity."},
        {"title": "SMB lateral movement detected", "source": "EDR", "description": "Suspicious SMB connections between workstations. PsExec lateral movement pattern."},
    ],
}

_SOURCE_IPS = [
    "203.0.113.42", "198.51.100.17", "192.0.2.88", "203.0.113.100",
    "198.51.100.55", "10.0.1.50", "10.0.2.100", "10.0.3.25",
    "172.16.0.15", "172.16.1.30", "192.168.1.100", "192.168.2.50",
]

_DEST_IPS = [
    "10.0.1.10", "10.0.1.20", "10.0.2.50", "10.0.3.100",
    "172.16.0.5", "172.16.1.10", "192.168.1.50", "192.168.2.25",
]

_USERS = [
    "jsmith", "admin", "root", "svc_backup", "mwilson",
    "kjohnson", "dlee", "analyst01", "svc_monitoring", "tgarcia",
]

_HOSTNAMES = [
    "WS-FINANCE-01", "WS-HR-03", "SRV-DB-01", "SRV-WEB-02",
    "SRV-APP-01", "WS-DEV-05", "SRV-FILE-01", "WS-EXEC-02",
    "SRV-MAIL-01", "WS-IT-04",
]


class AlertSimulator:
    """Generates realistic security alerts for testing and demonstrations."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def generate(
        self,
        count: int = 10,
        categories: list[AlertCategory] | None = None,
        time_span_hours: int = 4,
    ) -> list[Alert]:
        """Generate a batch of simulated alerts.

        Args:
            count: Number of alerts to generate.
            categories: Limit to specific categories. None = all categories.
            time_span_hours: Time span over which to spread alerts.

        Returns:
            List of simulated Alert objects.
        """
        if categories is None:
            categories = list(AlertCategory)

        base_time = datetime.utcnow() - timedelta(hours=time_span_hours)
        alerts: list[Alert] = []

        for _ in range(count):
            category = self._rng.choice(categories)
            templates = _ALERT_TEMPLATES[category]
            template = self._rng.choice(templates)

            offset = self._rng.uniform(0, time_span_hours * 3600)
            timestamp = base_time + timedelta(seconds=offset)

            alert = Alert(
                timestamp=timestamp,
                source=template["source"],
                title=template["title"],
                description=template["description"],
                source_ip=self._rng.choice(_SOURCE_IPS),
                dest_ip=self._rng.choice(_DEST_IPS),
                user=self._rng.choice(_USERS),
                hostname=self._rng.choice(_HOSTNAMES),
            )
            alerts.append(alert)

        return sorted(alerts, key=lambda a: a.timestamp)

    def generate_attack_scenario(self, scenario: str = "kill_chain") -> list[Alert]:
        """Generate a specific attack scenario for demonstration.

        Args:
            scenario: One of 'kill_chain', 'brute_force_campaign', 'data_breach'.

        Returns:
            List of alerts forming the attack scenario.
        """
        if scenario == "kill_chain":
            return self._kill_chain_scenario()
        elif scenario == "brute_force_campaign":
            return self._brute_force_scenario()
        elif scenario == "data_breach":
            return self._data_breach_scenario()
        else:
            return self.generate(count=10)

    def _kill_chain_scenario(self) -> list[Alert]:
        """Simulate a full kill chain attack."""
        base_time = datetime.utcnow() - timedelta(hours=2)
        attacker_ip = "203.0.113.42"
        victim_user = "jsmith"
        victim_host = "WS-FINANCE-01"

        return [
            Alert(timestamp=base_time, source="Email Gateway", title="Phishing email detected", description="Spearphishing email with malicious attachment targeting finance department.", source_ip=attacker_ip, user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(minutes=5), source="EDR", title="Spearphishing attachment opened", description="User opened malicious Office document with embedded macro from phishing email.", source_ip=attacker_ip, user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(minutes=8), source="EDR", title="Malicious PowerShell execution", description="Encoded PowerShell command with suspicious download cradle detected.", user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(minutes=15), source="EDR", title="Backdoor installation attempt", description="Suspicious binary dropped in startup folder. Backdoor persistence mechanism.", user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(minutes=30), source="IDS", title="C2 beacon callback detected", description="Periodic outbound connections to known C2 infrastructure.", source_ip="10.0.1.50", dest_ip=attacker_ip, user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(minutes=45), source="IDS", title="Internal port scan detected", description="Internal host scanning multiple systems on common service ports.", source_ip="10.0.1.50", user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(hours=1), source="EDR", title="Pass-the-hash attack detected", description="NTLM authentication with pass-the-hash technique detected.", source_ip="10.0.1.50", dest_ip="10.0.2.50", user=victim_user, hostname=victim_host),
            Alert(timestamp=base_time + timedelta(hours=1, minutes=30), source="DLP", title="Large data transfer to external host", description="Abnormal volume of data uploaded to external host.", source_ip="10.0.2.50", dest_ip=attacker_ip, user=victim_user, hostname="SRV-DB-01"),
        ]

    def _brute_force_scenario(self) -> list[Alert]:
        """Simulate a brute force campaign."""
        base_time = datetime.utcnow() - timedelta(hours=1)
        attacker_ip = "198.51.100.17"

        alerts = []
        for i in range(8):
            alerts.append(Alert(
                timestamp=base_time + timedelta(seconds=i * 30),
                source="SIEM",
                title="Multiple failed login attempts",
                description="Excessive failed authentication attempts from single source IP. Brute force pattern.",
                source_ip=attacker_ip,
                dest_ip="10.0.1.10",
                user="admin",
                hostname="SRV-WEB-02",
            ))

        # Successful login after brute force
        alerts.append(Alert(
            timestamp=base_time + timedelta(minutes=5),
            source="SIEM",
            title="Unauthorized access to sensitive data",
            description="User accessed confidential files outside normal job function after successful brute force.",
            source_ip=attacker_ip,
            dest_ip="10.0.1.10",
            user="admin",
            hostname="SRV-WEB-02",
        ))
        return alerts

    def _data_breach_scenario(self) -> list[Alert]:
        """Simulate a data breach scenario."""
        base_time = datetime.utcnow() - timedelta(hours=3)
        insider_user = "dlee"

        return [
            Alert(timestamp=base_time, source="SIEM", title="After-hours access to critical systems", description="Anomalous off-hours access to production database by non-operations user.", user=insider_user, hostname="SRV-DB-01"),
            Alert(timestamp=base_time + timedelta(minutes=10), source="DLP", title="Unauthorized access to sensitive data", description="User accessed confidential files outside normal job function.", user=insider_user, hostname="SRV-DB-01"),
            Alert(timestamp=base_time + timedelta(minutes=20), source="DLP", title="Sensitive file upload detected", description="Confidential documents uploaded to personal file sharing service.", user=insider_user, hostname="SRV-DB-01", dest_ip="203.0.113.100"),
            Alert(timestamp=base_time + timedelta(minutes=25), source="DLP", title="Large data transfer to external host", description="Abnormal volume of data exfiltration to external cloud storage service.", user=insider_user, hostname="SRV-DB-01", source_ip="10.0.2.50", dest_ip="203.0.113.100"),
        ]
