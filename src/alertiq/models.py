"""Pydantic data models for ALERTIQ."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AlertCategory(str, Enum):
    """Categories for security alert classification."""

    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DATA_EXFIL = "data_exfil"
    INSIDER_THREAT = "insider_threat"
    DOS = "dos"
    LATERAL_MOVEMENT = "lateral_movement"


class Severity(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""

    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    CONTAINED = "contained"
    REMEDIATED = "remediated"
    CLOSED = "closed"


class ContainmentAction(str, Enum):
    """Automated containment actions."""

    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    REVOKE_SESSION = "revoke_session"
    BLOCK_DOMAIN = "block_domain"


class MITRETactic(BaseModel):
    """A MITRE ATT&CK tactic."""

    tactic_id: str = Field(..., description="MITRE tactic ID, e.g. TA0001")
    name: str = Field(..., description="Tactic name, e.g. Initial Access")
    description: str = Field(default="", description="Tactic description")


class MITRETechnique(BaseModel):
    """A MITRE ATT&CK technique."""

    technique_id: str = Field(..., description="MITRE technique ID, e.g. T1566")
    name: str = Field(..., description="Technique name, e.g. Phishing")
    tactic_id: str = Field(..., description="Parent tactic ID")
    description: str = Field(default="", description="Technique description")


class Alert(BaseModel):
    """A security alert to be triaged."""

    alert_id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(..., description="Alert source system (e.g. IDS, EDR, SIEM)")
    title: str = Field(..., description="Alert title")
    description: str = Field(default="", description="Alert description")
    category: AlertCategory | None = Field(default=None, description="Classified category")
    severity: Severity = Field(default=Severity.MEDIUM, description="Alert severity")
    priority_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Priority score 0-100")
    source_ip: str | None = Field(default=None, description="Source IP address")
    dest_ip: str | None = Field(default=None, description="Destination IP address")
    user: str | None = Field(default=None, description="Associated username")
    hostname: str | None = Field(default=None, description="Associated hostname")
    mitre_tactics: list[MITRETactic] = Field(default_factory=list)
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(default_factory=dict)
    dedup_key: str | None = Field(default=None, description="Deduplication grouping key")
    incident_id: str | None = Field(default=None, description="Linked incident ID")


class TimelineEvent(BaseModel):
    """A single event in an attack timeline."""

    timestamp: datetime
    alert_id: str
    description: str
    tactic: str | None = None
    technique: str | None = None


class Incident(BaseModel):
    """A correlated incident composed of multiple alerts."""

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:6].upper()}")
    title: str = Field(default="", description="Incident title")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: IncidentStatus = Field(default=IncidentStatus.NEW)
    severity: Severity = Field(default=Severity.MEDIUM)
    priority_score: float = Field(default=0.0, ge=0.0, le=100.0)
    alerts: list[Alert] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    correlation_rule: str | None = Field(default=None, description="Rule that created this incident")
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    affected_ips: list[str] = Field(default_factory=list)
    mitre_tactics: list[MITRETactic] = Field(default_factory=list)
    containment_actions: list[ContainmentAction] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PlaybookStep(BaseModel):
    """A single step in a response playbook."""

    step_number: int
    action: str
    description: str
    automated: bool = Field(default=False, description="Whether this step can be automated")
    containment_action: ContainmentAction | None = None


class Playbook(BaseModel):
    """An incident response playbook for a specific alert category."""

    playbook_id: str = Field(default_factory=lambda: f"PB-{uuid.uuid4().hex[:6].upper()}")
    name: str
    category: AlertCategory
    description: str = ""
    severity_threshold: Severity = Field(default=Severity.MEDIUM)
    steps: list[PlaybookStep] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list, description="Applicable MITRE tactic IDs")


# ---- MITRE ATT&CK Reference Data ----

MITRE_TACTICS: dict[str, MITRETactic] = {
    "TA0001": MITRETactic(tactic_id="TA0001", name="Initial Access", description="Entry vectors into the network"),
    "TA0002": MITRETactic(tactic_id="TA0002", name="Execution", description="Running malicious code"),
    "TA0003": MITRETactic(tactic_id="TA0003", name="Persistence", description="Maintaining foothold"),
    "TA0004": MITRETactic(tactic_id="TA0004", name="Privilege Escalation", description="Gaining higher permissions"),
    "TA0005": MITRETactic(tactic_id="TA0005", name="Defense Evasion", description="Avoiding detection"),
    "TA0006": MITRETactic(tactic_id="TA0006", name="Credential Access", description="Stealing credentials"),
    "TA0007": MITRETactic(tactic_id="TA0007", name="Discovery", description="Exploring the environment"),
    "TA0008": MITRETactic(tactic_id="TA0008", name="Lateral Movement", description="Moving through the network"),
    "TA0009": MITRETactic(tactic_id="TA0009", name="Collection", description="Gathering target data"),
    "TA0010": MITRETactic(tactic_id="TA0010", name="Exfiltration", description="Stealing data"),
    "TA0011": MITRETactic(tactic_id="TA0011", name="Command and Control", description="Communicating with compromised systems"),
    "TA0040": MITRETactic(tactic_id="TA0040", name="Impact", description="Disrupting availability or integrity"),
}

MITRE_TECHNIQUES: dict[str, MITRETechnique] = {
    "T1566": MITRETechnique(technique_id="T1566", name="Phishing", tactic_id="TA0001", description="Sending phishing messages to gain access"),
    "T1566.001": MITRETechnique(technique_id="T1566.001", name="Spearphishing Attachment", tactic_id="TA0001", description="Phishing with malicious attachment"),
    "T1566.002": MITRETechnique(technique_id="T1566.002", name="Spearphishing Link", tactic_id="TA0001", description="Phishing with malicious link"),
    "T1059": MITRETechnique(technique_id="T1059", name="Command and Scripting Interpreter", tactic_id="TA0002", description="Abusing command interpreters"),
    "T1059.001": MITRETechnique(technique_id="T1059.001", name="PowerShell", tactic_id="TA0002", description="Abusing PowerShell"),
    "T1078": MITRETechnique(technique_id="T1078", name="Valid Accounts", tactic_id="TA0003", description="Using legitimate credentials"),
    "T1110": MITRETechnique(technique_id="T1110", name="Brute Force", tactic_id="TA0006", description="Brute forcing credentials"),
    "T1110.001": MITRETechnique(technique_id="T1110.001", name="Password Guessing", tactic_id="TA0006", description="Guessing passwords"),
    "T1110.003": MITRETechnique(technique_id="T1110.003", name="Password Spraying", tactic_id="TA0006", description="Spraying common passwords"),
    "T1071": MITRETechnique(technique_id="T1071", name="Application Layer Protocol", tactic_id="TA0011", description="Using application protocols for C2"),
    "T1048": MITRETechnique(technique_id="T1048", name="Exfiltration Over Alternative Protocol", tactic_id="TA0010", description="Exfiltrating data over non-standard protocols"),
    "T1048.003": MITRETechnique(technique_id="T1048.003", name="Exfiltration Over Unencrypted Non-C2 Protocol", tactic_id="TA0010", description="Exfiltrating over unencrypted protocols"),
    "T1021": MITRETechnique(technique_id="T1021", name="Remote Services", tactic_id="TA0008", description="Using remote services for lateral movement"),
    "T1021.001": MITRETechnique(technique_id="T1021.001", name="Remote Desktop Protocol", tactic_id="TA0008", description="Using RDP for lateral movement"),
    "T1486": MITRETechnique(technique_id="T1486", name="Data Encrypted for Impact", tactic_id="TA0040", description="Encrypting data for ransom"),
    "T1498": MITRETechnique(technique_id="T1498", name="Network Denial of Service", tactic_id="TA0040", description="DoS attack on network"),
    "T1040": MITRETechnique(technique_id="T1040", name="Network Sniffing", tactic_id="TA0006", description="Sniffing network traffic"),
    "T1567": MITRETechnique(technique_id="T1567", name="Exfiltration Over Web Service", tactic_id="TA0010", description="Exfiltrating data via web services"),
    "T1071.001": MITRETechnique(technique_id="T1071.001", name="Web Protocols", tactic_id="TA0011", description="Using web protocols for C2"),
    "T1547": MITRETechnique(technique_id="T1547", name="Boot or Logon Autostart Execution", tactic_id="TA0003", description="Persistence via autostart"),
}

# Mapping of alert categories to their typical MITRE tactics and techniques
CATEGORY_MITRE_MAP: dict[AlertCategory, dict[str, list[str]]] = {
    AlertCategory.MALWARE: {
        "tactics": ["TA0002", "TA0003", "TA0005", "TA0011"],
        "techniques": ["T1059", "T1059.001", "T1547", "T1071"],
    },
    AlertCategory.PHISHING: {
        "tactics": ["TA0001"],
        "techniques": ["T1566", "T1566.001", "T1566.002"],
    },
    AlertCategory.BRUTE_FORCE: {
        "tactics": ["TA0006"],
        "techniques": ["T1110", "T1110.001", "T1110.003"],
    },
    AlertCategory.DATA_EXFIL: {
        "tactics": ["TA0009", "TA0010"],
        "techniques": ["T1048", "T1048.003", "T1567"],
    },
    AlertCategory.INSIDER_THREAT: {
        "tactics": ["TA0009", "TA0010", "TA0006"],
        "techniques": ["T1078", "T1567", "T1040"],
    },
    AlertCategory.DOS: {
        "tactics": ["TA0040"],
        "techniques": ["T1498"],
    },
    AlertCategory.LATERAL_MOVEMENT: {
        "tactics": ["TA0007", "TA0008"],
        "techniques": ["T1021", "T1021.001"],
    },
}
