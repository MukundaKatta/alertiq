"""AlertClassifier - Categorizes security alerts by threat type."""

from __future__ import annotations

import re

from alertiq.models import (
    Alert,
    AlertCategory,
    CATEGORY_MITRE_MAP,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
)


# Keyword patterns for each alert category
_CATEGORY_PATTERNS: dict[AlertCategory, list[re.Pattern[str]]] = {
    AlertCategory.MALWARE: [
        re.compile(r"malware|trojan|virus|worm|ransomware|backdoor|rootkit|keylogger", re.I),
        re.compile(r"malicious\s+(file|binary|executable|payload|process)", re.I),
        re.compile(r"c2\s+(beacon|callback|communication)", re.I),
        re.compile(r"suspicious\s+(process|execution|binary)", re.I),
    ],
    AlertCategory.PHISHING: [
        re.compile(r"phish(ing)?|spear.?phish", re.I),
        re.compile(r"suspicious\s+(email|link|attachment|url)", re.I),
        re.compile(r"credential\s+harvest", re.I),
        re.compile(r"impersonat(ion|ing)", re.I),
    ],
    AlertCategory.BRUTE_FORCE: [
        re.compile(r"brute\s*force|password\s+(spray|guess)", re.I),
        re.compile(r"(multiple|repeated|excessive)\s+(failed|unsuccessful)\s+(login|auth|logon)", re.I),
        re.compile(r"account\s+lockout", re.I),
        re.compile(r"credential\s+stuff", re.I),
    ],
    AlertCategory.DATA_EXFIL: [
        re.compile(r"(data|info(rmation)?)\s+(exfil|leak|theft|loss)", re.I),
        re.compile(r"(large|unusual|abnormal)\s+(upload|transfer|outbound)", re.I),
        re.compile(r"(sensitive|confidential)\s+(data|file).*transfer", re.I),
        re.compile(r"dns\s+tunnel", re.I),
    ],
    AlertCategory.INSIDER_THREAT: [
        re.compile(r"insider\s+threat", re.I),
        re.compile(r"(unauthorized|anomalous)\s+(access|activity)", re.I),
        re.compile(r"privilege\s+(abuse|misuse)", re.I),
        re.compile(r"(after.hours|off.hours)\s+access", re.I),
        re.compile(r"policy\s+violation", re.I),
    ],
    AlertCategory.DOS: [
        re.compile(r"(d)dos|denial\s+of\s+service", re.I),
        re.compile(r"(syn|udp|icmp)\s+flood", re.I),
        re.compile(r"(traffic|request)\s+(spike|surge|flood)", re.I),
        re.compile(r"(bandwidth|resource)\s+exhaust", re.I),
    ],
    AlertCategory.LATERAL_MOVEMENT: [
        re.compile(r"lateral\s+mov", re.I),
        re.compile(r"(rdp|smb|ssh|psexec|wmi)\s+(connection|session|from|to)", re.I),
        re.compile(r"pass.the.(hash|ticket)", re.I),
        re.compile(r"(internal|east.west)\s+(scan|pivot|spread)", re.I),
    ],
}


class AlertClassifier:
    """Classifies security alerts into threat categories and maps to MITRE ATT&CK."""

    def __init__(self) -> None:
        self._patterns = _CATEGORY_PATTERNS

    def classify(self, alert: Alert) -> Alert:
        """Classify a single alert, setting its category and MITRE mappings.

        Returns the alert with updated category, mitre_tactics, and mitre_techniques.
        """
        text = f"{alert.title} {alert.description} {alert.source}".lower()
        scores: dict[AlertCategory, float] = {}

        for category, patterns in self._patterns.items():
            score = 0.0
            for pattern in patterns:
                matches = pattern.findall(text)
                score += len(matches) * 1.0
            if score > 0:
                scores[category] = score

        if not scores:
            # Default to malware if no patterns match
            alert.category = AlertCategory.MALWARE
        else:
            alert.category = max(scores, key=scores.get)  # type: ignore[arg-type]

        # Map to MITRE ATT&CK
        self._apply_mitre_mapping(alert)
        return alert

    def classify_batch(self, alerts: list[Alert]) -> list[Alert]:
        """Classify a batch of alerts."""
        return [self.classify(alert) for alert in alerts]

    def _apply_mitre_mapping(self, alert: Alert) -> None:
        """Apply MITRE ATT&CK tactic and technique mappings based on category."""
        if alert.category is None:
            return

        mapping = CATEGORY_MITRE_MAP.get(alert.category, {})
        tactic_ids = mapping.get("tactics", [])
        technique_ids = mapping.get("techniques", [])

        alert.mitre_tactics = [
            MITRE_TACTICS[tid] for tid in tactic_ids if tid in MITRE_TACTICS
        ]
        alert.mitre_techniques = [
            MITRE_TECHNIQUES[tid] for tid in technique_ids if tid in MITRE_TECHNIQUES
        ]
