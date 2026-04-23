"""PriorityEngine - Scores alert severity using MITRE ATT&CK tactics."""

from __future__ import annotations

import ipaddress

from alertiq.models import Alert, AlertCategory, Severity


# Base severity scores per category
_CATEGORY_BASE_SCORES: dict[AlertCategory, float] = {
    AlertCategory.MALWARE: 50.0,
    AlertCategory.PHISHING: 55.0,
    AlertCategory.BRUTE_FORCE: 45.0,
    AlertCategory.DATA_EXFIL: 85.0,
    AlertCategory.INSIDER_THREAT: 75.0,
    AlertCategory.DOS: 60.0,
    AlertCategory.LATERAL_MOVEMENT: 80.0,
}

# MITRE tactic severity weights - later stages in kill chain score higher
_TACTIC_WEIGHTS: dict[str, float] = {
    "TA0001": 5.0,   # Initial Access
    "TA0002": 8.0,   # Execution
    "TA0003": 10.0,  # Persistence
    "TA0004": 12.0,  # Privilege Escalation
    "TA0005": 7.0,   # Defense Evasion
    "TA0006": 9.0,   # Credential Access
    "TA0007": 6.0,   # Discovery
    "TA0008": 14.0,  # Lateral Movement
    "TA0009": 11.0,  # Collection
    "TA0010": 15.0,  # Exfiltration
    "TA0011": 13.0,  # Command and Control
    "TA0040": 16.0,  # Impact
}

# Score thresholds for severity mapping
_SEVERITY_THRESHOLDS: list[tuple[float, Severity]] = [
    (85.0, Severity.CRITICAL),
    (65.0, Severity.HIGH),
    (45.0, Severity.MEDIUM),
    (25.0, Severity.LOW),
    (0.0, Severity.INFO),
]


class PriorityEngine:
    """Scores alert priority using MITRE ATT&CK tactic weighting.

    The priority score is computed as:
      base_score (from category) + sum(tactic_weights) + contextual_adjustments

    The score is clamped to [0, 100] and mapped to a severity level.
    """

    def __init__(self) -> None:
        self._category_scores = _CATEGORY_BASE_SCORES
        self._tactic_weights = _TACTIC_WEIGHTS

    def score(self, alert: Alert) -> Alert:
        """Compute priority score and severity for a single alert.

        Returns the alert with updated priority_score and severity.
        """
        base = self._category_scores.get(alert.category, 40.0) if alert.category else 40.0

        # Sum tactic weights
        tactic_bonus = sum(
            self._tactic_weights.get(t.tactic_id, 0.0)
            for t in alert.mitre_tactics
        )

        # Contextual adjustments
        context_bonus = self._contextual_adjustments(alert)

        raw_score = base + tactic_bonus + context_bonus
        alert.priority_score = round(min(max(raw_score, 0.0), 100.0), 1)
        alert.severity = self._score_to_severity(alert.priority_score)
        return alert

    def score_batch(self, alerts: list[Alert]) -> list[Alert]:
        """Score a batch of alerts."""
        return [self.score(alert) for alert in alerts]

    def _contextual_adjustments(self, alert: Alert) -> float:
        """Apply contextual adjustments based on alert metadata."""
        bonus = 0.0

        # External source IP adds risk
        if alert.source_ip and not self._is_private_ip(alert.source_ip):
            bonus += 5.0

        # Alerts involving privileged users
        if alert.user and any(
            keyword in alert.user.lower()
            for keyword in ("admin", "root", "system", "service")
        ):
            bonus += 8.0

        # Multiple MITRE techniques indicate higher sophistication
        if len(alert.mitre_techniques) > 2:
            bonus += 5.0

        return bonus

    _PRIVATE_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]

    @classmethod
    def _is_private_ip(cls, ip: str) -> bool:
        """Check if an IP address is in a private range."""
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in cls._PRIVATE_NETWORKS)
        except ValueError:
            return False

    @staticmethod
    def _score_to_severity(score: float) -> Severity:
        """Map a numerical score to a severity level."""
        for threshold, severity in _SEVERITY_THRESHOLDS:
            if score >= threshold:
                return severity
        return Severity.INFO
