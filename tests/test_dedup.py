"""Tests for AlertDeduplicator."""

from datetime import datetime, timedelta

from alertiq.models import Alert, AlertCategory
from alertiq.triage.dedup import AlertDeduplicator


class TestAlertDeduplicator:
    def setup_method(self):
        self.dedup = AlertDeduplicator(time_window_seconds=300)

    def test_group_identical_alerts(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time + timedelta(seconds=i * 10))
            for i in range(5)
        ]
        groups = self.dedup.deduplicate(alerts)
        assert len(groups) == 1
        key = list(groups.keys())[0]
        assert len(groups[key]) == 5

    def test_separate_different_categories(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time),
            Alert(source="IDS", title="DDoS", category=AlertCategory.DOS, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time + timedelta(seconds=30)),
        ]
        groups = self.dedup.deduplicate(alerts)
        assert len(groups) == 2

    def test_split_by_time_window(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time),
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time + timedelta(seconds=600)),
        ]
        groups = self.dedup.deduplicate(alerts)
        assert len(groups) == 2

    def test_get_representative(self):
        alerts = [
            Alert(source="EDR", title="Alert 1", priority_score=30.0),
            Alert(source="EDR", title="Alert 2", priority_score=80.0),
            Alert(source="EDR", title="Alert 3", priority_score=50.0),
        ]
        rep = self.dedup.get_representative(alerts)
        assert rep.title == "Alert 2"

    def test_summary(self):
        base_time = datetime(2025, 1, 1, 12, 0, 0)
        alerts = [
            Alert(source="EDR", title="Malware", category=AlertCategory.MALWARE, severity="high", priority_score=70.0, source_ip="10.0.1.1", user="admin", hostname="SRV-01", timestamp=base_time + timedelta(seconds=i * 10))
            for i in range(3)
        ]
        groups = self.dedup.deduplicate(alerts)
        summaries = self.dedup.summary(groups)
        assert len(summaries) == 1
        assert summaries[0]["count"] == 3
        assert summaries[0]["category"] == "malware"
