"""Tests for AlertSimulator."""

from alertiq.models import AlertCategory
from alertiq.simulator import AlertSimulator


class TestAlertSimulator:
    def test_generate_random(self):
        sim = AlertSimulator(seed=42)
        alerts = sim.generate(count=15)
        assert len(alerts) == 15
        assert all(a.source for a in alerts)
        assert all(a.title for a in alerts)

    def test_generate_specific_categories(self):
        sim = AlertSimulator(seed=42)
        alerts = sim.generate(count=10, categories=[AlertCategory.MALWARE, AlertCategory.PHISHING])
        assert len(alerts) == 10

    def test_alerts_sorted_by_time(self):
        sim = AlertSimulator(seed=42)
        alerts = sim.generate(count=20)
        for i in range(1, len(alerts)):
            assert alerts[i].timestamp >= alerts[i - 1].timestamp

    def test_reproducible_with_seed(self):
        alerts1 = AlertSimulator(seed=123).generate(count=10)
        alerts2 = AlertSimulator(seed=123).generate(count=10)
        assert [a.title for a in alerts1] == [a.title for a in alerts2]

    def test_kill_chain_scenario(self):
        sim = AlertSimulator()
        alerts = sim.generate_attack_scenario("kill_chain")
        assert len(alerts) > 5
        # Should span from phishing to exfiltration
        titles = " ".join(a.title for a in alerts).lower()
        assert "phishing" in titles or "c2" in titles

    def test_brute_force_scenario(self):
        sim = AlertSimulator()
        alerts = sim.generate_attack_scenario("brute_force_campaign")
        assert len(alerts) > 5
        bf_count = sum(1 for a in alerts if "failed login" in a.title.lower())
        assert bf_count >= 5

    def test_data_breach_scenario(self):
        sim = AlertSimulator()
        alerts = sim.generate_attack_scenario("data_breach")
        assert len(alerts) >= 3
