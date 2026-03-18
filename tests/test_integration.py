"""Integration tests for Alertiq."""
from src.core import Alertiq

class TestAlertiq:
    def setup_method(self):
        self.c = Alertiq()
    def test_10_ops(self):
        for i in range(10): self.c.manage(i=i)
        assert self.c.get_stats()["ops"] == 10
    def test_service_name(self):
        assert self.c.manage()["service"] == "alertiq"
    def test_different_inputs(self):
        self.c.manage(type="a"); self.c.manage(type="b")
        assert self.c.get_stats()["ops"] == 2
    def test_config(self):
        c = Alertiq(config={"debug": True})
        assert c.config["debug"] is True
    def test_empty_call(self):
        assert self.c.manage()["ok"] is True
    def test_large_batch(self):
        for _ in range(100): self.c.manage()
        assert self.c.get_stats()["ops"] == 100
