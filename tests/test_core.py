"""Tests for Alertiq."""
from src.core import Alertiq
def test_init(): assert Alertiq().get_stats()["ops"] == 0
def test_op(): c = Alertiq(); c.manage(x=1); assert c.get_stats()["ops"] == 1
def test_multi(): c = Alertiq(); [c.manage() for _ in range(5)]; assert c.get_stats()["ops"] == 5
def test_reset(): c = Alertiq(); c.manage(); c.reset(); assert c.get_stats()["ops"] == 0
def test_service_name(): c = Alertiq(); r = c.manage(); assert r["service"] == "alertiq"
