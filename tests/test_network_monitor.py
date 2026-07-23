"""Tests for the Network Activity Monitor: blocklist engine, DB layer, page."""
import json
import os

import pytest

from db import DB
from blocklist_engine import BlocklistEngine


# --------------------------------------------------------------------------- #
# blocklist engine
# --------------------------------------------------------------------------- #
@pytest.fixture
def rules_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({
        "blocklist": [
            {"pattern": "malware-c2.example", "reason": "C2", "severity": "critical"},
            {"pattern": "*.casino-online.example", "reason": "Gambling", "severity": "medium"},
            {"pattern": "bad severity.example", "reason": "x", "severity": "not-a-sev"},
        ],
        "employees": {"192.168.10.20": "a.kapoor"},
    }))
    return str(path)


def test_exact_and_subdomain_match(rules_file):
    eng = BlocklistEngine(rules_file)
    assert eng.is_blocked("malware-c2.example")
    assert eng.is_blocked("sub.malware-c2.example")   # bare pattern → subdomains too
    assert not eng.is_blocked("notmalware-c2.example")


def test_wildcard_matches_subdomain_not_apex(rules_file):
    eng = BlocklistEngine(rules_file)
    assert eng.is_blocked("ads.casino-online.example")
    assert not eng.is_blocked("casino-online.example")  # *. excludes the apex


def test_match_returns_reason_and_severity(rules_file):
    eng = BlocklistEngine(rules_file)
    m = eng.match("malware-c2.example")
    assert m["reason"] == "C2" and m["severity"] == "critical"


def test_invalid_severity_falls_back(rules_file):
    eng = BlocklistEngine(rules_file)
    assert eng.match("bad severity.example")["severity"] == "medium"


def test_case_insensitive(rules_file):
    eng = BlocklistEngine(rules_file)
    assert eng.is_blocked("MALWARE-C2.EXAMPLE")


def test_employee_lookup_with_fallback(rules_file):
    eng = BlocklistEngine(rules_file)
    assert eng.employee_for("192.168.10.20") == "a.kapoor"
    assert eng.employee_for("10.0.0.9") == "10.0.0.9"


def test_missing_file_is_allow_all(tmp_path):
    eng = BlocklistEngine(str(tmp_path / "nope.json"))
    assert eng.rule_count == 0
    assert not eng.is_blocked("anything.example")


def test_shipped_config_loads():
    """The real config/blocklist.json must parse and contain rules."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    eng = BlocklistEngine(os.path.join(root, "config", "blocklist.json"))
    assert eng.rule_count > 0
    assert eng.is_blocked("malware-c2.example")


# --------------------------------------------------------------------------- #
# DB layer
# --------------------------------------------------------------------------- #
def test_insert_and_query_event():
    db = DB(":memory:")
    eid = db.insert_network_event({
        "timestamp": "2026-07-23T10:00:00", "src_ip": "192.168.10.20",
        "dst_ip": "1.1.1.1", "domain": "google.com", "port": 53,
        "protocol": "DNS", "status": "allowed", "employee_name": "a.kapoor",
    })
    assert eid > 0
    rows = db.query_network_events()
    assert len(rows) == 1 and rows[0]["domain"] == "google.com"


def test_query_filters():
    db = DB(":memory:")
    db.insert_network_event({"domain": "google.com", "src_ip": "192.168.10.20",
                             "status": "allowed", "port": 53, "protocol": "DNS"})
    db.insert_network_event({"domain": "malware-c2.example", "src_ip": "192.168.10.21",
                             "status": "blocked", "port": 443, "protocol": "TLS"})
    assert len(db.query_network_events(status="blocked")) == 1
    assert len(db.query_network_events(domain="google")) == 1
    assert len(db.query_network_events(src_ip="10.21")) == 1


def test_alert_ack_and_stats():
    db = DB(":memory:")
    eid = db.insert_network_event({"domain": "malware-c2.example", "src_ip": "192.168.10.21",
                                   "status": "blocked", "port": 443, "protocol": "TLS"})
    aid = db.insert_network_alert({"event_id": eid, "severity": "critical",
                                   "domain": "malware-c2.example", "src_ip": "192.168.10.21",
                                   "created_at": "2026-07-23T10:00:00"})
    assert len(db.query_network_alerts(only_unacked=True)) == 1
    db.set_network_alert_ack(aid, True)
    assert len(db.query_network_alerts(only_unacked=True)) == 0

    stats = db.network_stats()
    assert stats["total"] == 1 and stats["blocked"] == 1
    assert stats["top_blocked"][0] == ("malware-c2.example", 1)


def test_clear_network_data():
    db = DB(":memory:")
    db.insert_network_event({"domain": "x.example", "status": "blocked", "src_ip": "1.2.3.4"})
    db.clear_network_data()
    assert db.network_stats()["total"] == 0


# --------------------------------------------------------------------------- #
# page (offscreen)
# --------------------------------------------------------------------------- #
def test_page_builds_and_receives_events(qtbot):
    from screens.network_page import NetworkPage
    db = DB(":memory:")
    page = NetworkPage(db=db)
    qtbot.addWidget(page)

    page._on_event({"timestamp": "2026-07-23T10:00:00", "src_ip": "192.168.10.20",
                    "domain": "google.com", "port": 53, "protocol": "DNS",
                    "status": "allowed", "employee_name": "a.kapoor"})
    page._on_event({"timestamp": "2026-07-23T10:00:01", "src_ip": "192.168.10.21",
                    "domain": "malware-c2.example", "port": 443, "protocol": "TLS",
                    "status": "blocked", "blocked_reason": "C2", "employee_name": "j.rivera"})
    assert page._table.rowCount() == 2
    assert page._total == 2 and page._blocked == 1
    assert len(page._employees) == 2


def test_page_filters_hide_rows(qtbot):
    from screens.network_page import NetworkPage
    db = DB(":memory:")
    page = NetworkPage(db=db)
    qtbot.addWidget(page)
    page._on_event({"domain": "google.com", "src_ip": "192.168.10.20",
                    "status": "allowed", "port": 53, "protocol": "DNS"})
    page._on_event({"domain": "malware-c2.example", "src_ip": "192.168.10.21",
                    "status": "blocked", "port": 443, "protocol": "TLS"})
    page._f_status.setCurrentText("Blocked")
    assert page._table.isRowHidden(0)       # allowed row hidden
    assert not page._table.isRowHidden(1)   # blocked row visible


def test_demo_worker_emits(qtbot):
    """The demo feed should persist and stream events without root."""
    from workers.network_monitor_worker import NetworkMonitorWorker
    db = DB(":memory:")
    worker = NetworkMonitorWorker(db=db, blocklist=BlocklistEngine(), demo=True)
    captured = []
    worker.event_captured.connect(lambda e: captured.append(e))
    worker.start()
    qtbot.waitUntil(lambda: len(captured) >= 3, timeout=5000)
    worker.stop()
    worker.wait(3000)
    assert len(captured) >= 3
    assert db.network_stats()["total"] >= 3


def test_sni_extractor_handles_garbage():
    from workers.network_monitor_worker import _extract_sni, _extract_http_host
    assert _extract_sni(b"\x00\x01\x02") is None
    assert _extract_sni(b"") is None
    assert _extract_http_host(b"not http at all") is None
    assert _extract_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == "example.com"
