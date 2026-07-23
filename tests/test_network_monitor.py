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
# retention / purge
# --------------------------------------------------------------------------- #
def test_purge_keep_last_trims_to_cap():
    db = DB(":memory:")
    for i in range(10):
        db.insert_network_event({"domain": f"d{i}.example", "src_ip": "1.2.3.4",
                                 "status": "allowed", "port": 53, "protocol": "DNS"})
    deleted = db.purge_network_events_keep_last(4)
    assert deleted == 6
    rows = db.query_network_events(limit=100)
    assert len(rows) == 4
    # the 4 newest survive (d6..d9)
    assert {r["domain"] for r in rows} == {"d6.example", "d7.example", "d8.example", "d9.example"}


def test_purge_keep_last_noop_when_under_cap():
    db = DB(":memory:")
    for i in range(3):
        db.insert_network_event({"domain": f"d{i}.example", "src_ip": "1.2.3.4",
                                 "status": "allowed"})
    assert db.purge_network_events_keep_last(50000) == 0
    assert db.network_event_count() == 3


def test_purge_keep_last_removes_orphan_alerts():
    db = DB(":memory:")
    ids = []
    for i in range(5):
        eid = db.insert_network_event({"domain": f"bad{i}.example", "src_ip": "1.2.3.4",
                                       "status": "blocked"})
        db.insert_network_alert({"event_id": eid, "severity": "high",
                                 "domain": f"bad{i}.example", "created_at": "2026-07-23T10:00:00"})
        ids.append(eid)
    db.purge_network_events_keep_last(2)
    alerts = db.query_network_alerts(limit=100)
    assert len(alerts) == 2  # alerts for purged events are gone too


def test_purge_older_than_by_age():
    db = DB(":memory:")
    db.insert_network_event({"domain": "old.example", "src_ip": "1.2.3.4",
                             "status": "allowed", "timestamp": "2000-01-01T00:00:00+00:00"})
    db.insert_network_event({"domain": "new.example", "src_ip": "1.2.3.4",
                             "status": "allowed",
                             "timestamp": _dt_now_iso()})
    deleted = db.purge_network_events_older_than(30)
    assert deleted == 1
    rows = db.query_network_events(limit=100)
    assert len(rows) == 1 and rows[0]["domain"] == "new.example"


def test_event_count_and_size():
    db = DB(":memory:")
    assert db.network_event_count() == 0
    db.insert_network_event({"domain": "x.example", "src_ip": "1.2.3.4", "status": "allowed"})
    assert db.network_event_count() == 1
    assert db.db_size_bytes() == 0  # in-memory


def test_purge_and_vacuum_on_disk(tmp_path):
    path = str(tmp_path / "net.db")
    db = DB(path)
    for i in range(200):
        db.insert_network_event({"domain": f"d{i}.example", "src_ip": "1.2.3.4",
                                 "status": "allowed"})
    db.purge_network_events_keep_last(10)
    db.vacuum()  # must not raise
    assert db.network_event_count() == 10
    assert db.db_size_bytes() > 0


def test_page_retention_apply(qtbot):
    from screens.network_page import NetworkPage
    db = DB(":memory:")
    page = NetworkPage(db=db)
    qtbot.addWidget(page)
    for i in range(20):
        db.insert_network_event({"domain": f"d{i}.example", "src_ip": "1.2.3.4",
                                 "status": "allowed"})
    page._ret_mode.setCurrentIndex(0)   # keep-last-N-events
    page._ret_rows_val = 5
    deleted = page._apply_retention()
    assert deleted == 15
    assert db.network_event_count() == 5


def _dt_now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


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


def test_worker_handle_classifies_persists_emits(rules_file, qtbot):
    """The core capture path: classify against the blocklist, persist, emit."""
    from workers.network_monitor_worker import NetworkMonitorWorker
    db = DB(":memory:")
    worker = NetworkMonitorWorker(db=db, blocklist=BlocklistEngine(rules_file))
    events, alerts = [], []
    worker.event_captured.connect(lambda e: events.append(e))
    worker.alert_raised.connect(lambda a: alerts.append(a))

    worker._handle("192.168.10.20", "1.1.1.1", "google.com", 53, "DNS")
    worker._handle("192.168.10.20", "9.9.9.9", "malware-c2.example", 443, "TLS")

    assert len(events) == 2
    assert events[0]["status"] == "allowed"
    assert events[1]["status"] == "blocked"
    assert events[1]["employee_name"] == "a.kapoor"       # from rules_file map
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    assert db.network_stats()["blocked"] == 1


def test_worker_handle_ignores_empty_domain(qtbot):
    from workers.network_monitor_worker import NetworkMonitorWorker
    db = DB(":memory:")
    worker = NetworkMonitorWorker(db=db, blocklist=BlocklistEngine())
    worker._handle("1.2.3.4", "5.6.7.8", "", 53, "DNS")
    assert db.network_event_count() == 0


def test_list_interfaces_returns_list():
    from workers.network_monitor_worker import list_interfaces
    ifaces = list_interfaces()
    assert isinstance(ifaces, list)


def test_sni_extractor_handles_garbage():
    from workers.network_monitor_worker import _extract_sni, _extract_http_host
    assert _extract_sni(b"\x00\x01\x02") is None
    assert _extract_sni(b"") is None
    assert _extract_http_host(b"not http at all") is None
    assert _extract_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n") == "example.com"
