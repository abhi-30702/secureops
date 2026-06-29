from models import Client, Scan, Finding
from db import DB
from tool_checker import TOOLS
from screens.dashboard import DashboardScreen


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def _make_db_with_data() -> DB:
    db = DB(":memory:")
    db.insert_client(Client(
        id=None, name="Acme", domain="acme.com",
        firewall="none", notes="", created_at="2026-06-03T00:00:00"
    ))
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T10:00:00",
                              finished_at=None))
    db.insert_finding(Finding(id=None, scan_id=sid, host_id=None, tool="nuclei",
                              severity="high", title="XSS", description="",
                              raw_json="{}", created_at="2026-06-03T10:01:00"))
    return db


def test_dashboard_has_four_metric_cards(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._metric_cards) == 4


def test_dashboard_metric_card_labels(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    titles = [c.title for c in screen._metric_cards]
    assert "Clients" in titles
    assert "Scans" in titles
    assert "Findings" in titles
    assert "Incidents" in titles


def test_dashboard_warning_banner_hidden_when_tools_ok(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._warning_banner.isVisible()


def test_dashboard_warning_banner_shown_when_critical_missing(qtbot):
    screen = DashboardScreen(_critical_missing())
    qtbot.addWidget(screen)
    screen.show()
    assert screen._warning_banner.isVisible()


def test_dashboard_has_severity_strip(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._severity_strip is not None


def test_dashboard_has_threat_feed(qtbot):
    from screens.widgets.threat_feed import ThreatFeed
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._threat_feed is not None
    assert isinstance(screen._threat_feed, ThreatFeed)


def test_dashboard_refresh_updates_metrics(qtbot):
    db = _make_db_with_data()
    screen = DashboardScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen.refresh()
    findings_card = next(c for c in screen._metric_cards if c.title == "Findings")
    assert findings_card._value_label.text() != "0"
