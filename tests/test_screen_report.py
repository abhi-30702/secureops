from db import DB
from models import Client, Scan, Host, Finding
from screens.report import ReportScreen


def _make_db():
    db = DB(":memory:")
    client = Client(id=None, name="Acme Corp", domain="acme.com",
                    firewall="none", notes="", created_at="2026-06-03T00:00:00")
    db.insert_client(client)
    scan = Scan(id=None, client_id=1, target="acme.com", status="complete",
                started_at="2026-06-03T10:00:00", finished_at="2026-06-03T10:04:00")
    scan_id = db.insert_scan(scan)
    host = Host(id=None, scan_id=scan_id, subdomain="api.acme.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")
    db.insert_host(host)
    finding = Finding(id=None, scan_id=scan_id, host_id=1, tool="nuclei",
                      severity="high", title="XSS Detected", description="desc",
                      raw_json="{}", created_at="2026-06-03T10:02:00")
    db.insert_finding(finding)
    return db, scan_id


def test_report_has_export_button(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._export_btn is not None


def test_report_export_button_disabled_by_default(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert not screen._export_btn.isEnabled()


def test_report_load_scan_enables_export(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._export_btn.isEnabled()


def test_report_load_scan_populates_summary(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._scan_id == scan_id


def test_report_reset_disables_export(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert not screen._export_btn.isEnabled()


def test_report_reset_clears_scan_id(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert screen._scan_id is None


def test_report_has_scroll_area(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._scroll is not None


def test_report_advisor_panel_built_after_load(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._advisor_panel is not None


def test_report_advisor_shows_disabled_message_when_off(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    # advisor disabled (no setting saved) — run button should be absent
    assert screen._run_advisor_btn is None


def test_report_advisor_run_button_present_when_enabled(qtbot):
    db, scan_id = _make_db()
    db.set_setting("ai_advisor_enabled", "1")
    db.set_setting("gemini_api_key", "test-key")
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._run_advisor_btn is not None
    assert screen._run_advisor_btn.isEnabled()


def test_report_reset_cancels_worker(qtbot):
    db, scan_id = _make_db()
    db.set_setting("ai_advisor_enabled", "1")
    db.set_setting("gemini_api_key", "test-key")
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert screen._advisor_worker is None
