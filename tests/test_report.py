import pytest
from models import Finding
from datetime import datetime, timezone


def _make_log_finding(db, scan_id, title="SSH Brute Force", severity="high"):
    f = Finding(
        id=None, scan_id=scan_id, host_id=None,
        tool="log-analyzer", severity=severity,
        title=title, description="10 failed attempts from 1.2.3.4",
        raw_json="", created_at=datetime.now(timezone.utc).isoformat(),
    )
    f.id = db.insert_finding(f)
    return f


def test_report_shows_log_section_when_log_findings_exist(qtbot, db):
    from screens.report import ReportScreen
    from models import Scan
    scan = Scan(id=None, client_id=None, target="test.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    scan_id = db.insert_scan(scan)
    _make_log_finding(db, scan_id)

    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)

    from PyQt6.QtWidgets import QLabel
    found_log_section = False
    for i in range(screen._content_layout.count()):
        item = screen._content_layout.itemAt(i)
        if item and item.widget():
            for child in item.widget().findChildren(QLabel):
                if "Log Analysis" in child.text():
                    found_log_section = True
    assert found_log_section, "Log Analysis section not found in report"


def test_report_hides_log_section_when_no_log_findings(qtbot, db):
    from screens.report import ReportScreen
    from models import Scan, Finding
    scan = Scan(id=None, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    scan_id = db.insert_scan(scan)
    f = Finding(id=None, scan_id=scan_id, host_id=None, tool="nmap", severity="medium",
                title="Open port", description="Port 80 open", raw_json="",
                created_at=datetime.now(timezone.utc).isoformat())
    db.insert_finding(f)

    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)

    from PyQt6.QtWidgets import QLabel
    found_log_section = False
    for i in range(screen._content_layout.count()):
        item = screen._content_layout.itemAt(i)
        if item and item.widget():
            for child in item.widget().findChildren(QLabel):
                if "Log Analysis" in child.text():
                    found_log_section = True
    assert not found_log_section, "Log Analysis section should not appear for scan-only findings"
