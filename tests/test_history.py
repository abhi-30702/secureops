from models import Finding, Scan
from db import DB
from screens.history import HistoryScreen


def _db_with_scans() -> DB:
    db = DB(":memory:")
    s1 = db.insert_scan(Scan(id=None, client_id=None, target="a.com",
                             status="complete", started_at="2026-06-01T09:00:00",
                             finished_at="2026-06-01T09:20:00"))
    s2 = db.insert_scan(Scan(id=None, client_id=None, target="10.0.0.5",
                             status="failed", started_at="2026-06-02T11:00:00",
                             finished_at=None))
    for sev in ("critical", "high", "high"):
        db.insert_finding(Finding(id=None, scan_id=s1, host_id=None, tool="nuclei",
                                  severity=sev, title="f", description="",
                                  raw_json="{}", created_at="2026-06-01T09:05:00"))
    return db


def test_query_all_scans_newest_first():
    db = _db_with_scans()
    scans = db.query_all_scans()
    assert len(scans) == 2
    assert scans[0].target == "10.0.0.5"  # 06-02 before 06-01


def test_finding_counts_by_scan():
    db = _db_with_scans()
    counts = db.finding_counts_by_scan()
    s1 = db.query_all_scans()[1].id  # a.com
    assert counts[s1] == {"critical": 1, "high": 2}


def test_history_populates_rows(qtbot):
    db = _db_with_scans()
    screen = HistoryScreen(db=db)
    qtbot.addWidget(screen)
    assert screen._table.rowCount() == 2
    assert len(screen._scan_ids) == 2


def test_history_empty_state(qtbot):
    screen = HistoryScreen(db=DB(":memory:"))
    qtbot.addWidget(screen)
    assert screen._table.rowCount() == 0
    assert screen._empty_label.isVisibleTo(screen) or not screen._table.isVisibleTo(screen)


def test_history_emits_scan_selected(qtbot):
    db = _db_with_scans()
    screen = HistoryScreen(db=db)
    qtbot.addWidget(screen)
    screen._table.selectRow(0)
    with qtbot.waitSignal(screen.scan_selected, timeout=1000) as blocker:
        screen._open_selected()
    assert blocker.args[0] == screen._scan_ids[0]


def test_history_view_button_disabled_until_selection(qtbot):
    db = _db_with_scans()
    screen = HistoryScreen(db=db)
    qtbot.addWidget(screen)
    assert not screen._open_btn.isEnabled()
    screen._table.selectRow(0)
    assert screen._open_btn.isEnabled()
