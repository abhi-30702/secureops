from models import Finding, Scan
from db import DB
from screens.widgets.threat_feed import ThreatFeed


def _make_db_with_findings(n: int) -> DB:
    db = DB(":memory:")
    scan = Scan(id=None, client_id=None, target="t.com", status="complete",
                started_at="2026-06-03T10:00:00", finished_at=None)
    sid = db.insert_scan(scan)
    for i in range(n):
        db.insert_finding(Finding(id=None, scan_id=sid, host_id=None,
                                  tool="nuclei", severity="high",
                                  title=f"Finding {i}", description="",
                                  raw_json="{}", created_at=f"2026-06-03T10:{i:02d}:00"))
    return db


def test_threat_feed_starts_empty(qtbot):
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    assert feed.card_count == 0


def test_threat_feed_refresh_adds_cards(qtbot):
    db = _make_db_with_findings(5)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    assert feed.card_count == 5


def test_threat_feed_respects_limit(qtbot):
    db = _make_db_with_findings(25)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    assert feed.card_count == 20


def test_threat_feed_clear_empties(qtbot):
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.clear()
    assert feed.card_count == 0


def test_threat_feed_refresh_replaces_old_cards(qtbot):
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.refresh(db)
    assert feed.card_count == 3


def test_threat_feed_clear_feed_mutes_existing(qtbot):
    # clear_feed() hides current findings and keeps them hidden on refresh.
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.clear_feed()
    assert feed.card_count == 0
    feed.refresh(db)
    assert feed.card_count == 0  # old findings stay muted


def test_threat_feed_clear_feed_shows_new_findings(qtbot):
    # Findings created after a clear still appear.
    db = _make_db_with_findings(3)
    feed = ThreatFeed()
    qtbot.addWidget(feed)
    feed.refresh(db)
    feed.clear_feed()
    from models import Finding
    db.insert_finding(Finding(id=None, scan_id=1, host_id=None, tool="nuclei",
                              severity="critical", title="Fresh",
                              description="", raw_json="{}",
                              created_at="2099-01-01T00:00:00"))
    feed.refresh(db)
    assert feed.card_count == 1
