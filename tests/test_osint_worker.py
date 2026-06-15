import gc
import pytest
from unittest.mock import patch
from datetime import datetime, timezone

from db import DB
from models import Scan
from workers.osint_worker import OsintWorker


FAKE_ITEMS = [
    {"item_type": "email",     "value": "admin@example.com", "source": "theharvester"},
    {"item_type": "subdomain", "value": "mail.example.com",  "source": "theharvester"},
    {"item_type": "ip",        "value": "10.0.0.1",          "source": "theharvester"},
]


def _make_db_with_scan(scan_id_hint: int = 1) -> tuple[DB, int]:
    """Return a DB with one scan row inserted; also return the real scan_id."""
    db = DB(":memory:")
    scan_id = db.insert_scan(Scan(
        id=None, client_id=None, target="example.com",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    ))
    return db, scan_id


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


# ── Test 1 ────────────────────────────────────────────────────────────────────

def test_items_emitted_on_successful_run(qtbot):
    """item_found is emitted once per item returned by theHarvester."""
    db, scan_id = _make_db_with_scan()
    worker = OsintWorker(domain="example.com", scan_id=scan_id, db=db)

    emitted = []
    worker.item_found.connect(emitted.append)

    with patch("workers.osint_worker.theharvester.run", return_value=FAKE_ITEMS):
        worker.run()

    assert len(emitted) == 3


# ── Test 2 ────────────────────────────────────────────────────────────────────

def test_items_written_to_db(qtbot):
    """Every item is persisted to osint_items before the signal fires."""
    db, scan_id = _make_db_with_scan()
    worker = OsintWorker(domain="example.com", scan_id=scan_id, db=db)

    with patch("workers.osint_worker.theharvester.run", return_value=FAKE_ITEMS):
        worker.run()

    stored = db.get_osint_items(scan_id=scan_id)
    assert len(stored) == 3


# ── Test 3 ────────────────────────────────────────────────────────────────────

def test_scan_failed_on_tool_error(qtbot):
    """If theharvester.run raises unexpectedly, scan_failed is emitted."""
    db, scan_id = _make_db_with_scan()
    worker = OsintWorker(domain="example.com", scan_id=scan_id, db=db)

    failed_msgs = []
    worker.scan_failed.connect(failed_msgs.append)

    with patch("workers.osint_worker.theharvester.run", side_effect=RuntimeError("test error")):
        worker.run()

    assert len(failed_msgs) == 1
    assert "test error" in failed_msgs[0]


# ── Test 4 ────────────────────────────────────────────────────────────────────

def test_cancel_before_run(qtbot):
    """Calling stop() before run() prevents any items from being emitted
    and marks the scan as 'cancelled' in the DB."""
    db, scan_id = _make_db_with_scan()
    worker = OsintWorker(domain="example.com", scan_id=scan_id, db=db)

    emitted = []
    worker.item_found.connect(emitted.append)

    worker.stop()  # cancel before run

    with patch("workers.osint_worker.theharvester.run", return_value=FAKE_ITEMS):
        worker.run()

    assert len(emitted) == 0

    row = db._conn.execute(
        "SELECT status FROM scans WHERE id=?", (scan_id,)
    ).fetchone()
    assert row["status"] == "cancelled"


# ── Test 5 ────────────────────────────────────────────────────────────────────

def test_scan_complete_fires_with_count(qtbot):
    """scan_complete is emitted with (0, total_items) after a successful run."""
    db, scan_id = _make_db_with_scan()
    worker = OsintWorker(domain="example.com", scan_id=scan_id, db=db)

    complete_args = []
    worker.scan_complete.connect(lambda exit_code, count: complete_args.append((exit_code, count)))

    with patch("workers.osint_worker.theharvester.run", return_value=FAKE_ITEMS):
        worker.run()

    assert len(complete_args) == 1
    assert complete_args[0] == (0, 3)
