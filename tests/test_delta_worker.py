import gc
import pytest
from datetime import datetime, timezone
from db import DB
from models import Scan, Finding
from workers.delta_worker import DeltaWorker


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scan(db: DB, target: str, status: str = "complete") -> int:
    return db.insert_scan(Scan(None, None, target, status, _now(), _now()))


def _finding(db: DB, scan_id: int, tool: str, title: str, desc: str = "") -> None:
    db.insert_finding(Finding(None, scan_id, None, tool, "high", title, desc, "{}", _now()))


def test_no_previous_scan_all_new(qtbot):
    db = DB(":memory:")
    scan_id = _scan(db, "example.com")
    _finding(db, scan_id, "nuclei", "XSS", "cross-site")
    _finding(db, scan_id, "nmap", "Open port", "port 22")

    results = []
    worker = DeltaWorker(scan_id=scan_id, db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    with qtbot.waitSignal(worker.delta_ready, timeout=3000):
        worker.start()

    assert len(results) == 1
    target, new_count, resolved_count = results[0]
    assert target == "example.com"
    assert new_count == 2
    assert resolved_count == 0


def test_new_findings_detected(qtbot):
    db = DB(":memory:")
    prev_id = _scan(db, "example.com")
    _finding(db, prev_id, "nuclei", "Old Bug", "was there before")

    curr_id = _scan(db, "example.com")
    _finding(db, curr_id, "nuclei", "Old Bug", "was there before")
    _finding(db, curr_id, "nuclei", "New Bug", "appeared now")

    results = []
    worker = DeltaWorker(scan_id=curr_id, db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    with qtbot.waitSignal(worker.delta_ready, timeout=3000):
        worker.start()

    target, new_count, resolved_count = results[0]
    assert new_count == 1
    assert resolved_count == 0


def test_resolved_findings_detected(qtbot):
    db = DB(":memory:")
    prev_id = _scan(db, "example.com")
    _finding(db, prev_id, "nuclei", "Gone Bug", "no longer present")
    _finding(db, prev_id, "nmap", "Old Port", "was open")

    curr_id = _scan(db, "example.com")
    # neither finding is present in the new scan

    results = []
    worker = DeltaWorker(scan_id=curr_id, db=db)
    worker.delta_ready.connect(lambda t, n, r: results.append((t, n, r)))
    with qtbot.waitSignal(worker.delta_ready, timeout=3000):
        worker.start()

    target, new_count, resolved_count = results[0]
    assert new_count == 0
    assert resolved_count == 2


def test_error_emitted_on_bad_scan_id(qtbot):
    db = DB(":memory:")
    errors = []
    worker = DeltaWorker(scan_id=99999, db=db)
    worker.error_occurred.connect(lambda msg: errors.append(msg))
    with qtbot.waitSignal(worker.error_occurred, timeout=3000):
        worker.start()

    assert len(errors) == 1
