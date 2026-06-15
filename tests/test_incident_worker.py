import textwrap
import threading
import tempfile
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import pytest

from workers.incident_worker import IncidentWorker
from db import DB
from models import Scan


def _make_worker(log_path: str = "", yara_extra_path: str = "") -> tuple[IncidentWorker, DB]:
    db = DB(":memory:")
    scan_id = db.insert_scan(Scan(
        id=None, client_id=None, target="incident",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    ))
    w = IncidentWorker(
        log_path=log_path,
        scan_id=scan_id,
        db=db,
        yara_extra_path=yara_extra_path,
    )
    return w, db


# ── Stage 1 tests ────────────────────────────────────────────────────────────

def test_stage1_file_not_found_emits_scan_failed(qtbot, tmp_path):
    w, _ = _make_worker(log_path=str(tmp_path / "missing.log"))
    failed = []
    w.scan_failed.connect(failed.append)
    mock_runner = MagicMock()
    result = w._stage1_log_analysis(mock_runner)
    assert result is None
    assert len(failed) == 1


def test_stage1_ssh_brute_force_emits_finding(qtbot, tmp_path):
    log = tmp_path / "auth.log"
    # Write 6 SSH failure lines (threshold is 5)
    lines = "\n".join(
        [f"Jun 11 00:0{i}:00 server sshd[123]: Failed password for root from 10.0.0.1 port 222{i} ssh2"
         for i in range(6)]
    )
    log.write_text(lines)

    w, db = _make_worker(log_path=str(log))
    findings = []
    w.finding_found.connect(findings.append)
    mock_runner = MagicMock()
    result = w._stage1_log_analysis(mock_runner)

    assert result is not None
    assert len(findings) >= 1
    assert any("ssh" in f.title.lower() or "brute" in f.title.lower() for f in findings)


def test_stage1_finding_written_to_db(qtbot, tmp_path):
    log = tmp_path / "auth.log"
    lines = "\n".join(
        [f"Jun 11 00:0{i}:00 server sshd[1]: Failed password for root from 10.0.0.1 port 222{i} ssh2"
         for i in range(6)]
    )
    log.write_text(lines)

    w, db = _make_worker(log_path=str(log))
    mock_runner = MagicMock()
    w._stage1_log_analysis(mock_runner)

    stored = db.query_findings_by_scan(w._scan_id)
    assert len(stored) >= 1
    assert all(f.tool == "log-analyzer" for f in stored)


# ── Stage 2 tests ────────────────────────────────────────────────────────────

def test_stage2_yara_match_emits_finding(qtbot, tmp_path):
    w, db = _make_worker()
    findings = []
    w.finding_found.connect(findings.append)

    mock_match = [{"file": "/tmp/shell.php", "rule": "Webshell_PHP_Eval", "severity": "high", "description": "YARA match"}]
    with patch("workers.tools.yara_scanner.run", return_value=mock_match):
        count = w._stage2_yara_scan()

    assert count == 1
    assert len(findings) == 1
    assert findings[0].tool == "yara"


def test_stage2_yara_match_written_to_db(qtbot, tmp_path):
    w, db = _make_worker()
    mock_match = [{"file": "/tmp/shell.php", "rule": "Webshell_PHP_Eval", "severity": "high", "description": "YARA match"}]
    with patch("workers.tools.yara_scanner.run", return_value=mock_match):
        w._stage2_yara_scan()

    stored = db.query_findings_by_scan(w._scan_id)
    assert any(f.tool == "yara" for f in stored)


def test_stage2_yara_error_returns_zero(qtbot):
    w, _ = _make_worker()
    with patch("workers.tools.yara_scanner.run", side_effect=Exception("yara error")):
        count = w._stage2_yara_scan()
    assert count == 0


# ── Stage 3 tests ────────────────────────────────────────────────────────────

def test_stage3_persistence_finding_emitted(qtbot):
    w, db = _make_worker()
    findings = []
    w.finding_found.connect(findings.append)

    mock_results = [{"check": "suid", "path": "/tmp/evil", "detail": "not in baseline", "severity": "high"}]
    with patch("workers.tools.persistence_checker.run", return_value=mock_results):
        count = w._stage3_persistence()

    assert count == 1
    assert len(findings) == 1
    assert findings[0].tool == "persistence"


def test_stage3_persistence_written_to_db(qtbot):
    w, db = _make_worker()
    mock_results = [{"check": "cron", "path": "/etc/cron.d/evil", "detail": "recent", "severity": "high"}]
    with patch("workers.tools.persistence_checker.run", return_value=mock_results):
        w._stage3_persistence()

    stored = db.query_findings_by_scan(w._scan_id)
    assert any(f.tool == "persistence" for f in stored)


def test_stage3_persistence_event_written_to_db(qtbot):
    w, db = _make_worker()
    mock_results = [{"check": "suid", "path": "/tmp/evil", "detail": "bad", "severity": "high"}]
    with patch("workers.tools.persistence_checker.run", return_value=mock_results):
        w._stage3_persistence()

    events = db.get_incident_events(w._scan_id)
    assert len(events) == 1
    assert events[0]["event_type"] == "persistence"


def test_stage3_error_returns_zero(qtbot):
    w, _ = _make_worker()
    with patch("workers.tools.persistence_checker.run", side_effect=Exception("perm denied")):
        count = w._stage3_persistence()
    assert count == 0


# ── Cancel test ──────────────────────────────────────────────────────────────

def test_cancel_sets_db_status_cancelled(qtbot, tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("no matches here\n")
    w, db = _make_worker(log_path=str(log))
    w.stop()  # cancel before run

    with qtbot.waitSignal(w.scan_complete, timeout=3000, raising=False):
        w.start()
        w.wait(2000)

    # After cancellation the scan status should not be "running"
    row = db._conn.execute("SELECT status FROM scans WHERE id=?", (w._scan_id,)).fetchone()
    assert row[0] in ("cancelled", "complete", "failed")

    # Ensure the QThread is fully stopped before teardown to prevent
    # dangling Qt objects from corrupting subsequent tests.
    w.stop()
    w.wait(500)
    w.deleteLater()
