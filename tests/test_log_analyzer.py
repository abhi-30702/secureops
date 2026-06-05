import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from models import Scan
from workers.log_analyzer import LogAnalyzerWorker


def _write_log(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _make_worker(db, content: str):
    path = _write_log(content)
    scan = Scan(id=None, client_id=None, target=path, status="running",
                started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    scan_id = db.insert_scan(scan)
    return LogAnalyzerWorker(path=path, scan_id=scan_id, db=db), scan_id, path


SSH_BRUTE_LOG = "\n".join(
    [f"Jun  5 10:00:{i:02d} host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
     for i in range(10)]
)

NGINX_SCANNER_LOG = "\n".join([
    '5.6.7.8 - - [05/Jun/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 200 "-" "sqlmap/1.7"',
    '5.6.7.8 - - [05/Jun/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 200 "-" "sqlmap/1.7"',
])


def test_log_analyzer_emits_scan_complete(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000) as blocker:
            worker.start()
        hosts, findings = blocker.args
        assert hosts == 0
        assert findings >= 0
    finally:
        os.unlink(path)


def test_log_analyzer_detects_ssh_brute_force(qtbot, db):
    worker, scan_id, path = _make_worker(db, SSH_BRUTE_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any(f.severity == "high" for f in findings), "Expected at least one HIGH finding"
        assert any("ssh" in f.title.lower() or "brute" in f.title.lower() for f in findings)
    finally:
        os.unlink(path)


def test_log_analyzer_detects_scanner_ua(qtbot, db):
    worker, scan_id, path = _make_worker(db, NGINX_SCANNER_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any(f.tool == "log-analyzer" for f in findings)
    finally:
        os.unlink(path)


def test_log_analyzer_stores_findings_in_db(qtbot, db):
    worker, scan_id, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        db_findings = db.query_findings_by_scan(scan_id)
        assert all(f.tool == "log-analyzer" for f in db_findings)
    finally:
        os.unlink(path)


def test_log_analyzer_emits_scan_failed_for_missing_file(qtbot, db):
    scan = Scan(id=None, client_id=None, target="/nonexistent/path.log", status="running",
                started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    scan_id = db.insert_scan(scan)
    worker = LogAnalyzerWorker(path="/nonexistent/path.log", scan_id=scan_id, db=db)
    failed_msgs = []
    worker.scan_failed.connect(failed_msgs.append)
    with qtbot.waitSignal(worker.scan_failed, timeout=5000):
        worker.start()
    assert failed_msgs


def test_log_analyzer_emits_log_lines(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    log_lines = []
    worker.log_line.connect(log_lines.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any("log-analyzer" in line for line in log_lines)
    finally:
        os.unlink(path)


def test_log_analyzer_skips_ai_advisor_when_disabled(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with patch("workers.log_analyzer.GeminiClient") as mock_gemini:
            with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                worker.start()
            mock_gemini.assert_not_called()
    finally:
        os.unlink(path)


def test_log_analyzer_groups_brute_force_into_one_finding(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        brute_force = [f for f in findings if "brute" in f.title.lower() or "ssh" in f.title.lower()]
        assert len(brute_force) == 1, f"Expected 1 grouped finding, got {len(brute_force)}"
    finally:
        os.unlink(path)
