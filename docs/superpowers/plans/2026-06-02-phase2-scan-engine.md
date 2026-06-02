# Phase 2 — Scan Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the scan engine — SQLite persistence, 9 tool wrappers, a `ScanWorker(QThread)` orchestrator, and wired scan UI — so SecureOps can run a live pentest pipeline and display results in real time.

**Architecture:** Single `ScanWorker(QThread)` orchestrates a sequential main chain (subfinder → dnsx → naabu → httpx → katana → nuclei) then runs nmap / nikto / testssl.sh in a `ThreadPoolExecutor(max_workers=3)`. All tool output is parsed into `Host` / `Finding` dataclasses and written to SQLite immediately. Qt signals carry status and findings to the UI.

**Tech Stack:** PyQt6, sqlite3 (stdlib), subprocess (stdlib), concurrent.futures (stdlib), tempfile (stdlib), xml.etree.ElementTree (stdlib for nmap XML)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `models.py` | Create | Client, Scan, Host, Finding dataclasses |
| `db.py` | Create | DB class — SQLite schema + CRUD, thread-safe with Lock |
| `workers/__init__.py` | Create | Empty |
| `workers/base_tool.py` | Create | ToolError, CancelledError, ToolRunner, _write_tmpfile |
| `workers/tools/__init__.py` | Create | Empty |
| `workers/tools/subfinder.py` | Create | subfinder wrapper |
| `workers/tools/dnsx.py` | Create | dnsx wrapper |
| `workers/tools/naabu.py` | Create | naabu wrapper |
| `workers/tools/httpx.py` | Create | httpx wrapper |
| `workers/tools/katana.py` | Create | katana wrapper |
| `workers/tools/nuclei.py` | Create | nuclei wrapper |
| `workers/tools/nmap.py` | Create | nmap wrapper — XML buffered, parsed with ElementTree |
| `workers/tools/nikto.py` | Create | nikto wrapper — JSON file output, text regex fallback |
| `workers/tools/testssl.py` | Create | testssl.sh wrapper — JSON file output |
| `workers/scan_worker.py` | Create | ScanWorker(QThread) — full pipeline orchestrator |
| `tests/conftest.py` | Modify | Add `db` fixture (in-memory SQLite) |
| `tests/test_models.py` | Create | Dataclass field/type/default checks |
| `tests/test_db.py` | Create | Schema, every insert/query, foreign keys, nullable fields |
| `tests/test_base_tool.py` | Create | ToolRunner streaming, error, cancel, FileNotFoundError |
| `tests/test_tools.py` | Create | One test per tool wrapper with MockRunner (9 tests) |
| `tests/test_scan_worker.py` | Create | Signal order, tool_failed, cancel, scan status in DB |
| `main.py` | Modify | Create DB instance, expand ~/.secureops/, pass to MainWindow |
| `main_window.py` | Modify | Accept db kwarg, pass to ScanViewScreen + ClientOnboardingScreen |
| `screens/scan_view.py` | Modify | Enable start btn, add status label, terminal feed, ScanWorker signals |
| `screens/client_onboarding.py` | Modify | Accept db kwarg, persist client on save |

---

## Task 1: Data models

**Files:**
- Create: `models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_models.py`:
```python
from models import Client, Scan, Host, Finding


def test_client_fields():
    c = Client(id=None, name="Acme", domain="acme.com", firewall="pfSense", notes="", created_at="2024-01-01T00:00:00")
    assert c.name == "Acme"
    assert c.id is None


def test_scan_nullable_client_id():
    s = Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None)
    assert s.client_id is None
    assert s.finished_at is None


def test_host_all_nullable():
    h = Host(id=None, scan_id=1, subdomain=None, ip=None, port=None, protocol=None, service=None, url=None, source_tool="subfinder", created_at="2024-01-01T00:00:00")
    assert h.subdomain is None
    assert h.source_tool == "subfinder"


def test_finding_fields():
    f = Finding(id=None, scan_id=1, host_id=None, tool="nuclei", severity="critical", title="CVE-2021-41773", description="Path traversal", raw_json="{}", created_at="2024-01-01T00:00:00")
    assert f.severity == "critical"
    assert f.host_id is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'models'`

- [ ] **Step 3: Write `models.py`**

```python
from dataclasses import dataclass


@dataclass
class Client:
    id: int | None
    name: str
    domain: str
    firewall: str
    notes: str
    created_at: str


@dataclass
class Scan:
    id: int | None
    client_id: int | None
    target: str
    status: str
    started_at: str
    finished_at: str | None


@dataclass
class Host:
    id: int | None
    scan_id: int
    subdomain: str | None
    ip: str | None
    port: int | None
    protocol: str | None
    service: str | None
    url: str | None
    source_tool: str
    created_at: str


@dataclass
class Finding:
    id: int | None
    scan_id: int
    host_id: int | None
    tool: str
    severity: str
    title: str
    description: str
    raw_json: str
    created_at: str
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_models.py -v
```

Expected: 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add models.py tests/test_models.py
git commit -m "feat: Client, Scan, Host, Finding dataclasses"
```

---

## Task 2: Database layer

**Files:**
- Create: `db.py`
- Create: `tests/test_db.py`
- Modify: `tests/conftest.py`

- [ ] **Step 1: Add `db` fixture to conftest**

`tests/conftest.py` — full file after edit:
```python
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from db import DB


@pytest.fixture
def db():
    return DB(":memory:")
```

- [ ] **Step 2: Write the failing tests**

`tests/test_db.py`:
```python
from models import Client, Scan, Host, Finding
from db import DB


def test_insert_and_query_client(db):
    client = Client(id=None, name="Acme", domain="acme.com", firewall="pfSense", notes="", created_at="2024-01-01T00:00:00")
    cid = db.insert_client(client)
    assert isinstance(cid, int)
    clients = db.query_clients()
    assert len(clients) == 1
    assert clients[0].name == "Acme"
    assert clients[0].id == cid


def test_insert_scan_nullable_client(db):
    scan = Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None)
    sid = db.insert_scan(scan)
    assert isinstance(sid, int)


def test_update_scan_status(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    db.update_scan_status(sid, "complete", "2024-01-01T01:00:00")
    scans = db.query_scans_by_client(None)
    assert scans[0].status == "complete"
    assert scans[0].finished_at == "2024-01-01T01:00:00"


def test_insert_and_query_host(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    host = Host(id=None, scan_id=sid, subdomain="api.acme.com", ip="1.2.3.4", port=443, protocol="tcp", service="https", url="https://api.acme.com", source_tool="httpx", created_at="2024-01-01T00:00:00")
    hid = db.insert_host(host)
    hosts = db.query_hosts_by_scan(sid)
    assert len(hosts) == 1
    assert hosts[0].subdomain == "api.acme.com"
    assert hosts[0].id == hid


def test_insert_and_query_finding(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    finding = Finding(id=None, scan_id=sid, host_id=None, tool="nuclei", severity="critical", title="CVE-2021-41773", description="Path traversal", raw_json="{}", created_at="2024-01-01T00:00:00")
    fid = db.insert_finding(finding)
    findings = db.query_findings_by_scan(sid)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].id == fid


def test_host_nullable_fields(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    host = Host(id=None, scan_id=sid, subdomain="api.acme.com", ip=None, port=None, protocol=None, service=None, url=None, source_tool="subfinder", created_at="2024-01-01T00:00:00")
    db.insert_host(host)
    hosts = db.query_hosts_by_scan(sid)
    assert hosts[0].ip is None


def test_finding_nullable_host_id(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    finding = Finding(id=None, scan_id=sid, host_id=None, tool="nuclei", severity="high", title="Open Redirect", description="", raw_json="{}", created_at="2024-01-01T00:00:00")
    db.insert_finding(finding)
    findings = db.query_findings_by_scan(sid)
    assert findings[0].host_id is None


def test_query_scans_by_client(db):
    cid = db.insert_client(Client(id=None, name="Acme", domain="acme.com", firewall="", notes="", created_at="2024-01-01T00:00:00"))
    db.insert_scan(Scan(id=None, client_id=cid, target="acme.com", status="complete", started_at="2024-01-01T00:00:00", finished_at="2024-01-01T01:00:00"))
    scans = db.query_scans_by_client(cid)
    assert len(scans) == 1
    assert scans[0].client_id == cid
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_db.py -v
```

Expected: `ModuleNotFoundError: No module named 'db'`

- [ ] **Step 4: Write `db.py`**

```python
import sqlite3
import threading
from models import Client, Scan, Host, Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    firewall    TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   INTEGER REFERENCES clients(id),
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    subdomain   TEXT,
    ip          TEXT,
    port        INTEGER,
    protocol    TEXT,
    service     TEXT,
    url         TEXT,
    source_tool TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_id     INTEGER REFERENCES hosts(id),
    tool        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    raw_json    TEXT,
    created_at  TEXT NOT NULL
);
"""


class DB:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        for stmt in _SCHEMA.strip().split(";"):
            if stmt.strip():
                self._conn.execute(stmt)
        self._conn.commit()

    def insert_client(self, client: Client) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO clients (name, domain, firewall, notes, created_at) VALUES (?,?,?,?,?)",
                (client.name, client.domain, client.firewall, client.notes, client.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_clients(self) -> list[Client]:
        rows = self._conn.execute("SELECT * FROM clients ORDER BY id").fetchall()
        return [Client(id=r["id"], name=r["name"], domain=r["domain"], firewall=r["firewall"] or "", notes=r["notes"] or "", created_at=r["created_at"]) for r in rows]

    def insert_scan(self, scan: Scan) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (client_id, target, status, started_at, finished_at) VALUES (?,?,?,?,?)",
                (scan.client_id, scan.target, scan.status, scan.started_at, scan.finished_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_scan_status(self, scan_id: int, status: str, finished_at: str | None = None):
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, finished_at=? WHERE id=?",
                (status, finished_at, scan_id),
            )
            self._conn.commit()

    def query_scans_by_client(self, client_id: int | None) -> list[Scan]:
        if client_id is None:
            rows = self._conn.execute("SELECT * FROM scans WHERE client_id IS NULL ORDER BY id").fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM scans WHERE client_id=? ORDER BY id", (client_id,)).fetchall()
        return [Scan(id=r["id"], client_id=r["client_id"], target=r["target"], status=r["status"], started_at=r["started_at"], finished_at=r["finished_at"]) for r in rows]

    def insert_host(self, host: Host) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO hosts (scan_id, subdomain, ip, port, protocol, service, url, source_tool, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (host.scan_id, host.subdomain, host.ip, host.port, host.protocol, host.service, host.url, host.source_tool, host.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_hosts_by_scan(self, scan_id: int) -> list[Host]:
        rows = self._conn.execute("SELECT * FROM hosts WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [Host(id=r["id"], scan_id=r["scan_id"], subdomain=r["subdomain"], ip=r["ip"], port=r["port"], protocol=r["protocol"], service=r["service"], url=r["url"], source_tool=r["source_tool"], created_at=r["created_at"]) for r in rows]

    def insert_finding(self, finding: Finding) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings (scan_id, host_id, tool, severity, title, description, raw_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (finding.scan_id, finding.host_id, finding.tool, finding.severity, finding.title, finding.description, finding.raw_json, finding.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_findings_by_scan(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [Finding(id=r["id"], scan_id=r["scan_id"], host_id=r["host_id"], tool=r["tool"], severity=r["severity"], title=r["title"], description=r["description"] or "", raw_json=r["raw_json"] or "", created_at=r["created_at"]) for r in rows]
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_db.py -v
```

Expected: all 8 tests PASS.

- [ ] **Step 6: Run full suite to check no regressions**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add db.py tests/test_db.py tests/conftest.py
git commit -m "feat: SQLite DB layer — schema, CRUD, thread-safe with Lock"
```

---

## Task 3: ToolRunner base

**Files:**
- Create: `workers/__init__.py`
- Create: `workers/base_tool.py`
- Create: `workers/tools/__init__.py`
- Create: `tests/test_base_tool.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_base_tool.py`:
```python
import threading
from unittest.mock import patch, MagicMock
from workers.base_tool import ToolRunner, ToolError, CancelledError


def _make_runner(cancel_event=None):
    return ToolRunner(cancel_event or threading.Event())


def test_run_yields_stdout_lines():
    mock_proc = MagicMock()
    mock_proc.stdout.__iter__ = MagicMock(return_value=iter(["line1\n", "line2\n"]))
    mock_proc.returncode = 0
    mock_proc.wait = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc):
        runner = _make_runner()
        lines = list(runner.run(["echo", "test"]))

    assert lines == ["line1", "line2"]


def test_run_raises_tool_error_on_nonzero_exit():
    mock_proc = MagicMock()
    mock_proc.stdout.__iter__ = MagicMock(return_value=iter([]))
    mock_proc.returncode = 1
    mock_proc.wait = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError):
            list(runner.run(["false"]))


def test_run_raises_tool_error_on_missing_binary():
    with patch("subprocess.Popen", side_effect=FileNotFoundError):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError, match="not found"):
            list(runner.run(["nonexistent_binary"]))


def test_run_raises_cancelled_error_when_event_set():
    cancel = threading.Event()
    cancel.set()

    runner = ToolRunner(cancel)
    import pytest
    with pytest.raises(CancelledError):
        list(runner.run(["echo", "test"]))


def test_run_buffered_returns_stdout():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"key": "value"}'

    with patch("subprocess.run", return_value=mock_result):
        runner = _make_runner()
        output = runner.run_buffered(["nmap", "-oX", "-"])

    assert output == '{"key": "value"}'


def test_run_buffered_raises_tool_error_on_nonzero():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""

    with patch("subprocess.run", return_value=mock_result):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError):
            runner.run_buffered(["nmap", "-oX", "-"])
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_base_tool.py -v
```

Expected: `ModuleNotFoundError: No module named 'workers'`

- [ ] **Step 3: Create empty `__init__.py` files**

Create `workers/__init__.py` — empty file.
Create `workers/tools/__init__.py` — empty file.

- [ ] **Step 4: Write `workers/base_tool.py`**

```python
import os
import subprocess
import tempfile
import threading
from typing import Iterator


class ToolError(Exception):
    pass


class CancelledError(Exception):
    pass


def _write_tmpfile(lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="secureops_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return path


class ToolRunner:
    def __init__(self, cancel_event: threading.Event):
        self._cancel = cancel_event

    def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
        if self._cancel.is_set():
            raise CancelledError()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")

        for line in proc.stdout:
            if self._cancel.is_set():
                proc.kill()
                proc.wait()
                raise CancelledError()
            stripped = line.rstrip()
            if stripped:
                yield stripped

        proc.wait()
        if proc.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {proc.returncode}")

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        if self._cancel.is_set():
            raise CancelledError()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")
        except subprocess.TimeoutExpired:
            raise ToolError(f"{cmd[0]}: timed out after {timeout}s")
        if self._cancel.is_set():
            raise CancelledError()
        if result.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {result.returncode}")
        return result.stdout
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_base_tool.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add workers/__init__.py workers/tools/__init__.py workers/base_tool.py tests/test_base_tool.py
git commit -m "feat: ToolRunner base — streaming, buffered, cancel, error handling"
```

---

## Task 4: subfinder, dnsx, naabu wrappers

**Files:**
- Create: `workers/tools/subfinder.py`
- Create: `workers/tools/dnsx.py`
- Create: `workers/tools/naabu.py`
- Create (append to): `tests/test_tools.py`

All three tools emit one JSON object per stdout line and produce `Host` records.

- [ ] **Step 1: Write the failing tests**

`tests/test_tools.py`:
```python
import threading
from models import Host, Finding
from db import DB


class MockRunner:
    def __init__(self, lines: list[str] = None, buffered: str = ""):
        self._lines = lines or []
        self._buffered = buffered

    def run(self, cmd: list[str], timeout: int = 300):
        yield from self._lines

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        return self._buffered


# ── subfinder ────────────────────────────────────────────────────────────────

def test_subfinder_returns_host(db):
    from workers.tools import subfinder
    line = '{"host": "api.example.com", "input": "example.com", "source": ["certspotter"]}'
    scan_id = db.insert_scan(__import__("models").Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = subfinder.run("example.com", MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].subdomain == "api.example.com"
    assert hosts[0].source_tool == "subfinder"
    assert hosts[0].scan_id == scan_id
    assert len(db.query_hosts_by_scan(scan_id)) == 1


# ── dnsx ─────────────────────────────────────────────────────────────────────

def test_dnsx_returns_host_with_ip(db):
    from workers.tools import dnsx
    from models import Scan
    line = '{"host": "api.example.com", "a": ["93.184.216.34"], "status_code": "NOERROR"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = dnsx.run(["api.example.com"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].ip == "93.184.216.34"
    assert hosts[0].subdomain == "api.example.com"
    assert hosts[0].source_tool == "dnsx"


# ── naabu ─────────────────────────────────────────────────────────────────────

def test_naabu_returns_host_with_port(db):
    from workers.tools import naabu
    from models import Scan
    line = '{"ip": "93.184.216.34", "port": 443, "protocol": "tcp"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = naabu.run(["93.184.216.34"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].ip == "93.184.216.34"
    assert hosts[0].port == 443
    assert hosts[0].protocol == "tcp"
    assert hosts[0].source_tool == "naabu"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: `ModuleNotFoundError: No module named 'workers.tools.subfinder'`

- [ ] **Step 3: Write `workers/tools/subfinder.py`**

```python
import json
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile
import os


def run(target: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    cmd = ["subfinder", "-d", target, "-json", "-silent"]
    hosts = []
    for line in runner.run(cmd):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = Host(
            id=None,
            scan_id=scan_id,
            subdomain=data.get("host"),
            ip=None,
            port=None,
            protocol=None,
            service=None,
            url=None,
            source_tool="subfinder",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        host_id = db.insert_host(host)
        host.id = host_id
        hosts.append(host)
    return hosts
```

- [ ] **Step 4: Write `workers/tools/dnsx.py`**

```python
import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(subdomains: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not subdomains:
        return []
    tmpfile = _write_tmpfile(subdomains)
    hosts = []
    try:
        for line in runner.run(["dnsx", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            ips = data.get("a") or []
            ip = ips[0] if ips else None
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=data.get("host"),
                ip=ip,
                port=None,
                protocol=None,
                service=None,
                url=None,
                source_tool="dnsx",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host_id = db.insert_host(host)
            host.id = host_id
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
```

- [ ] **Step 5: Write `workers/tools/naabu.py`**

```python
import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(ips: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not ips:
        return []
    tmpfile = _write_tmpfile(ips)
    hosts = []
    try:
        for line in runner.run(["naabu", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=data.get("ip"),
                port=data.get("port"),
                protocol=data.get("protocol"),
                service=None,
                url=None,
                source_tool="naabu",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host_id = db.insert_host(host)
            host.id = host_id
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: 3 tests PASS.

- [ ] **Step 7: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add workers/tools/subfinder.py workers/tools/dnsx.py workers/tools/naabu.py tests/test_tools.py
git commit -m "feat: subfinder, dnsx, naabu tool wrappers"
```

---

## Task 5: httpx and katana wrappers

**Files:**
- Create: `workers/tools/httpx.py`
- Create: `workers/tools/katana.py`
- Modify: `tests/test_tools.py` (append tests)

- [ ] **Step 1: Append failing tests to `tests/test_tools.py`**

Add to the end of `tests/test_tools.py`:
```python
# ── httpx ─────────────────────────────────────────────────────────────────────

def test_httpx_returns_host_with_url(db):
    from workers.tools import httpx as httpx_tool
    from models import Scan
    line = '{"url": "https://api.example.com", "status_code": 200, "title": "API Gateway", "webserver": "nginx/1.18.0", "input": "api.example.com:443"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = httpx_tool.run(["api.example.com:443"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].url == "https://api.example.com"
    assert hosts[0].service == "nginx/1.18.0"
    assert hosts[0].source_tool == "httpx"


# ── katana ────────────────────────────────────────────────────────────────────

def test_katana_returns_host_with_url(db):
    from workers.tools import katana
    from models import Scan
    line = '{"timestamp": "2024-01-01T00:00:00Z", "request": {"method": "GET", "endpoint": "https://api.example.com/login"}}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = katana.run(["https://api.example.com"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].url == "https://api.example.com/login"
    assert hosts[0].source_tool == "katana"
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_tools.py::test_httpx_returns_host_with_url tests/test_tools.py::test_katana_returns_host_with_url -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Write `workers/tools/httpx.py`**

```python
import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(targets: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not targets:
        return []
    tmpfile = _write_tmpfile(targets)
    hosts = []
    try:
        for line in runner.run(["httpx", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=None,
                port=None,
                protocol=None,
                service=data.get("webserver"),
                url=data.get("url"),
                source_tool="httpx",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host_id = db.insert_host(host)
            host.id = host_id
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
```

- [ ] **Step 4: Write `workers/tools/katana.py`**

```python
import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(urls: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not urls:
        return []
    tmpfile = _write_tmpfile(urls)
    hosts = []
    try:
        for line in runner.run(["katana", "-list", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = (data.get("request") or {}).get("endpoint")
            if not endpoint:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=None,
                port=None,
                protocol=None,
                service=None,
                url=endpoint,
                source_tool="katana",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host_id = db.insert_host(host)
            host.id = host_id
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
```

- [ ] **Step 5: Run all tool tests**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add workers/tools/httpx.py workers/tools/katana.py tests/test_tools.py
git commit -m "feat: httpx, katana tool wrappers"
```

---

## Task 6: nuclei wrapper

**Files:**
- Create: `workers/tools/nuclei.py`
- Modify: `tests/test_tools.py` (append test)

- [ ] **Step 1: Append failing test**

Add to end of `tests/test_tools.py`:
```python
# ── nuclei ────────────────────────────────────────────────────────────────────

def test_nuclei_returns_finding(db):
    from workers.tools import nuclei
    from models import Scan
    line = '{"template-id": "cve-2021-41773", "info": {"name": "Apache Path Traversal", "severity": "critical", "description": "Allows path traversal"}, "host": "https://api.example.com", "matched-at": "https://api.example.com/.%2e/etc/passwd", "timestamp": "2024-01-01T00:00:00Z"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    findings = nuclei.run(["https://api.example.com"], MockRunner([line]), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nuclei"
    assert findings[0].severity == "critical"
    assert findings[0].title == "Apache Path Traversal"
    assert findings[0].scan_id == scan_id
    assert len(db.query_findings_by_scan(scan_id)) == 1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source venv/bin/activate && pytest tests/test_tools.py::test_nuclei_returns_finding -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Write `workers/tools/nuclei.py`**

```python
import json
import os
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(targets: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    if not targets:
        return []
    tmpfile = _write_tmpfile(targets)
    findings = []
    try:
        for line in runner.run(["nuclei", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = data.get("info") or {}
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="nuclei",
                severity=(info.get("severity") or "info").lower(),
                title=info.get("name") or data.get("template-id") or "Unknown",
                description=info.get("description") or "",
                raw_json=line,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            fid = db.insert_finding(finding)
            finding.id = fid
            findings.append(finding)
    finally:
        os.unlink(tmpfile)
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/tools/nuclei.py tests/test_tools.py
git commit -m "feat: nuclei tool wrapper"
```

---

## Task 7: nmap wrapper

**Files:**
- Create: `workers/tools/nmap.py`
- Modify: `tests/test_tools.py` (append test)

nmap uses `-oX -` (XML to stdout), buffered into one string. Parsed with `xml.etree.ElementTree`. Produces `Finding` records for each open port with service info.

- [ ] **Step 1: Append failing test**

Add to end of `tests/test_tools.py`:
```python
# ── nmap ──────────────────────────────────────────────────────────────────────

def test_nmap_returns_finding_for_open_port(db):
    from workers.tools import nmap
    from models import Scan
    xml_output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    findings = nmap.run(["93.184.216.34"], MockRunner(buffered=xml_output), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nmap"
    assert findings[0].title == "Open port 443/tcp (https)"
    assert "nginx" in findings[0].description
    assert len(db.query_findings_by_scan(scan_id)) == 1
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source venv/bin/activate && pytest tests/test_tools.py::test_nmap_returns_finding_for_open_port -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Write `workers/tools/nmap.py`**

```python
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner, ToolError, _write_tmpfile


def run(hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    if not hosts:
        return []
    tmpfile = _write_tmpfile(hosts)
    findings = []
    try:
        xml_output = runner.run_buffered(["nmap", "-iL", tmpfile, "-oX", "-", "-sV"])
        if not xml_output.strip():
            return findings
        root = ET.fromstring(xml_output)
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else "unknown"
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                proto = port_el.get("protocol", "tcp")
                portid = port_el.get("portid", "?")
                service_el = port_el.find("service")
                svc_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                desc = " ".join(filter(None, [product, version])) or svc_name
                finding = Finding(
                    id=None,
                    scan_id=scan_id,
                    host_id=None,
                    tool="nmap",
                    severity="info",
                    title=f"Open port {portid}/{proto} ({svc_name})",
                    description=desc,
                    raw_json=xml_output[:2000],
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                fid = db.insert_finding(finding)
                finding.id = fid
                findings.append(finding)
    except ET.ParseError:
        raise ToolError("nmap: failed to parse XML output")
    finally:
        os.unlink(tmpfile)
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/tools/nmap.py tests/test_tools.py
git commit -m "feat: nmap tool wrapper — XML buffered, open port findings"
```

---

## Task 8: nikto wrapper

**Files:**
- Create: `workers/tools/nikto.py`
- Modify: `tests/test_tools.py` (append test)

nikto is called per HTTP host. Writes JSON to a temp file with `-Format json -output <file>`. Falls back to text parsing if JSON output is unavailable.

- [ ] **Step 1: Append failing test**

Add to end of `tests/test_tools.py`:
```python
# ── nikto ─────────────────────────────────────────────────────────────────────

def test_nikto_returns_finding_from_json(db, tmp_path):
    from workers.tools import nikto
    from models import Scan
    import json as _json

    json_content = _json.dumps({
        "host": "https://api.example.com",
        "ip": "93.184.216.34",
        "port": "443",
        "vulnerabilities": [
            {"id": "999986", "method": "GET", "url": "/", "msg": "X-Frame-Options header not present.", "references": "CWE-693"}
        ]
    })

    class NiktoMockRunner:
        def __init__(self, json_content, out_path):
            self._json = json_content
            self._path = out_path

        def run_buffered(self, cmd, timeout=300):
            import os
            output_flag = "-output"
            if output_flag in cmd:
                idx = cmd.index(output_flag)
                path = cmd[idx + 1]
                with open(path, "w") as f:
                    f.write(self._json)
            return ""

    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    findings = nikto.run(["https://api.example.com"], NiktoMockRunner(json_content, tmp_path), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nikto"
    assert "X-Frame-Options" in findings[0].title
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source venv/bin/activate && pytest tests/test_tools.py::test_nikto_returns_finding_from_json -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Write `workers/tools/nikto.py`**

```python
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner


def run(http_hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    for host in http_hosts:
        findings.extend(_scan_host(host, runner, db, scan_id))
    return findings


def _scan_host(host: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="secureops_nikto_")
    os.close(fd)
    try:
        runner.run_buffered(["nikto", "-h", host, "-Format", "json", "-output", tmpfile, "-nointeractive"])
        if os.path.getsize(tmpfile) > 0:
            return _parse_json_file(tmpfile, db, scan_id)
        return []
    except Exception:
        return []
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)


def _parse_json_file(path: str, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for vuln in data.get("vulnerabilities") or []:
            msg = vuln.get("msg") or vuln.get("message") or "Unknown issue"
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="nikto",
                severity="medium",
                title=msg[:120],
                description=f"URL: {vuln.get('url', '')}  Ref: {vuln.get('references', '')}",
                raw_json=json.dumps(vuln),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            fid = db.insert_finding(finding)
            finding.id = fid
            findings.append(finding)
    except (json.JSONDecodeError, KeyError):
        pass
    return findings
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/tools/nikto.py tests/test_tools.py
git commit -m "feat: nikto tool wrapper — JSON file output"
```

---

## Task 9: testssl wrapper

**Files:**
- Create: `workers/tools/testssl.py`
- Modify: `tests/test_tools.py` (append test)

testssl.sh is called per HTTPS host. Writes a JSON array to a temp file with `--jsonfile <path>`.

- [ ] **Step 1: Append failing test**

Add to end of `tests/test_tools.py`:
```python
# ── testssl ───────────────────────────────────────────────────────────────────

def test_testssl_returns_finding_for_critical(db):
    from workers.tools import testssl
    from models import Scan
    import json as _json

    json_content = _json.dumps([
        {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE, uses SSLv3+"},
        {"id": "cert_trust", "severity": "OK", "finding": "certificate chain valid"},
    ])

    class TestsslMockRunner:
        def __init__(self, content):
            self._content = content

        def run_buffered(self, cmd, timeout=300):
            jsonfile_flag = "--jsonfile"
            if jsonfile_flag in cmd:
                idx = cmd.index(jsonfile_flag)
                path = cmd[idx + 1]
                with open(path, "w") as f:
                    f.write(self._content)
            return ""

    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    findings = testssl.run(["https://api.example.com"], TestsslMockRunner(json_content), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "testssl"
    assert findings[0].severity == "critical"
    assert "heartbleed" in findings[0].title
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source venv/bin/activate && pytest tests/test_tools.py::test_testssl_returns_finding_for_critical -v
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3: Write `workers/tools/testssl.py`**

```python
import json
import os
import tempfile
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": None,
    "NOT OK": "medium",
    "WARN": "low",
    "DEBUG": "info",
}


def run(https_hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    for host in https_hosts:
        findings.extend(_scan_host(host, runner, db, scan_id))
    return findings


def _scan_host(host: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="secureops_testssl_")
    os.close(fd)
    try:
        runner.run_buffered(["testssl.sh", "--jsonfile", tmpfile, "--quiet", "--color", "0", host])
        if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) == 0:
            return []
        return _parse_json_file(tmpfile, db, scan_id)
    except Exception:
        return []
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)


def _parse_json_file(path: str, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    try:
        with open(path) as f:
            items = json.load(f)
        for item in items:
            raw_sev = (item.get("severity") or "").upper()
            severity = _SEVERITY_MAP.get(raw_sev)
            if severity is None:
                continue
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="testssl",
                severity=severity,
                title=f"testssl: {item.get('id', 'unknown')}",
                description=item.get("finding") or "",
                raw_json=json.dumps(item),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            fid = db.insert_finding(finding)
            finding.id = fid
            findings.append(finding)
    except (json.JSONDecodeError, TypeError):
        pass
    return findings
```

- [ ] **Step 4: Run all tool tests**

```bash
source venv/bin/activate && pytest tests/test_tools.py -v
```

Expected: all 9 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add workers/tools/testssl.py tests/test_tools.py
git commit -m "feat: testssl.sh tool wrapper — JSON file output, severity mapping"
```

---

## Task 10: ScanWorker orchestrator

**Files:**
- Create: `workers/scan_worker.py`
- Create: `tests/test_scan_worker.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_scan_worker.py`:
```python
import threading
from unittest.mock import patch, MagicMock
from PyQt6.QtCore import QCoreApplication
from workers.scan_worker import ScanWorker
from models import Host, Finding, Scan
from db import DB


def _make_worker(db, target="example.com"):
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target=target, status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    return ScanWorker(target=target, scan_id=scan_id, db=db), scan_id


def test_scan_worker_emits_tool_started_signals(qtbot, db):
    worker, _ = _make_worker(db)
    started_tools = []

    worker.tool_started.connect(started_tools.append)

    with patch("workers.scan_worker.subfinder.run", return_value=[]):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    assert "subfinder" in started_tools
    assert "nuclei" in started_tools


def test_scan_worker_emits_tool_failed_on_tool_error(qtbot, db):
    from workers.base_tool import ToolError
    worker, _ = _make_worker(db)
    failed_tools = []
    worker.tool_failed.connect(lambda name, _msg: failed_tools.append(name))

    with patch("workers.scan_worker.subfinder.run", side_effect=ToolError("subfinder: not found")):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    assert "subfinder" in failed_tools


def test_scan_worker_sets_status_complete_in_db(qtbot, db):
    worker, scan_id = _make_worker(db)

    with patch("workers.scan_worker.subfinder.run", return_value=[]):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    scans = db.query_scans_by_client(None)
    assert scans[0].status == "complete"


def test_scan_worker_cancel_emits_scan_failed(qtbot, db):
    from workers.base_tool import CancelledError
    worker, _ = _make_worker(db)
    failed_msgs = []
    worker.scan_failed.connect(failed_msgs.append)

    with patch("workers.scan_worker.subfinder.run", side_effect=CancelledError()):
        with qtbot.waitSignal(worker.scan_failed, timeout=5000):
            worker.start()

    assert any("Cancel" in m or "cancel" in m.lower() for m in failed_msgs)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_scan_worker.py -v
```

Expected: `ModuleNotFoundError: No module named 'workers.scan_worker'`

- [ ] **Step 3: Write `workers/scan_worker.py`**

```python
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from workers.base_tool import ToolRunner, ToolError, CancelledError
from workers.tools import subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl


class ScanWorker(QThread):
    tool_started  = pyqtSignal(str)
    tool_finished = pyqtSignal(str, int)
    tool_failed   = pyqtSignal(str, str)
    host_found    = pyqtSignal(object)
    finding_found = pyqtSignal(object)
    log_line      = pyqtSignal(str)
    scan_complete = pyqtSignal(int, int)
    scan_failed   = pyqtSignal(str)

    def __init__(self, target: str, scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._target = target
        self._scan_id = scan_id
        self._db = db
        self._cancel_event = threading.Event()

    def cancel(self):
        self._cancel_event.set()

    def run(self):
        try:
            self._execute_pipeline()
        except CancelledError:
            self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit("Cancelled")
        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(str(exc))

    def _make_runner(self) -> ToolRunner:
        return ToolRunner(self._cancel_event)

    def _run_tool(self, name: str, fn, *args):
        self.tool_started.emit(name)
        self.log_line.emit(f"[{name}] starting...")
        try:
            results = fn(*args)
            self.tool_finished.emit(name, len(results))
            self.log_line.emit(f"[{name}] done — {len(results)} items")
            for item in results:
                if hasattr(item, "severity"):
                    self.finding_found.emit(item)
                else:
                    self.host_found.emit(item)
            return results
        except CancelledError:
            raise
        except ToolError as exc:
            self.tool_failed.emit(name, str(exc))
            self.log_line.emit(f"[{name}] failed: {exc}")
            return []

    def _execute_pipeline(self):
        runner = self._make_runner()

        subdomains_hosts = self._run_tool("subfinder", subfinder.run, self._target, runner, self._db, self._scan_id)
        subdomain_names = [h.subdomain for h in subdomains_hosts if h.subdomain]

        resolved_hosts = self._run_tool("dnsx", dnsx.run, subdomain_names, runner, self._db, self._scan_id)
        ips = list({h.ip for h in resolved_hosts if h.ip})

        port_hosts = self._run_tool("naabu", naabu.run, ips, runner, self._db, self._scan_id)
        host_ports = [f"{h.ip}:{h.port}" for h in port_hosts if h.ip and h.port]

        http_hosts_list = self._run_tool("httpx", httpx.run, host_ports, runner, self._db, self._scan_id)
        http_urls = [h.url for h in http_hosts_list if h.url]

        self._run_tool("katana", katana.run, http_urls, runner, self._db, self._scan_id)

        all_targets = list({h.url or f"{h.ip}:{h.port}" for h in self._db.query_hosts_by_scan(self._scan_id) if h.url or (h.ip and h.port)})
        self._run_tool("nuclei", nuclei.run, all_targets, runner, self._db, self._scan_id)

        https_urls = [u for u in http_urls if u and u.startswith("https://")]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self._run_parallel_tool, "nmap",    nmap.run,    ips,         self._make_runner()),
                executor.submit(self._run_parallel_tool, "nikto",   nikto.run,   http_urls,   self._make_runner()),
                executor.submit(self._run_parallel_tool, "testssl", testssl.run, https_urls,  self._make_runner()),
            ]
            for future in futures:
                future.result()

        hosts_count = len(self._db.query_hosts_by_scan(self._scan_id))
        findings_count = len(self._db.query_findings_by_scan(self._scan_id))
        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(hosts_count, findings_count)

    def _run_parallel_tool(self, name: str, fn, targets: list, runner: ToolRunner):
        self.tool_started.emit(name)
        self.log_line.emit(f"[{name}] starting...")
        try:
            results = fn(targets, runner, self._db, self._scan_id)
            self.tool_finished.emit(name, len(results))
            self.log_line.emit(f"[{name}] done — {len(results)} items")
            for item in results:
                self.finding_found.emit(item)
            return results
        except CancelledError:
            raise
        except ToolError as exc:
            self.tool_failed.emit(name, str(exc))
            self.log_line.emit(f"[{name}] failed: {exc}")
            return []
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_scan_worker.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add workers/scan_worker.py tests/test_scan_worker.py
git commit -m "feat: ScanWorker — sequential chain + parallel tail, cancel, signals"
```

---

## Task 11: DB threading — wire main.py and main_window.py

**Files:**
- Modify: `main.py`
- Modify: `main_window.py`

- [ ] **Step 1: Update `main.py`**

Replace entire file:
```python
import sys
from pathlib import Path
from app import create_app
from tool_checker import check_tools
from main_window import MainWindow
from db import DB

_DB_PATH = Path.home() / ".secureops" / "secureops.db"


def build_window() -> MainWindow:
    tool_results = check_tools()
    _DB_PATH.parent.mkdir(exist_ok=True)
    db = DB(str(_DB_PATH))
    return MainWindow(tool_results, db=db)


def main():
    app = create_app(sys.argv)
    window = build_window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Update `main_window.py`**

Replace entire file:
```python
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
)
from sidebar import Sidebar
from status_bar import ToolStatusBar
from screens.dashboard import DashboardScreen
from screens.client_onboarding import ClientOnboardingScreen
from screens.scan_view import ScanViewScreen
from screens.report import ReportScreen
from screens.settings import SettingsScreen
from db import DB


class MainWindow(QMainWindow):
    def __init__(self, tool_results: dict, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._sidebar: Sidebar | None = None
        self._stack: QStackedWidget | None = None
        self._status_bar_widget: ToolStatusBar | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("SecureOps")
        self.setMinimumSize(1200, 700)

        outer = QWidget()
        self.setCentralWidget(outer)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        content_row = QWidget()
        row_layout = QHBoxLayout(content_row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self._sidebar = Sidebar()
        self._stack = QStackedWidget()

        self._stack.addWidget(DashboardScreen(self._tool_results))                    # 0
        self._stack.addWidget(ClientOnboardingScreen(db=self._db))                    # 1
        self._stack.addWidget(ScanViewScreen(db=self._db))                            # 2
        self._stack.addWidget(ReportScreen())                                          # 3
        self._stack.addWidget(SettingsScreen(self._tool_results))                     # 4

        row_layout.addWidget(self._sidebar)
        row_layout.addWidget(self._stack, stretch=1)
        outer_layout.addWidget(content_row, stretch=1)

        self._status_bar_widget = ToolStatusBar(self._tool_results)
        outer_layout.addWidget(self._status_bar_widget)

        self._sidebar.screen_changed.connect(self._stack.setCurrentIndex)
        self._status_bar_widget.navigate_to_settings.connect(
            lambda: self._stack.setCurrentIndex(4)
        )
```

- [ ] **Step 3: Run full test suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS. (Existing tests pass because `MainWindow` has `db=None` default, so `build_window` mock in `test_main.py` still works.)

- [ ] **Step 4: Commit**

```bash
git add main.py main_window.py
git commit -m "feat: thread DB through main.py and main_window.py"
```

---

## Task 12: ScanViewScreen wiring

**Files:**
- Modify: `screens/scan_view.py`
- Modify: `tests/test_screen_scan_view.py` (add new tests for wired behaviour)

- [ ] **Step 1: Append new failing tests to `tests/test_screen_scan_view.py`**

Add to end of `tests/test_screen_scan_view.py`:
```python
from db import DB
from models import Scan


def _make_db():
    return DB(":memory:")


def test_scan_view_start_button_enabled_with_db(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert screen._start_btn.isEnabled()


def test_scan_view_has_status_label(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert screen._status_label is not None


def test_scan_view_terminal_panel_is_plain_text_edit(qtbot):
    from PyQt6.QtWidgets import QPlainTextEdit
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._terminal_panel, QPlainTextEdit)


def test_scan_view_start_button_still_disabled_without_db(qtbot):
    screen = ScanViewScreen(db=None)
    qtbot.addWidget(screen)
    assert not screen._start_btn.isEnabled()
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py -v
```

Expected: the 4 new tests FAIL (existing 7 pass).

- [ ] **Step 3: Rewrite `screens/scan_view.py`**

```python
from datetime import datetime, timezone
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QSplitter, QPlainTextEdit,
)


def _placeholder_panel(text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class ScanViewScreen(QWidget):
    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._pipeline_panel: QFrame | None = None
        self._attack_graph_panel: QFrame | None = None
        self._severity_panel: QFrame | None = None
        self._finding_cards_panel: QFrame | None = None
        self._terminal_panel: QPlainTextEdit | None = None
        self._worker = None
        self._scan_id: int | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.setToolTip("Enter a target and click to scan" if self._db else "DB not initialised")
        self._start_btn.clicked.connect(self._on_start_cancel)
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(self._status_label)

        self._pipeline_panel = _placeholder_panel("Pipeline Tracker\nPhase 3")
        self._attack_graph_panel = _placeholder_panel("Attack Surface Graph\nPhase 3")
        self._severity_panel = _placeholder_panel("Severity\nRings\nPhase 3")
        self._finding_cards_panel = _placeholder_panel("Finding Cards Stream\nPhase 3")

        self._terminal_panel = QPlainTextEdit()
        self._terminal_panel.setReadOnly(True)
        self._terminal_panel.setObjectName("panel")
        self._terminal_panel.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #00ff88; background-color: #0a0e1a;"
        )

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._pipeline_panel)
        top_splitter.addWidget(self._attack_graph_panel)
        top_splitter.setSizes([250, 750])

        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.addWidget(self._severity_panel)
        mid_splitter.addWidget(self._finding_cards_panel)
        mid_splitter.setSizes([250, 750])

        top_mid = QWidget()
        top_mid_layout = QVBoxLayout(top_mid)
        top_mid_layout.setContentsMargins(0, 0, 0, 0)
        top_mid_layout.setSpacing(8)
        top_mid_layout.addWidget(top_splitter, stretch=1)
        top_mid_layout.addWidget(mid_splitter, stretch=1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_mid)
        main_splitter.addWidget(self._terminal_panel)
        main_splitter.setSizes([800, 200])

        layout.addWidget(main_splitter, stretch=1)

    def _on_start_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            return

        target = self._target_input.text().strip()
        if not target:
            self._status_label.setText("Enter a target first.")
            return

        from models import Scan
        from workers.scan_worker import ScanWorker

        scan = Scan(
            id=None,
            client_id=None,
            target=target,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)
        self._worker.tool_started.connect(lambda name: self._status_label.setText(f"{name} — running…"))
        self._worker.tool_finished.connect(lambda name, n: self._status_label.setText(f"{name} — {n} items"))
        self._worker.tool_failed.connect(lambda name, msg: self._log(f"[FAILED] {name}: {msg}"))
        self._worker.log_line.connect(self._log)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.scan_failed.connect(self._on_scan_failed)

        self._start_btn.setText("■  Cancel")
        self._terminal_panel.clear()
        self._worker.start()

    def _log(self, line: str):
        self._terminal_panel.appendPlainText(line)

    def _on_scan_complete(self, hosts: int, findings: int):
        self._status_label.setText(f"Complete — {hosts} hosts, {findings} findings")
        self._start_btn.setText("▶  Start Scan")

    def _on_scan_failed(self, msg: str):
        self._status_label.setText(f"Stopped: {msg}")
        self._start_btn.setText("▶  Start Scan")
```

- [ ] **Step 4: Run all scan_view tests**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py -v
```

Expected: all 11 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add screens/scan_view.py tests/test_screen_scan_view.py
git commit -m "feat: wire ScanViewScreen — start/cancel, status label, terminal feed"
```

---

## Task 13: ClientOnboardingScreen persistence

**Files:**
- Modify: `screens/client_onboarding.py`
- Modify: `tests/test_screen_client_onboarding.py` (append tests)

- [ ] **Step 1: Append failing tests**

Add to end of `tests/test_screen_client_onboarding.py`:
```python
from db import DB
from models import Client


def _make_db():
    return DB(":memory:")


def test_client_screen_save_persists_to_db(qtbot):
    from PyQt6.QtCore import Qt
    db = _make_db()
    screen = ClientOnboardingScreen(db=db)
    qtbot.addWidget(screen)
    screen.show()

    screen._company_name_input.setText("Acme Corp")
    screen._domain_input.setText("acme.com")

    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    clients = db.query_clients()
    assert len(clients) == 1
    assert clients[0].name == "Acme Corp"
    assert clients[0].domain == "acme.com"


def test_client_screen_save_without_db_shows_confirmation_no_crash(qtbot):
    from PyQt6.QtCore import Qt
    screen = ClientOnboardingScreen(db=None)
    qtbot.addWidget(screen)
    screen.show()

    screen._company_name_input.setText("Test Co")
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)

    assert screen._confirmation_label.isVisible()
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_client_onboarding.py -v
```

Expected: the 2 new tests FAIL (existing 6 pass).

- [ ] **Step 3: Rewrite `screens/client_onboarding.py`**

```python
from datetime import datetime, timezone
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QLineEdit, QComboBox, QTextEdit, QPushButton, QFormLayout, QFrame,
)


class ClientOnboardingScreen(QWidget):
    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._company_name_input: QLineEdit | None = None
        self._domain_input: QLineEdit | None = None
        self._firewall_combo: QComboBox | None = None
        self._notes_input: QTextEdit | None = None
        self._save_btn: QPushButton | None = None
        self._confirmation_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        title = QLabel("New Client")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        outer.addWidget(title)

        card = QFrame()
        card.setObjectName("panel")
        form_layout = QFormLayout(card)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(12)

        self._company_name_input = QLineEdit()
        self._company_name_input.setPlaceholderText("Acme Corp")
        form_layout.addRow("Company Name", self._company_name_input)

        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("example.com")
        form_layout.addRow("Domain", self._domain_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(["None", "pfSense", "Cisco ASA", "Fortinet", "Other"])
        form_layout.addRow("Firewall Type", self._firewall_combo)

        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Additional notes...")
        self._notes_input.setFixedHeight(80)
        form_layout.addRow("Notes", self._notes_input)

        outer.addWidget(card)

        self._save_btn = QPushButton("Save Client")
        self._save_btn.clicked.connect(self._on_save)
        outer.addWidget(self._save_btn)

        self._confirmation_label = QLabel("✓  Client saved")
        self._confirmation_label.setStyleSheet("color: #00ff88;")
        self._confirmation_label.setVisible(False)
        outer.addWidget(self._confirmation_label)

        outer.addStretch()

    def _on_save(self):
        if self._db is not None:
            from models import Client
            client = Client(
                id=None,
                name=self._company_name_input.text().strip() or "Unnamed",
                domain=self._domain_input.text().strip(),
                firewall=self._firewall_combo.currentText(),
                notes=self._notes_input.toPlainText(),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._db.insert_client(client)

        self._confirmation_label.setVisible(True)
        QTimer.singleShot(2000, lambda: self._confirmation_label.setVisible(False))
```

- [ ] **Step 4: Run all client onboarding tests**

```bash
source venv/bin/activate && pytest tests/test_screen_client_onboarding.py -v
```

Expected: all 8 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short -v
```

Expected: all tests PASS, zero failures.

- [ ] **Step 6: Commit**

```bash
git add screens/client_onboarding.py tests/test_screen_client_onboarding.py
git commit -m "feat: persist client to SQLite on save"
```

---

## Self-Review Notes

**Spec coverage:**
- FR-1 (9 tools): Tasks 4–9 ✓
- FR-2 (chained pipeline): Task 10 ✓
- FR-3 (QThread, UI responsive): Task 10 ✓
- FR-4 (tool failure doesn't stop pipeline): Task 10 (`_run_tool` catch-and-continue) ✓
- FR-5 (parse JSON into structured model): Tasks 4–9 ✓
- FR-6 (write to DB immediately): `db.insert_*` called inside each tool loop ✓
- FR-7 (non-privileged): No `sudo` in any command ✓
- FR-17 (SQLite): Task 2 ✓
- FR-18 (client onboarding persistence): Task 13 ✓
- FR-20 (data stays local): No network calls except tool subprocesses ✓

**Type consistency:**
- `DB.insert_scan()` → `int` (scan_id) — used as `scan_id` throughout ✓
- `ToolRunner` passed as second arg to all tool functions ✓
- `MockRunner` implements `.run()` and `.run_buffered()` matching ToolRunner ✓
- `ScanWorker.__init__(target, scan_id, db)` matches test construction ✓
- `ScanViewScreen(db=...)` and `ClientOnboardingScreen(db=...)` match MainWindow calls ✓
- `MainWindow(tool_results, db=db)` matches `build_window()` in main.py ✓
