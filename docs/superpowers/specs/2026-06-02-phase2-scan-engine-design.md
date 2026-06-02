# Phase 2 — Scan Engine Design

**Date:** 2026-06-02
**Status:** Approved
**Phase:** 2 of 7

---

## Overview

Phase 2 adds the scan engine to the SecureOps skeleton built in Phase 1. It delivers:
- A local SQLite database (clients, scans, hosts, findings)
- Nine tool wrappers (subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl.sh)
- A `ScanWorker(QThread)` orchestrator that chains tools and emits Qt signals
- Wired scan view: live terminal feed, status label, working Start/Cancel button
- Client onboarding persistence (the Phase 1 form shell now saves to SQLite)

Phase 3 (live visuals — pipeline tracker, attack graph, severity rings, streaming cards) builds on top of Phase 2's signals and DB without changes to the engine.

---

## 1. File Structure

```
models.py                   — Finding, Host, Scan, Client dataclasses
db.py                       — SQLite schema creation + CRUD helpers
workers/
  __init__.py
  base_tool.py              — ToolRunner: subprocess launch, stdout streaming
  scan_worker.py            — ScanWorker(QThread): pipeline orchestrator
  tools/
    __init__.py
    subfinder.py
    dnsx.py
    naabu.py
    httpx.py
    katana.py
    nuclei.py
    nmap.py
    nikto.py
    testssl.py
```

Existing files updated:
- `screens/scan_view.py` — terminal feed panel, status label, wired Start/Cancel
- `screens/client_onboarding.py` — save button persists to SQLite
- `main.py` — creates `DB` instance, passes to `MainWindow`
- `main_window.py` — threads `DB` through to `ScanViewScreen` and `ClientOnboardingScreen`

---

## 2. Database Schema

```sql
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
    status      TEXT NOT NULL,   -- running | complete | failed | cancelled
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
    severity    TEXT NOT NULL,   -- critical | high | medium | low | info
    title       TEXT NOT NULL,
    description TEXT,
    raw_json    TEXT,
    created_at  TEXT NOT NULL
);
```

`hosts` is the pipeline's working state — each tool reads from it and appends to it. `findings` captures vulnerability-layer output (nuclei, nmap, nikto, testssl). `client_id` on scans is nullable so standalone scans work without a client record.

All timestamps are ISO-8601 strings (`datetime.utcnow().isoformat()`). SQLite commits on every insert — no transaction held open across a scan, so a mid-scan crash does not lose completed work.

---

## 3. Data Models

```python
# models.py

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
    client_id: int | None   # None = standalone scan
    target: str
    status: str             # running | complete | failed | cancelled
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
    severity: str           # critical | high | medium | low | info
    title: str
    description: str
    raw_json: str
    created_at: str
```

`db.py` exposes one `insert_*` and one `query_by_scan_id` function per model. No ORM.

---

## 4. ToolRunner Base

```python
# workers/base_tool.py

class ToolError(Exception):
    pass

class CancelledError(Exception):
    """Raised by ToolRunner when the cancel event is set. Not caught by per-tool handlers — propagates to ScanWorker's top-level handler to stop the entire pipeline."""
    pass

class ToolRunner:
    def __init__(self, cancel_event: threading.Event): ...

    def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
        """
        Launch cmd, yield stdout lines as they arrive.
        Raises ToolError on non-zero exit, timeout, or FileNotFoundError.
        Checks cancel_event between lines — stops iteration if set.
        """
```

Each tool module exposes a single function with the signature:

```python
def run(input_data: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host | Finding]:
```

It calls `runner.run(cmd)`, parses each yielded line, writes to `db` immediately, and returns the structured results. Tool functions know nothing about Qt or threads.

---

## 5. Tool Wrappers

### 5.1 ProjectDiscovery tools (JSON lines, stdout)

All six emit one JSON object per stdout line with `-json` flag.

| Tool | Command | Input | Output written |
|------|---------|-------|----------------|
| subfinder | `subfinder -d <target> -json -silent` | domain string | `hosts` (subdomain) |
| dnsx | `dnsx -l <tmpfile> -json -silent` | subdomains file | `hosts` (ip added) |
| naabu | `naabu -l <tmpfile> -json -silent` | IPs file | `hosts` (port) |
| httpx | `httpx -l <tmpfile> -json -silent` | hosts:ports file | `hosts` (url, service) |
| katana | `katana -list <tmpfile> -json -silent` | URLs file | `hosts` (url) |
| nuclei | `nuclei -l <tmpfile> -json -silent` | all hosts file | `findings` |

dnsx, naabu, httpx, katana, and nuclei receive their input lists via a temporary file (`-l /tmp/secureops_input_<tool>.txt`) rather than stdin, to avoid subprocess stdin complexity.

### 5.2 Kali-native tools (special handling)

**nmap** — `nmap -iL <hosts_file> -oJ -` writes a single JSON object to stdout after completion (not line-by-line). `ToolRunner.run()` buffers all output and yields it as one line when the process exits. Parser walks `nmaprun.host[].ports[].port[]` entries, writes `Finding` per open port with service info.

**nikto** — `nikto -h <host> -Format json -output /tmp/nikto_out.json`. Writes JSON to a file. If `-Format json` fails (older nikto version), fall back to text output and parse "OSVDB-" / "+ " lines with regex. Writes `Finding` per issue found.

**testssl.sh** — `testssl.sh --jsonfile /tmp/testssl_out.json --quiet <host>`. Reads the output file after process exits. Writes `Finding` per severity-rated issue (`severity` field maps directly from testssl's `severity` values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

---

## 6. Pipeline Orchestrator (ScanWorker)

```python
# workers/scan_worker.py

class ScanWorker(QThread):
    tool_started  = pyqtSignal(str)        # tool name
    tool_finished = pyqtSignal(str, int)   # tool name, item count
    tool_failed   = pyqtSignal(str, str)   # tool name, error message
    host_found    = pyqtSignal(object)     # Host dataclass
    finding_found = pyqtSignal(object)     # Finding dataclass
    log_line      = pyqtSignal(str)        # raw terminal line
    scan_complete = pyqtSignal(int, int)   # total hosts, total findings
    scan_failed   = pyqtSignal(str)        # error message

    def __init__(self, target: str, scan_id: int, db: DB, parent=None): ...
    def run(self): ...
    def cancel(self): ...
```

### 6.1 Pipeline execution order

```
1. subfinder(target)         → subdomains      (list[Host])
2. dnsx(subdomains)          → resolved IPs    (list[Host])
3. naabu(ips)                → open ports      (list[Host])
4. httpx(hosts+ports)        → http services   (list[Host])
5. katana(http_urls)         → crawled URLs    (list[Host])
6. nuclei(all_hosts)         → vulns           (list[Finding])

── parallel tail (ThreadPoolExecutor, max_workers=3) ──
7. nmap(discovered_hosts)    → service info    (list[Finding])
8. nikto(http_hosts)         → web issues      (list[Finding])
9. testssl(https_hosts)      → tls issues      (list[Finding])
```

Each step: emit `tool_started`, call tool function, emit `tool_finished(name, count)` or `tool_failed(name, error)` on `ToolError`, check cancel event, pass results to next step.

After the sequential chain completes, nmap/nikto/testssl are submitted to a `ThreadPoolExecutor(max_workers=3)`. Each future emits `finding_found` per result via a callback. `ScanWorker` calls `executor.shutdown(wait=True)` before emitting `scan_complete`.

### 6.2 Cancel

`cancel()` sets a `threading.Event`. `ToolRunner.run()` checks the event between stdout lines and raises `CancelledError` if set. `CancelledError` is not caught by per-tool `except ToolError` handlers — it propagates to the top-level handler in `ScanWorker.run()`, which updates scan status to `cancelled` in SQLite and emits `scan_failed("Cancelled")`.

### 6.3 Top-level safety net

`ScanWorker.run()` wraps the entire pipeline in `try/except Exception`. Any unexpected exception updates scan status to `failed`, emits `scan_failed(str(e))`, and exits cleanly. No exception from a worker thread ever reaches the Qt main thread.

---

## 7. UI Wiring

### 7.1 ScanViewScreen changes

- **`_target_input`** — already exists. Used as the scan target.
- **`_start_btn`** — enabled. Click creates a `Scan` record in SQLite, instantiates `ScanWorker`, connects signals, calls `worker.start()`. Label switches to "Cancel". On complete/failed, reverts to "Start Scan".
- **`_status_label`** — new `QLabel` added above the panels. Driven by `tool_started` / `tool_finished` signals. Final text: `"Complete — {n} hosts, {m} findings"`.
- **`_terminal_panel`** — replaced from placeholder `QFrame` to `QPlainTextEdit` (read-only, monospace font, dark background). `log_line` signal appends text and auto-scrolls.
- Four placeholder panels (pipeline tracker, attack graph, severity rings, finding cards) remain unchanged — Phase 3 replaces them.

### 7.2 ClientOnboardingScreen changes

The "Save Client" button calls `db.insert_client(client)` and shows the existing confirmation label. No other changes.

### 7.3 MainWindow and main.py changes

`main.py` creates `DB(path="~/.secureops/secureops.db")` and passes it to `MainWindow`. `MainWindow._setup_ui()` passes `db` to `DashboardScreen`, `ScanViewScreen`, and `ClientOnboardingScreen` constructors. `SettingsScreen` and `ReportScreen` don't need it in Phase 2.

---

## 8. Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Tool binary not found | `ToolError` → `tool_failed` signal, pipeline continues |
| Tool exits non-zero | `ToolError` → `tool_failed` signal, pipeline continues |
| Tool times out (300s default) | `ToolError` → `tool_failed` signal, pipeline continues |
| nikto `-Format json` unavailable | Falls back to text parsing silently |
| DB insert fails | Logs warning, does not stop tool or pipeline |
| Cancel requested | Stops between lines, sets status `cancelled`, emits `scan_failed` |
| Unexpected exception | Top-level catch, sets status `failed`, emits `scan_failed` |

---

## 9. Testing

| File | What it tests |
|------|--------------|
| `tests/test_db.py` | In-memory SQLite: every insert/query, foreign keys, nullable fields |
| `tests/test_models.py` | Dataclass field types and defaults |
| `tests/test_tools.py` | Each tool function with mocked `subprocess.Popen` and canned JSON output — 9 tests |
| `tests/test_scan_worker.py` | All 9 tool functions patched: signal order, `tool_failed` on `ToolError`, cancel, DB scan status on completion |

No integration tests against real binaries in Phase 2. Mock tests fully cover parsing and orchestration logic.

---

## 10. PRD Requirements Covered

| ID | Requirement | Covered |
|----|-------------|---------|
| FR-1 | Nine scanning tools | All 9 wrappers |
| FR-2 | Chained pipeline | `ScanWorker.run()` |
| FR-3 | Background thread, UI responsive | `QThread` + signals |
| FR-4 | Tool failure does not crash pipeline | `ToolError` catch-and-continue |
| FR-5 | Parse JSON output into structured model | Per-tool parsers → `Finding`/`Host` |
| FR-6 | Finding written to DB immediately | `db.insert_*` called inside tool loop |
| FR-7 | Non-privileged tool modes | Default flags only; no `sudo` |
| FR-17 | SQLite persistence | `db.py` schema |
| FR-18 | Client onboarding persisted | `ClientOnboardingScreen` saves to DB |
| FR-20 | Data stays local | No network calls outside tool subprocesses |
