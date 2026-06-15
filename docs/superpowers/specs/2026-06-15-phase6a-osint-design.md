# Phase 6a — OSINT Module Design Spec

**Version:** 1.0
**Date:** 2026-06-15
**Owner:** Abhishek K — Fidelitus Corp
**Status:** Approved — ready to plan

---

## 1. Overview

Phase 6a adds a dedicated OSINT (Open Source Intelligence) module to SecureOps. It wraps the `theHarvester` CLI tool to harvest emails, subdomains, IP ranges, and interesting URLs from public sources for any target domain. Results stream into a live table on `OsintPage` and are persisted in a new `osint_items` SQLite table.

This is Phase 6a of a two-part Phase 6:
- **6a (this spec):** OSINT — theHarvester wrapper + OsintPage + osint_items table
- **6b (next session):** Cloud Audit — boto3 AWS + google-cloud GCP + CloudPage

**PRD requirements covered:** FR-31, FR-32 (partial — theHarvester sources; LinkedIn/Shodan optional via API key)

---

## 2. Architecture

`OsintWorker` (QThread) runs a single stage: it calls `theharvester.run()`, which executes `theHarvester` as a subprocess, parses the JSON output file, and returns a flat list of typed items. The worker writes each item to SQLite immediately (`insert_osint_item`), then emits `item_found(dict)` to the UI. On completion it emits `scan_complete(int, int)`.

`OsintPage` is a QWidget screen with a domain input, source selector, Start/Stop button, a streaming `QTableWidget` (Type | Value | Source), and a read-only terminal strip. It is wired into the sidebar at index 7 and into `MainWindow._stack` at index 7.

```
theHarvester CLI
      ↓
theharvester.run() → list[dict]
      ↓
OsintWorker.run() [QThread]
      ↓ (per item)
db.insert_osint_item()   →   SQLite osint_items table
item_found.emit(dict)    →   OsintPage._on_item_found() → QTableWidget row
      ↓ (on finish)
scan_complete.emit(0, N) →   OsintPage._on_complete()
```

---

## 3. Data layer

### 3.1 New table: `osint_items`

Add to `db.py` `_SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS osint_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    domain      TEXT,
    item_type   TEXT,
    value       TEXT,
    source      TEXT,
    created_at  TEXT
);
```

`item_type` values: `'email'` | `'subdomain'` | `'ip'` | `'url'`

### 3.2 New DB methods

```python
def insert_osint_item(self, item: dict) -> int:
    """Write one OSINT item. Returns new row id."""

def get_osint_items(self, scan_id: int) -> list[dict]:
    """Return all items for scan_id, ordered by id."""
```

Both follow the existing locking pattern (`with self._lock`).

---

## 4. Tool wrapper: `workers/tools/theharvester.py`

**Interface:**
```python
def run(domain: str, sources: str, output_file: str) -> list[dict]:
    """
    Execute theHarvester and parse results.
    Returns list of dicts: {item_type, value, source}.
    Returns [] on any error (tool missing, parse failure, timeout).
    """
```

**Implementation:**
- Calls: `theHarvester -d <domain> -b <sources> -f <output_file>` (no extension — theHarvester adds `.json` itself)
- Timeout: 1800 seconds (30 minutes)
- Reads `<output_file>.json` after subprocess completes
- Extracts four keys from the JSON output:
  - `emails` → `item_type="email"`
  - `hosts` → `item_type="subdomain"`
  - `ips` → `item_type="ip"`
  - `interesting_urls` → `item_type="url"`
- Each value is a string entry in the list; deduplicates within the call
- Returns `[]` on `FileNotFoundError`, `subprocess.TimeoutExpired`, `json.JSONDecodeError`, or any other exception — never raises

**Default sources:** `google,bing,dnsdumpster,certspotter,crtsh`

These five sources require no API key and are reliably fast. Shodan is added by the worker if a `shodan_api_key` setting is found in the DB.

---

## 5. Worker: `workers/osint_worker.py`

```python
class OsintWorker(QThread):
    item_found     = pyqtSignal(dict)        # one OSINT item
    log_line       = pyqtSignal(str)         # raw terminal line
    scan_complete  = pyqtSignal(int, int)    # (0, total_items)
    scan_failed    = pyqtSignal(str)         # error message
    error_occurred = pyqtSignal(str, str)    # (tool_name, error_message)

    def __init__(self, domain: str, scan_id: int, db: DB,
                 sources: str = "", parent=None): ...

    def stop(self) -> None: ...   # sets threading.Event

    def run(self) -> None:
        # 1. Build sources string (default + shodan if key present)
        # 2. Check cancel
        # 3. Call theharvester.run(domain, sources, output_file)
        # 4. If returns [] and domain was non-empty: could be tool error or zero results
        # 5. For each item: db.insert_osint_item() → item_found.emit()
        # 6. db.update_scan_status("complete", ...) → scan_complete.emit(0, count)
        # On exception: scan_failed.emit(msg), update_scan_status("failed")
```

**Key behaviours:**
- `sources` constructor arg overrides the default; if empty, defaults to `google,bing,dnsdumpster,certspotter,crtsh` (+ Shodan if key present)
- Cancel is checked once before the single stage — theHarvester is a blocking subprocess call, so mid-run cancel only takes effect after it returns
- DB write always happens before signal emission (same ordering as all other workers)
- Output JSON file written to `/tmp/secureops_harvest_<scan_id>.json`; cleaned up after parsing

---

## 6. UI: `screens/osint_page.py`

### 6.1 Layout

```
[Domain: ___________________] [Sources: google,bing,... ] [▶ Start Scan]
Status: Idle — enter a domain and click Start Scan
┌──────────────────────────────────────────────────────────────────────┐
│ Type        │ Value                          │ Source                │
├─────────────┼────────────────────────────────┼───────────────────────┤
│ email       │ admin@fidelitus.com            │ google                │
│ subdomain   │ mail.fidelitus.com             │ dnsdumpster           │
│ ip          │ 203.0.113.42                   │ crtsh                 │
└──────────────────────────────────────────────────────────────────────┘
[Terminal strip — raw theHarvester output]
```

### 6.2 Widget structure

```
QVBoxLayout
├── QHBoxLayout (top bar)
│   ├── QLineEdit  _domain_input
│   ├── QLineEdit  _sources_input  (pre-filled default, editable)
│   └── QPushButton _start_btn
├── QLabel _status_label
├── QSplitter (Vertical)
│   ├── QTableWidget _table  (3 cols: Type | Value | Source, stretch last col)
│   └── QPlainTextEdit _terminal  (read-only)
```

### 6.3 Behaviour

- **Start:** Creates `Scan` row in DB, instantiates `OsintWorker`, connects signals, calls `worker.start()`
- **`_on_item_found(item: dict)`:** Inserts a new row at bottom of `_table` with type badge, value, source
- **`_on_complete(_, count)`:** Updates status label; releases worker (`deleteLater`)
- **`_on_failed(msg)`:** Updates status label with error; releases worker
- **Stop:** Calls `worker.stop()`; button shows "Stopping…" until `finished` fires
- **`_db is None` guard:** Start button disabled if no DB (same pattern as IncidentPage)

### 6.4 Colour palette

Uses Phase 4/5 palette:
- Background: `#FEFACD` (Lemon Chiffon)
- Accent: `#5F4A8B` (Ultra Violet)
- Text: `#2A1F45` (Deep Violet)
- Table alternating row: `#FFFEF2` / `#FEFACD`
- Type badge colours: email → `#5F4A8B`, subdomain → `#5A7A9B`, ip → `#B38B00`, url → `#C94A62`

---

## 7. Sidebar + MainWindow wiring

- `sidebar.py`: append `("🔍", "OSINT", 7)` to `_NAV_ITEMS` (making it 8 entries)
- `main_window.py`: import `OsintPage`, add `self._osint = OsintPage(db=self._db)` to stack at index 7
- No `scan_ready` signal needed — OSINT findings are stored in `osint_items`, not linked to the report page via signal

---

## 8. Testing

### `tests/test_theharvester.py` (3 tests)

| Test | What it checks |
|------|---------------|
| `test_returns_empty_when_tool_missing` | Patches subprocess to raise `FileNotFoundError` → returns `[]` |
| `test_parses_json_output_correctly` | Writes a fake JSON file with emails/hosts/ips → returns correctly typed items |
| `test_malformed_json_returns_empty` | Writes invalid JSON → returns `[]` without raising |

### `tests/test_osint_worker.py` (5 tests)

| Test | What it checks |
|------|---------------|
| `test_items_emitted_on_successful_run` | Mocks `theharvester.run` → `item_found` fires for each item |
| `test_items_written_to_db` | Mocks run → items appear in `db.get_osint_items(scan_id)` |
| `test_scan_failed_on_tool_error` | Mocks run to raise → `scan_failed` fires |
| `test_cancel_before_run` | `worker.stop()` before `start()` → scan status not "running" after |
| `test_scan_complete_fires_with_count` | Mocks run returning 3 items → `scan_complete` emits `(0, 3)` |

---

## 9. File map

| Action | Path |
|--------|------|
| Modify | `db.py` |
| Create | `workers/tools/theharvester.py` |
| Create | `workers/osint_worker.py` |
| Create | `screens/osint_page.py` |
| Modify | `sidebar.py` |
| Modify | `main_window.py` |
| Create | `tests/test_theharvester.py` |
| Create | `tests/test_osint_worker.py` |

---

## 10. Constraints

- No exploitation — detection and intelligence gathering only
- Cloud credentials rule does not apply here (no credentials needed for OSINT)
- theHarvester subprocess runs as current user (non-root)
- Output JSON file is cleaned up after parsing (`os.unlink`)
- Shodan integration is additive — if no API key, Shodan source is silently omitted
- UI never blocks — theHarvester runs on QThread, main thread handles only UI
