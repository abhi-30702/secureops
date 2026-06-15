# Phase 6a — OSINT Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an OSINT page that runs theHarvester against a target domain and streams typed intelligence items (subdomains, emails, IPs, URLs, people) into a live table backed by a new `osint_items` SQLite table.

**Architecture:** `OsintWorker` (QThread) calls `theharvester.run()` which shells out to theHarvester 4.10.1, parses its JSON output file, and returns typed items. The worker writes each item to `osint_items` then emits `item_found(dict)`. `OsintPage` streams rows into a `QTableWidget`. Sidebar index 7, stack index 7.

**Tech Stack:** PyQt6, theHarvester 4.10.1 (at `/usr/bin/theHarvester`), SQLite, pytest-qt

---

## theHarvester 4.10.1 JSON output reference

The JSON file (saved as `<stem>.json`) contains only keys that have data:
- `cmd` — always present (string, the command args)
- `hosts` — subdomains, sometimes `host:ip` format
- `ips` — resolved IPs (only when `-n` flag used or DNS resolution enabled)
- `emails` — email addresses (only if source supports it)
- `interesting_urls` — interesting URLs found
- `linkedin_people`, `people` — names from LinkedIn/people sources
- `shodan` — Shodan results

Valid no-API-key sources (confirmed working on 4.10.1):
`crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl`

---

## File map

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

## Task 1: DB — `osint_items` table + methods

**Files:** Modify `db.py`

- [ ] **Step 1.1: Add table to `_SCHEMA`**

In `db.py`, find `_SCHEMA = """` and add before the closing `"""`:

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

- [ ] **Step 1.2: Add `insert_osint_item` after `insert_incident_event`**

```python
    def insert_osint_item(self, item: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO osint_items "
                "(scan_id, domain, item_type, value, source, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    item.get("scan_id"),
                    item.get("domain", ""),
                    item.get("item_type", ""),
                    item.get("value", ""),
                    item.get("source", ""),
                    item.get("created_at", ""),
                ),
            )
            self._conn.commit()
            return cur.lastrowid
```

- [ ] **Step 1.3: Add `get_osint_items` after `insert_osint_item`**

```python
    def get_osint_items(self, scan_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, scan_id, domain, item_type, value, source, created_at "
                "FROM osint_items WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [
            {
                "id": r["id"], "scan_id": r["scan_id"], "domain": r["domain"],
                "item_type": r["item_type"], "value": r["value"],
                "source": r["source"], "created_at": r["created_at"],
            }
            for r in rows
        ]
```

- [ ] **Step 1.4: Smoke test**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
python -c "
from db import DB
db = DB(':memory:')
iid = db.insert_osint_item({'scan_id': 1, 'domain': 'test.com', 'item_type': 'email', 'value': 'a@test.com', 'source': 'google', 'created_at': '2026-06-15'})
items = db.get_osint_items(1)
assert len(items) == 1 and items[0]['item_type'] == 'email'
print('OK')
"
```

Expected: `OK`

- [ ] **Step 1.5: Run existing tests**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/ --ignore=tests/test_theharvester.py --ignore=tests/test_osint_worker.py -q 2>&1 | tail -3
```

Expected: `310 passed`

- [ ] **Step 1.6: Commit**

```bash
git add db.py
git commit -m "feat: add osint_items table and insert/get methods to DB"
```

---

## Task 2: theHarvester tool wrapper (TDD)

**Files:** Create `workers/tools/theharvester.py`, `tests/test_theharvester.py`

- [ ] **Step 2.1: Write failing tests**

Create `tests/test_theharvester.py`:

```python
import json
import os
import pytest
from unittest.mock import patch, MagicMock


def test_returns_empty_when_tool_missing():
    """subprocess.run raising FileNotFoundError → []"""
    with patch("subprocess.run", side_effect=FileNotFoundError):
        from workers.tools import theharvester
        result = theharvester.run("test.com", "crtsh", "/tmp/th_missing")
    assert result == []


def test_parses_json_output_correctly(tmp_path):
    """Valid JSON with hosts, emails, ips → correctly typed items."""
    out_json = tmp_path / "harvest.json"
    out_json.write_text(json.dumps({
        "cmd": "-d test.com -b crtsh",
        "hosts": ["mail.test.com", "api.test.com:1.2.3.4"],
        "emails": ["admin@test.com"],
        "ips": ["5.6.7.8"],
        "interesting_urls": ["https://test.com/admin"],
    }))

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    stem = str(tmp_path / "harvest")

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import theharvester
        result = theharvester.run("test.com", "crtsh", stem)

    types = {r["item_type"] for r in result}
    assert "subdomain" in types
    assert "email" in types
    assert "ip" in types
    assert "url" in types
    values = [r["value"] for r in result]
    assert "mail.test.com" in values
    assert "admin@test.com" in values


def test_malformed_json_returns_empty(tmp_path):
    """Corrupt JSON → [] without raising."""
    out_json = tmp_path / "harvest.json"
    out_json.write_text("NOT JSON {{")

    mock_proc = MagicMock()
    mock_proc.returncode = 0
    stem = str(tmp_path / "harvest")

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import theharvester
        result = theharvester.run("test.com", "crtsh", stem)

    assert result == []
```

- [ ] **Step 2.2: Run — expect failure**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/test_theharvester.py -v 2>&1 | head -15
```

Expected: `ModuleNotFoundError`

- [ ] **Step 2.3: Create `workers/tools/theharvester.py`**

```python
import json
import os
import subprocess

_DEFAULT_SOURCES = "crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl"
_TIMEOUT = 1800


def run(domain: str, sources: str, output_stem: str) -> list[dict]:
    """Run theHarvester and return typed OSINT items.

    output_stem: path without extension — theHarvester appends .json itself.
    Returns [] on any error.
    """
    if not sources:
        sources = _DEFAULT_SOURCES
    try:
        subprocess.run(
            ["theHarvester", "-d", domain, "-b", sources, "-f", output_stem],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except Exception:
        return []

    json_path = output_stem + ".json"
    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception:
        return []
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass
        try:
            os.unlink(output_stem + ".xml")
        except OSError:
            pass

    items: list[dict] = []
    seen: set[str] = set()

    def _add(item_type: str, value: str) -> None:
        value = value.strip()
        if not value:
            return
        key = f"{item_type}:{value}"
        if key in seen:
            return
        seen.add(key)
        items.append({"item_type": item_type, "value": value, "source": sources})

    for raw in data.get("hosts", []):
        host = raw.split(":")[0].strip()
        _add("subdomain", host)
        if ":" in raw:
            _add("ip", raw.split(":")[1].strip())

    for val in data.get("emails", []):
        _add("email", val)

    for val in data.get("ips", []):
        _add("ip", val)

    for val in data.get("interesting_urls", []):
        _add("url", val)

    for val in data.get("linkedin_people", []):
        _add("name", val)

    for val in data.get("people", []):
        _add("name", val)

    return items
```

- [ ] **Step 2.4: Run — expect pass**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/test_theharvester.py -v
```

Expected: `3 passed`

- [ ] **Step 2.5: Commit**

```bash
git add workers/tools/theharvester.py tests/test_theharvester.py
git commit -m "feat: add theHarvester tool wrapper with typed OSINT item parsing"
```

---

## Task 3: OsintWorker (TDD)

**Files:** Create `workers/osint_worker.py`, `tests/test_osint_worker.py`

- [ ] **Step 3.1: Write failing tests**

Create `tests/test_osint_worker.py`:

```python
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from workers.osint_worker import OsintWorker
from db import DB
from models import Scan


def _make_worker(domain="test.com", sources="") -> tuple[OsintWorker, DB]:
    db = DB(":memory:")
    scan_id = db.insert_scan(Scan(
        id=None, client_id=None, target=domain,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    ))
    w = OsintWorker(domain=domain, scan_id=scan_id, db=db, sources=sources)
    return w, db


_MOCK_ITEMS = [
    {"item_type": "email",     "value": "a@test.com",   "source": "crtsh"},
    {"item_type": "subdomain", "value": "mail.test.com", "source": "crtsh"},
    {"item_type": "ip",        "value": "1.2.3.4",      "source": "crtsh"},
]


def test_items_emitted_on_successful_run(qtbot):
    w, _ = _make_worker()
    emitted = []
    w.item_found.connect(emitted.append)
    with patch("workers.tools.theharvester.run", return_value=_MOCK_ITEMS):
        with qtbot.waitSignal(w.scan_complete, timeout=5000):
            w.start()
    assert len(emitted) == 3


def test_items_written_to_db(qtbot):
    w, db = _make_worker()
    with patch("workers.tools.theharvester.run", return_value=_MOCK_ITEMS):
        with qtbot.waitSignal(w.scan_complete, timeout=5000):
            w.start()
    stored = db.get_osint_items(w._scan_id)
    assert len(stored) == 3
    assert stored[0]["item_type"] == "email"


def test_scan_failed_on_tool_error(qtbot):
    w, _ = _make_worker()
    failed = []
    w.scan_failed.connect(failed.append)
    with patch("workers.tools.theharvester.run", side_effect=Exception("fail")):
        with qtbot.waitSignal(w.scan_failed, timeout=5000):
            w.start()
    assert len(failed) == 1


def test_scan_complete_fires_with_count(qtbot):
    w, _ = _make_worker()
    counts = []
    w.scan_complete.connect(lambda h, n: counts.append(n))
    with patch("workers.tools.theharvester.run", return_value=_MOCK_ITEMS):
        with qtbot.waitSignal(w.scan_complete, timeout=5000):
            w.start()
    assert counts == [3]


def test_cancel_before_run(qtbot):
    w, db = _make_worker()
    w.stop()
    with patch("workers.tools.theharvester.run", return_value=_MOCK_ITEMS):
        with qtbot.waitSignal(w.scan_complete, timeout=3000, raising=False):
            w.start()
            w.wait(2000)
    row = db._conn.execute("SELECT status FROM scans WHERE id=?", (w._scan_id,)).fetchone()
    assert row[0] != "running"
```

- [ ] **Step 3.2: Run — expect failure**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/test_osint_worker.py -v 2>&1 | head -15
```

Expected: `ModuleNotFoundError`

- [ ] **Step 3.3: Create `workers/osint_worker.py`**

```python
import threading
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding, Scan


class OsintWorker(QThread):
    item_found     = pyqtSignal(dict)
    log_line       = pyqtSignal(str)
    scan_complete  = pyqtSignal(int, int)
    scan_failed    = pyqtSignal(str)
    error_occurred = pyqtSignal(str, str)

    def __init__(self, domain: str, scan_id: int, db: DB,
                 sources: str = "", parent=None):
        super().__init__(parent)
        self._domain = domain
        self._scan_id = scan_id
        self._db = db
        self._sources = sources
        self._cancel = threading.Event()

    def stop(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        if self._cancel.is_set():
            self._db.update_scan_status(self._scan_id, "cancelled",
                                        datetime.now(timezone.utc).isoformat())
            self.scan_complete.emit(0, 0)
            return

        output_stem = f"/tmp/secureops_harvest_{self._scan_id}"
        self.log_line.emit(f"[osint] running theHarvester on {self._domain}")

        try:
            from workers.tools import theharvester
            items = theharvester.run(self._domain, self._sources, output_stem)
        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed",
                                        datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(f"theHarvester error: {exc}")
            return

        count = 0
        for item in items:
            item["scan_id"] = self._scan_id
            item["domain"] = self._domain
            item["created_at"] = datetime.now(timezone.utc).isoformat()
            item["id"] = self._db.insert_osint_item(item)
            self.item_found.emit(item)
            self.log_line.emit(f"[osint] {item['item_type']}: {item['value']}")
            count += 1

        self._db.update_scan_status(self._scan_id, "complete",
                                    datetime.now(timezone.utc).isoformat())
        self.log_line.emit(f"[osint] complete — {count} items")
        self.scan_complete.emit(0, count)
```

- [ ] **Step 3.4: Run — expect pass**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/test_osint_worker.py -v
```

Expected: `5 passed`

- [ ] **Step 3.5: Commit**

```bash
git add workers/osint_worker.py tests/test_osint_worker.py
git commit -m "feat: add OsintWorker with theHarvester pipeline and DB persistence"
```

---

## Task 4: OsintPage UI

**Files:** Create `screens/osint_page.py`

- [ ] **Step 4.1: Create `screens/osint_page.py`**

```python
from datetime import datetime, timezone

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter,
    QPlainTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
)

from db import DB
from models import Scan
from workers.osint_worker import OsintWorker

_TYPE_COLORS = {
    "email":     "#5F4A8B",
    "subdomain": "#5A7A9B",
    "ip":        "#B38B00",
    "url":       "#C94A62",
    "name":      "#00805A",
}

_BTN_STYLE = (
    "QPushButton { background: #5F4A8B; color: #FEFACD; border-radius: 4px; padding: 4px 12px; }"
    "QPushButton:hover { background: #8B75C2; }"
    "QPushButton:disabled { background: #5A7A9B; color: #FFFEF2; }"
)


class OsintPage(QWidget):
    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker: OsintWorker | None = None
        self._scan_id: int | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # top bar
        top = QHBoxLayout()
        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("Target domain (e.g. fidelitus.com)")
        self._sources_input = QLineEdit("crtsh,dnsdumpster,rapiddns,certspotter,hackertarget,commoncrawl")
        self._sources_input.setFixedWidth(380)
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.setStyleSheet(_BTN_STYLE)
        self._start_btn.clicked.connect(self._on_start_stop)
        top.addWidget(QLabel("Domain:"))
        top.addWidget(self._domain_input, stretch=1)
        top.addSpacing(8)
        top.addWidget(QLabel("Sources:"))
        top.addWidget(self._sources_input)
        top.addSpacing(8)
        top.addWidget(self._start_btn)
        layout.addLayout(top)

        self._status_label = QLabel("Idle — enter a domain and click Start Scan")
        self._status_label.setStyleSheet("color: #2A1F45; font-size: 11px;")
        layout.addWidget(self._status_label)

        # table
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setStyleSheet("background: #FEFACD; color: #2A1F45; font-size: 11px;")
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)

        # terminal
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setMaximumHeight(150)
        self._terminal.setStyleSheet(
            "font-family: monospace; font-size: 10px; color: #2A1F45; background: #FEFACD;"
        )

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self._table)
        splitter.addWidget(self._terminal)
        splitter.setSizes([600, 150])
        layout.addWidget(splitter, stretch=1)

    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        domain = self._domain_input.text().strip()
        if not domain:
            self._status_label.setText("Please enter a domain first.")
            self._status_label.setStyleSheet("color: #C94A62; font-size: 11px;")
            return

        scan = Scan(id=None, client_id=None, target=domain, status="running",
                    started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
        self._scan_id = self._db.insert_scan(scan)
        self._table.setRowCount(0)
        self._terminal.clear()

        self._worker = OsintWorker(
            domain=domain, scan_id=self._scan_id, db=self._db,
            sources=self._sources_input.text().strip(),
        )
        self._worker.item_found.connect(self._on_item)
        self._worker.log_line.connect(self._terminal.appendPlainText)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

        self._start_btn.setText("■  Stop Scan")
        self._status_label.setText(f"Scanning {domain}…")
        self._status_label.setStyleSheet("color: #5F4A8B; font-size: 11px;")

    def _on_item(self, item: dict):
        row = self._table.rowCount()
        self._table.insertRow(row)
        itype = item.get("item_type", "")
        color = _TYPE_COLORS.get(itype, "#2A1F45")
        type_cell = QTableWidgetItem(itype)
        type_cell.setForeground(QColor(color))
        self._table.setItem(row, 0, type_cell)
        self._table.setItem(row, 1, QTableWidgetItem(item.get("value", "")))
        self._table.setItem(row, 2, QTableWidgetItem(item.get("source", "")))
        self._table.scrollToBottom()

    def _on_complete(self, _, count: int):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Done — {count} items found")
        self._status_label.setStyleSheet("color: #00A85A; font-size: 11px;")
        if self._worker:
            self._worker.deleteLater()
            self._worker = None

    def _on_failed(self, msg: str):
        self._start_btn.setText("▶  Start Scan")
        self._start_btn.setEnabled(True)
        self._scan_id = None
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet("color: #C94A62; font-size: 11px;")
        if self._worker:
            self._worker.deleteLater()
            self._worker = None

    def _on_worker_finished(self):
        if not self._start_btn.isEnabled():
            self._start_btn.setText("▶  Start Scan")
            self._start_btn.setEnabled(True)
```

- [ ] **Step 4.2: Import check**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
QT_QPA_PLATFORM=offscreen python -c "from screens.osint_page import OsintPage; print('OK')"
```

Expected: `OK`

- [ ] **Step 4.3: Regression check**

```bash
QT_QPA_PLATFORM=offscreen pytest tests/ --ignore=tests/test_theharvester.py --ignore=tests/test_osint_worker.py -q 2>&1 | tail -3
```

Expected: `310 passed`

- [ ] **Step 4.4: Commit**

```bash
git add screens/osint_page.py
git commit -m "feat: add OsintPage UI with live QTableWidget OSINT results"
```

---

## Task 5: Sidebar + MainWindow wiring

**Files:** Modify `sidebar.py`, `main_window.py`

- [ ] **Step 5.1: Add OSINT to sidebar**

In `sidebar.py`, find `_NAV_ITEMS` and append:

```python
    ("🔍", "OSINT", 7),
```

Making the list 8 entries total.

- [ ] **Step 5.2: Add OsintPage to MainWindow**

In `main_window.py`:

Add import after existing screen imports:
```python
from screens.osint_page import OsintPage
```

In `_setup_ui`, after the `self._incident` block (index 6):
```python
        self._osint = OsintPage(db=self._db)
        self._stack.addWidget(self._osint)                    # 7
```

- [ ] **Step 5.3: Verify**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication; app = QApplication([])
from main_window import MainWindow
w = MainWindow(tool_results={}, db=None)
print('Stack size:', w._stack.count())
print('Index 7:', type(w._stack.widget(7)).__name__)
from sidebar import _NAV_ITEMS
print('Nav items:', [l for _,l,_ in _NAV_ITEMS])
print('OK')
"
```

Expected:
```
Stack size: 8
Index 7: OsintPage
Nav items: [..., 'Incident', 'OSINT']
OK
```

- [ ] **Step 5.4: Update count assertions in tests**

Run:
```bash
QT_QPA_PLATFORM=offscreen pytest tests/ --ignore=tests/test_theharvester.py --ignore=tests/test_osint_worker.py -q 2>&1 | tail -5
```

If `test_main_window_stack_has_seven_screens` or `test_sidebar_has_seven_nav_buttons` fail (they assert count=7), update them:
- `test_main_window.py`: change stack count assertion to `8`; rename to `test_main_window_stack_has_eight_screens`
- `test_sidebar.py`: change button count assertion to `8`; rename to `test_sidebar_has_eight_nav_buttons`

- [ ] **Step 5.5: Commit**

```bash
git add sidebar.py main_window.py tests/test_main_window.py tests/test_sidebar.py
git commit -m "feat: wire OsintPage into sidebar and MainWindow stack at index 7"
```

---

## Task 6: Full test suite + smoke test

**Files:** none new

- [ ] **Step 6.1: Run full suite**

```bash
cd /home/kaelix/Desktop/secureops && source venv/bin/activate
QT_QPA_PLATFORM=offscreen pytest tests/ -q 2>&1 | tail -5
```

Expected: `318 passed` (310 + 3 theharvester + 5 osint_worker). Zero failures. If any fail, fix before continuing.

- [ ] **Step 6.2: Smoke test**

```bash
QT_QPA_PLATFORM=offscreen python -c "
from workers.osint_worker import OsintWorker
from workers.tools.theharvester import run as th_run
from screens.osint_page import OsintPage
from db import DB
db = DB(':memory:')
print('osint_items table:', db._conn.execute(\"SELECT name FROM sqlite_master WHERE name='osint_items'\").fetchone())
print('get_osint_items:', db.get_osint_items(1))
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 6.3: Final commit**

```bash
git add -A
git commit -m "feat: Phase 6a complete — OSINT module with theHarvester, live table, and DB persistence"
```
