# Phase 7 — Multi-Target Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the company registry, per-company auto-fill on all scan pages, and a BatchScanWorker for sequential multi-company external scans.

**Architecture:** `companies` table in SQLite → registry UI in `client_onboarding.py` → reusable `CompanySelector` widget → auto-fill on ScanView, OsintPage, InternalPage → `BatchScanWorker` for "Scan All" mode.

**Tech Stack:** PyQt6, SQLite, existing tool wrappers (subfinder, httpx, nuclei)

---

## Task 1: DB — companies table + CRUD + seeding

**Files:**
- Modify: `db.py`
- Create: `tests/test_db_companies.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_db_companies.py
import json
import pytest
from db import DB


@pytest.fixture
def fresh_db():
    return DB(":memory:")


def test_seed_companies_on_empty_db(fresh_db):
    companies = fresh_db.get_companies()
    assert len(companies) == 9
    names = [c["name"] for c in companies]
    assert "the organisation HQ" in names


def test_insert_and_get_company(fresh_db):
    cid = fresh_db.insert_company({
        "name": "Test Co",
        "domains": '["test.com"]',
        "ip_ranges": '["10.99.0.0/24"]',
        "firewall_type": "pfSense",
    })
    companies = fresh_db.get_companies()
    found = next((c for c in companies if c["id"] == cid), None)
    assert found is not None
    assert found["name"] == "Test Co"
    assert found["name"] == "Test Co"


def test_get_companies_ordered_by_name(fresh_db):
    # Seed data is present; verify alphabetical order
    companies = fresh_db.get_companies()
    names = [c["name"] for c in companies]
    assert names == sorted(names)


def test_update_company(fresh_db):
    cid = fresh_db.insert_company({"name": "Old Name", "domains": "[]"})
    fresh_db.update_company(cid, {"name": "New Name"})
    companies = fresh_db.get_companies()
    found = next(c for c in companies if c["id"] == cid)
    assert found["name"] == "New Name"
    assert found["name"] == "New Name"


def test_delete_company(fresh_db):
    initial = len(fresh_db.get_companies())
    cid = fresh_db.insert_company({"name": "To Delete", "domains": "[]"})
    assert len(fresh_db.get_companies()) == initial + 1
    fresh_db.delete_company(cid)
    assert len(fresh_db.get_companies()) == initial
```

- [ ] **Step 2: Run to confirm failures**

```bash
source venv/bin/activate && pytest tests/test_db_companies.py -v
```
Expected: 5 errors (methods not found)

- [ ] **Step 3: Implement companies table + methods in db.py**

Read `db.py` first to understand the existing pattern (`_SCHEMA`, `_lock`, `row_factory`).

**Add to `_SCHEMA` string** (after the last existing `CREATE TABLE` block):

```sql
CREATE TABLE IF NOT EXISTS companies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    domains       TEXT DEFAULT '[]',
    ip_ranges     TEXT DEFAULT '[]',
    firewall_type TEXT DEFAULT '',
    created_at    TEXT DEFAULT ''
);
```

**Add seed data constant** (before the `DB` class):

```python
_SEED_COMPANIES = [
    {"name": "the organisation HQ",      "domains": '["example.com"]',         "ip_ranges": '["10.0.0.0/24"]'},
    {"name": "the organisation Education",    "domains": '["exampleedu.com"]',      "ip_ranges": '["10.0.8.0/24"]'},
    {"name": "the organisation Finance",      "domains": '["examplefinance.com"]',  "ip_ranges": '["10.0.3.0/24"]'},
    {"name": "the organisation Healthcare",   "domains": '["examplehealth.com"]',   "ip_ranges": '["10.0.7.0/24"]'},
    {"name": "the organisation HR Solutions", "domains": '["examplehr.com"]',       "ip_ranges": '["10.0.2.0/24"]'},
    {"name": "the organisation Legal",        "domains": '["examplelegal.com"]',    "ip_ranges": '["10.0.6.0/24"]'},
    {"name": "the organisation Logistics",    "domains": '["examplelogistics.com"]',"ip_ranges": '["10.0.4.0/24"]'},
    {"name": "the organisation Properties",   "domains": '["exampleproperties.com"]',"ip_ranges": '["10.0.1.0/24"]'},
    {"name": "the organisation Tech",         "domains": '["exampletech.com"]',     "ip_ranges": '["10.0.5.0/24"]'},
]
```

**Add methods to `DB` class** (alongside existing `insert_client`, `query_clients`):

```python
def _ensure_seed_companies(self) -> None:
    with self._lock:
        count = self._conn.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
        if count == 0:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).isoformat()
            for c in _SEED_COMPANIES:
                self._conn.execute(
                    "INSERT INTO companies (name, domains, ip_ranges, firewall_type, created_at) "
                    "VALUES (?,?,?,?,?)",
                    (c["name"], c.get("domains","[]"), c.get("ip_ranges","[]"),
                     c.get("firewall_type",""), now),
                )
            self._conn.commit()

def insert_company(self, company: dict) -> int:
    from datetime import datetime, timezone
    with self._lock:
        cur = self._conn.execute(
            "INSERT INTO companies (name, domains, ip_ranges, firewall_type, created_at) "
            "VALUES (?,?,?,?,?)",
            (company.get("name",""), company.get("domains","[]"),
             company.get("ip_ranges","[]"), company.get("firewall_type",""),
             company.get("created_at", datetime.now(timezone.utc).isoformat())),
        )
        self._conn.commit()
        return cur.lastrowid

def get_companies(self) -> list[dict]:
    with self._lock:
        rows = self._conn.execute(
            "SELECT id, name, domains, ip_ranges, firewall_type, created_at "
            "FROM companies ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]

def update_company(self, company_id: int, company: dict) -> None:
    with self._lock:
        self._conn.execute(
            "UPDATE companies SET name=?, domains=?, ip_ranges=?, firewall_type=? "
            "WHERE id=?",
            (company.get("name",""), company.get("domains","[]"),
             company.get("ip_ranges","[]"), company.get("firewall_type",""),
             company_id),
        )
        self._conn.commit()

def delete_company(self, company_id: int) -> None:
    with self._lock:
        self._conn.execute("DELETE FROM companies WHERE id=?", (company_id,))
        self._conn.commit()
```

**Call `_ensure_seed_companies()` from `__init__`**, after `_create_schema()`:

```python
def __init__(self, path: str = "secureops.db"):
    ...
    self._create_schema()
    self._ensure_seed_companies()   # ← add this line
```

- [ ] **Step 4: Run to confirm passing**

```bash
pytest tests/test_db_companies.py -v
```
Expected: 5 passed

- [ ] **Step 5: Run full suite (sanity check)**

```bash
pytest tests/ -p no:randomly -q
```
Expected: 336 tests passed (331 + 5 new)

- [ ] **Step 6: Commit**

```bash
git add db.py tests/test_db_companies.py
git commit -m "feat: add companies table with CRUD, seeding 9 the organisation subsidiaries"
```

---

## Task 2: Company registry UI (rewrite client_onboarding.py)

**Files:**
- Rewrite: `screens/client_onboarding.py`

Read `screens/client_onboarding.py` first (81 lines). Replace entirely.

Read `db.py` to confirm `get_companies()`, `insert_company()`, `update_company()`, `delete_company()` signatures.

- [ ] **Step 1: Implement rewritten client_onboarding.py**

```python
import json
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QListWidget,
    QPushButton, QFormLayout, QLineEdit, QComboBox, QSplitter, QFrame,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from db import DB

_FIREWALL_OPTS = ["None", "pfSense", "Cisco ASA", "Fortinet", "Palo Alto", "Other"]


class ClientOnboardingScreen(QWidget):
    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._selected_id: int | None = None
        self._build_ui()
        if self._db:
            self._load_companies()

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(0)

        # Left: company list
        left = QVBoxLayout()
        left.setSpacing(8)
        hdr = QLabel("Companies")
        hdr.setFont(QFont("DM Sans", 14, QFont.Weight.Bold))
        hdr.setStyleSheet("color: #00e5ff;")
        left.addWidget(hdr)
        self._company_list = QListWidget()
        self._company_list.setFixedWidth(210)
        self._company_list.currentRowChanged.connect(self._on_company_selected)
        left.addWidget(self._company_list)
        btn_row = QHBoxLayout()
        self._add_btn = QPushButton("＋ Add")
        self._add_btn.clicked.connect(self._on_add)
        self._delete_btn = QPushButton("✕ Delete")
        self._delete_btn.clicked.connect(self._on_delete)
        btn_row.addWidget(self._add_btn)
        btn_row.addWidget(self._delete_btn)
        left.addLayout(btn_row)

        left_w = QWidget()
        left_w.setLayout(left)
        root.addWidget(left_w)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.VLine)
        div.setStyleSheet("color: #0d2440;")
        root.addWidget(div)

        # Right: edit form
        right = QVBoxLayout()
        right.setContentsMargins(20, 0, 0, 0)
        right.setSpacing(12)
        form_hdr = QLabel("Company Details")
        form_hdr.setFont(QFont("DM Sans", 13, QFont.Weight.Bold))
        form_hdr.setStyleSheet("color: #e2eaf4;")
        right.addWidget(form_hdr)

        form = QFormLayout()
        form.setSpacing(10)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("the organisation Tech")
        form.addRow("Name:", self._name_input)

        self._domains_input = QLineEdit()
        self._domains_input.setPlaceholderText("example.com, sub.example.com")
        form.addRow("Domains:", self._domains_input)

        self._ip_ranges_input = QLineEdit()
        self._ip_ranges_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        form.addRow("IP Ranges:", self._ip_ranges_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(_FIREWALL_OPTS)
        form.addRow("Firewall:", self._firewall_combo)

        right.addLayout(form)

        self._save_btn = QPushButton("Save")
        self._save_btn.setEnabled(False)
        self._save_btn.clicked.connect(self._on_save)
        right.addWidget(self._save_btn)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #00ff88; font-size: 11px;")
        right.addWidget(self._status_label)

        right.addStretch()

        right_w = QWidget()
        right_w.setLayout(right)
        root.addWidget(right_w, 1)

    def _load_companies(self):
        self._company_list.clear()
        self._companies = self._db.get_companies()
        for c in self._companies:
            self._company_list.addItem(c["name"])
        if self._companies:
            self._company_list.setCurrentRow(0)

    def _on_company_selected(self, row: int):
        if row < 0 or not self._companies:
            self._save_btn.setEnabled(False)
            return
        c = self._companies[row]
        self._selected_id = c["id"]
        self._name_input.setText(c["name"])
        # domains: stored as JSON array → comma-separated for display
        try:
            domains = ", ".join(json.loads(c.get("domains", "[]")))
        except Exception:
            domains = c.get("domains", "")
        self._domains_input.setText(domains)
        try:
            ranges = ", ".join(json.loads(c.get("ip_ranges", "[]")))
        except Exception:
            ranges = c.get("ip_ranges", "")
        self._ip_ranges_input.setText(ranges)
        fw = c.get("firewall_type", "None")
        idx = self._firewall_combo.findText(fw)
        self._firewall_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._save_btn.setEnabled(True)
        self._status_label.setText("")

    def _on_add(self):
        self._selected_id = None
        self._name_input.clear()
        self._domains_input.clear()
        self._ip_ranges_input.clear()
        self._firewall_combo.setCurrentIndex(0)
        self._save_btn.setEnabled(True)
        self._company_list.clearSelection()
        self._name_input.setFocus()

    def _on_delete(self):
        row = self._company_list.currentRow()
        if row < 0 or not self._companies or not self._db:
            return
        cid = self._companies[row]["id"]
        self._db.delete_company(cid)
        self._load_companies()
        self._save_btn.setEnabled(False)
        self._status_label.setText("Deleted.")

    def _on_save(self):
        if not self._db:
            return
        def _to_json_array(text: str) -> str:
            parts = [p.strip() for p in text.split(",") if p.strip()]
            return json.dumps(parts)

        data = {
            "name": self._name_input.text().strip() or "Unnamed Company",
            "domains": _to_json_array(self._domains_input.text()),
            "ip_ranges": _to_json_array(self._ip_ranges_input.text()),
            "firewall_type": self._firewall_combo.currentText(),
        }
        if self._selected_id is not None:
            self._db.update_company(self._selected_id, data)
        else:
            self._selected_id = self._db.insert_company(data)
        self._load_companies()
        self._status_label.setText("Saved ✓")
```

- [ ] **Step 2: Verify import**

```bash
QT_QPA_PLATFORM=offscreen python -c "from screens.client_onboarding import ClientOnboardingScreen; print('OK')"
```

- [ ] **Step 3: Check existing onboarding tests still pass**

```bash
pytest tests/ -k "onboarding or client" -v
```

- [ ] **Step 4: Commit**

```bash
git add screens/client_onboarding.py
git commit -m "feat: rewrite client_onboarding as 9-company registry with list + edit form"
```

---

## Task 3: CompanySelector widget + screen wiring

**Files:**
- Create: `screens/widgets/company_selector.py`
- Create: `tests/test_company_selector.py`
- Modify: `screens/scan_view.py`
- Modify: `screens/osint_page.py`
- Modify: `screens/internal_page.py`

Read `screens/scan_view.py`, `screens/osint_page.py`, `screens/internal_page.py` first.

- [ ] **Step 1: Write failing tests for CompanySelector**

```python
# tests/test_company_selector.py
import gc
import json
import pytest
from PyQt6.QtWidgets import QApplication
from db import DB
from screens.widgets.company_selector import CompanySelector


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _db_with_companies():
    db = DB(":memory:")
    # DB seeds 9 companies automatically; add one more for predictability
    db.insert_company({"name": "ZZZ Test", "domains": '["zzz.com"]'})
    return db


def test_selector_populates_from_db(qtbot):
    db = _db_with_companies()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    # 9 seeded + 1 inserted = 10 companies (alphabetical, "ZZZ Test" last)
    assert sel._combo.count() == 10


def test_signal_emitted_on_change(qtbot):
    db = _db_with_companies()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    received = []
    sel.company_selected.connect(received.append)
    # Trigger selection change to index 1
    if sel._combo.count() > 1:
        sel._combo.setCurrentIndex(1)
    assert len(received) >= 1
    assert "name" in received[-1]


def test_refresh_updates_items(qtbot):
    db = _db_with_companies()
    sel = CompanySelector(db=db)
    qtbot.addWidget(sel)
    initial_count = sel._combo.count()
    db.insert_company({"name": "Extra Co", "domains": '["extra.com"]'})
    sel.refresh()
    assert sel._combo.count() == initial_count + 1
```

- [ ] **Step 2: Run to confirm failures**

```bash
pytest tests/test_company_selector.py -v
```
Expected: 3 errors (module not found)

- [ ] **Step 3: Implement CompanySelector widget**

```python
# screens/widgets/company_selector.py
import json
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QComboBox
from PyQt6.QtCore import pyqtSignal
from db import DB


class CompanySelector(QWidget):
    company_selected = pyqtSignal(dict)

    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        self._companies: list[dict] = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Company:"))
        self._combo = QComboBox()
        self._combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self._combo.currentIndexChanged.connect(self._on_changed)
        layout.addWidget(self._combo, 1)
        self.refresh()

    def refresh(self) -> None:
        self._combo.blockSignals(True)
        self._combo.clear()
        self._companies = self._db.get_companies() if self._db else []
        for c in self._companies:
            self._combo.addItem(c["name"])
        self._combo.blockSignals(False)
        if self._companies:
            self._on_changed(0)

    def current_company(self) -> dict | None:
        idx = self._combo.currentIndex()
        if 0 <= idx < len(self._companies):
            return self._companies[idx]
        return None

    def _on_changed(self, index: int) -> None:
        if 0 <= index < len(self._companies):
            self.company_selected.emit(self._companies[index])
```

- [ ] **Step 4: Run selector tests**

```bash
pytest tests/test_company_selector.py -v
```
Expected: 3 passed

- [ ] **Step 5: Add CompanySelector to ScanView**

Read `screens/scan_view.py`. Find where `_target_input` is created (probably in a top bar). Add a `CompanySelector` immediately before it.

In the `__init__` or `_build_ui` method, after creating `_target_input`:
```python
if self._db:
    self._company_selector = CompanySelector(db=self._db)
    self._company_selector.company_selected.connect(self._on_company_selected)
    # insert into layout BEFORE the target input row
else:
    self._company_selector = None
```

Add handler:
```python
def _on_company_selected(self, company: dict) -> None:
    import json
    try:
        domains = json.loads(company.get("domains", "[]"))
        if domains:
            self._target_input.setText(domains[0])
    except Exception:
        pass
```

**IMPORTANT:** `CompanySelector` is added to the existing layout — do not restructure the layout. Find the right insertion point by reading the existing code.

- [ ] **Step 6: Add CompanySelector to OsintPage**

Read `screens/osint_page.py`. Add before `_domain_input`:
```python
if self._db:
    self._company_selector = CompanySelector(db=self._db)
    self._company_selector.company_selected.connect(self._on_company_selected)
else:
    self._company_selector = None
```

Handler:
```python
def _on_company_selected(self, company: dict) -> None:
    import json
    try:
        domains = json.loads(company.get("domains", "[]"))
        if domains:
            self._domain_input.setText(domains[0])
    except Exception:
        pass
```

- [ ] **Step 7: Add CompanySelector to InternalPage**

Read `screens/internal_page.py`. Add before the subnet input. Handler fills `_subnet_input` with first IP range:
```python
def _on_company_selected(self, company: dict) -> None:
    import json
    try:
        ranges = json.loads(company.get("ip_ranges", "[]"))
        if ranges:
            self._subnet_input.setText(ranges[0])
    except Exception:
        pass
```

- [ ] **Step 8: Run full suite**

```bash
pytest tests/ -p no:randomly -q
```
Expected: 339 passed (336 + 3 selector tests)

- [ ] **Step 9: Commit**

```bash
git add screens/widgets/company_selector.py tests/test_company_selector.py \
        screens/scan_view.py screens/osint_page.py screens/internal_page.py
git commit -m "feat: add CompanySelector widget and wire into all scan pages"
```

---

## Task 4: BatchScanWorker (TDD)

**Files:**
- Create: `workers/batch_scan_worker.py`
- Create: `tests/test_batch_scan_worker.py`

Read `workers/scan_worker.py` for context on how the existing tool wrappers are called.
Read `db.py` for `insert_scan`, `insert_finding`, `update_scan_status` signatures.
Read `models.py` for `Scan` and `Finding` dataclasses.
Read `workers/tools/subfinder.py`, `workers/tools/httpx.py`, `workers/tools/nuclei.py` to understand their `run()` signatures.

- [ ] **Step 1: Write failing tests**

```python
# tests/test_batch_scan_worker.py
import gc
import json
import pytest
from unittest.mock import patch, MagicMock
from db import DB
from workers.batch_scan_worker import BatchScanWorker


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


COMPANIES = [
    {"id": 1, "name": "Co A", "domains": '["a.com"]', "ip_ranges": "[]", "firewall_type": ""},
    {"id": 2, "name": "Co B", "domains": '["b.com"]', "ip_ranges": "[]", "firewall_type": ""},
]


def _make_db():
    db = DB(":memory:")
    return db


def test_company_started_emitted():
    db = _make_db()
    started = []

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[]):
        worker = BatchScanWorker(companies=COMPANIES, db=db)
        worker.company_started.connect(lambda name, idx: started.append(name))
        worker.run()

    assert "Co A" in started
    assert "Co B" in started


def test_findings_written_to_db():
    db = _make_db()

    fake_finding = {
        "tool": "nuclei", "severity": "high",
        "title": "XSS", "description": "found xss",
        "host": "a.com", "port": None, "raw": "{}",
    }

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[{"host": "a.com"}]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[{"url": "http://a.com"}]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[fake_finding]):
        worker = BatchScanWorker(companies=[COMPANIES[0]], db=db)
        worker.run()

    rows = db._conn.execute("SELECT * FROM findings").fetchall()
    assert len(rows) >= 1
    assert rows[0]["title"] == "XSS"


def test_companies_with_no_domain_skipped():
    db = _make_db()
    empty_company = {"id": 3, "name": "Empty", "domains": "[]", "ip_ranges": "[]", "firewall_type": ""}

    with patch("workers.batch_scan_worker.subfinder.run") as mock_sub:
        worker = BatchScanWorker(companies=[empty_company], db=db)
        worker.run()

    mock_sub.assert_not_called()


def test_batch_complete_fires():
    db = _make_db()
    completed = []

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[]):
        worker = BatchScanWorker(companies=COMPANIES, db=db)
        worker.batch_complete.connect(lambda scanned, total: completed.append((scanned, total)))
        worker.run()

    assert len(completed) == 1
    assert completed[0][0] == 2   # 2 companies scanned
```

- [ ] **Step 2: Run to confirm failures**

```bash
pytest tests/test_batch_scan_worker.py -v
```
Expected: 4 errors (module not found)

- [ ] **Step 3: Read tool wrapper signatures**

Before implementing, read these files to understand the `run()` signatures:
- `workers/tools/subfinder.py` — `run(domain) -> list[dict]` — returns dicts with "host" key
- `workers/tools/httpx.py` — `run(hosts) -> list[dict]` — takes list of host strings, returns dicts with "url" key
- `workers/tools/nuclei.py` — `run(urls) -> list[dict]` — takes list of URL strings, returns finding dicts

Also read `models.py` for `Scan` and `Finding` dataclasses.
Also read `db.py` for exact `insert_scan`, `insert_finding` signatures.

- [ ] **Step 4: Implement BatchScanWorker**

```python
# workers/batch_scan_worker.py
import json
import threading
from datetime import datetime, timezone
from PyQt6.QtCore import QThread, pyqtSignal
from db import DB
from workers.tools import subfinder, httpx, nuclei


class BatchScanWorker(QThread):
    company_started  = pyqtSignal(str, int)    # (company_name, index)
    finding_discovered = pyqtSignal(dict)
    tool_log         = pyqtSignal(str)
    company_complete = pyqtSignal(str, int)    # (company_name, finding_count)
    batch_complete   = pyqtSignal(int, int)    # (companies_scanned, total_findings)
    error_occurred   = pyqtSignal(str, str)

    def __init__(self, companies: list[dict], db: DB, parent=None):
        super().__init__(parent)
        self._companies = companies
        self._db = db
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        total_findings = 0
        scanned = 0

        for i, company in enumerate(self._companies):
            if self._stop.is_set():
                break

            # Get first domain
            try:
                domains = json.loads(company.get("domains", "[]"))
            except Exception:
                domains = []
            if not domains:
                continue

            domain = domains[0]
            self.company_started.emit(company["name"], i)
            self.tool_log.emit(f"[batch] scanning {company['name']} ({domain})")

            # Create scan record
            from models import Scan
            scan = Scan(
                id=None,
                client_id=company.get("id", 1),
                scan_type="external",
                target=domain,
                status="running",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            scan_id = self._db.insert_scan(scan)

            count = self._run_company(domain, scan_id, company.get("id", 1))
            self._db.update_scan_status(scan_id, "complete")
            self.company_complete.emit(company["name"], count)
            total_findings += count
            scanned += 1

        self.batch_complete.emit(scanned, total_findings)

    def _run_company(self, domain: str, scan_id: int, client_id: int) -> int:
        count = 0
        try:
            hosts_raw = subfinder.run(domain)
            hosts = [h.get("host", "") for h in hosts_raw if h.get("host")]
            if not hosts:
                hosts = [domain]
        except Exception:
            hosts = [domain]

        try:
            live_raw = httpx.run(hosts)
            urls = [h.get("url", "") for h in live_raw if h.get("url")]
        except Exception:
            urls = []

        if not urls:
            return count

        try:
            findings_raw = nuclei.run(urls)
            for f in findings_raw:
                f["scan_id"] = scan_id
                f["created_at"] = datetime.now(timezone.utc).isoformat()
                self._save_finding(f)
                self.finding_discovered.emit(f)
                count += 1
        except Exception as e:
            self.error_occurred.emit(domain, str(e))

        return count

    def _save_finding(self, f: dict) -> None:
        from models import Finding
        finding = Finding(
            id=None,
            scan_id=f.get("scan_id"),
            tool=f.get("tool", "nuclei"),
            severity=f.get("severity", "info"),
            title=f.get("title", ""),
            description=f.get("description", ""),
            host=f.get("host", ""),
            port=f.get("port"),
            raw_json=f.get("raw", "{}"),
            created_at=f.get("created_at", ""),
        )
        self._db.insert_finding(finding)
```

**IMPORTANT:** Before writing the final code, read `db.py` and `models.py` to verify exact field names. `Finding` dataclass fields may differ. Adjust accordingly.

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_batch_scan_worker.py -v
```
Expected: 4 passed

- [ ] **Step 6: Add "Scan All Companies" button to ScanView**

Read `screens/scan_view.py`. In the top bar (or near `_start_btn`), add:
```python
self._batch_btn = QPushButton("⚡ Scan All Companies")
self._batch_btn.setEnabled(self._db is not None)
self._batch_btn.clicked.connect(self._on_batch_scan)
```

Add handler:
```python
def _on_batch_scan(self):
    from workers.batch_scan_worker import BatchScanWorker
    companies = self._db.get_companies()
    if not companies:
        self._status_label.setText("No companies registered.")
        return
    self._batch_worker = BatchScanWorker(companies=companies, db=self._db)
    self._batch_worker.finding_discovered.connect(self._on_finding)
    self._batch_worker.tool_log.connect(self._on_tool_log)
    self._batch_worker.company_started.connect(
        lambda name, idx: self._status_label.setText(f"Scanning {name}…")
    )
    self._batch_worker.batch_complete.connect(
        lambda n, total: self._status_label.setText(f"Batch complete — {n} companies, {total} findings")
    )
    self._batch_worker.finished.connect(self._batch_worker.deleteLater)
    self._batch_worker.start()
```

(Store `_batch_worker` on self to prevent GC.)

- [ ] **Step 7: Run full suite**

```bash
pytest tests/ -p no:randomly -q
```
Expected: 343 passed (339 + 4 batch tests)

- [ ] **Step 8: Commit**

```bash
git add workers/batch_scan_worker.py tests/test_batch_scan_worker.py screens/scan_view.py
git commit -m "feat: add BatchScanWorker for sequential multi-company external scans"
```

---

## Task 5: Full test suite + smoke test

**Files:** None new.

- [ ] **Step 1: Full test suite**

```bash
source venv/bin/activate && pytest tests/ -p no:randomly -q
```
Expected: **343 tests passed** (331 + 5 db_companies + 3 selector + 4 batch), no errors.

- [ ] **Step 2: Smoke test company registry**

```bash
QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication
import sys
app = QApplication.instance() or QApplication(sys.argv)
from db import DB
from screens.client_onboarding import ClientOnboardingScreen
db = DB(':memory:')
companies = db.get_companies()
assert len(companies) == 9, f'Expected 9 seed companies, got {len(companies)}'
page = ClientOnboardingScreen(db=db)
assert page._company_list.count() == 9
assert page._name_input is not None
print('Company registry smoke test PASSED')
"
```

- [ ] **Step 3: Smoke test CompanySelector**

```bash
QT_QPA_PLATFORM=offscreen python -c "
from PyQt6.QtWidgets import QApplication
import sys
app = QApplication.instance() or QApplication(sys.argv)
from db import DB
from screens.widgets.company_selector import CompanySelector
db = DB(':memory:')
sel = CompanySelector(db=db)
assert sel._combo.count() == 9
assert sel.current_company() is not None
print('CompanySelector smoke test PASSED')
"
```

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "feat: Phase 7 complete — 9-company registry, CompanySelector widget, BatchScanWorker"
```

Only commit Phase 7 files. Exclude `.superpowers/`, PRD, PDF files.
