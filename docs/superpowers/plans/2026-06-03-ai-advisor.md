# AI Advisor (Phase 6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in AI Advisor to SecureOps that analyzes completed scan findings via Google Gemini and surfaces prioritized defensive recommendations in the Report screen, with per-item accept/discard and PDF export.

**Architecture:** A dedicated `advisor/` package (gemini_client, prompt_builder, worker) mirrors the existing `scheduler/` and `report/` module pattern. An `AdvisoryItem` model and two new DB tables (`advisory_items`, `app_settings`) persist advisor state. The Report screen gains a panel launched post-scan; the PDF generator gains an optional advisory section.

**Tech Stack:** PyQt6, Google Gemini API (`google-generativeai`), SQLite, ReportLab, pytest + pytest-qt.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `models.py` | Modify | Add `AdvisoryItem` dataclass |
| `db.py` | Modify | Add `advisory_items` + `app_settings` tables, CRUD methods |
| `advisor/__init__.py` | Create | Package marker (empty) |
| `advisor/gemini_client.py` | Create | Raw Gemini API call |
| `advisor/prompt_builder.py` | Create | Build findings prompt |
| `advisor/worker.py` | Create | QThread orchestrator + response parser |
| `screens/settings.py` | Modify | Add AI Advisor section (toggle + API key + save) |
| `screens/report.py` | Modify | Add advisor panel, update `export_pdf()` |
| `report/pdf_generator.py` | Modify | Add optional advisory section |
| `requirements.txt` | Modify | Add `google-generativeai` |
| `tests/test_models.py` | Modify | Add `AdvisoryItem` test |
| `tests/test_db.py` | Modify | Add advisory_items + app_settings tests |
| `tests/test_advisor_gemini_client.py` | Create | GeminiClient unit tests |
| `tests/test_advisor_prompt_builder.py` | Create | PromptBuilder unit tests |
| `tests/test_advisor_worker.py` | Create | `parse_advisor_response` unit tests |
| `tests/test_screen_settings.py` | Modify | AI Advisor settings tests |
| `tests/test_screen_report.py` | Modify | Advisor panel tests |
| `tests/test_report_pdf.py` | Modify | Advisory PDF section test |

---

## Task 1: Add `AdvisoryItem` dataclass

**Files:**
- Modify: `models.py`
- Modify: `tests/test_models.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_models.py`:

```python
from models import AdvisoryItem


def test_advisory_item_fields():
    item = AdvisoryItem(
        id=None, scan_id=1, tier="immediate",
        text="Patch the vulnerable service", accepted=False,
        created_at="2026-06-03T00:00:00",
    )
    assert item.id is None
    assert item.scan_id == 1
    assert item.tier == "immediate"
    assert item.text == "Patch the vulnerable service"
    assert item.accepted is False


def test_advisory_item_accepted_flag():
    item = AdvisoryItem(
        id=5, scan_id=2, tier="preventive",
        text="Enable MFA", accepted=True,
        created_at="2026-06-03T00:00:00",
    )
    assert item.id == 5
    assert item.accepted is True
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest tests/test_models.py::test_advisory_item_fields -v
```
Expected: `FAILED` — `ImportError: cannot import name 'AdvisoryItem'`

- [ ] **Step 3: Add `AdvisoryItem` to `models.py`**

Append after the `Schedule` dataclass at the bottom of `models.py`:

```python
@dataclass
class AdvisoryItem:
    id: int | None
    scan_id: int
    tier: str          # "immediate" | "short_term" | "preventive"
    text: str
    accepted: bool
    created_at: str
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_models.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add models.py tests/test_models.py
git commit -m "feat: add AdvisoryItem dataclass"
```

---

## Task 2: DB tables and CRUD

**Files:**
- Modify: `db.py`
- Modify: `tests/test_db.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_db.py`:

```python
from models import AdvisoryItem


def test_insert_and_query_advisory_item(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    item = AdvisoryItem(id=None, scan_id=sid, tier="immediate",
                        text="Patch now", accepted=False,
                        created_at="2026-06-03T00:00:00")
    iid = db.insert_advisory_item(item)
    items = db.query_advisory_items_by_scan(sid)
    assert len(items) == 1
    assert items[0].tier == "immediate"
    assert items[0].id == iid
    assert items[0].accepted is False


def test_update_advisory_item_accepted(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    iid = db.insert_advisory_item(AdvisoryItem(id=None, scan_id=sid, tier="preventive",
                                               text="Enable monitoring", accepted=False,
                                               created_at="2026-06-03T00:00:00"))
    db.update_advisory_item_accepted(iid, True)
    items = db.query_advisory_items_by_scan(sid)
    assert items[0].accepted is True


def test_delete_advisory_items_by_scan(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    for tier in ("immediate", "short_term", "preventive"):
        db.insert_advisory_item(AdvisoryItem(id=None, scan_id=sid, tier=tier,
                                             text="action", accepted=False,
                                             created_at="2026-06-03T00:00:00"))
    db.delete_advisory_items_by_scan(sid)
    assert db.query_advisory_items_by_scan(sid) == []


def test_get_setting_returns_none_when_absent(db):
    assert db.get_setting("ai_advisor_enabled") is None


def test_set_and_get_setting(db):
    db.set_setting("ai_advisor_enabled", "1")
    assert db.get_setting("ai_advisor_enabled") == "1"


def test_set_setting_overwrites(db):
    db.set_setting("gemini_api_key", "old-key")
    db.set_setting("gemini_api_key", "new-key")
    assert db.get_setting("gemini_api_key") == "new-key"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_db.py::test_insert_and_query_advisory_item -v
```
Expected: `FAILED` — `AttributeError: 'DB' object has no attribute 'insert_advisory_item'`

- [ ] **Step 3: Add tables to `_SCHEMA` in `db.py`**

In `db.py`, append to the `_SCHEMA` string (before the closing `"""`):

```python
CREATE TABLE IF NOT EXISTS advisory_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id),
    tier       TEXT NOT NULL,
    text       TEXT NOT NULL,
    accepted   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

- [ ] **Step 4: Add CRUD methods to the `DB` class in `db.py`**

Add the following six methods to the `DB` class, after `query_recent_findings`:

```python
def insert_advisory_item(self, item) -> int:
    with self._lock:
        cur = self._conn.execute(
            "INSERT INTO advisory_items (scan_id, tier, text, accepted, created_at)"
            " VALUES (?,?,?,?,?)",
            (item.scan_id, item.tier, item.text,
             1 if item.accepted else 0, item.created_at),
        )
        self._conn.commit()
        return cur.lastrowid

def query_advisory_items_by_scan(self, scan_id: int) -> list:
    rows = self._conn.execute(
        "SELECT * FROM advisory_items WHERE scan_id=? ORDER BY id", (scan_id,)
    ).fetchall()
    from models import AdvisoryItem
    return [AdvisoryItem(id=r["id"], scan_id=r["scan_id"], tier=r["tier"],
                         text=r["text"], accepted=bool(r["accepted"]),
                         created_at=r["created_at"]) for r in rows]

def update_advisory_item_accepted(self, item_id: int, accepted: bool) -> None:
    with self._lock:
        self._conn.execute(
            "UPDATE advisory_items SET accepted=? WHERE id=?",
            (1 if accepted else 0, item_id),
        )
        self._conn.commit()

def delete_advisory_items_by_scan(self, scan_id: int) -> None:
    with self._lock:
        self._conn.execute(
            "DELETE FROM advisory_items WHERE scan_id=?", (scan_id,)
        )
        self._conn.commit()

def get_setting(self, key: str) -> str | None:
    row = self._conn.execute(
        "SELECT value FROM app_settings WHERE key=?", (key,)
    ).fetchone()
    return row["value"] if row else None

def set_setting(self, key: str, value: str) -> None:
    with self._lock:
        self._conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self._conn.commit()
```

- [ ] **Step 5: Run tests to verify they pass**

```
pytest tests/test_db.py -v
```
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add db.py tests/test_db.py
git commit -m "feat: add advisory_items and app_settings DB tables with CRUD"
```

---

## Task 3: `advisor/gemini_client.py`

**Files:**
- Create: `advisor/__init__.py`
- Create: `advisor/gemini_client.py`
- Create: `tests/test_advisor_gemini_client.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_advisor_gemini_client.py`:

```python
import sys
from unittest.mock import MagicMock
import pytest


def _mock_genai(response_text: str = "response") -> MagicMock:
    m = MagicMock()
    m.GenerativeModel.return_value.generate_content.return_value.text = response_text
    return m


def test_gemini_client_returns_text(monkeypatch):
    monkeypatch.setitem(sys.modules, "google.generativeai", _mock_genai("hello"))
    from advisor.gemini_client import GeminiClient
    assert GeminiClient("key").generate("prompt") == "hello"


def test_gemini_client_configures_api_key(monkeypatch):
    mock_genai = _mock_genai()
    monkeypatch.setitem(sys.modules, "google.generativeai", mock_genai)
    from advisor.gemini_client import GeminiClient
    GeminiClient("my-secret-key").generate("prompt")
    mock_genai.configure.assert_called_once_with(api_key="my-secret-key")


def test_gemini_client_wraps_api_error(monkeypatch):
    mock_genai = MagicMock()
    mock_genai.GenerativeModel.return_value.generate_content.side_effect = Exception("quota")
    monkeypatch.setitem(sys.modules, "google.generativeai", mock_genai)
    from advisor.gemini_client import GeminiClient
    with pytest.raises(RuntimeError, match="quota"):
        GeminiClient("key").generate("prompt")
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_advisor_gemini_client.py -v
```
Expected: `FAILED` — `ModuleNotFoundError: No module named 'advisor'`

- [ ] **Step 3: Create `advisor/__init__.py`**

Create `advisor/__init__.py` as an empty file.

- [ ] **Step 4: Create `advisor/gemini_client.py`**

```python
class GeminiClient:
    def __init__(self, api_key: str):
        self._api_key = api_key

    def generate(self, prompt: str) -> str:
        try:
            import google.generativeai as genai
        except ImportError:
            raise RuntimeError(
                "google-generativeai is not installed. Run: pip install google-generativeai"
            )
        try:
            genai.configure(api_key=self._api_key)
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(prompt)
            return response.text
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc
```

- [ ] **Step 5: Run tests to verify they pass**

```
pytest tests/test_advisor_gemini_client.py -v
```
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add advisor/__init__.py advisor/gemini_client.py tests/test_advisor_gemini_client.py
git commit -m "feat: advisor package and GeminiClient"
```

---

## Task 4: `advisor/prompt_builder.py`

**Files:**
- Create: `advisor/prompt_builder.py`
- Create: `tests/test_advisor_prompt_builder.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_advisor_prompt_builder.py`:

```python
from models import Scan, Client, Host, Finding
from advisor.prompt_builder import PromptBuilder


def _scan():
    return Scan(id=1, client_id=1, target="example.com",
                status="complete", started_at="2026-06-03T10:00:00", finished_at=None)


def _client():
    return Client(id=1, name="Acme", domain="example.com",
                  firewall="pfSense", notes="", created_at="2026-06-03T00:00:00")


def _finding():
    return Finding(id=1, scan_id=1, host_id=None, tool="nuclei",
                   severity="high", title="SQL Injection",
                   description="Found unsanitised input", raw_json="{}",
                   created_at="2026-06-03T10:01:00")


def _host():
    return Host(id=1, scan_id=1, subdomain="api.example.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")


def test_prompt_contains_target():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "example.com" in prompt


def test_prompt_contains_firewall():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "pfSense" in prompt


def test_prompt_contains_finding_title():
    prompt = PromptBuilder().build(_scan(), _client(), [], [_finding()])
    assert "SQL Injection" in prompt


def test_prompt_contains_finding_severity():
    prompt = PromptBuilder().build(_scan(), _client(), [], [_finding()])
    assert "HIGH" in prompt


def test_prompt_contains_host():
    prompt = PromptBuilder().build(_scan(), _client(), [_host()], [])
    assert "api.example.com" in prompt


def test_prompt_has_all_three_section_markers():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "IMMEDIATE:" in prompt
    assert "SHORT_TERM:" in prompt
    assert "PREVENTIVE:" in prompt


def test_prompt_no_client_uses_unknown_firewall():
    prompt = PromptBuilder().build(_scan(), None, [], [])
    assert "unknown" in prompt


def test_prompt_no_exploitation_instruction():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "exploitation" in prompt.lower() or "offensive" in prompt.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_advisor_prompt_builder.py -v
```
Expected: `FAILED` — `ModuleNotFoundError: No module named 'advisor.prompt_builder'`

- [ ] **Step 3: Create `advisor/prompt_builder.py`**

```python
class PromptBuilder:
    def build(self, scan, client, hosts, findings) -> str:
        firewall = (client.firewall if client else None) or "unknown"

        findings_text = "\n".join(
            f"[{f.severity.upper()}] {f.title}: {f.description[:200]}"
            for f in findings
        ) or "No findings."

        hosts_text = "\n".join(
            f"{h.subdomain or h.ip or 'unknown'}"
            f"  port={h.port or 'N/A'}  service={h.service or 'N/A'}"
            for h in hosts
        ) or "No hosts."

        return (
            "You are a security advisor reviewing a penetration test scan result.\n"
            "Produce ONLY defensive precautions and remediation guidance.\n"
            "Do NOT include any exploitation steps, attack methods, or offensive techniques.\n\n"
            "Respond in EXACTLY this format — no other text, no preamble:\n"
            "IMMEDIATE:\n"
            "1. [action]\n"
            "SHORT_TERM:\n"
            "1. [action]\n"
            "PREVENTIVE:\n"
            "1. [action]\n\n"
            f"Target: {scan.target}\n"
            f"Client firewall: {firewall}\n\n"
            f"FINDINGS:\n{findings_text}\n\n"
            f"HOSTS:\n{hosts_text}"
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_advisor_prompt_builder.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add advisor/prompt_builder.py tests/test_advisor_prompt_builder.py
git commit -m "feat: PromptBuilder constructs Gemini findings prompt"
```

---

## Task 5: `advisor/worker.py`

**Files:**
- Create: `advisor/worker.py`
- Create: `tests/test_advisor_worker.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_advisor_worker.py`:

```python
from advisor.worker import parse_advisor_response


_VALID = """\
IMMEDIATE:
1. Patch OpenSSL immediately
2. Disable SSLv3 and TLS 1.0
SHORT_TERM:
1. Review firewall rules for port 443
PREVENTIVE:
1. Enable automated dependency scanning
"""

_MISSING_PREVENTIVE = """\
IMMEDIATE:
1. Do something
SHORT_TERM:
1. Do something else
"""

_EMPTY = ""


def test_parse_valid_response_count():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert len(items) == 4


def test_parse_valid_response_tiers():
    items = parse_advisor_response(_VALID, scan_id=1)
    tiers = {i.tier for i in items}
    assert tiers == {"immediate", "short_term", "preventive"}


def test_parse_valid_response_scan_id():
    items = parse_advisor_response(_VALID, scan_id=7)
    assert all(i.scan_id == 7 for i in items)


def test_parse_valid_response_not_accepted():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert all(i.accepted is False for i in items)


def test_parse_valid_response_no_id():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert all(i.id is None for i in items)


def test_parse_immediate_text():
    items = parse_advisor_response(_VALID, scan_id=1)
    immediate = [i for i in items if i.tier == "immediate"]
    assert any("OpenSSL" in i.text for i in immediate)


def test_parse_missing_tier_returns_empty():
    assert parse_advisor_response(_MISSING_PREVENTIVE, scan_id=1) == []


def test_parse_empty_response_returns_empty():
    assert parse_advisor_response(_EMPTY, scan_id=1) == []
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_advisor_worker.py -v
```
Expected: `FAILED` — `ModuleNotFoundError: No module named 'advisor.worker'`

- [ ] **Step 3: Create `advisor/worker.py`**

```python
from PyQt6.QtCore import QThread, pyqtSignal
from datetime import datetime, timezone
from models import AdvisoryItem


def parse_advisor_response(text: str, scan_id: int) -> list[AdvisoryItem]:
    tier_map = {
        "IMMEDIATE:": "immediate",
        "SHORT_TERM:": "short_term",
        "PREVENTIVE:": "preventive",
    }
    items: list[AdvisoryItem] = []
    current_tier: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped in tier_map:
            current_tier = tier_map[stripped]
        elif current_tier and stripped and stripped[0].isdigit() and ". " in stripped:
            _, item_text = stripped.split(". ", 1)
            if item_text.strip():
                items.append(AdvisoryItem(
                    id=None,
                    scan_id=scan_id,
                    tier=current_tier,
                    text=item_text.strip(),
                    accepted=False,
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

    required = {"immediate", "short_term", "preventive"}
    if not required.issubset({i.tier for i in items}):
        return []
    return items


class AdvisorWorker(QThread):
    item_ready = pyqtSignal(object)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, scan_id: int, db, api_key: str, parent=None):
        super().__init__(parent)
        self._scan_id = scan_id
        self._db = db
        self._api_key = api_key
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def run(self) -> None:
        try:
            scan = self._resolve_scan()
            if scan is None or self._cancelled:
                self.finished.emit()
                return

            client = self._resolve_client(scan.client_id)
            hosts = self._db.query_hosts_by_scan(self._scan_id)
            findings = self._db.query_findings_by_scan(self._scan_id)

            if self._cancelled:
                self.finished.emit()
                return

            from advisor.prompt_builder import PromptBuilder
            from advisor.gemini_client import GeminiClient

            prompt = PromptBuilder().build(scan, client, hosts, findings)
            response = GeminiClient(self._api_key).generate(prompt)

            if self._cancelled:
                self.finished.emit()
                return

            items = parse_advisor_response(response, self._scan_id)
            if not items:
                self.error.emit("Could not parse advisor response — try again")
                return

            for item in items:
                if self._cancelled:
                    break
                item.id = self._db.insert_advisory_item(item)
                self.item_ready.emit(item)

            self.finished.emit()

        except RuntimeError as exc:
            self.error.emit(str(exc))
        except Exception as exc:
            self.error.emit(f"Unexpected error: {exc}")

    def _resolve_scan(self):
        for c in self._db.query_clients():
            for s in self._db.query_scans_by_client(c.id):
                if s.id == self._scan_id:
                    return s
        for s in self._db.query_scans_by_client(None):
            if s.id == self._scan_id:
                return s
        return None

    def _resolve_client(self, client_id):
        if client_id is None:
            return None
        for c in self._db.query_clients():
            if c.id == client_id:
                return c
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_advisor_worker.py -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add advisor/worker.py tests/test_advisor_worker.py
git commit -m "feat: AdvisorWorker QThread and parse_advisor_response"
```

---

## Task 6: Settings screen — AI Advisor section

**Files:**
- Modify: `screens/settings.py`
- Modify: `tests/test_screen_settings.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_screen_settings.py`:

```python
def test_settings_has_advisor_checkbox(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._advisor_enabled_cb is not None


def test_settings_advisor_disabled_by_default(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._advisor_enabled_cb.isChecked()


def test_settings_api_key_disabled_when_advisor_off(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._api_key_input.isEnabled()


def test_settings_api_key_enabled_when_advisor_toggled_on(qtbot):
    screen = SettingsScreen(_all_present(), db=_make_db())
    qtbot.addWidget(screen)
    screen._advisor_enabled_cb.setChecked(True)
    assert screen._api_key_input.isEnabled()


def test_settings_save_persists_advisor_enabled(qtbot):
    db = _make_db()
    screen = SettingsScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen._advisor_enabled_cb.setChecked(True)
    screen._advisor_save_btn.click()
    assert db.get_setting("ai_advisor_enabled") == "1"


def test_settings_save_persists_api_key(qtbot):
    db = _make_db()
    screen = SettingsScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    screen._advisor_enabled_cb.setChecked(True)
    screen._api_key_input.setText("my-gemini-key")
    screen._advisor_save_btn.click()
    assert db.get_setting("gemini_api_key") == "my-gemini-key"


def test_settings_loads_saved_api_key(qtbot):
    db = _make_db()
    db.set_setting("ai_advisor_enabled", "1")
    db.set_setting("gemini_api_key", "existing-key")
    screen = SettingsScreen(_all_present(), db=db)
    qtbot.addWidget(screen)
    assert screen._advisor_enabled_cb.isChecked()
    assert screen._api_key_input.text() == "existing-key"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_screen_settings.py::test_settings_has_advisor_checkbox -v
```
Expected: `FAILED` — `AttributeError: 'SettingsScreen' object has no attribute '_advisor_enabled_cb'`

- [ ] **Step 3: Add imports and instance variables to `screens/settings.py`**

In `screens/settings.py`, add `QCheckBox` to the existing `QWidget` imports line:

```python
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QScrollArea, QComboBox, QCheckBox,
)
```

In `SettingsScreen.__init__`, add three new instance variables after `self._schedules_layout`:

```python
self._advisor_enabled_cb: QCheckBox | None = None
self._api_key_input: QLineEdit | None = None
self._advisor_save_btn: QPushButton | None = None
```

- [ ] **Step 4: Add `_build_advisor_section` call inside `_setup_ui`**

In `_setup_ui`, after the line `layout.addWidget(sched_list)` and `self._refresh_schedules()`, append:

```python
        self._build_advisor_section(layout)
```

- [ ] **Step 5: Add `_build_advisor_section`, `_on_advisor_toggled`, `_on_save_advisor_settings` methods**

Add these three methods to `SettingsScreen`, after `_refresh_schedules`:

```python
    def _build_advisor_section(self, layout: QVBoxLayout) -> None:
        advisor_label = QLabel("AI ADVISOR")
        advisor_label.setStyleSheet("color: #64748b; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(advisor_label)

        self._advisor_enabled_cb = QCheckBox("Enable AI Advisor (Google Gemini)")
        self._advisor_enabled_cb.setStyleSheet("color: #e2e8f0;")
        enabled = self._db is not None and self._db.get_setting("ai_advisor_enabled") == "1"
        self._advisor_enabled_cb.setChecked(enabled)
        self._advisor_enabled_cb.toggled.connect(self._on_advisor_toggled)
        layout.addWidget(self._advisor_enabled_cb)

        self._api_key_input = QLineEdit()
        self._api_key_input.setPlaceholderText("Gemini API key")
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._api_key_input.setEnabled(enabled)
        if self._db:
            saved_key = self._db.get_setting("gemini_api_key")
            if saved_key:
                self._api_key_input.setText(saved_key)
        layout.addWidget(self._api_key_input)

        save_row = QHBoxLayout()
        self._advisor_save_btn = QPushButton("Save")
        self._advisor_save_btn.setFixedWidth(80)
        self._advisor_save_btn.clicked.connect(self._on_save_advisor_settings)
        save_row.addWidget(self._advisor_save_btn)
        save_row.addStretch()
        layout.addLayout(save_row)

    def _on_advisor_toggled(self, checked: bool) -> None:
        if self._api_key_input:
            self._api_key_input.setEnabled(checked)

    def _on_save_advisor_settings(self) -> None:
        if not self._db:
            return
        self._db.set_setting(
            "ai_advisor_enabled",
            "1" if self._advisor_enabled_cb.isChecked() else "0",
        )
        self._db.set_setting("gemini_api_key", self._api_key_input.text().strip())
```

- [ ] **Step 6: Run tests to verify they pass**

```
pytest tests/test_screen_settings.py -v
```
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add screens/settings.py tests/test_screen_settings.py
git commit -m "feat: AI Advisor section in Settings (toggle, API key, save)"
```

---

## Task 7: Report screen — advisor panel

**Files:**
- Modify: `screens/report.py`
- Modify: `tests/test_screen_report.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_screen_report.py`:

```python
def test_report_advisor_panel_built_after_load(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._advisor_panel is not None


def test_report_advisor_shows_disabled_message_when_off(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    # advisor disabled (no setting saved) — run button should be absent
    assert screen._run_advisor_btn is None


def test_report_advisor_run_button_present_when_enabled(qtbot):
    db, scan_id = _make_db()
    db.set_setting("ai_advisor_enabled", "1")
    db.set_setting("gemini_api_key", "test-key")
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._run_advisor_btn is not None
    assert screen._run_advisor_btn.isEnabled()


def test_report_reset_cancels_worker(qtbot):
    db, scan_id = _make_db()
    db.set_setting("ai_advisor_enabled", "1")
    db.set_setting("gemini_api_key", "test-key")
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert screen._advisor_worker is None
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_screen_report.py::test_report_advisor_panel_built_after_load -v
```
Expected: `FAILED` — `AttributeError: 'ReportScreen' object has no attribute '_advisor_panel'`

- [ ] **Step 3: Add new instance variables to `ReportScreen.__init__`**

In `screens/report.py`, add to `__init__` after `self._content_layout`:

```python
        self._advisor_panel: QFrame | None = None
        self._run_advisor_btn: QPushButton | None = None
        self._advisor_status: QLabel | None = None
        self._tier_layouts: dict = {}
        self._advisor_worker: object | None = None
```

- [ ] **Step 4: Update `load_scan` to build the advisor panel**

In `load_scan`, replace the existing last three lines:

```python
        self._content_layout.addWidget(self._build_findings_panel(findings))
        self._content_layout.addStretch()
        self._export_btn.setEnabled(True)
```

with:

```python
        self._content_layout.addWidget(self._build_findings_panel(findings))
        self._advisor_panel = None
        self._run_advisor_btn = None
        self._advisor_status = None
        self._tier_layouts = {}
        self._build_advisor_panel()
        self._content_layout.addStretch()
        self._export_btn.setEnabled(True)
```

- [ ] **Step 5: Update `reset` to cancel any running worker**

In `reset`, replace the existing body:

```python
    def reset(self):
        self._scan_id = None
        self._export_btn.setEnabled(False)
        self._show_placeholder()
```

with:

```python
    def reset(self):
        if self._advisor_worker is not None:
            self._advisor_worker.cancel()
            self._advisor_worker = None
        self._scan_id = None
        self._advisor_panel = None
        self._run_advisor_btn = None
        self._advisor_status = None
        self._tier_layouts = {}
        self._export_btn.setEnabled(False)
        self._show_placeholder()
```

- [ ] **Step 6: Add `_build_advisor_panel` method**

Add after `_build_findings_panel`:

```python
    def _build_advisor_panel(self) -> None:
        if not self._db:
            return

        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(16, 12, 16, 12)
        panel_layout.setSpacing(8)
        self._advisor_panel = panel

        header_row = QHBoxLayout()
        header = QLabel("AI Advisor")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #e2e8f0;")
        header_row.addWidget(header)
        header_row.addStretch()
        panel_layout.addLayout(header_row)

        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""

        if not enabled or not api_key:
            info = QLabel("AI Advisor disabled — enable in Settings.")
            info.setStyleSheet("color: #64748b; font-size: 11px;")
            panel_layout.addWidget(info)
            self._content_layout.addWidget(panel)
            return

        self._run_advisor_btn = QPushButton("Run Advisor")
        self._run_advisor_btn.setFixedWidth(110)
        self._run_advisor_btn.clicked.connect(self._on_run_advisor)
        header_row.addWidget(self._run_advisor_btn)

        self._advisor_status = QLabel("")
        self._advisor_status.setStyleSheet("color: #64748b; font-size: 11px;")
        panel_layout.addWidget(self._advisor_status)

        for tier, label in (("immediate", "IMMEDIATE"), ("short_term", "SHORT-TERM"),
                             ("preventive", "PREVENTIVE")):
            sub_header = QLabel(label)
            sub_header.setStyleSheet("color: #94a3b8; font-size: 10px; letter-spacing: 1px;")
            sub_header.hide()
            panel_layout.addWidget(sub_header)
            tier_box = QVBoxLayout()
            tier_box.setSpacing(4)
            panel_layout.addLayout(tier_box)
            self._tier_layouts[tier] = {"header": sub_header, "layout": tier_box}

        disclaimer = QLabel("AI-generated — review before sending to client.")
        disclaimer.setStyleSheet("color: #64748b; font-size: 10px; font-style: italic;")
        panel_layout.addWidget(disclaimer)

        self._content_layout.addWidget(panel)
```

- [ ] **Step 7: Add `_on_run_advisor`, `_on_advisor_item_ready`, `_on_advisor_finished`, `_on_advisor_error`, `_build_item_card`, `_accept_item`, `_discard_item` methods**

Add after `_build_advisor_panel`:

```python
    def _on_run_advisor(self) -> None:
        if not self._db or self._scan_id is None:
            return
        api_key = self._db.get_setting("gemini_api_key") or ""
        if not api_key:
            if self._advisor_status:
                self._advisor_status.setText("No API key — add one in Settings.")
            return

        self._db.delete_advisory_items_by_scan(self._scan_id)
        for tier_data in self._tier_layouts.values():
            tier_data["header"].hide()
            while tier_data["layout"].count():
                item = tier_data["layout"].takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

        if self._run_advisor_btn:
            self._run_advisor_btn.setText("Analyzing…")
            self._run_advisor_btn.setEnabled(False)
        if self._advisor_status:
            self._advisor_status.setText("Contacting Gemini API…")

        from advisor.worker import AdvisorWorker
        self._advisor_worker = AdvisorWorker(
            scan_id=self._scan_id, db=self._db, api_key=api_key,
        )
        self._advisor_worker.item_ready.connect(self._on_advisor_item_ready)
        self._advisor_worker.finished.connect(self._on_advisor_finished)
        self._advisor_worker.error.connect(self._on_advisor_error)
        self._advisor_worker.start()

    def _on_advisor_item_ready(self, item) -> None:
        tier_data = self._tier_layouts.get(item.tier)
        if tier_data is None:
            return
        tier_data["header"].show()
        tier_data["layout"].addWidget(self._build_item_card(item))

    def _on_advisor_finished(self) -> None:
        if self._run_advisor_btn:
            self._run_advisor_btn.setText("Run Advisor")
            self._run_advisor_btn.setEnabled(True)
        if self._advisor_status:
            self._advisor_status.setText("Analysis complete.")

    def _on_advisor_error(self, msg: str) -> None:
        if self._run_advisor_btn:
            self._run_advisor_btn.setText("Run Advisor")
            self._run_advisor_btn.setEnabled(True)
        if self._advisor_status:
            self._advisor_status.setText(f"Error: {msg}")

    def _build_item_card(self, item) -> QFrame:
        card = QFrame()
        card.setStyleSheet(
            "QFrame { border-left: 3px solid #38bdf8;"
            " background-color: #0f172a; border-radius: 3px; }"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(10, 6, 10, 6)
        card_layout.setSpacing(4)

        text_lbl = QLabel(item.text)
        text_lbl.setWordWrap(True)
        text_lbl.setStyleSheet("color: #e2e8f0; font-size: 11px;")
        card_layout.addWidget(text_lbl)

        btn_row = QHBoxLayout()
        accept_btn = QPushButton("✓ Accept")
        accept_btn.setFixedWidth(80)
        accept_btn.setStyleSheet(
            "QPushButton { color: #00ff88; border: 1px solid #00ff88;"
            " border-radius: 3px; padding: 2px 6px; font-size: 10px; }"
            " QPushButton:hover { background-color: #00ff8820; }"
        )
        discard_btn = QPushButton("✗ Discard")
        discard_btn.setFixedWidth(80)
        discard_btn.setStyleSheet(
            "QPushButton { color: #ff4444; border: 1px solid #ff4444;"
            " border-radius: 3px; padding: 2px 6px; font-size: 10px; }"
            " QPushButton:hover { background-color: #ff444420; }"
        )
        accept_btn.clicked.connect(
            lambda: self._accept_item(item, card, accept_btn, discard_btn)
        )
        discard_btn.clicked.connect(lambda: self._discard_item(item, card))
        btn_row.addWidget(accept_btn)
        btn_row.addWidget(discard_btn)
        btn_row.addStretch()
        card_layout.addLayout(btn_row)
        return card

    def _accept_item(self, item, card: QFrame,
                     accept_btn: QPushButton, discard_btn: QPushButton) -> None:
        if self._db and item.id is not None:
            self._db.update_advisory_item_accepted(item.id, True)
        card.setStyleSheet(
            "QFrame { border-left: 3px solid #00ff88;"
            " background-color: #0a1628; border-radius: 3px; }"
        )
        accept_btn.setEnabled(False)
        discard_btn.setEnabled(False)

    def _discard_item(self, item, card: QFrame) -> None:
        if self._db and item.id is not None:
            self._db.update_advisory_item_accepted(item.id, False)
        card.hide()
```

- [ ] **Step 8: Update `export_pdf` to include accepted advisory items**

In `export_pdf`, replace:

```python
        try:
            from report.pdf_generator import PdfGenerator
            PdfGenerator(scan=scan, hosts=hosts, findings=findings,
                         output_path=path).generate()
```

with:

```python
        advisory_items = [
            i for i in self._db.query_advisory_items_by_scan(self._scan_id)
            if i.accepted
        ]
        try:
            from report.pdf_generator import PdfGenerator
            PdfGenerator(scan=scan, hosts=hosts, findings=findings,
                         output_path=path, advisory_items=advisory_items).generate()
```

- [ ] **Step 9: Run tests to verify they pass**

```
pytest tests/test_screen_report.py -v
```
Expected: all PASS

- [ ] **Step 10: Commit**

```bash
git add screens/report.py tests/test_screen_report.py
git commit -m "feat: AI Advisor panel in Report screen with accept/discard per item"
```

---

## Task 8: PDF advisory section

**Files:**
- Modify: `report/pdf_generator.py`
- Modify: `tests/test_report_pdf.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_report_pdf.py`. First read that file to find the existing test pattern, then append:

```python
from models import AdvisoryItem   # add to imports at top of test_report_pdf.py


def test_pdf_advisory_section_present_when_accepted_items(tmp_path):
    items = [
        AdvisoryItem(id=1, scan_id=1, tier="immediate",
                     text="Patch OpenSSL", accepted=True,
                     created_at="2026-06-03T10:00:00"),
        AdvisoryItem(id=2, scan_id=1, tier="short_term",
                     text="Review firewall rules", accepted=True,
                     created_at="2026-06-03T10:00:00"),
        AdvisoryItem(id=3, scan_id=1, tier="preventive",
                     text="Enable dependency scanning", accepted=True,
                     created_at="2026-06-03T10:00:00"),
    ]
    out = str(tmp_path / "report.pdf")
    PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path=out,
                 advisory_items=items).generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 0


def test_pdf_no_advisory_section_when_no_items(tmp_path):
    out = str(tmp_path / "report_no_advisory.pdf")
    PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path=out).generate()
    assert os.path.exists(out)
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_report_pdf.py::test_pdf_advisory_section_present_when_accepted_items -v
```
Expected: `FAILED` — `TypeError: PdfGenerator.__init__() got an unexpected keyword argument 'advisory_items'`

- [ ] **Step 3: Add `advisory_items` parameter to `PdfGenerator.__init__`**

In `report/pdf_generator.py`, update the `__init__` signature from:

```python
    def __init__(self, scan: Scan, hosts: list[Host], findings: list[Finding],
                 client: Client | None = None, output_path: str = "report.pdf"):
        self._scan = scan
        self._hosts = hosts
        self._findings = findings
        self._client = client
        self._output_path = output_path
        self._styles = getSampleStyleSheet()
        self._setup_styles()
```

to:

```python
    def __init__(self, scan: Scan, hosts: list[Host], findings: list[Finding],
                 client: Client | None = None, output_path: str = "report.pdf",
                 advisory_items: list | None = None):
        self._scan = scan
        self._hosts = hosts
        self._findings = findings
        self._client = client
        self._output_path = output_path
        self._advisory_items = advisory_items or []
        self._styles = getSampleStyleSheet()
        self._setup_styles()
```

- [ ] **Step 4: Add advisory section call to `generate`**

In `generate`, replace:

```python
        story += self._iso_section()
        story += self._host_appendix()
```

with:

```python
        story += self._iso_section()
        if self._advisory_items:
            story += self._advisory_section()
        story += self._host_appendix()
```

- [ ] **Step 5: Add `_advisory_section` method**

Add after `_iso_section`:

```python
    def _advisory_section(self) -> list:
        story = [
            PageBreak(),
            Paragraph("AI Advisory", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
            Paragraph(
                "<i>AI-generated content — reviewed and accepted by consultant.</i>",
                self._body,
            ),
            Spacer(1, 0.3 * cm),
        ]
        for tier, heading in (
            ("immediate", "Immediate Actions"),
            ("short_term", "Short-Term Actions"),
            ("preventive", "Preventive Measures"),
        ):
            tier_items = [i for i in self._advisory_items if i.tier == tier]
            if not tier_items:
                continue
            story.append(Paragraph(heading, self._h2))
            for item in tier_items:
                story.append(Paragraph(f"• {item.text}", self._body))
            story.append(Spacer(1, 0.2 * cm))
        return story
```

- [ ] **Step 6: Run tests to verify they pass**

```
pytest tests/test_report_pdf.py -v
```
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add report/pdf_generator.py tests/test_report_pdf.py
git commit -m "feat: AI Advisory section in PDF export"
```

---

## Task 9: Add `google-generativeai` to requirements

**Files:**
- Modify: `requirements.txt`

- [ ] **Step 1: Update `requirements.txt`**

Add `google-generativeai>=0.8.0` to `requirements.txt`:

```
PyQt6>=6.6.0
pytest>=8.0.0
pytest-qt>=4.4.0
google-generativeai>=0.8.0
```

- [ ] **Step 2: Install the package**

```
pip install google-generativeai
```

- [ ] **Step 3: Run the full test suite**

```
pytest -v
```
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add requirements.txt
git commit -m "chore: add google-generativeai dependency"
```

---

## Task 10: Final integration check

- [ ] **Step 1: Run the full test suite one last time**

```
pytest -v
```
Expected: all PASS, no errors

- [ ] **Step 2: Mark Phase 6 complete in `CLAUDE.md`**

In `CLAUDE.md`, update the phase table row:

```markdown
| 6 | AI Advisor agent (opt-in, consent, redaction, local-LLM alt) | Complete |
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "chore: mark Phase 6 complete in CLAUDE.md"
```
