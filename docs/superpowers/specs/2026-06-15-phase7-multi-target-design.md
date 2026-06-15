# Phase 7 — Multi-Target Orchestration Design Spec

**Version:** 1.0  
**Date:** 2026-06-15  
**Owner:** Abhishek K — Fidelitus Corp  
**Status:** Approved — ready to plan  

---

## 1. Overview

Phase 7 adds the 9-company registry and multi-target scan orchestration. Every previous scan module (external, internal, OSINT, cloud) becomes company-aware: the user selects a company and the relevant fields (domain, IP range, AWS profile, GCP project) auto-fill from the registry. A `BatchScanWorker` runs the external scan pipeline sequentially across all registered companies.

**PRD requirements:** FR-9, FR-10, FR-11 (sequential mode)

---

## 2. Architecture

```
companies table (SQLite)
       ↓
CompanySelector widget (reusable QComboBox)
       ↓ (auto-fills per screen)
ScanView / InternalPage / OsintPage / CloudPage

BatchScanWorker (QThread)
  → iterates companies
  → per company: calls tool wrappers directly (subfinder→dnsx→naabu→httpx→nuclei)
  → writes findings to DB (with company_id tag)
  → emits per-company and per-finding signals
       ↓
ScanView shows live progress + findings (existing widgets)
```

---

## 3. Data layer

### 3.1 New table: `companies`

Add to `db.py` `_SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS companies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    domains      TEXT DEFAULT '[]',    -- JSON array of domain strings
    ip_ranges    TEXT DEFAULT '[]',    -- JSON array e.g. ["192.168.1.0/24"]
    aws_profile  TEXT DEFAULT '',
    gcp_project  TEXT DEFAULT '',
    firewall_type TEXT DEFAULT '',
    created_at   TEXT
);
```

### 3.2 New DB methods

```python
def insert_company(self, company: dict) -> int:
    """Insert company record. Returns new row id."""

def get_companies(self) -> list[dict]:
    """Return all companies ordered by name."""

def update_company(self, company_id: int, company: dict) -> None:
    """Update mutable fields of an existing company."""

def delete_company(self, company_id: int) -> None:
    """Delete a company record."""
```

Each method uses `with self._lock`. `get_companies` returns list of dicts with all columns.

### 3.3 Pre-seed data

`db.py` seeds 9 placeholder Fidelitus companies on first run (in `_ensure_seed_companies()`, called from `__init__` after schema creation). Seed only if `companies` table is empty.

```python
_SEED_COMPANIES = [
    {"name": "Fidelitus Corp HQ",       "domains": '["fidelitus.com"]',         "ip_ranges": '["10.0.0.0/24"]'},
    {"name": "Fidelitus Properties",    "domains": '["fidelitusproperties.com"]', "ip_ranges": '["10.0.1.0/24"]'},
    {"name": "Fidelitus HR Solutions",  "domains": '["fidelitushr.com"]',        "ip_ranges": '["10.0.2.0/24"]'},
    {"name": "Fidelitus Finance",       "domains": '["fidelitusfinance.com"]',   "ip_ranges": '["10.0.3.0/24"]'},
    {"name": "Fidelitus Logistics",     "domains": '["fidelituslogistics.com"]', "ip_ranges": '["10.0.4.0/24"]'},
    {"name": "Fidelitus Tech",          "domains": '["fidelitustech.com"]',      "ip_ranges": '["10.0.5.0/24"]'},
    {"name": "Fidelitus Legal",         "domains": '["fidelituslegal.com"]',     "ip_ranges": '["10.0.6.0/24"]'},
    {"name": "Fidelitus Healthcare",    "domains": '["fidelitushealth.com"]',    "ip_ranges": '["10.0.7.0/24"]'},
    {"name": "Fidelitus Education",     "domains": '["fidelitusedu.com"]',       "ip_ranges": '["10.0.8.0/24"]'},
]
```

---

## 4. Company Registry UI (`client_onboarding.py` rewrite)

Replace the current single-form widget with a two-panel registry.

### 4.1 Layout

```
QHBoxLayout
├── Left panel (QVBoxLayout, fixed width 220px)
│   ├── QLabel "Companies"  (header)
│   ├── QListWidget _company_list  (one item per company)
│   └── QHBoxLayout
│       ├── QPushButton _add_btn    "＋ Add"
│       └── QPushButton _delete_btn "✕ Delete"
└── Right panel (QVBoxLayout)
    ├── QLabel "Company Details"
    ├── QFormLayout
    │   ├── QLineEdit _name_input
    │   ├── QLineEdit _domains_input   (comma-separated, e.g. "example.com, sub.example.com")
    │   ├── QLineEdit _ip_ranges_input (comma-separated CIDR, e.g. "192.168.1.0/24")
    │   ├── QLineEdit _aws_profile_input
    │   ├── QLineEdit _gcp_project_input
    │   └── QComboBox _firewall_combo
    └── QPushButton _save_btn  "Save"
    └── QLabel _status_label
```

### 4.2 Behaviour

- **Startup**: `_company_list` populated from `db.get_companies()`. First company selected by default.
- **Select company**: Right panel fills with that company's data (editing mode).
- **Add**: Creates blank form, saves new company on "Save".
- **Delete**: Removes selected company from DB + list.
- **Save**: Calls `db.update_company(id, ...)` if existing, `db.insert_company(...)` if new.
- Domains/IP ranges: stored as JSON arrays, displayed comma-separated.
- No colour palette override — uses the global dark theme (this is the "New Client" screen which uses the dark cyberpunk theme, not the Lemon Chiffon palette).

---

## 5. CompanySelector widget (`screens/widgets/company_selector.py`)

A reusable QComboBox wrapper that:
- Loads companies from DB on init
- Emits `company_selected(dict)` signal when user picks a company
- Has a `refresh()` method to reload from DB

```python
class CompanySelector(QWidget):
    company_selected = pyqtSignal(dict)   # emits the full company dict

    def __init__(self, db: DB, parent=None): ...
    def refresh(self) -> None: ...        # reload from DB
    def current_company(self) -> dict | None: ...
```

---

## 6. Company selectors on existing screens

### ScanView (`screens/scan_view.py`)

Add `CompanySelector` above the target input. When a company is selected:
- `_target_input.setText(first_domain_from_company)`

(Domains are a JSON array — take the first element as the scan target.)

### OsintPage (`screens/osint_page.py`)

Add `CompanySelector` above domain input. On selection:
- `_domain_input.setText(first_domain)`

### CloudPage (`screens/cloud_page.py`)

Add `CompanySelector` above AWS/GCP inputs. On selection:
- `_aws_profile.setText(company["aws_profile"])`
- `_gcp_project.setText(company["gcp_project"])`

### InternalPage (`screens/internal_page.py`)

Add `CompanySelector` above subnet input. On selection:
- `_subnet_input.setText(first_ip_range_from_company)`

---

## 7. BatchScanWorker (`workers/batch_scan_worker.py`)

```python
class BatchScanWorker(QThread):
    company_started    = pyqtSignal(str, int)    # (company_name, company_index)
    finding_discovered = pyqtSignal(dict)
    tool_log           = pyqtSignal(str)
    company_complete   = pyqtSignal(str, int)    # (company_name, findings_count)
    batch_complete     = pyqtSignal(int, int)    # (companies_scanned, total_findings)
    error_occurred     = pyqtSignal(str, str)    # (company_name, error)

    def __init__(self, companies: list[dict], db: DB, parent=None): ...
    def stop(self) -> None: ...

    def run(self) -> None:
        for i, company in enumerate(companies):
            if self._stop.is_set(): break
            self.company_started.emit(company["name"], i)
            domain = _first_domain(company)
            if not domain:
                continue
            scan_id = self._db.insert_scan(Scan(..., client_id=company["id"], target=domain))
            findings = self._run_company_scan(domain, scan_id)
            self.company_complete.emit(company["name"], len(findings))

        self.batch_complete.emit(scanned, total)
```

`_run_company_scan(domain, scan_id)` calls tool wrappers directly:
- `subfinder.run(domain)` → hostnames
- `httpx.run(hosts)` → live URLs (with port)
- `nuclei.run(urls)` → findings
- Each finding written to DB immediately via `db.insert_finding()`
- Each finding emitted via `finding_discovered`

This is a lightweight pipeline — not the full 7-tool external pipeline, but the core discovery → scan chain (subfinder + httpx + nuclei). Full pipeline (dnsx, naabu, katana, nmap, nikto) can be added in Phase 9.

---

## 8. Batch scan trigger on ScanView

Add a "Scan All Companies" button to ScanView. It:
- Creates a `BatchScanWorker(companies=db.get_companies(), db=db)`
- Connects signals to existing widgets (finding_discovered → FindingCards, tool_log → terminal)
- Shows per-company progress in `_status_label`

---

## 9. Testing

### `tests/test_db_companies.py` (5 tests)

| Test | What it checks |
|------|---------------|
| `test_insert_and_get_company` | insert + get_companies returns it |
| `test_get_companies_ordered_by_name` | multiple companies returned alphabetically |
| `test_update_company` | update a field, get_companies reflects change |
| `test_delete_company` | delete, get_companies returns one fewer |
| `test_seed_companies_on_empty_db` | fresh DB has 9 seeded companies |

### `tests/test_batch_scan_worker.py` (4 tests)

| Test | What it checks |
|------|---------------|
| `test_company_started_emitted` | mock tool wrappers → `company_started` fires per company |
| `test_findings_written_to_db` | mock nuclei returning 1 finding → it's in DB |
| `test_companies_with_no_domain_skipped` | company with empty domains → no scan run |
| `test_batch_complete_fires` | mock all tools → `batch_complete` fires with totals |

### `tests/test_company_selector.py` (3 tests)

| Test | What it checks |
|------|---------------|
| `test_selector_populates_from_db` | 3 companies in DB → combo has 3 items |
| `test_signal_emitted_on_change` | change selection → `company_selected` emits with correct dict |
| `test_refresh_updates_items` | add company to DB, call `refresh()` → combo updates |

---

## 10. File map

| Action | Path |
|--------|------|
| Modify | `db.py` (companies table + CRUD + seeding) |
| Rewrite | `screens/client_onboarding.py` |
| Create | `screens/widgets/company_selector.py` |
| Modify | `screens/scan_view.py` (add CompanySelector) |
| Modify | `screens/osint_page.py` (add CompanySelector) |
| Modify | `screens/cloud_page.py` (add CompanySelector) |
| Modify | `screens/internal_page.py` (add CompanySelector) |
| Create | `workers/batch_scan_worker.py` |
| Create | `tests/test_db_companies.py` |
| Create | `tests/test_batch_scan_worker.py` |
| Create | `tests/test_company_selector.py` |

---

## 11. Constraints

- Batch scan is sequential only (FR-10 says "sequential or configurable parallel" — parallel is Phase 9)
- `companies` table is independent of `clients` table (clients = ad-hoc, companies = Fidelitus registry)
- Seeding only happens on empty DB — never overwrites user data
- CompanySelector is optional UI enhancement — all pages still work without it (db=None guard)
- BatchScanWorker runs a lightweight pipeline (subfinder + httpx + nuclei) — not the full 9-tool chain
