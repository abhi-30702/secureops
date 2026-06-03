# Phase 6 — AI Advisor Agent: Design Spec

**Date:** 2026-06-03
**Status:** Approved
**Author:** Abhishek K

---

## Overview

Phase 6 adds an opt-in AI Advisor to SecureOps. After a scan completes, the advisor reads the structured findings from the database, sends them to the Google Gemini API, and returns prioritized defensive recommendations grouped by urgency tier. The consultant reviews each recommendation individually, accepting or discarding it, and accepted items are included in the PDF export. All scanning and reporting works fully offline without this feature.

---

## 1. Architecture

A dedicated `advisor/` package mirrors the existing `scheduler/` and `report/` module pattern.

```
advisor/
  __init__.py
  gemini_client.py     ← raw Gemini API call (key + prompt → text)
  prompt_builder.py    ← builds structured prompt from scan DB data
  worker.py            ← QThread orchestrator; emits signals to Report screen
```

### Signals on `AdvisorWorker`

| Signal | Payload | Purpose |
|--------|---------|---------|
| `item_ready` | `AdvisoryItem` | Emitted per parsed recommendation as they arrive |
| `finished` | — | All items done |
| `error` | `str` | API/network/parse failure |

The worker queries the DB itself (given `scan_id` and `db`) so the Report screen only starts it and listens to signals — no data passed directly.

`google-generativeai` is added to `requirements.txt`. The import is guarded so the app starts normally if the package is absent.

---

## 2. Data Model

### New dataclass in `models.py`

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

### New DB table: `advisory_items`

Columns mirror the dataclass. Created in `db.py` alongside existing tables.

### New DB methods

| Method | Purpose |
|--------|---------|
| `insert_advisory_item(item) → int` | Persist a new item |
| `query_advisory_items_by_scan(scan_id) → list[AdvisoryItem]` | Load all items for a scan |
| `update_advisory_item_accepted(item_id, accepted: bool)` | Accept or discard an item |
| `delete_advisory_items_by_scan(scan_id)` | Clear items before re-running the advisor |

### App settings persistence

New `app_settings` key/value table in the existing SQLite DB. Two keys:
- `gemini_api_key` — the user's Gemini API key (stored locally, never logged)
- `ai_advisor_enabled` — `"1"` or `"0"`, default `"0"`

New DB methods: `get_setting(key) → str | None` and `set_setting(key, value)`.

---

## 3. UI

### 3.1 Settings screen

New "AI ADVISOR" section below the scheduled scans section:

- `QCheckBox` "Enable AI Advisor (Google Gemini)" — OFF by default; loads state from `app_settings` on init
- `QLineEdit` for API key in password mode; enabled only when checkbox is checked
- "Save" button — writes both values to `app_settings` in DB

### 3.2 Report screen

New `_build_advisor_panel()` called at the bottom of `load_scan()`.

**When advisor is disabled or no API key is saved:**
Renders a muted label: "AI Advisor disabled — enable in Settings."

**When advisor is enabled:**

1. Panel header "AI Advisor" with a "Run Advisor" button
2. On click:
   - Button changes to "Analyzing…" (disabled)
   - Status label shows progress
   - `AdvisorWorker` is launched with `scan_id` and `db`
3. As `item_ready` signals arrive, items are rendered under three sub-headers:
   - **Immediate** — act now
   - **Short-term** — within days
   - **Preventive** — ongoing hygiene
4. Each item is a card with:
   - Advisory text
   - `✓ Accept` button (green) → calls `update_advisory_item_accepted(id, True)`, card dims
   - `✗ Discard` button (red) → calls `update_advisory_item_accepted(id, False)`, card is hidden
5. Disclaimer always visible at the bottom: *"AI-generated — review before sending to client."*
6. On `error(str)`: error shown inline, "Run Advisor" re-enables for retry
7. Running the advisor again calls `delete_advisory_items_by_scan` first to clear previous results

---

## 4. Prompt Builder

`prompt_builder.py` constructs a single prompt from:
- `Scan.target`
- `Client.firewall` (to tailor remediation advice to known stack)
- All `Finding` records for the scan (severity, title, description, tool)
- All `Host` records (subdomains, IPs, ports, services)

Output format requested from Gemini is structured plain text with three labeled sections: `IMMEDIATE:`, `SHORT_TERM:`, `PREVENTIVE:`, each containing numbered items. `gemini_client.py` returns the raw text; `worker.py` parses it into `AdvisoryItem` instances before emitting `item_ready`.

The prompt explicitly instructs Gemini to produce only defensive precautions and remediation guidance — no exploitation steps.

If the response cannot be parsed into the three expected sections (e.g. Gemini returns free-form text), `worker.py` emits `error("Could not parse advisor response — try again")` rather than producing malformed items.

---

## 5. PDF Integration

`PdfGenerator.__init__` gains `advisory_items: list[AdvisoryItem] | None = None`.

When `advisory_items` contains accepted items (`accepted=True`), the PDF gains a section after findings:

- Section header: **AI Advisory**
- Italicised disclaimer: *"AI-generated content — reviewed and accepted by consultant."*
- Items grouped under: **Immediate Actions**, **Short-Term Actions**, **Preventive Measures**
- Each item is a bullet point in the existing corporate PDF style

`ReportScreen.export_pdf()` queries `db.query_advisory_items_by_scan(scan_id)`, filters to `accepted=True`, and passes the list to `PdfGenerator`. If no accepted items exist, the section is omitted and the PDF is identical to today.

---

## 6. Safeguards and Error Handling

| Concern | Handling |
|---------|----------|
| Network / API failure | `GeminiClient` wraps call in `try/except`; emits `error(str)` on worker |
| Missing API key on "Run Advisor" | Inline message in Report screen; worker not launched |
| `google-generativeai` not installed | Guarded import; advisor panel shows install prompt |
| Navigation away mid-analysis | `AdvisorWorker` checks `_cancelled` flag before and after API call |
| Advisor disabled / unavailable | Report screen, PDF export, and all scan data work fully without it |
| Offensive output risk | Prompt explicitly restricts Gemini to defensive/remediation scope only |

---

## 7. Files Changed or Created

| File | Change |
|------|--------|
| `advisor/__init__.py` | New (empty) |
| `advisor/gemini_client.py` | New |
| `advisor/prompt_builder.py` | New |
| `advisor/worker.py` | New |
| `models.py` | Add `AdvisoryItem` dataclass |
| `db.py` | Add `advisory_items` table, `app_settings` table, new CRUD methods |
| `screens/settings.py` | Add AI Advisor section (toggle + API key + save) |
| `screens/report.py` | Add `_build_advisor_panel()`, update `export_pdf()` |
| `report/pdf_generator.py` | Add optional `advisory_items` parameter and PDF section |
| `requirements.txt` | Add `google-generativeai` |
| `tests/test_advisor_*.py` | New test files per module |

---

## 8. Out of Scope for Phase 6

- Ollama or any other local-LLM backend (deferred)
- Per-finding inline guidance cards (summary tier output only)
- ISO 27001 mapping in the AI output (already in the PDF from Phase 4)
- Redaction of client-identifying details before sending (deferred)
