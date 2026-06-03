# Phase 4 — Final Report + Professional PDF Export Design

**Date:** 2026-06-03  
**Status:** Approved  
**Phase:** 4 of 7

---

## Overview

Phase 4 replaces the `ReportScreen` placeholder with a live, scrollable in-app report that populates from the DB when a scan completes, and adds a `PdfGenerator` that exports a professional, client-ready PDF in a light corporate theme.

**Deliverables:**
- `report/` package — `PdfGenerator` class (ReportLab)
- `ReportScreen` — live scrollable report view, populated from DB
- `ScanViewScreen` gains `scan_ready = pyqtSignal(int)` — emits `scan_id` on completion
- `MainWindow` wires `scan_ready` → `report_screen.load_scan()` + auto-navigates to Report

No changes to the scan engine, DB schema, or widget layer.

---

## 1. File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `report/__init__.py` | Create | Empty package marker |
| `report/pdf_generator.py` | Create | `PdfGenerator` class — ReportLab PDF |
| `screens/report.py` | Rewrite | Live `ReportScreen` — in-app report view |
| `screens/scan_view.py` | Modify | Add `scan_ready = pyqtSignal(int)` signal |
| `main_window.py` | Modify | Wire signal, pass db to ReportScreen, auto-navigate |
| `tests/test_report_pdf.py` | Create | PDF generation tests |
| `tests/test_screen_report.py` | Rewrite | Live report screen tests |
| `tests/test_screen_scan_view.py` | Modify | 1 new test: scan_ready signal exists |
| `tests/test_main_window.py` | Modify | 1 new test: ReportScreen gets db |

---

## 2. PDF Structure

**Theme:** Light corporate. White background, `#1e293b` dark headings, severity colour badges, clean sans-serif typography.

**Sections:**

| # | Section | Content |
|---|---------|---------|
| 1 | Cover page | App name, "Security Assessment Report", target domain, scan date, risk rating badge (colour-coded) |
| 2 | Executive Summary | Scan overview, total hosts, findings by severity, overall risk rating, scan duration |
| 3 | Risk Breakdown | Severity count table (Critical / High / Medium / Low / Info) with coloured rows |
| 4 | Findings by Severity | Critical → High → Medium → Low → Info. Each finding: title, tool, description, recommended action |
| 5 | ISO 27001 Control Gap | Table mapping unique finding tools/types to ISO 27001 Annex A controls |
| 6 | Appendix: Host Inventory | Table of all discovered hosts (subdomain, IP, port, service, source tool) |

**Risk Rating algorithm:**
- Any `critical` finding → **CRITICAL** (red)
- Any `high` finding → **HIGH** (orange)
- Any `medium` finding → **MEDIUM** (yellow)
- Only `low`/`info` → **LOW** (blue)
- Zero findings → **PASSED** (green)

**ISO 27001 mapping (by source tool):**

| Tool | ISO Control | Title |
|------|-------------|-------|
| testssl | A.10.1 | Cryptographic controls |
| nikto | A.14.2 | Security in development processes |
| nuclei | A.12.6 | Technical vulnerability management |
| nmap | A.13.1 | Network security management |
| httpx | A.13.1 | Network security management |
| katana | A.14.2 | Security in development processes |
| subfinder / dnsx / naabu | A.13.1 | Network security management |
| (default) | A.12.6 | Technical vulnerability management |

**Recommended actions (generic, by severity):**
- `critical` → "Remediate immediately. This finding represents a critical risk to the assessed environment."
- `high` → "Remediate within 30 days. This finding represents a significant risk."
- `medium` → "Remediate within 90 days. Review and apply available patches or hardening guidance."
- `low` → "Review and address as part of routine maintenance cycles."
- `info` → "Informational — no immediate action required."

---

## 3. PdfGenerator

### Class signature

```python
class PdfGenerator:
    def __init__(
        self,
        scan: Scan,
        hosts: list[Host],
        findings: list[Finding],
        client: Client | None = None,
        output_path: str = "report.pdf",
    ): ...

    def generate(self) -> str:
        """Generates the PDF and returns the absolute path written."""
```

### ReportLab approach

Use `reportlab.platypus` (`SimpleDocTemplate`, `Table`, `Paragraph`, `Spacer`, `PageBreak`) with a `StyleSheet` for consistent typography.

- A4 page size, 2cm margins
- Header/footer on each page via `PageTemplate` with `onPage` callback: app name left, page number right
- Cover page: centred layout, risk badge drawn with `reportlab.graphics` `Drawing` + `Rect`
- Severity bar in findings: coloured `Paragraph` with background set via `TableStyle`

### Pure-Python, no Qt dependency

`PdfGenerator` takes plain Python dataclasses (from `models.py`) and writes a file. No PyQt6 imports. This makes it testable without a display.

---

## 4. ReportScreen

### Layout

```
[Title: Security Report ─────────────────] [Export PDF]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QScrollArea
  ┌─ Summary panel ──────────────────────────────────┐
  │  Target: example.com  ·  Date: 2026-06-03        │
  │  Status: Complete  ·  Duration: 4m 12s           │
  │  Hosts: 23  ·  Findings: 47                      │
  └──────────────────────────────────────────────────┘
  ┌─ Severity breakdown ─────────────────────────────┐
  │  ● Critical: 2  ● High: 8  ● Medium: 15  ● Low: 22│
  └──────────────────────────────────────────────────┘
  ┌─ Findings ───────────────────────────────────────┐
  │  [CRITICAL] Finding title (tool)                 │
  │             description text                     │
  │  [HIGH] ...                                      │
  └──────────────────────────────────────────────────┘
```

### Attribute types

```python
self._export_btn: QPushButton
self._scroll: QScrollArea
self._summary_panel: QFrame
self._severity_panel: QFrame
self._findings_panel: QFrame
self._db: DB | None
self._scan_id: int | None
```

### Public interface

```python
def load_scan(self, scan_id: int) -> None:
    """Loads scan data from DB and populates all panels. Enables export button."""

def export_pdf(self) -> None:
    """Opens QFileDialog, generates PDF via PdfGenerator, shows success/error."""

def reset(self) -> None:
    """Clears all panels back to placeholder state. Disables export button."""
```

### Export flow

1. User clicks "Export PDF"
2. `QFileDialog.getSaveFileName(...)` → user picks path (default: `SecureOps_Report_<target>_<date>.pdf`)
3. `PdfGenerator(scan, hosts, findings, client, path).generate()` called in-thread (PDF generation is fast — under 1s — so no QThread needed for Phase 4)
4. Success: status message + offer to open folder (via `QDesktopServices.openUrl`)
5. Error: `QMessageBox.critical(...)`

---

## 5. ScanViewScreen Changes

Add one signal and emit it from `_on_scan_complete`:

```python
from PyQt6.QtCore import pyqtSignal

class ScanViewScreen(QWidget):
    scan_ready = pyqtSignal(int)   # emits scan_id when scan completes successfully
    ...

    def _on_scan_complete(self, hosts: int, findings: int):
        self._status_label.setText(f"Complete — {hosts} hosts, {findings} findings")
        self._start_btn.setEnabled(True)
        self._start_btn.setText("▶  Start Scan")
        if self._worker:
            self._worker.deleteLater()
            self._worker = None
        if self._scan_id is not None:
            self.scan_ready.emit(self._scan_id)
```

---

## 6. MainWindow Changes

```python
self._scan_view  = ScanViewScreen(db=self._db)       # keep reference
self._report     = ReportScreen(db=self._db)         # pass db

# In _setup_ui():
self._scan_view.scan_ready.connect(self._on_scan_ready)

def _on_scan_ready(self, scan_id: int):
    self._report.load_scan(scan_id)
    self._stack.setCurrentIndex(3)   # navigate to Report
```

---

## 7. Testing

| File | Coverage |
|------|----------|
| `tests/test_report_pdf.py` | PDF file created, non-empty, no exception on empty findings, covers all severity levels |
| `tests/test_screen_report.py` | load_scan populates panels, export button enabled after load, reset disables button |
| `tests/test_screen_scan_view.py` | `scan_ready` signal attribute exists |
| `tests/test_main_window.py` | ReportScreen in stack gets db kwarg |

PDF rendering not tested visually — tests confirm file creation and exception-free generation.

---

## 8. PRD Requirements Covered

| ID | Requirement | Where |
|----|-------------|-------|
| FR-13 | On completion, enable PDF export | ScanViewScreen.scan_ready + ReportScreen |
| FR-14 | Professional PDF, light corporate theme | PdfGenerator |
| FR-15 | Executive summary, risk rating, findings, ISO 27001 map, charts | PdfGenerator sections |
| FR-16 | Self-contained, client-ready | PdfGenerator (standalone file) |
