# Phase 4 — Final Report + Professional PDF Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Replace the `ReportScreen` placeholder with a live in-app report view, add a `PdfGenerator` that exports a professional PDF using ReportLab, wire `ScanViewScreen → MainWindow → ReportScreen` so the report auto-loads when a scan completes, and add a `scan_ready` signal to `ScanViewScreen`.

**Architecture:** `PdfGenerator` is a pure-Python class (no Qt dependency). `ReportScreen` loads from DB on `load_scan(scan_id)`. `ScanViewScreen` emits `scan_ready(int)` on completion. `MainWindow` auto-navigates to Report.

**Tech Stack:** ReportLab 4.5.1 (already installed), PyQt6, SQLite via existing `DB` class.

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `report/__init__.py` | Create | Empty package marker |
| `report/pdf_generator.py` | Create | `PdfGenerator` — ReportLab PDF, all sections |
| `tests/test_report_pdf.py` | Create | PDF generation tests (no Qt needed) |
| `screens/report.py` | Rewrite | `ReportScreen` — live scrollable report view |
| `tests/test_screen_report.py` | Rewrite | ReportScreen tests |
| `screens/scan_view.py` | Modify | Add `scan_ready = pyqtSignal(int)` |
| `tests/test_screen_scan_view.py` | Modify | 1 new test: scan_ready attribute |
| `main_window.py` | Modify | Wire signal, pass db to ReportScreen, auto-navigate |
| `tests/test_main_window.py` | Modify | 1 new test: ReportScreen has db |

---

## Task 1: PdfGenerator

**Files:**
- Create: `report/__init__.py`
- Create: `report/pdf_generator.py`
- Create: `tests/test_report_pdf.py`

- [ ] **Step 1: Create `report/__init__.py`**

Empty file.

- [ ] **Step 2: Write failing tests**

Create `tests/test_report_pdf.py`:

```python
import os
import tempfile
from models import Scan, Host, Finding
from report.pdf_generator import PdfGenerator


def _scan() -> Scan:
    return Scan(id=1, client_id=None, target="example.com",
                status="complete", started_at="2026-06-03T10:00:00",
                finished_at="2026-06-03T10:04:00")


def _host() -> Host:
    return Host(id=1, scan_id=1, subdomain="api.example.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")


def _finding(severity: str = "high", tool: str = "nuclei",
             title: str = "Test Finding") -> Finding:
    return Finding(id=1, scan_id=1, host_id=1, tool=tool, severity=severity,
                   title=title, description="A test finding description.",
                   raw_json="{}", created_at="2026-06-03T10:02:00")


def test_pdf_generates_file(tmp_path):
    path = str(tmp_path / "report.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[_host()], findings=[_finding()],
                       output_path=path)
    result = gen.generate()
    assert result == path
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_pdf_with_no_findings(tmp_path):
    path = str(tmp_path / "empty.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path=path)
    gen.generate()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 500


def test_pdf_with_all_severities(tmp_path):
    path = str(tmp_path / "all_sev.pdf")
    findings = [
        _finding("critical", "nuclei", "Critical issue"),
        _finding("high", "nmap", "High issue"),
        _finding("medium", "nikto", "Medium issue"),
        _finding("low", "testssl", "Low issue"),
        _finding("info", "httpx", "Info item"),
    ]
    gen = PdfGenerator(scan=_scan(), hosts=[_host()], findings=findings,
                       output_path=path)
    gen.generate()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_pdf_risk_rating_critical(tmp_path):
    path = str(tmp_path / "critical.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[_finding("critical")],
                       output_path=path)
    assert gen._risk_rating() == "CRITICAL"


def test_pdf_risk_rating_passed(tmp_path):
    path = str(tmp_path / "passed.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path=path)
    assert gen._risk_rating() == "PASSED"


def test_pdf_risk_rating_high(tmp_path):
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[_finding("high")],
                       output_path="/dev/null")
    assert gen._risk_rating() == "HIGH"


def test_pdf_iso_mapping_testssl(tmp_path):
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path="/dev/null")
    ctrl, _ = gen._iso_control("testssl")
    assert ctrl == "A.10.1"


def test_pdf_iso_mapping_default(tmp_path):
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path="/dev/null")
    ctrl, _ = gen._iso_control("unknown_tool")
    assert ctrl == "A.12.6"
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_report_pdf.py -v
```
Expected: `ModuleNotFoundError: No module named 'report'`

- [ ] **Step 4: Write `report/pdf_generator.py`**

```python
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from models import Scan, Host, Finding, Client

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#ff4444"),
    "high":     colors.HexColor("#ff8800"),
    "medium":   colors.HexColor("#ffcc00"),
    "low":      colors.HexColor("#4488ff"),
    "info":     colors.HexColor("#64748b"),
}

_RISK_COLORS = {
    "CRITICAL": colors.HexColor("#ff4444"),
    "HIGH":     colors.HexColor("#ff8800"),
    "MEDIUM":   colors.HexColor("#ffcc00"),
    "LOW":      colors.HexColor("#4488ff"),
    "PASSED":   colors.HexColor("#00c853"),
}

_ISO_MAP = {
    "testssl":   ("A.10.1", "Cryptographic controls"),
    "nikto":     ("A.14.2", "Security in development processes"),
    "nuclei":    ("A.12.6", "Technical vulnerability management"),
    "nmap":      ("A.13.1", "Network security management"),
    "httpx":     ("A.13.1", "Network security management"),
    "katana":    ("A.14.2", "Security in development processes"),
    "subfinder": ("A.13.1", "Network security management"),
    "dnsx":      ("A.13.1", "Network security management"),
    "naabu":     ("A.13.1", "Network security management"),
}

_REMEDIATION = {
    "critical": "Remediate immediately. This finding represents a critical risk to the assessed environment.",
    "high":     "Remediate within 30 days. This finding represents a significant risk.",
    "medium":   "Remediate within 90 days. Review and apply available patches or hardening guidance.",
    "low":      "Review and address as part of routine maintenance cycles.",
    "info":     "Informational — no immediate action required.",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class PdfGenerator:
    def __init__(
        self,
        scan: Scan,
        hosts: list,
        findings: list,
        client=None,
        output_path: str = "report.pdf",
    ):
        self._scan = scan
        self._hosts = hosts
        self._findings = findings
        self._client = client
        self._output_path = output_path
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self._h1 = ParagraphStyle(
            "H1", parent=self._styles["Heading1"],
            fontSize=22, textColor=colors.HexColor("#1e293b"),
            spaceAfter=8,
        )
        self._h2 = ParagraphStyle(
            "H2", parent=self._styles["Heading2"],
            fontSize=16, textColor=colors.HexColor("#1e293b"),
            spaceBefore=16, spaceAfter=6,
        )
        self._h3 = ParagraphStyle(
            "H3", parent=self._styles["Heading3"],
            fontSize=13, textColor=colors.HexColor("#334155"),
            spaceBefore=10, spaceAfter=4,
        )
        self._body = ParagraphStyle(
            "Body", parent=self._styles["Normal"],
            fontSize=10, textColor=colors.HexColor("#334155"),
            spaceAfter=4, leading=14,
        )
        self._muted = ParagraphStyle(
            "Muted", parent=self._styles["Normal"],
            fontSize=9, textColor=colors.HexColor("#64748b"),
            spaceAfter=3,
        )
        self._cover_title = ParagraphStyle(
            "CoverTitle",
            fontSize=28, textColor=colors.HexColor("#1e293b"),
            alignment=TA_CENTER, spaceAfter=8, fontName="Helvetica-Bold",
        )
        self._cover_sub = ParagraphStyle(
            "CoverSub",
            fontSize=14, textColor=colors.HexColor("#64748b"),
            alignment=TA_CENTER, spaceAfter=6,
        )

    def generate(self) -> str:
        doc = SimpleDocTemplate(
            self._output_path,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
            title=f"Security Assessment Report — {self._scan.target}",
            author="SecureOps",
        )
        story = []
        story += self._cover_page()
        story.append(PageBreak())
        story += self._executive_summary()
        story.append(PageBreak())
        story += self._severity_breakdown()
        story += self._findings_section()
        story.append(PageBreak())
        story += self._iso_section()
        story += self._host_appendix()
        doc.build(story, onFirstPage=self._page_header, onLaterPages=self._page_header)
        return self._output_path

    def _page_header(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(2*cm, 1.2*cm, "SecureOps — Confidential")
        canvas.drawRightString(A4[0] - 2*cm, 1.2*cm, f"Page {doc.page}")
        canvas.restoreState()

    def _cover_page(self) -> list:
        rating = self._risk_rating()
        rating_color = _RISK_COLORS.get(rating, colors.grey)
        story = [
            Spacer(1, 3*cm),
            Paragraph("SecureOps", self._cover_sub),
            Paragraph("Security Assessment Report", self._cover_title),
            Spacer(1, 1*cm),
        ]
        target_name = (self._client.name if self._client else None) or self._scan.target
        story += [
            Paragraph(f"Target: {target_name}", self._cover_sub),
            Paragraph(f"Domain: {self._scan.target}", self._cover_sub),
            Paragraph(f"Scan Date: {self._scan.started_at[:10]}", self._cover_sub),
            Spacer(1, 1.5*cm),
        ]
        badge_data = [[Paragraph(f"OVERALL RISK: {rating}", ParagraphStyle(
            "Badge", fontSize=14, textColor=colors.white,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        ))]]
        badge = Table(badge_data, colWidths=[10*cm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), rating_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        story.append(Table([[badge]], colWidths=[A4[0] - 4*cm]))
        story[-1].setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
        return story

    def _executive_summary(self) -> list:
        story = [Paragraph("Executive Summary", self._h1)]
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))

        counts = self._severity_counts()
        total = sum(counts.values())
        duration = self._scan_duration()

        rows = [
            ["Target", self._scan.target],
            ["Scan Date", self._scan.started_at[:10]],
            ["Scan Duration", duration],
            ["Status", self._scan.status.capitalize()],
            ["Hosts Discovered", str(len(self._hosts))],
            ["Total Findings", str(total)],
            ["Critical", str(counts.get("critical", 0))],
            ["High", str(counts.get("high", 0))],
            ["Medium", str(counts.get("medium", 0))],
            ["Low", str(counts.get("low", 0))],
            ["Info", str(counts.get("info", 0))],
        ]
        t = Table(rows, colWidths=[5*cm, 11*cm])
        t.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#334155")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ]))
        story.append(Spacer(1, 0.4*cm))
        story.append(t)
        return story

    def _severity_breakdown(self) -> list:
        story = [Paragraph("Risk Breakdown", self._h2)]
        counts = self._severity_counts()
        rows = [["Severity", "Count", "Action"]]
        row_colors = []
        for sev in _SEVERITY_ORDER:
            n = counts.get(sev, 0)
            rows.append([sev.upper(), str(n), _REMEDIATION.get(sev, "").split(".")[0]])
            row_colors.append(_SEVERITY_COLORS.get(sev, colors.grey))

        t = Table(rows, colWidths=[3*cm, 2*cm, 11*cm])
        style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ]
        for i, sev in enumerate(_SEVERITY_ORDER):
            style.append(("TEXTCOLOR", (0, i+1), (0, i+1), row_colors[i]))
            style.append(("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))
        return story

    def _findings_section(self) -> list:
        story = [Paragraph("Findings", self._h1)]
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))

        by_severity: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in self._findings:
            sev = f.severity if f.severity in by_severity else "info"
            by_severity[sev].append(f)

        for sev in _SEVERITY_ORDER:
            findings = by_severity[sev]
            if not findings:
                continue
            sev_color = _SEVERITY_COLORS.get(sev, colors.grey)
            story.append(Paragraph(sev.upper(), ParagraphStyle(
                f"SevHead_{sev}", fontSize=12, textColor=sev_color,
                fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4,
            )))
            story.append(HRFlowable(width="100%", thickness=1, color=sev_color))
            for f in findings:
                story.append(Paragraph(f.title, self._h3))
                story.append(Paragraph(f"Tool: {f.tool}", self._muted))
                if f.description:
                    story.append(Paragraph(f.description, self._body))
                action = _REMEDIATION.get(sev, "")
                story.append(Paragraph(f"Recommended Action: {action}", self._muted))
                story.append(Spacer(1, 0.3*cm))

        if not self._findings:
            story.append(Paragraph("No findings recorded for this scan.", self._body))
        return story

    def _iso_section(self) -> list:
        story = [Paragraph("ISO 27001 Control Gap Analysis", self._h1)]
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))

        seen: dict[str, tuple] = {}
        for f in self._findings:
            ctrl, title = self._iso_control(f.tool)
            if ctrl not in seen:
                seen[ctrl] = (ctrl, title, f.tool)

        if seen:
            rows = [["ISO Control", "Title", "Source Tool"]]
            for ctrl, (ctrl_id, ctrl_title, tool) in sorted(seen.items()):
                rows.append([ctrl_id, ctrl_title, tool])
            t = Table(rows, colWidths=[3*cm, 9*cm, 4*cm])
            t.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No findings to map.", self._body))

        story.append(Spacer(1, 0.5*cm))
        return story

    def _host_appendix(self) -> list:
        story = [PageBreak(), Paragraph("Appendix: Host Inventory", self._h1)]
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
        story.append(Spacer(1, 0.3*cm))

        if self._hosts:
            rows = [["Subdomain", "IP", "Port", "Service", "Tool"]]
            for h in self._hosts:
                rows.append([
                    h.subdomain or "—",
                    h.ip or "—",
                    str(h.port) if h.port else "—",
                    h.service or "—",
                    h.source_tool,
                ])
            t = Table(rows, colWidths=[5*cm, 3.5*cm, 2*cm, 2.5*cm, 3*cm])
            t.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No hosts discovered.", self._body))
        return story

    def _risk_rating(self) -> str:
        severities = {f.severity for f in self._findings}
        for sev in ("critical", "high", "medium", "low"):
            if sev in severities:
                return sev.upper()
        return "PASSED"

    def _iso_control(self, tool: str) -> tuple[str, str]:
        return _ISO_MAP.get(tool, ("A.12.6", "Technical vulnerability management"))

    def _severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def _scan_duration(self) -> str:
        if not self._scan.finished_at or not self._scan.started_at:
            return "—"
        try:
            from datetime import datetime
            fmt = "%Y-%m-%dT%H:%M:%S"
            start = datetime.fromisoformat(self._scan.started_at[:19])
            end = datetime.fromisoformat(self._scan.finished_at[:19])
            delta = int((end - start).total_seconds())
            m, s = divmod(delta, 60)
            return f"{m}m {s}s"
        except Exception:
            return "—"
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_report_pdf.py -v
```
Expected: all 8 tests PASS.

- [ ] **Step 6: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 7: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add report/__init__.py report/pdf_generator.py tests/test_report_pdf.py
git commit -m "feat: PdfGenerator — ReportLab PDF export with all sections

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: ReportScreen

**Files:**
- Rewrite: `screens/report.py`
- Rewrite: `tests/test_screen_report.py`

- [ ] **Step 1: Write failing tests**

Rewrite `tests/test_screen_report.py`:

```python
from db import DB
from models import Client, Scan, Host, Finding
from screens.report import ReportScreen


def _make_db() -> DB:
    db = DB(":memory:")
    client = Client(id=None, name="Acme Corp", domain="acme.com",
                    firewall="none", notes="", created_at="2026-06-03T00:00:00")
    db.insert_client(client)
    scan = Scan(id=None, client_id=1, target="acme.com", status="complete",
                started_at="2026-06-03T10:00:00", finished_at="2026-06-03T10:04:00")
    scan_id = db.insert_scan(scan)
    host = Host(id=None, scan_id=scan_id, subdomain="api.acme.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")
    db.insert_host(host)
    finding = Finding(id=None, scan_id=scan_id, host_id=1, tool="nuclei",
                      severity="high", title="XSS Detected", description="desc",
                      raw_json="{}", created_at="2026-06-03T10:02:00")
    db.insert_finding(finding)
    return db, scan_id


def test_report_has_export_button(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._export_btn is not None


def test_report_export_button_disabled_by_default(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert not screen._export_btn.isEnabled()


def test_report_load_scan_enables_export(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._export_btn.isEnabled()


def test_report_load_scan_populates_summary(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    assert screen._scan_id == scan_id


def test_report_reset_disables_export(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert not screen._export_btn.isEnabled()


def test_report_reset_clears_scan_id(qtbot):
    db, scan_id = _make_db()
    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)
    screen.reset()
    assert screen._scan_id is None


def test_report_has_scroll_area(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._scroll is not None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_report.py -v
```
Expected: failures since `ReportScreen` still has old interface.

- [ ] **Step 3: Rewrite `screens/report.py`**

```python
import os
from datetime import datetime
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QFileDialog, QMessageBox,
)
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtCore import QUrl


_SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#4488ff",
    "info":     "#64748b",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReportScreen(QWidget):
    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self._db = db
        self._scan_id: int | None = None
        self._export_btn: QPushButton | None = None
        self._scroll: QScrollArea | None = None
        self._content: QWidget | None = None
        self._content_layout: QVBoxLayout | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        top_bar = QHBoxLayout()
        title = QLabel("Security Report")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        self._export_btn = QPushButton("Export PDF")
        self._export_btn.setEnabled(False)
        self._export_btn.setFixedWidth(130)
        self._export_btn.clicked.connect(self.export_pdf)
        top_bar.addWidget(title)
        top_bar.addStretch()
        top_bar.addWidget(self._export_btn)
        layout.addLayout(top_bar)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._content = QWidget()
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 0, 0)
        self._content_layout.setSpacing(12)
        self._scroll.setWidget(self._content)
        layout.addWidget(self._scroll, stretch=1)

        self._show_placeholder()

    def _show_placeholder(self):
        self._clear_content()
        ph = QLabel("Run a scan to generate a report.")
        ph.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ph.setStyleSheet("color: #64748b; font-size: 14px;")
        self._content_layout.addStretch()
        self._content_layout.addWidget(ph)
        self._content_layout.addStretch()

    def _clear_content(self):
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def load_scan(self, scan_id: int):
        if not self._db:
            return
        self._scan_id = scan_id
        scan = next(
            (s for s in self._db.query_scans_by_client(None)
             if s.id == scan_id), None
        ) or next(
            (s for cl in self._db.query_clients()
             for s in self._db.query_scans_by_client(cl.id)
             if s.id == scan_id), None
        )
        if not scan:
            return
        hosts = self._db.query_hosts_by_scan(scan_id)
        findings = self._db.query_findings_by_scan(scan_id)

        self._clear_content()
        self._content_layout.addWidget(self._build_summary(scan, hosts, findings))
        self._content_layout.addWidget(self._build_severity_panel(findings))
        self._content_layout.addWidget(self._build_findings_panel(findings))
        self._content_layout.addStretch()
        self._export_btn.setEnabled(True)

    def _build_summary(self, scan, hosts, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        header = QLabel("Summary")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(header)

        duration = "—"
        if scan.finished_at:
            try:
                start = datetime.fromisoformat(scan.started_at[:19])
                end = datetime.fromisoformat(scan.finished_at[:19])
                delta = int((end - start).total_seconds())
                m, s = divmod(delta, 60)
                duration = f"{m}m {s}s"
            except Exception:
                pass

        for label, value in [
            ("Target", scan.target),
            ("Date", scan.started_at[:10]),
            ("Status", scan.status.capitalize()),
            ("Duration", duration),
            ("Hosts discovered", str(len(hosts))),
            ("Total findings", str(len(findings))),
        ]:
            row = QLabel(f"<b>{label}:</b>  {value}")
            row.setStyleSheet("color: #cbd5e1; font-size: 11px;")
            layout.addWidget(row)

        return panel

    def _build_severity_panel(self, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(6)

        header = QLabel("Severity Breakdown")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(header)

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(16)
        for sev in _SEVERITY_ORDER:
            n = counts.get(sev, 0)
            color = _SEVERITY_COLORS.get(sev, "#64748b")
            lbl = QLabel(f'<span style="color:{color}">●</span> {sev.capitalize()}: <b>{n}</b>')
            lbl.setStyleSheet("color: #cbd5e1; font-size: 11px;")
            row_layout.addWidget(lbl)
        row_layout.addStretch()
        layout.addWidget(row_widget)
        return panel

    def _build_findings_panel(self, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Findings")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(header)

        by_sev: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "info"
            by_sev[sev].append(f)

        if not findings:
            lbl = QLabel("No findings recorded.")
            lbl.setStyleSheet("color: #64748b; font-size: 11px;")
            layout.addWidget(lbl)
            return panel

        for sev in _SEVERITY_ORDER:
            if not by_sev[sev]:
                continue
            color = _SEVERITY_COLORS.get(sev, "#64748b")
            sev_label = QLabel(f'<span style="color:{color}; font-weight:bold;">{sev.upper()} ({len(by_sev[sev])})</span>')
            sev_label.setStyleSheet("font-size: 12px;")
            layout.addWidget(sev_label)
            for f in by_sev[sev]:
                card = QFrame()
                card.setStyleSheet(
                    f"QFrame {{ border-left: 3px solid {color}; "
                    f"background-color: #0f172a; border-radius: 3px; }}"
                )
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(10, 6, 10, 6)
                card_layout.setSpacing(2)
                title_lbl = QLabel(f.title)
                title_lbl.setStyleSheet("color: #e2e8f0; font-size: 12px; font-weight: bold;")
                tool_lbl = QLabel(f"Tool: {f.tool}")
                tool_lbl.setStyleSheet("color: #64748b; font-size: 10px;")
                card_layout.addWidget(title_lbl)
                card_layout.addWidget(tool_lbl)
                if f.description:
                    desc_lbl = QLabel(f.description[:200])
                    desc_lbl.setWordWrap(True)
                    desc_lbl.setStyleSheet("color: #94a3b8; font-size: 10px;")
                    card_layout.addWidget(desc_lbl)
                layout.addWidget(card)

        return panel

    def export_pdf(self):
        if not self._db or self._scan_id is None:
            return
        scan = next(
            (s for s in self._db.query_scans_by_client(None)
             if s.id == self._scan_id), None
        ) or next(
            (s for cl in self._db.query_clients()
             for s in self._db.query_scans_by_client(cl.id)
             if s.id == self._scan_id), None
        )
        if not scan:
            return
        hosts = self._db.query_hosts_by_scan(self._scan_id)
        findings = self._db.query_findings_by_scan(self._scan_id)

        default_name = f"SecureOps_Report_{scan.target}_{scan.started_at[:10]}.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", default_name, "PDF Files (*.pdf)"
        )
        if not path:
            return

        try:
            from report.pdf_generator import PdfGenerator
            gen = PdfGenerator(scan=scan, hosts=hosts, findings=findings,
                               output_path=path)
            gen.generate()
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def reset(self):
        self._scan_id = None
        self._export_btn.setEnabled(False)
        self._show_placeholder()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_report.py -v
```
Expected: all 7 tests PASS.

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/report.py tests/test_screen_report.py
git commit -m "feat: ReportScreen — live scrollable report view with PDF export

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: scan_ready signal + MainWindow wiring

**Files:**
- Modify: `screens/scan_view.py`
- Modify: `main_window.py`
- Modify: `tests/test_screen_scan_view.py` (append 1 test)
- Modify: `tests/test_main_window.py` (append 1 test)

- [ ] **Step 1: Append failing tests**

Append to `tests/test_screen_scan_view.py`:
```python
def test_scan_view_has_scan_ready_signal(qtbot):
    from PyQt6.QtCore import pyqtSignal
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert hasattr(screen, "scan_ready")
```

Read `tests/test_main_window.py`, then append:
```python
def test_main_window_report_screen_has_db(qtbot):
    from screens.report import ReportScreen
    db = _make_db()
    win = MainWindow(tool_results={}, db=db)
    qtbot.addWidget(win)
    report = win._stack.widget(3)
    assert isinstance(report, ReportScreen)
    assert report._db is db
```

- [ ] **Step 2: Run new tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py::test_scan_view_has_scan_ready_signal tests/test_main_window.py::test_main_window_report_screen_has_db -v
```

- [ ] **Step 3: Add `scan_ready` signal to `screens/scan_view.py`**

Read the file first. Then:

1. Add `pyqtSignal` to the existing `PyQt6.QtCore` import.
2. Add `scan_ready = pyqtSignal(int)` as a class attribute of `ScanViewScreen` (before `__init__`).
3. In `_on_scan_complete`, after setting the button text, add:
   ```python
   if self._scan_id is not None:
       self.scan_ready.emit(self._scan_id)
   ```

- [ ] **Step 4: Update `main_window.py`**

Read the file first. Then:

1. Update `ReportScreen()` construction to `ReportScreen(db=self._db)`.
2. Keep a reference to `ScanViewScreen`: store it as `self._scan_view`.
3. Keep a reference to `ReportScreen`: store it as `self._report`.
4. Wire the signal after adding widgets to stack:
   ```python
   self._scan_view.scan_ready.connect(self._on_scan_ready)
   ```
5. Add `_on_scan_ready` method:
   ```python
   def _on_scan_ready(self, scan_id: int):
       self._report.load_scan(scan_id)
       self._stack.setCurrentIndex(3)
   ```

- [ ] **Step 5: Run all modified tests**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py tests/test_main_window.py -v
```
All must pass.

- [ ] **Step 6: Run full suite**

```bash
source venv/bin/activate && pytest --tb=short
```
All must pass.

- [ ] **Step 7: Commit**

```bash
git config user.email "abhi30702@gmail.com"
git add screens/scan_view.py main_window.py tests/test_screen_scan_view.py tests/test_main_window.py
git commit -m "feat: scan_ready signal, MainWindow auto-navigates to Report on scan complete

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Notes

**Spec coverage:**
- FR-13: PDF export enabled on scan complete (scan_ready → ReportScreen) ✓
- FR-14: Professional PDF via ReportLab, light corporate theme ✓
- FR-15: Executive summary, risk rating, findings by severity, ISO 27001 map, host appendix ✓
- FR-16: Self-contained PDF suitable for client distribution ✓

**Architecture:**
- PdfGenerator: pure Python, no Qt dependency, testable without display ✓
- ReportScreen: loads from DB on demand, no coupling to ScanWorker ✓
- `scan_ready` signal: clean decoupling — ScanViewScreen doesn't know about ReportScreen ✓
- MainWindow wires the signal: single point of integration ✓
