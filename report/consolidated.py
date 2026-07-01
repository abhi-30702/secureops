"""Consolidated multi-company reporting (Phase 7).

Builds a group-level report across several companies:
  * a group executive summary with per-company risk ratings,
  * a cross-company correlation table (weaknesses shared by 2+ subsidiaries),
  * a per-subsidiary section for each company.

The per-company sections reuse PdfGenerator so the layout matches the
single-scan report exactly.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from report.pdf_generator import (
    PdfGenerator, _SEVERITY_COLORS, _RISK_COLORS, _SEVERITY_ORDER,
)

_RISK_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "PASSED": 0}


def _normalize_title(title: str) -> str:
    """Collapse a finding title to its vulnerability identity.

    Findings carry a host/target suffix after an em-dash (e.g.
    "Open port 22 — 10.0.0.5"); stripping it lets the same weakness on
    different hosts/companies correlate.
    """
    return title.split(" — ")[0].strip().lower()


def correlate_cross_company(per_company: list[tuple[str, list]]) -> list[dict]:
    """Find weaknesses shared by two or more subsidiaries.

    Args:
        per_company: list of (company_name, findings) pairs.

    Returns:
        A list of {"title", "severity", "companies"} dicts, one per
        weakness that appears in >= 2 distinct companies, ordered by the
        number of affected companies (descending) then title.
    """
    # key -> {"title": display, "severity": worst, "companies": set}
    groups: dict[str, dict] = {}
    for company_name, findings in per_company:
        for f in findings:
            key = _normalize_title(f.title)
            if not key:
                continue
            g = groups.setdefault(key, {
                "title": f.title.split(" — ")[0].strip(),
                "severity": f.severity,
                "companies": set(),
            })
            g["companies"].add(company_name)
            if _SEVERITY_ORDER.index(_norm_sev(f.severity)) < \
               _SEVERITY_ORDER.index(_norm_sev(g["severity"])):
                g["severity"] = f.severity

    shared = [
        {
            "title": g["title"],
            "severity": g["severity"],
            "companies": sorted(g["companies"]),
        }
        for g in groups.values()
        if len(g["companies"]) >= 2
    ]
    shared.sort(key=lambda d: (-len(d["companies"]), d["title"].lower()))
    return shared


def _norm_sev(sev: str) -> str:
    return sev if sev in _SEVERITY_ORDER else "info"


class ConsolidatedPdfGenerator:
    """Render a group-level PDF spanning multiple subsidiaries."""

    def __init__(self, companies_data: list[dict], output_path: str = "consolidated.pdf",
                 group_name: str = "Consolidated Report"):
        # companies_data: list of {"company", "scan", "hosts", "findings"}
        self._data = companies_data
        self._output_path = output_path
        self._group_name = group_name
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        self._h1 = ParagraphStyle(
            "CH1", parent=self._styles["Heading1"], fontSize=22,
            textColor=colors.HexColor("#1e293b"), spaceAfter=8,
        )
        self._h2 = ParagraphStyle(
            "CH2", parent=self._styles["Heading2"], fontSize=16,
            textColor=colors.HexColor("#1e293b"), spaceBefore=16, spaceAfter=6,
        )
        self._body = ParagraphStyle(
            "CBody", parent=self._styles["Normal"], fontSize=10,
            textColor=colors.HexColor("#334155"), spaceAfter=4, leading=14,
        )
        self._muted = ParagraphStyle(
            "CMuted", parent=self._styles["Normal"], fontSize=9,
            textColor=colors.HexColor("#64748b"), spaceAfter=3,
        )
        self._cover_title = ParagraphStyle(
            "CCoverTitle", fontSize=28, textColor=colors.HexColor("#1e293b"),
            alignment=TA_CENTER, spaceAfter=8, fontName="Helvetica-Bold",
        )
        self._cover_sub = ParagraphStyle(
            "CCoverSub", fontSize=14, textColor=colors.HexColor("#64748b"),
            alignment=TA_CENTER, spaceAfter=6,
        )

    def generate(self) -> str:
        doc = SimpleDocTemplate(
            self._output_path, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm,
            title=f"Consolidated Security Report — {self._group_name}",
            author="SecureOps",
        )
        story = []
        story += self._cover_page()
        story.append(PageBreak())
        story += self._group_summary()
        story += self._correlation_section()
        for entry in self._data:
            story.append(PageBreak())
            story += self._company_section(entry)
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
        rating = self._group_rating()
        rating_color = _RISK_COLORS.get(rating, colors.grey)
        story = [
            Spacer(1, 3*cm),
            Paragraph("SecureOps", self._cover_sub),
            Paragraph("Consolidated Security Report", self._cover_title),
            Spacer(1, 1*cm),
            Paragraph(f"Group: {self._group_name}", self._cover_sub),
            Paragraph(f"Subsidiaries Assessed: {len(self._data)}", self._cover_sub),
            Spacer(1, 1.5*cm),
        ]
        badge_style = ParagraphStyle(
            "CBadge", fontSize=14, textColor=colors.white,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        )
        badge_inner = Table(
            [[Paragraph(f"GROUP RISK: {rating}", badge_style)]], colWidths=[10*cm],
        )
        badge_inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), rating_color),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 12),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
        ]))
        outer = Table([[badge_inner]], colWidths=[A4[0] - 4*cm])
        outer.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
        story.append(outer)
        return story

    def _group_summary(self) -> list:
        story = [
            Paragraph("Group Executive Summary", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
            Spacer(1, 0.3*cm),
        ]
        totals = {s: 0 for s in _SEVERITY_ORDER}
        rows = [["Subsidiary", "Risk", "Critical", "High", "Medium", "Low", "Total"]]
        risk_row_colors = []
        for entry in self._data:
            counts = self._counts(entry["findings"])
            for s in _SEVERITY_ORDER:
                totals[s] += counts.get(s, 0)
            rating = self._rating(entry["findings"])
            risk_row_colors.append(_RISK_COLORS.get(rating, colors.grey))
            rows.append([
                (entry.get("company") or {}).get("name", entry["scan"].target),
                rating,
                str(counts.get("critical", 0)), str(counts.get("high", 0)),
                str(counts.get("medium", 0)), str(counts.get("low", 0)),
                str(sum(counts.values())),
            ])
        rows.append([
            "GROUP TOTAL", self._group_rating(),
            str(totals["critical"]), str(totals["high"]),
            str(totals["medium"]), str(totals["low"]),
            str(sum(totals.values())),
        ])
        t = Table(rows, colWidths=[5*cm, 2.4*cm, 1.8*cm, 1.6*cm, 1.8*cm, 1.4*cm, 1.6*cm])
        style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.HexColor("#f8fafc"), colors.white]),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e2e8f0")),
        ]
        for i, c in enumerate(risk_row_colors, start=1):
            style.append(("TEXTCOLOR", (1, i), (1, i), c))
            style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))
        return story

    def _correlation_section(self) -> list:
        story = [
            Paragraph("Cross-Company Correlation", self._h2),
            Paragraph(
                "Weaknesses observed across two or more subsidiaries — often a "
                "shared-infrastructure or shared-configuration issue worth fixing "
                "once at the group level.",
                self._body,
            ),
            Spacer(1, 0.3*cm),
        ]
        per_company = [
            ((e.get("company") or {}).get("name", e["scan"].target), e["findings"])
            for e in self._data
        ]
        shared = correlate_cross_company(per_company)
        if not shared:
            story.append(Paragraph(
                "No weaknesses were found to span multiple subsidiaries.", self._body,
            ))
            story.append(Spacer(1, 0.4*cm))
            return story
        rows = [["Weakness", "Severity", "Affected Subsidiaries"]]
        sev_cells = []
        for s in shared:
            rows.append([
                Paragraph(s["title"], self._muted),
                s["severity"].upper(),
                Paragraph(", ".join(s["companies"]), self._muted),
            ])
            sev_cells.append(_SEVERITY_COLORS.get(_norm_sev(s["severity"]), colors.grey))
        t = Table(rows, colWidths=[7*cm, 2.5*cm, 6.5*cm])
        style = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ]
        for i, c in enumerate(sev_cells, start=1):
            style.append(("TEXTCOLOR", (1, i), (1, i), c))
            style.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))
        return story

    def _company_section(self, entry: dict) -> list:
        name = (entry.get("company") or {}).get("name", entry["scan"].target)
        story = [
            Paragraph(f"Subsidiary: {name}", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
            Spacer(1, 0.2*cm),
        ]
        # Reuse the single-scan generator for the per-company body.
        gen = PdfGenerator(
            scan=entry["scan"], hosts=entry["hosts"], findings=entry["findings"],
            client=None,
        )
        net = [f for f in entry["findings"] if f.tool != "log-analyzer"]
        story += gen._severity_breakdown()
        story += gen._findings_section(net)
        return story

    # ── helpers ──────────────────────────────────────────────────────────────

    def _counts(self, findings: list) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[_norm_sev(f.severity)] = counts.get(_norm_sev(f.severity), 0) + 1
        return counts

    def _rating(self, findings: list) -> str:
        sevs = {_norm_sev(f.severity) for f in findings}
        for sev in ("critical", "high", "medium", "low"):
            if sev in sevs:
                return sev.upper()
        return "PASSED"

    def _group_rating(self) -> str:
        worst = "PASSED"
        for entry in self._data:
            r = self._rating(entry["findings"])
            if _RISK_RANK[r] > _RISK_RANK[worst]:
                worst = r
        return worst


def build_consolidated_data(db, scan_ids: list[int]) -> list[dict]:
    """Assemble per-company report data for a set of scans.

    Returns a list of {"company", "scan", "hosts", "findings"} dicts, one
    per scan, matching each scan to its company by client_id.
    """
    companies_by_id = {c["id"]: c for c in db.get_companies()}
    data = []
    for sid in scan_ids:
        scan = _find_scan(db, sid)
        if scan is None:
            continue
        data.append({
            "company": companies_by_id.get(scan.client_id),
            "scan": scan,
            "hosts": db.query_hosts_by_scan(sid),
            "findings": db.query_findings_by_scan(sid),
        })
    return data


def _find_scan(db, scan_id: int):
    for client in db.query_clients():
        for s in db.query_scans_by_client(client.id):
            if s.id == scan_id:
                return s
    for s in db.query_scans_by_client(None):
        if s.id == scan_id:
            return s
    # Companies are stored separately from clients; scans created by the batch
    # worker carry a company id as client_id, so also scan those.
    for c in db.get_companies():
        for s in db.query_scans_by_client(c["id"]):
            if s.id == scan_id:
                return s
    return None
