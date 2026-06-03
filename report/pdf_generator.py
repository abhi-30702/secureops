from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable,
)
from reportlab.lib.enums import TA_CENTER
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
    def __init__(self, scan: Scan, hosts: list[Host], findings: list[Finding],
                 client: Client | None = None, output_path: str = "report.pdf"):
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
            fontSize=22, textColor=colors.HexColor("#1e293b"), spaceAfter=8,
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
            fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=3,
        )
        self._cover_title = ParagraphStyle(
            "CoverTitle", fontSize=28, textColor=colors.HexColor("#1e293b"),
            alignment=TA_CENTER, spaceAfter=8, fontName="Helvetica-Bold",
        )
        self._cover_sub = ParagraphStyle(
            "CoverSub", fontSize=14, textColor=colors.HexColor("#64748b"),
            alignment=TA_CENTER, spaceAfter=6,
        )

    def generate(self) -> str:
        doc = SimpleDocTemplate(
            self._output_path, pagesize=A4,
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
        target_name = (self._client.name if self._client else None) or self._scan.target
        story = [
            Spacer(1, 3*cm),
            Paragraph("SecureOps", self._cover_sub),
            Paragraph("Security Assessment Report", self._cover_title),
            Spacer(1, 1*cm),
            Paragraph(f"Target: {target_name}", self._cover_sub),
            Paragraph(f"Domain: {self._scan.target}", self._cover_sub),
            Paragraph(f"Scan Date: {(self._scan.started_at or '')[:10]}", self._cover_sub),
            Spacer(1, 1.5*cm),
        ]
        badge_style = ParagraphStyle(
            "Badge", fontSize=14, textColor=colors.white,
            alignment=TA_CENTER, fontName="Helvetica-Bold",
        )
        badge_inner = Table(
            [[Paragraph(f"OVERALL RISK: {rating}", badge_style)]],
            colWidths=[10*cm],
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

    def _executive_summary(self) -> list:
        story = [
            Paragraph("Executive Summary", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
        ]
        counts = self._severity_counts()
        total = sum(counts.values())
        rows = [
            ["Target", self._scan.target],
            ["Scan Date", (self._scan.started_at or "")[:10]],
            ["Scan Duration", self._scan_duration()],
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
        for i, c in enumerate(row_colors):
            style.append(("TEXTCOLOR", (0, i+1), (0, i+1), c))
            style.append(("FONTNAME", (0, i+1), (0, i+1), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))
        return story

    def _findings_section(self) -> list:
        story = [
            Paragraph("Findings", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
        ]
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
                story.append(Paragraph(
                    f"Recommended Action: {_REMEDIATION.get(sev, '')}", self._muted
                ))
                story.append(Spacer(1, 0.3*cm))

        if not self._findings:
            story.append(Paragraph("No findings recorded for this scan.", self._body))
        return story

    def _iso_section(self) -> list:
        story = [
            Paragraph("ISO 27001 Control Gap Analysis", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
            Spacer(1, 0.3*cm),
        ]
        seen: dict[str, tuple] = {}
        for f in self._findings:
            ctrl, title = self._iso_control(f.tool)
            if ctrl not in seen:
                seen[ctrl] = (ctrl, title, f.tool)
        if seen:
            rows = [["ISO Control", "Title", "Source Tool"]]
            for ctrl in sorted(seen):
                ctrl_id, ctrl_title, tool = seen[ctrl]
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
        story = [
            PageBreak(),
            Paragraph("Appendix: Host Inventory", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
            Spacer(1, 0.3*cm),
        ]
        if self._hosts:
            rows = [["Subdomain", "IP", "Port", "Service", "Tool"]]
            for h in self._hosts:
                rows.append([
                    h.subdomain or "—", h.ip or "—",
                    str(h.port) if h.port else "—",
                    h.service or "—", h.source_tool,
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
            sev = f.severity if f.severity in _SEVERITY_COLORS else "info"
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _scan_duration(self) -> str:
        if not self._scan.finished_at or not self._scan.started_at:
            return "—"
        try:
            start = datetime.fromisoformat(self._scan.started_at[:19])
            end = datetime.fromisoformat(self._scan.finished_at[:19])
            delta = int((end - start).total_seconds())
            m, s = divmod(delta, 60)
            return f"{m}m {s}s"
        except (ValueError, OverflowError, TypeError):
            return "—"
