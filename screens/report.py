import os
from datetime import datetime
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QFileDialog, QMessageBox,
)
from PyQt6.QtGui import QDesktopServices

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

    def _find_scan(self, scan_id: int):
        # Search across all clients (and null-client scans)
        for client in self._db.query_clients():
            for s in self._db.query_scans_by_client(client.id):
                if s.id == scan_id:
                    return s
        # Also check scans with no client
        for s in self._db.query_scans_by_client(None):
            if s.id == scan_id:
                return s
        return None

    def load_scan(self, scan_id: int):
        if not self._db:
            return
        scan = self._find_scan(scan_id)
        if not scan:
            return
        self._scan_id = scan_id
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
            except (ValueError, TypeError):
                pass

        for label, value in [
            ("Target", scan.target),
            ("Date", (scan.started_at or "")[:10]),
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

        if not findings:
            lbl = QLabel("No findings recorded.")
            lbl.setStyleSheet("color: #64748b; font-size: 11px;")
            layout.addWidget(lbl)
            return panel

        by_sev: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "info"
            by_sev[sev].append(f)

        for sev in _SEVERITY_ORDER:
            if not by_sev[sev]:
                continue
            color = _SEVERITY_COLORS.get(sev, "#64748b")
            sev_label = QLabel(
                f'<span style="color:{color}; font-weight:bold;">{sev.upper()} ({len(by_sev[sev])})</span>'
            )
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
                title_lbl.setStyleSheet(
                    "color: #e2e8f0; font-size: 12px; font-weight: bold;"
                )
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
        scan = self._find_scan(self._scan_id)
        if not scan:
            return
        hosts = self._db.query_hosts_by_scan(self._scan_id)
        findings = self._db.query_findings_by_scan(self._scan_id)

        default_name = f"SecureOps_Report_{scan.target}_{(scan.started_at or '')[:10]}.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", default_name, "PDF Files (*.pdf)"
        )
        if not path:
            return

        try:
            from report.pdf_generator import PdfGenerator
            PdfGenerator(scan=scan, hosts=hosts, findings=findings,
                         output_path=path).generate()
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def reset(self):
        self._scan_id = None
        self._export_btn.setEnabled(False)
        self._show_placeholder()
