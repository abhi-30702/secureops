import os
from datetime import datetime
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QFrame, QFileDialog, QMessageBox,
)
from PyQt6.QtGui import QDesktopServices
from screens.widgets.theme import (
    TXT, TXT2, TXT3, ACCENT, CARD, CRITICAL, SUCCESS, SEVERITY_COLORS,
)

_SEVERITY_COLORS = SEVERITY_COLORS
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
        self._advisor_panel: QFrame | None = None
        self._run_advisor_btn: QPushButton | None = None
        self._advisor_status: QLabel | None = None
        self._tier_layouts: dict = {}
        self._advisor_worker: object | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        top_bar = QHBoxLayout()
        title = QLabel("Security Report")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {TXT};")
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
        ph.setStyleSheet(f"color: {TXT3}; font-size: 14px;")
        self._content_layout.addStretch()
        self._content_layout.addWidget(ph)
        self._content_layout.addStretch()

    def _clear_content(self):
        while self._content_layout.count():
            item = self._content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _find_scan(self, scan_id: int):
        for client in self._db.query_clients():
            for s in self._db.query_scans_by_client(client.id):
                if s.id == scan_id:
                    return s
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
        net_findings = [f for f in findings if f.tool != "log-analyzer"]
        log_findings = [f for f in findings if f.tool == "log-analyzer"]

        self._content_layout.addWidget(self._build_summary(scan, hosts, findings))
        self._content_layout.addWidget(self._build_severity_panel(findings))
        self._content_layout.addWidget(self._build_findings_panel(net_findings))
        if log_findings:
            self._content_layout.addWidget(self._build_log_panel(log_findings))
        if self._advisor_worker is not None:
            self._advisor_worker.cancel()
            self._advisor_worker.wait(500)
            self._advisor_worker = None
        self._advisor_panel = None
        self._run_advisor_btn = None
        self._advisor_status = None
        self._tier_layouts = {}
        self._build_advisor_panel()
        self._content_layout.addStretch()
        self._export_btn.setEnabled(True)

    def _build_summary(self, scan, hosts, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        header = QLabel("Summary")
        header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {TXT};")
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
            row.setStyleSheet(f"color: {TXT2}; font-size: 11px;")
            layout.addWidget(row)

        return panel

    def _build_severity_panel(self, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(6)

        header = QLabel("Severity Breakdown")
        header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {TXT};")
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
            color = _SEVERITY_COLORS.get(sev, TXT3)
            lbl = QLabel(f'<span style="color:{color}">●</span> {sev.capitalize()}: <b>{n}</b>')
            lbl.setStyleSheet(f"color: {TXT2}; font-size: 11px;")
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
        header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {TXT};")
        layout.addWidget(header)

        if not findings:
            lbl = QLabel("No findings recorded.")
            lbl.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
            layout.addWidget(lbl)
            return panel

        by_sev: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "info"
            by_sev[sev].append(f)

        for sev in _SEVERITY_ORDER:
            if not by_sev[sev]:
                continue
            color = _SEVERITY_COLORS.get(sev, TXT3)
            sev_label = QLabel(
                f'<span style="color:{color}; font-weight:bold;">{sev.upper()} ({len(by_sev[sev])})</span>'
            )
            sev_label.setStyleSheet("font-size: 12px;")
            layout.addWidget(sev_label)
            for f in by_sev[sev]:
                card = QFrame()
                card.setStyleSheet(
                    f"QFrame {{ border-left: 3px solid {color}; "
                    f"background-color: {CARD}; border-radius: 3px; }}"
                )
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(10, 6, 10, 6)
                card_layout.setSpacing(2)
                title_lbl = QLabel(f.title)
                title_lbl.setStyleSheet(
                    f"color: {TXT}; font-size: 12px; font-weight: bold;"
                )
                tool_lbl = QLabel(f"Tool: {f.tool}")
                tool_lbl.setStyleSheet(f"color: {TXT3}; font-size: 10px;")
                card_layout.addWidget(title_lbl)
                card_layout.addWidget(tool_lbl)
                if f.description:
                    desc_lbl = QLabel(f.description[:200])
                    desc_lbl.setWordWrap(True)
                    desc_lbl.setStyleSheet(f"color: {TXT2}; font-size: 10px;")
                    card_layout.addWidget(desc_lbl)
                layout.addWidget(card)

        return panel

    def _build_log_panel(self, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Log Analysis Findings")
        header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {TXT};")
        layout.addWidget(header)

        by_sev: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "info"
            by_sev[sev].append(f)

        for sev in _SEVERITY_ORDER:
            if not by_sev[sev]:
                continue
            color = _SEVERITY_COLORS.get(sev, TXT3)
            sev_label = QLabel(
                f'<span style="color:{color}; font-weight:bold;">{sev.upper()} ({len(by_sev[sev])})</span>'
            )
            sev_label.setStyleSheet("font-size: 12px;")
            layout.addWidget(sev_label)
            for f in by_sev[sev]:
                card = QFrame()
                card.setStyleSheet(
                    f"QFrame {{ border-left: 3px solid {color}; "
                    f"background-color: {CARD}; border-radius: 3px; }}"
                )
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(10, 6, 10, 6)
                card_layout.setSpacing(2)
                title_lbl = QLabel(f.title)
                title_lbl.setStyleSheet(f"color: {TXT}; font-size: 12px; font-weight: bold;")
                card_layout.addWidget(title_lbl)
                if f.description:
                    desc_lbl = QLabel(f.description[:200])
                    desc_lbl.setWordWrap(True)
                    desc_lbl.setStyleSheet(f"color: {TXT2}; font-size: 10px;")
                    card_layout.addWidget(desc_lbl)
                layout.addWidget(card)

        return panel

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
        header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {TXT};")
        header_row.addWidget(header)
        header_row.addStretch()
        panel_layout.addLayout(header_row)

        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""

        if not enabled or not api_key:
            info = QLabel("AI Advisor disabled — enable in Settings.")
            info.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
            panel_layout.addWidget(info)
            self._content_layout.addWidget(panel)
            return

        self._run_advisor_btn = QPushButton("Run Advisor")
        self._run_advisor_btn.setFixedWidth(110)
        self._run_advisor_btn.clicked.connect(self._on_run_advisor)
        header_row.addWidget(self._run_advisor_btn)

        self._advisor_status = QLabel("")
        self._advisor_status.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
        panel_layout.addWidget(self._advisor_status)

        for tier, label in (("immediate", "IMMEDIATE"), ("short_term", "SHORT-TERM"),
                             ("preventive", "PREVENTIVE")):
            sub_header = QLabel(label)
            sub_header.setStyleSheet(f"color: {TXT2}; font-size: 10px; letter-spacing: 1px;")
            sub_header.hide()
            panel_layout.addWidget(sub_header)
            tier_box = QVBoxLayout()
            tier_box.setSpacing(4)
            panel_layout.addLayout(tier_box)
            self._tier_layouts[tier] = {"header": sub_header, "layout": tier_box}

        disclaimer = QLabel("AI-generated — review before sending to client.")
        disclaimer.setStyleSheet(f"color: {TXT3}; font-size: 10px; font-style: italic;")
        panel_layout.addWidget(disclaimer)

        self._content_layout.addWidget(panel)

    def _on_run_advisor(self) -> None:
        if not self._db or self._scan_id is None:
            return

        backend = self._db.get_setting("advisor_backend") or "gemini"
        redact = self._db.get_setting("advisor_redact") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""

        if backend == "ollama":
            # Local backend (FR-54): data never leaves the machine, so no
            # external-transmission consent is required — just a brief notice.
            model = self._db.get_setting("ollama_model") or "llama3"
            reply = QMessageBox.question(
                self,
                "Run local AI Advisor?",
                f"Scan findings will be analysed locally by Ollama (model: {model}). "
                "No data leaves your machine.\n\nProceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            status_text = f"Analysing locally with Ollama ({model})…"
        else:
            if not api_key:
                if self._advisor_status:
                    self._advisor_status.setText("No API key — add one in Settings.")
                return
            redaction_note = (
                "Identifying details (company name, hostnames, IPs) will be redacted "
                "before sending.\n\n"
                if redact else
                "This includes the target, subdomains, ports and vulnerabilities, and "
                "will leave your machine.\n\n"
            )
            reply = QMessageBox.question(
                self,
                "Send data to Gemini?",
                "Scan findings will be sent to the Google Gemini API to generate "
                "advisory recommendations.\n\n"
                + redaction_note +
                "Do you want to proceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            status_text = "Contacting Gemini API…"
        if reply != QMessageBox.StandardButton.Yes:
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
            self._advisor_status.setText(status_text)

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
            f"QFrame {{ border-left: 3px solid {ACCENT};"
            f" background-color: {CARD}; border-radius: 3px; }}"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(10, 6, 10, 6)
        card_layout.setSpacing(4)

        text_lbl = QLabel(item.text)
        text_lbl.setWordWrap(True)
        text_lbl.setStyleSheet(f"color: {TXT}; font-size: 11px;")
        card_layout.addWidget(text_lbl)

        btn_row = QHBoxLayout()
        accept_btn = QPushButton("✓ Accept")
        accept_btn.setFixedWidth(80)
        accept_btn.setStyleSheet(
            f"QPushButton {{ color: {SUCCESS}; border: 1px solid {SUCCESS};"
            f" border-radius: 3px; padding: 2px 6px; font-size: 10px; }}"
            f" QPushButton:hover {{ background-color: {SUCCESS}20; }}"
        )
        discard_btn = QPushButton("✗ Discard")
        discard_btn.setFixedWidth(80)
        discard_btn.setStyleSheet(
            f"QPushButton {{ color: {CRITICAL}; border: 1px solid {CRITICAL};"
            f" border-radius: 3px; padding: 2px 6px; font-size: 10px; }}"
            f" QPushButton:hover {{ background-color: {CRITICAL}20; }}"
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
            f"QFrame {{ border-left: 3px solid {SUCCESS};"
            f" background-color: {CARD}; border-radius: 3px; }}"
        )
        accept_btn.setEnabled(False)
        discard_btn.setEnabled(False)

    def _discard_item(self, item, card: QFrame) -> None:
        if self._db and item.id is not None:
            self._db.update_advisory_item_accepted(item.id, False)
        card.hide()

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

        advisory_items = [
            i for i in self._db.query_advisory_items_by_scan(self._scan_id)
            if i.accepted
        ]
        incident_events = self._db.get_incident_events(self._scan_id)
        osint_items = self._db.get_osint_items(self._scan_id)
        try:
            from report.pdf_generator import PdfGenerator
            PdfGenerator(scan=scan, hosts=hosts, findings=findings,
                         output_path=path, advisory_items=advisory_items,
                         incident_events=incident_events,
                         osint_items=osint_items).generate()
            QDesktopServices.openUrl(QUrl.fromLocalFile(os.path.dirname(path)))
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def reset(self):
        if self._advisor_worker is not None:
            self._advisor_worker.cancel()
            self._advisor_worker.wait(500)
            self._advisor_worker = None
        self._scan_id = None
        self._advisor_panel = None
        self._run_advisor_btn = None
        self._advisor_status = None
        self._tier_layouts = {}
        self._export_btn.setEnabled(False)
        self._show_placeholder()
