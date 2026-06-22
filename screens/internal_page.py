import ipaddress
from datetime import datetime, timezone

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit, QFrame,
)

from db import DB
from models import Scan
from screens.widgets.topology_graph import TopologyGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
from screens.widgets.company_selector import CompanySelector
from workers.internal_worker import InternalWorker
from screens.widgets.theme import BG, ACCENT, TXT as TEXT, CARD as SURFACE, ACCENT_H as HOVER, CRITICAL, SUCCESS


class InternalPage(QWidget):
    scan_ready = pyqtSignal(int)

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._worker: InternalWorker | None = None
        self._scan_id: int | None = None
        self._chips: list[tuple[str, QPushButton]] = []

        self._subnet_input: QLineEdit | None = None
        self._add_btn: QPushButton | None = None
        self._start_btn: QPushButton | None = None
        self._status_label: QLabel | None = None
        self._chips_row: QHBoxLayout | None = None
        self._topology: TopologyGraph | None = None
        self._severity_rings: SeverityRings | None = None
        self._finding_cards: FindingCards | None = None
        self._terminal: QPlainTextEdit | None = None
        self._company_selector: CompanySelector | None = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        if self._db:
            self._company_selector = CompanySelector(db=self._db)
            self._company_selector.company_selected.connect(self._on_company_selected)
            layout.addWidget(self._company_selector)

        # --- top bar ---
        top_bar = QHBoxLayout()
        self._subnet_input = QLineEdit()
        self._subnet_input.setPlaceholderText("192.168.1.0/24")
        self._subnet_input.setFixedWidth(220)
        self._subnet_input.returnPressed.connect(self._on_add_chip)

        self._add_btn = QPushButton("+ Add")
        self._add_btn.setFixedWidth(64)
        self._add_btn.clicked.connect(self._on_add_chip)

        self._start_btn = QPushButton("▶  Start Sweep")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)

        top_bar.addWidget(self._subnet_input)
        top_bar.addWidget(self._add_btn)
        top_bar.addStretch()
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        # --- chip row ---
        chip_frame = QFrame()
        chip_frame.setObjectName("panel")
        self._chips_row = QHBoxLayout(chip_frame)
        self._chips_row.setContentsMargins(8, 4, 8, 4)
        self._chips_row.setSpacing(6)
        self._chips_row.addStretch()
        layout.addWidget(chip_frame)

        # --- status label ---
        self._status_label = QLabel("Idle — add subnet ranges and click Start Sweep")
        self._status_label.setStyleSheet(f"color: {TEXT}; font-size: 11px;")
        layout.addWidget(self._status_label)

        # --- main body ---
        self._topology = TopologyGraph()
        self._severity_rings = SeverityRings()
        self._finding_cards = FindingCards()
        self._terminal = QPlainTextEdit()
        self._terminal.setReadOnly(True)
        self._terminal.setObjectName("panel")
        self._terminal.setStyleSheet(
            f"font-family: monospace; font-size: 11px; color: {TEXT}; background-color: {BG};"
        )

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right_layout.addWidget(self._severity_rings)
        right_layout.addWidget(self._finding_cards, stretch=1)

        body_splitter = QSplitter(Qt.Orientation.Horizontal)
        body_splitter.addWidget(self._topology)
        body_splitter.addWidget(right_panel)
        body_splitter.setSizes([700, 300])

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(body_splitter)
        main_splitter.addWidget(self._terminal)
        main_splitter.setSizes([750, 150])

        layout.addWidget(main_splitter, stretch=1)

    def showEvent(self, event):
        super().showEvent(event)
        self._load_saved_subnets()

    def _load_saved_subnets(self):
        if not self._db:
            return
        saved = self._db.get_setting("internal_subnets") or ""
        current = {s for s, _ in self._chips}
        for subnet in saved.split(","):
            subnet = subnet.strip()
            if subnet and subnet not in current:
                self._add_chip(subnet)

    def _on_company_selected(self, company: dict) -> None:
        import json
        try:
            ranges = json.loads(company.get("ip_ranges", "[]"))
            if ranges:
                self._subnet_input.setText(ranges[0])
        except Exception:
            pass

    def _on_add_chip(self):
        text = self._subnet_input.text().strip()
        if not text:
            return
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            self._status_label.setText(f"Invalid subnet: {text}")
            self._status_label.setStyleSheet(f"color: {CRITICAL}; font-size: 11px;")
            return
        existing = {s for s, _ in self._chips}
        if text not in existing:
            self._add_chip(text)
        self._subnet_input.clear()
        self._status_label.setText("Idle — click Start Sweep when ready")
        self._status_label.setStyleSheet(f"color: {TEXT}; font-size: 11px;")

    def _add_chip(self, subnet: str):
        btn = QPushButton(f"{subnet}  ×")
        btn.setStyleSheet(
            f"QPushButton {{ background: {SURFACE}; color: {ACCENT}; border: 1px solid {ACCENT};"
            " border-radius: 10px; padding: 2px 8px; font-size: 11px; }"
            f"QPushButton:hover {{ background: {HOVER}; color: {BG}; }}"
        )
        btn.clicked.connect(lambda: self._remove_chip(subnet))
        self._chips_row.insertWidget(self._chips_row.count() - 1, btn)
        self._chips.append((subnet, btn))

    def _remove_chip(self, subnet: str):
        self._chips = [(s, b) for s, b in self._chips if s != subnet]
        for i in range(self._chips_row.count()):
            item = self._chips_row.itemAt(i)
            if item and item.widget():
                w = item.widget()
                if w.text() == f"{subnet}  ×":
                    self._chips_row.removeWidget(w)
                    w.deleteLater()
                    break

    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return

        subnets = [s for s, _ in self._chips]
        if not subnets:
            self._status_label.setText("Add at least one subnet range first.")
            self._status_label.setStyleSheet(f"color: {CRITICAL}; font-size: 11px;")
            return

        scan = Scan(
            id=None, client_id=None,
            target=", ".join(subnets),
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            finished_at=None,
        )
        self._scan_id = self._db.insert_scan(scan)

        self._topology.reset()
        self._severity_rings.reset()
        self._finding_cards.reset()
        self._terminal.clear()

        self._worker = InternalWorker(subnets=subnets, scan_id=self._scan_id, db=self._db)
        self._worker.finding_found.connect(self._on_finding)
        self._worker.log_line.connect(self._terminal.appendPlainText)
        self._worker.scan_complete.connect(self._on_complete)
        self._worker.scan_failed.connect(self._on_failed)
        self._worker.start()
        self._worker.finished.connect(self._on_worker_finished)

        self._start_btn.setText("■  Stop Sweep")
        self._status_label.setText("Sweeping…")
        self._status_label.setStyleSheet(f"color: {ACCENT}; font-size: 11px;")

    def _on_finding(self, finding):
        ports = []
        for p in finding.description.replace("Open ports: ", "").split(", "):
            p = p.strip()
            if not p or p == "none":
                continue
            try:
                ports.append(int(p.split("/")[0]))
            except ValueError:
                pass
        device_type = finding.title.split(" — ")[0]
        ip = finding.title.split(" — ")[-1]
        self._topology.add_host(ip, device_type, ports)
        self._severity_rings.add_finding(finding)
        self._finding_cards.add_finding(finding)

    def _on_complete(self, hosts: int, findings: int):
        self._start_btn.setText("▶  Start Sweep")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Done — {hosts} hosts, {findings} findings")
        self._status_label.setStyleSheet(f"color: {SUCCESS}; font-size: 11px;")
        self._finding_cards.on_scan_complete(hosts, findings)
        if self._scan_id is not None:
            self.scan_ready.emit(self._scan_id)

    def _on_failed(self, msg: str):
        self._start_btn.setText("▶  Start Sweep")
        self._start_btn.setEnabled(True)
        self._status_label.setText(f"Error: {msg}")
        self._status_label.setStyleSheet(f"color: {CRITICAL}; font-size: 11px;")

    def _on_worker_finished(self):
        if not self._start_btn.isEnabled():
            self._start_btn.setText("▶  Start Sweep")
            self._start_btn.setEnabled(True)
