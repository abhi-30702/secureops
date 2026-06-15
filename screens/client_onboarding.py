import json
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QListWidget,
    QPushButton, QFormLayout, QLineEdit, QComboBox, QFrame,
)
from PyQt6.QtGui import QFont
from db import DB

_FIREWALL_OPTS = ["None", "pfSense", "Cisco ASA", "Fortinet", "Palo Alto", "Other"]


class ClientOnboardingScreen(QWidget):
    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._selected_id: int | None = None
        self._companies: list[dict] = []
        self._build_ui()
        if self._db:
            self._load_companies()

    def _build_ui(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(0)

        # Left panel: company list
        left = QVBoxLayout()
        left.setSpacing(8)
        hdr = QLabel("Companies")
        hdr.setFont(QFont("DM Sans", 14, QFont.Weight.Bold))
        hdr.setStyleSheet("color: #00e5ff;")
        left.addWidget(hdr)

        self._company_list = QListWidget()
        self._company_list.setFixedWidth(210)
        self._company_list.currentRowChanged.connect(self._on_company_selected)
        left.addWidget(self._company_list)

        btn_row = QHBoxLayout()
        self._add_btn = QPushButton("＋ Add")
        self._add_btn.clicked.connect(self._on_add)
        self._delete_btn = QPushButton("✕ Delete")
        self._delete_btn.clicked.connect(self._on_delete)
        btn_row.addWidget(self._add_btn)
        btn_row.addWidget(self._delete_btn)
        left.addLayout(btn_row)

        left_w = QWidget()
        left_w.setLayout(left)
        root.addWidget(left_w)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.VLine)
        div.setStyleSheet("color: #0d2440;")
        root.addWidget(div)

        # Right panel: edit form
        right = QVBoxLayout()
        right.setContentsMargins(20, 0, 0, 0)
        right.setSpacing(12)

        form_hdr = QLabel("Company Details")
        form_hdr.setFont(QFont("DM Sans", 13, QFont.Weight.Bold))
        form_hdr.setStyleSheet("color: #e2eaf4;")
        right.addWidget(form_hdr)

        form = QFormLayout()
        form.setSpacing(10)

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Fidelitus Tech")
        form.addRow("Name:", self._name_input)

        self._domains_input = QLineEdit()
        self._domains_input.setPlaceholderText("example.com, sub.example.com")
        form.addRow("Domains:", self._domains_input)

        self._ip_ranges_input = QLineEdit()
        self._ip_ranges_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        form.addRow("IP Ranges:", self._ip_ranges_input)

        self._aws_profile_input = QLineEdit()
        self._aws_profile_input.setPlaceholderText("default")
        form.addRow("AWS Profile:", self._aws_profile_input)

        self._gcp_project_input = QLineEdit()
        self._gcp_project_input.setPlaceholderText("my-gcp-project-123")
        form.addRow("GCP Project:", self._gcp_project_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(_FIREWALL_OPTS)
        form.addRow("Firewall:", self._firewall_combo)

        right.addLayout(form)

        self._save_btn = QPushButton("Save")
        self._save_btn.setEnabled(False)
        self._save_btn.clicked.connect(self._on_save)
        right.addWidget(self._save_btn)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #00ff88; font-size: 11px;")
        right.addWidget(self._status_label)

        right.addStretch()

        right_w = QWidget()
        right_w.setLayout(right)
        root.addWidget(right_w, 1)

    def _load_companies(self):
        self._company_list.clear()
        self._companies = self._db.get_companies()
        for c in self._companies:
            self._company_list.addItem(c["name"])
        if self._companies:
            self._company_list.setCurrentRow(0)

    def _on_company_selected(self, row: int):
        if row < 0 or not self._companies:
            self._save_btn.setEnabled(False)
            return
        c = self._companies[row]
        self._selected_id = c["id"]
        self._name_input.setText(c["name"])
        try:
            domains = ", ".join(json.loads(c.get("domains", "[]")))
        except Exception:
            domains = c.get("domains", "")
        self._domains_input.setText(domains)
        try:
            ranges = ", ".join(json.loads(c.get("ip_ranges", "[]")))
        except Exception:
            ranges = c.get("ip_ranges", "")
        self._ip_ranges_input.setText(ranges)
        self._aws_profile_input.setText(c.get("aws_profile", ""))
        self._gcp_project_input.setText(c.get("gcp_project", ""))
        fw = c.get("firewall_type", "None")
        idx = self._firewall_combo.findText(fw)
        self._firewall_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._save_btn.setEnabled(True)
        self._status_label.setText("")

    def _on_add(self):
        self._selected_id = None
        self._name_input.clear()
        self._domains_input.clear()
        self._ip_ranges_input.clear()
        self._aws_profile_input.clear()
        self._gcp_project_input.clear()
        self._firewall_combo.setCurrentIndex(0)
        self._save_btn.setEnabled(True)
        self._company_list.clearSelection()
        self._name_input.setFocus()

    def _on_delete(self):
        row = self._company_list.currentRow()
        if row < 0 or not self._companies or not self._db:
            return
        cid = self._companies[row]["id"]
        self._db.delete_company(cid)
        self._load_companies()
        self._save_btn.setEnabled(False)
        self._status_label.setText("Deleted.")

    def _on_save(self):
        if not self._db:
            return

        def _to_json_array(text: str) -> str:
            parts = [p.strip() for p in text.split(",") if p.strip()]
            return json.dumps(parts)

        data = {
            "name": self._name_input.text().strip() or "Unnamed Company",
            "domains": _to_json_array(self._domains_input.text()),
            "ip_ranges": _to_json_array(self._ip_ranges_input.text()),
            "aws_profile": self._aws_profile_input.text().strip(),
            "gcp_project": self._gcp_project_input.text().strip(),
            "firewall_type": self._firewall_combo.currentText(),
        }
        if self._selected_id is not None:
            self._db.update_company(self._selected_id, data)
        else:
            self._selected_id = self._db.insert_company(data)
        self._load_companies()
        self._status_label.setText("Saved ✓")
