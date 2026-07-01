import json
from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QListWidget,
    QFormLayout, QLineEdit, QComboBox,
)
from db import DB
from screens.widgets import theme as T
from screens.widgets.components import (
    PageHeader, Card, PrimaryButton, SecondaryButton, DangerButton,
)

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
        root = QVBoxLayout(self)
        root.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        root.setSpacing(T.SP_LG)

        root.addWidget(PageHeader(
            "Companies", "Register the companies and assets you are authorised to scan"
        ))

        body = QHBoxLayout()
        body.setSpacing(T.SP_LG)

        # ── Left: company list card ──────────────────────────────────────────
        list_card = Card("Company List")
        self._company_list = QListWidget()
        self._company_list.setMinimumWidth(220)
        self._company_list.currentRowChanged.connect(self._on_company_selected)
        list_card.add(self._company_list, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(T.SP_SM)
        self._add_btn = SecondaryButton("＋ Add", "Create a new company")
        self._add_btn.clicked.connect(self._on_add)
        self._delete_btn = DangerButton("✕ Delete", "Delete the selected company")
        self._delete_btn.clicked.connect(self._on_delete)
        btn_row.addWidget(self._add_btn)
        btn_row.addWidget(self._delete_btn)
        list_card.add_layout(btn_row)
        body.addWidget(list_card, stretch=0)

        # ── Right: details form card ─────────────────────────────────────────
        form_card = Card("Company Details")
        form = QFormLayout()
        form.setSpacing(T.SP_MD)
        form.setLabelAlignment(form.labelAlignment())

        self._name_input = QLineEdit()
        self._name_input.setPlaceholderText("Acme Corp")
        form.addRow("Name", self._name_input)

        self._domains_input = QLineEdit()
        self._domains_input.setPlaceholderText("example.com, sub.example.com")
        form.addRow("Domains", self._domains_input)

        self._ip_ranges_input = QLineEdit()
        self._ip_ranges_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        form.addRow("IP Ranges", self._ip_ranges_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(_FIREWALL_OPTS)
        form.addRow("Firewall", self._firewall_combo)

        form_card.add_layout(form)

        save_row = QHBoxLayout()
        self._save_btn = PrimaryButton("Save", "Save company details")
        self._save_btn.setEnabled(False)
        self._save_btn.clicked.connect(self._on_save)
        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color: {T.SUCCESS}; font-size: {T.FS_SMALL}px;")
        save_row.addWidget(self._save_btn)
        save_row.addWidget(self._status_label)
        save_row.addStretch()
        form_card.add_layout(save_row)
        form_card.body().addStretch()

        body.addWidget(form_card, stretch=1)
        root.addLayout(body, stretch=1)

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
            "firewall_type": self._firewall_combo.currentText(),
        }
        if self._selected_id is not None:
            self._db.update_company(self._selected_id, data)
        else:
            self._selected_id = self._db.insert_company(data)
        self._load_companies()
        self._status_label.setText("Saved ✓")
