from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QScrollArea, QComboBox, QCheckBox,
)
from datetime import datetime, timezone
from models import Schedule
from tool_checker import TOOLS, CRITICAL_TOOLS
from screens.widgets.theme import TXT, TXT2, TXT3, CRITICAL, HIGH, SUCCESS

_COLOR_CRITICAL = HIGH


class SettingsScreen(QWidget):
    def __init__(self, tool_results: dict, db=None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._tool_rows: dict[str, dict] = {}
        self._schedule_target: QLineEdit | None = None
        self._schedule_interval: QComboBox | None = None
        self._add_schedule_btn: QPushButton | None = None
        self._schedules_layout: QVBoxLayout | None = None
        self._subnet_input: QLineEdit | None = None
        self._advisor_enabled_cb: QCheckBox | None = None
        self._advisor_backend_combo: QComboBox | None = None
        self._api_key_input: QLineEdit | None = None
        self._ollama_model_input: QLineEdit | None = None
        self._advisor_save_btn: QPushButton | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Settings")
        title.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {TXT};")
        layout.addWidget(title)

        section_label = QLabel("TOOL STATUS")
        section_label.setStyleSheet(f"color: {TXT3}; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(section_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(4)

        for tool in TOOLS:
            present = self._tool_results.get(tool, False)
            is_critical = tool in CRITICAL_TOOLS
            row_widget = self._build_tool_row(tool, present, is_critical)
            container_layout.addWidget(row_widget)
            self._tool_rows[tool] = {
                "present": present,
                "is_critical": is_critical,
                "widget": row_widget,
            }

        container_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll, stretch=1)

        save_btn = QPushButton("Save Paths")
        save_btn.setEnabled(False)
        save_btn.setToolTip("Path overrides wired in Phase 2")
        layout.addWidget(save_btn)

        sched_label = QLabel("SCHEDULED SCANS")
        sched_label.setStyleSheet(f"color: {TXT3}; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(sched_label)

        sched_input_row = QHBoxLayout()
        self._schedule_target = QLineEdit()
        self._schedule_target.setPlaceholderText("Target domain (e.g. example.com)")
        self._schedule_interval = QComboBox()
        for label in ("Every 1h", "Every 4h", "Every 24h"):
            self._schedule_interval.addItem(label)
        self._schedule_interval.setCurrentIndex(2)
        self._add_schedule_btn = QPushButton("+ Add")
        self._add_schedule_btn.setFixedWidth(70)
        self._add_schedule_btn.clicked.connect(self._on_add_schedule)
        sched_input_row.addWidget(self._schedule_target, stretch=1)
        sched_input_row.addWidget(self._schedule_interval)
        sched_input_row.addWidget(self._add_schedule_btn)
        layout.addLayout(sched_input_row)

        sched_list = QFrame()
        sched_list.setObjectName("panel")
        self._schedules_layout = QVBoxLayout(sched_list)
        self._schedules_layout.setContentsMargins(8, 8, 8, 8)
        self._schedules_layout.setSpacing(4)
        layout.addWidget(sched_list)
        self._refresh_schedules()
        self._build_subnet_section(layout)
        self._build_advisor_section(layout)

    def _on_add_schedule(self):
        if not self._db:
            return
        target = self._schedule_target.text().strip()
        if not target:
            return
        interval_map = {"Every 1h": 1, "Every 4h": 4, "Every 24h": 24}
        interval_h = interval_map.get(self._schedule_interval.currentText(), 24)
        s = Schedule(id=None, target=target, interval_h=interval_h,
                     enabled=True, last_run=None,
                     created_at=datetime.now(timezone.utc).isoformat())
        self._db.insert_schedule(s)
        self._schedule_target.clear()
        self._refresh_schedules()

    def _refresh_schedules(self):
        if self._schedules_layout is None:
            return
        while self._schedules_layout.count():
            item = self._schedules_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not self._db:
            return
        for sched in self._db.query_schedules():
            row = QLabel(
                f"{sched.target}  ·  Every {sched.interval_h}h  ·  "
                f"{'Enabled' if sched.enabled else 'Disabled'}"
            )
            row.setStyleSheet(f"color: {TXT2}; font-size: 11px;")
            self._schedules_layout.addWidget(row)

    def _build_advisor_section(self, layout: QVBoxLayout) -> None:
        advisor_label = QLabel("AI ADVISOR")
        advisor_label.setStyleSheet(f"color: {TXT3}; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(advisor_label)

        self._advisor_enabled_cb = QCheckBox("Enable AI Advisor")
        self._advisor_enabled_cb.setStyleSheet(f"color: {TXT};")
        enabled = self._db is not None and self._db.get_setting("ai_advisor_enabled") == "1"
        self._advisor_enabled_cb.setChecked(enabled)
        self._advisor_enabled_cb.toggled.connect(self._on_advisor_toggled)
        layout.addWidget(self._advisor_enabled_cb)

        backend_row = QHBoxLayout()
        backend_lbl = QLabel("Backend:")
        backend_lbl.setStyleSheet(f"color: {TXT2}; font-size: 11px;")
        self._advisor_backend_combo = QComboBox()
        self._advisor_backend_combo.addItems(["Gemini (cloud)", "Ollama (local)"])
        saved_backend = (self._db.get_setting("advisor_backend") if self._db else None) or "gemini"
        self._advisor_backend_combo.setCurrentIndex(0 if saved_backend == "gemini" else 1)
        self._advisor_backend_combo.setEnabled(enabled)
        self._advisor_backend_combo.currentIndexChanged.connect(self._on_backend_changed)
        backend_row.addWidget(backend_lbl)
        backend_row.addWidget(self._advisor_backend_combo)
        backend_row.addStretch()
        layout.addLayout(backend_row)

        self._api_key_input = QLineEdit()
        self._api_key_input.setPlaceholderText("Gemini API key")
        self._api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        if self._db:
            saved_key = self._db.get_setting("gemini_api_key")
            if saved_key:
                self._api_key_input.setText(saved_key)
        layout.addWidget(self._api_key_input)

        self._ollama_model_input = QLineEdit()
        self._ollama_model_input.setPlaceholderText("Ollama model (e.g. llama3, mistral)")
        if self._db:
            saved_model = self._db.get_setting("ollama_model")
            self._ollama_model_input.setText(saved_model or "llama3")
        layout.addWidget(self._ollama_model_input)

        self._sync_backend_inputs(enabled)

        save_row = QHBoxLayout()
        self._advisor_save_btn = QPushButton("Save")
        self._advisor_save_btn.setFixedWidth(80)
        self._advisor_save_btn.clicked.connect(self._on_save_advisor_settings)
        save_row.addWidget(self._advisor_save_btn)
        save_row.addStretch()
        layout.addLayout(save_row)

    def _sync_backend_inputs(self, enabled: bool) -> None:
        if not enabled:
            if self._api_key_input:
                self._api_key_input.setEnabled(False)
            if self._ollama_model_input:
                self._ollama_model_input.setEnabled(False)
            return
        is_ollama = (
            self._advisor_backend_combo is not None
            and self._advisor_backend_combo.currentIndex() == 1
        )
        if self._api_key_input:
            self._api_key_input.setEnabled(not is_ollama)
        if self._ollama_model_input:
            self._ollama_model_input.setEnabled(is_ollama)

    def _on_advisor_toggled(self, checked: bool) -> None:
        if self._advisor_backend_combo:
            self._advisor_backend_combo.setEnabled(checked)
        self._sync_backend_inputs(checked)

    def _on_backend_changed(self, _index: int) -> None:
        enabled = self._advisor_enabled_cb.isChecked() if self._advisor_enabled_cb else False
        self._sync_backend_inputs(enabled)

    def _on_save_advisor_settings(self) -> None:
        if not self._db:
            return
        self._db.set_setting(
            "ai_advisor_enabled",
            "1" if self._advisor_enabled_cb.isChecked() else "0",
        )
        backend = (
            "ollama"
            if self._advisor_backend_combo and self._advisor_backend_combo.currentIndex() == 1
            else "gemini"
        )
        self._db.set_setting("advisor_backend", backend)
        if self._api_key_input:
            self._db.set_setting("gemini_api_key", self._api_key_input.text().strip())
        if self._ollama_model_input:
            self._db.set_setting("ollama_model", self._ollama_model_input.text().strip() or "llama3")

    def _build_subnet_section(self, layout: QVBoxLayout) -> None:
        subnet_label = QLabel("INTERNAL SUBNET RANGES")
        subnet_label.setStyleSheet(f"color: {TXT3}; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(subnet_label)

        self._subnet_input = QLineEdit()
        self._subnet_input.setPlaceholderText("192.168.1.0/24, 10.0.0.0/24")
        if self._db:
            saved = self._db.get_setting("internal_subnets")
            if saved:
                self._subnet_input.setText(saved)
        layout.addWidget(self._subnet_input)

        save_subnet_row = QHBoxLayout()
        save_subnet_btn = QPushButton("Save")
        save_subnet_btn.setFixedWidth(80)
        save_subnet_btn.clicked.connect(self._on_save_subnets)
        save_subnet_row.addWidget(save_subnet_btn)
        save_subnet_row.addStretch()
        layout.addLayout(save_subnet_row)

    def _on_save_subnets(self) -> None:
        if not self._db or not self._subnet_input:
            return
        self._db.set_setting("internal_subnets", self._subnet_input.text().strip())

    def _build_tool_row(self, tool: str, present: bool, is_critical: bool) -> QFrame:
        row = QFrame()
        row.setObjectName("panel")
        row.setFixedHeight(44)

        h = QHBoxLayout(row)
        h.setContentsMargins(12, 0, 12, 0)
        h.setSpacing(12)

        status_dot = QLabel("✓" if present else "✗")
        status_dot.setStyleSheet(
            f"color: {SUCCESS if present else CRITICAL}; font-size: 14px;"
        )
        status_dot.setFixedWidth(20)

        name_label = QLabel(tool)
        name_label.setStyleSheet(f"color: {TXT}; font-family: monospace;")

        if is_critical:
            critical_tag = QLabel("CRITICAL")
            critical_tag.setStyleSheet(
                f"color: {_COLOR_CRITICAL}; font-size: 9px; "
                f"border: 1px solid {_COLOR_CRITICAL}; border-radius: 3px; padding: 1px 4px;"
            )
        else:
            critical_tag = QLabel("")
            critical_tag.setFixedWidth(0)

        path_input = QLineEdit()
        path_input.setPlaceholderText(f"/usr/bin/{tool}")
        path_input.setFixedWidth(220)
        path_input.setEnabled(False)

        h.addWidget(status_dot)
        h.addWidget(name_label)
        h.addWidget(critical_tag)
        h.addStretch()
        h.addWidget(path_input)

        return row
