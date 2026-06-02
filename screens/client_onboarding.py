from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QTextEdit, QPushButton, QFormLayout, QFrame,
)


class ClientOnboardingScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._company_name_input: QLineEdit | None = None
        self._domain_input: QLineEdit | None = None
        self._firewall_combo: QComboBox | None = None
        self._notes_input: QTextEdit | None = None
        self._save_btn: QPushButton | None = None
        self._confirmation_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        title = QLabel("New Client")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        outer.addWidget(title)

        card = QFrame()
        card.setObjectName("panel")
        form_layout = QFormLayout(card)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(12)

        self._company_name_input = QLineEdit()
        self._company_name_input.setPlaceholderText("Acme Corp")
        form_layout.addRow("Company Name", self._company_name_input)

        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("example.com")
        form_layout.addRow("Domain", self._domain_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(["None", "pfSense", "Cisco ASA", "Fortinet", "Other"])
        form_layout.addRow("Firewall Type", self._firewall_combo)

        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Additional notes...")
        self._notes_input.setFixedHeight(80)
        form_layout.addRow("Notes", self._notes_input)

        outer.addWidget(card)

        self._save_btn = QPushButton("Save Client")
        self._save_btn.clicked.connect(self._on_save)
        outer.addWidget(self._save_btn)

        self._confirmation_label = QLabel("✓  Client saved (not persisted yet)")
        self._confirmation_label.setStyleSheet("color: #00ff88;")
        self._confirmation_label.setVisible(False)
        outer.addWidget(self._confirmation_label)

        outer.addStretch()

    def _on_save(self):
        self._confirmation_label.setVisible(True)
        QTimer.singleShot(2000, lambda: self._confirmation_label.setVisible(False))
