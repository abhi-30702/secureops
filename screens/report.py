from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFrame,
)


class ReportScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._export_btn: QPushButton | None = None
        self._placeholder_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Report")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(title)

        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._placeholder_label = QLabel(
            "Report assembles here during scan\nPhase 4"
        )
        self._placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder_label.setStyleSheet("color: #64748b; font-size: 14px;")

        subtitle = QLabel("Run a scan to generate a report")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #64748b; font-size: 11px;")

        panel_layout.addWidget(self._placeholder_label)
        panel_layout.addWidget(subtitle)
        layout.addWidget(panel, stretch=1)

        self._export_btn = QPushButton("Export PDF")
        self._export_btn.setEnabled(False)
        self._export_btn.setToolTip("PDF export available in Phase 4")
        layout.addWidget(self._export_btn)
