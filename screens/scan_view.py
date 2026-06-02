from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QSplitter,
)
from db import DB


def _placeholder_panel(text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class ScanViewScreen(QWidget):
    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._pipeline_panel: QFrame | None = None
        self._attack_graph_panel: QFrame | None = None
        self._severity_panel: QFrame | None = None
        self._finding_cards_panel: QFrame | None = None
        self._terminal_panel: QFrame | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(False)
        self._start_btn.setToolTip("Scan engine available in Phase 2")
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        self._pipeline_panel = _placeholder_panel("Pipeline Tracker\nPhase 3")
        self._attack_graph_panel = _placeholder_panel("Attack Surface Graph\nPhase 3")
        self._severity_panel = _placeholder_panel("Severity\nRings\nPhase 3")
        self._finding_cards_panel = _placeholder_panel("Finding Cards Stream\nPhase 3")
        self._terminal_panel = _placeholder_panel("Terminal Feed\nPhase 3")

        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._pipeline_panel)
        top_splitter.addWidget(self._attack_graph_panel)
        top_splitter.setSizes([250, 750])

        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.addWidget(self._severity_panel)
        mid_splitter.addWidget(self._finding_cards_panel)
        mid_splitter.setSizes([250, 750])

        top_mid = QWidget()
        top_mid_layout = QVBoxLayout(top_mid)
        top_mid_layout.setContentsMargins(0, 0, 0, 0)
        top_mid_layout.setSpacing(8)
        top_mid_layout.addWidget(top_splitter, stretch=1)
        top_mid_layout.addWidget(mid_splitter, stretch=1)

        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_mid)
        main_splitter.addWidget(self._terminal_panel)
        main_splitter.setSizes([800, 200])

        layout.addWidget(main_splitter, stretch=1)
