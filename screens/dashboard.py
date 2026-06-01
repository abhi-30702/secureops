from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
)
from tool_checker import is_critical_missing


class MetricCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("panel")
        self.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #64748b; font-size: 11px; text-transform: uppercase;")

        value_label = QLabel("0")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #e2e8f0;")

        layout.addWidget(title_label)
        layout.addWidget(value_label)


def _placeholder_panel(label_text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(label_text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class SeverityStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)

        for color, label in [
            ("#ff4444", "Critical"), ("#ff8800", "High"),
            ("#ffcc00", "Medium"), ("#4488ff", "Low"),
        ]:
            dot = QLabel(f"<span style='color:{color}'>●</span>  {label}  <b>0</b>")
            dot.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(dot)


class DashboardScreen(QWidget):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._metric_cards: list[MetricCard] = []
        self._warning_banner: QLabel | None = None
        self._severity_strip: SeverityStrip | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Warning banner (hidden by default)
        self._warning_banner = QLabel(
            "⚠  Critical tools missing — check Settings"
        )
        self._warning_banner.setStyleSheet(
            "background-color: #3d2800; color: #ffaa00; "
            "padding: 6px 12px; border: 1px solid #ffaa00; border-radius: 4px;"
        )
        self._warning_banner.setVisible(is_critical_missing(self._tool_results))
        layout.addWidget(self._warning_banner)

        # Metric cards
        cards_row = QHBoxLayout()
        for title in ("Clients", "Scans", "Findings"):
            card = MetricCard(title)
            self._metric_cards.append(card)
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # Middle panels
        middle_row = QHBoxLayout()
        middle_row.addWidget(
            _placeholder_panel("Attack Surface Graph\nLive in Phase 3"), stretch=1
        )
        middle_row.addWidget(
            _placeholder_panel("Threat Feed\nLive in Phase 3"), stretch=1
        )
        layout.addLayout(middle_row)

        # Severity strip
        self._severity_strip = SeverityStrip()
        layout.addWidget(self._severity_strip)

        layout.addStretch()
