from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel
from tool_checker import is_critical_missing, ready_count, TOOLS
from screens.widgets.morphism import StatusLED


class ToolStatusBar(QWidget):
    navigate_to_settings = pyqtSignal()

    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("status-bar-widget")
        self.setFixedHeight(28)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._tool_results = tool_results
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(6)

        n_ready = ready_count(self._tool_results)
        total = len(TOOLS)

        self._label = QLabel(f"Tools: {n_ready}/{total} ready")
        self._label.setStyleSheet("color: #71717A; font-size: 11px; background: transparent;")

        self._dot = StatusLED(self._dot_color())

        layout.addStretch()
        layout.addWidget(self._label)
        layout.addWidget(self._dot)

    def _dot_color(self) -> str:
        if is_critical_missing(self._tool_results):
            return "#ff4444"
        if ready_count(self._tool_results) < len(TOOLS):
            return "#ffaa00"
        return "#00ff88"

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.navigate_to_settings.emit()
        super().mousePressEvent(event)
