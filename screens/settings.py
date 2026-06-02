from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QScrollArea,
)
from tool_checker import TOOLS, CRITICAL_TOOLS


class SettingsScreen(QWidget):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._tool_rows: dict[str, dict] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Settings")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(title)

        section_label = QLabel("TOOL STATUS")
        section_label.setStyleSheet("color: #64748b; font-size: 10px; letter-spacing: 1px;")
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

    def _build_tool_row(self, tool: str, present: bool, is_critical: bool) -> QFrame:
        row = QFrame()
        row.setObjectName("panel")
        row.setFixedHeight(44)

        h = QHBoxLayout(row)
        h.setContentsMargins(12, 0, 12, 0)
        h.setSpacing(12)

        status_dot = QLabel("✓" if present else "✗")
        status_dot.setStyleSheet(
            f"color: {'#00ff88' if present else '#ff4444'}; font-size: 14px;"
        )
        status_dot.setFixedWidth(20)

        name_label = QLabel(tool)
        name_label.setStyleSheet("color: #e2e8f0; font-family: monospace;")

        if is_critical:
            critical_tag = QLabel("CRITICAL")
            critical_tag.setStyleSheet(
                "color: #ff8800; font-size: 9px; "
                "border: 1px solid #ff8800; border-radius: 3px; padding: 1px 4px;"
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
