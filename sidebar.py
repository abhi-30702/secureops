from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel

from screens.widgets import theme as T

# Fixed, always-labelled rail. Constants kept for backwards-compatible imports.
SIDEBAR_WIDTH = 212
COLLAPSED_WIDTH = SIDEBAR_WIDTH
EXPANDED_WIDTH = SIDEBAR_WIDTH

# (icon, label, screen_index, group) — display order; screen_index targets the stack.
_NAV_ITEMS = [
    ("▣", "Dashboard", 0, "Monitor"),
    ("⚡", "Scan", 2, "Assess"),
    ("⬡", "Internal", 5, "Assess"),
    ("☁", "Cloud", 8, "Assess"),
    ("\U0001f50d", "OSINT", 7, "Assess"),
    ("\U0001f525", "Incident", 6, "Respond"),
    ("\U0001f4c4", "Report", 3, "Manage"),
    ("＋", "Companies", 1, "Manage"),
    ("⚙", "Settings", 4, "Manage"),
]


class Sidebar(QWidget):
    screen_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self._active_index = 0
        # Buttons indexed by screen index (so _buttons[i] navigates to screen i),
        # regardless of the grouped display order. main_window + tests rely on this.
        self._buttons: list[QPushButton | None] = [None] * 9
        self._setup_ui()

    def _setup_ui(self):
        self.setFixedWidth(SIDEBAR_WIDTH)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo = QLabel("\U0001f512  SecureOps")
        logo.setFixedHeight(56)
        logo.setContentsMargins(18, 0, 0, 0)
        logo.setStyleSheet(
            f"color: {T.ACCENT}; font-size: {T.FS_TITLE}px; font-weight: bold;"
        )
        layout.addWidget(logo)

        current_group = None
        for icon, label, index, group in _NAV_ITEMS:
            if group != current_group:
                current_group = group
                hdr = QLabel(group.upper())
                hdr.setContentsMargins(18, 10, 0, 4)
                hdr.setStyleSheet(T.overline(T.TXT3, T.FS_TINY))
                layout.addWidget(hdr)

            btn = QPushButton(f"  {icon}   {label}")
            btn.setObjectName("nav-btn")
            btn.setFixedHeight(40)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(label)
            btn.setProperty("active", "false")
            btn.clicked.connect(lambda _checked=False, i=index: self._on_nav_click(i))
            self._buttons[index] = btn
            layout.addWidget(btn)

        layout.addStretch()

        version = QLabel("v1.2.0")
        version.setContentsMargins(18, 0, 0, 0)
        version.setFixedHeight(32)
        version.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_TINY}px;")
        layout.addWidget(version)

        self._refresh_active_styles()

    def _on_nav_click(self, index: int):
        self._active_index = index
        self._refresh_active_styles()
        self.screen_changed.emit(index)

    def _refresh_active_styles(self):
        for i, btn in enumerate(self._buttons):
            if btn is None:
                continue
            btn.setProperty("active", "true" if i == self._active_index else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    @property
    def active_index(self) -> int:
        return self._active_index
