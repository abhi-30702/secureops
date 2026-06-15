from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel

COLLAPSED_WIDTH = 52
EXPANDED_WIDTH = 180

_NAV_ITEMS = [
    ("⊞", "Dashboard", 0),
    ("+", "New Client", 1),
    ("⚡", "Scan", 2),
    ("📄", "Report", 3),
    ("⚙", "Settings", 4),
    ("⬡", "Internal", 5),
    ("🔥", "Incident", 6),
    ("🔍", "OSINT", 7),
]


class Sidebar(QWidget):
    screen_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self._active_index = 0
        self._buttons: list[QPushButton] = []
        self._setup_ui()
        self._setup_animation()

    def _setup_ui(self):
        self.setMinimumWidth(COLLAPSED_WIDTH)
        self.setMaximumWidth(COLLAPSED_WIDTH)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo = QLabel("🔒")
        logo.setFixedHeight(52)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size: 20px;")
        layout.addWidget(logo)

        for icon, label, index in _NAV_ITEMS:
            btn = QPushButton(icon)
            btn.setObjectName("nav-btn")
            btn.setFixedHeight(48)
            btn.setToolTip(label)
            btn.setProperty("active", False)
            btn.clicked.connect(lambda checked, i=index: self._on_nav_click(i))
            self._buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        version = QLabel("v0.1.0")
        version.setFixedHeight(32)
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #64748b; font-size: 10px;")
        layout.addWidget(version)

        self._refresh_active_styles()

    def _setup_animation(self):
        self._animation = QPropertyAnimation(self, b"maximumWidth")
        self._animation.setDuration(150)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def _on_nav_click(self, index: int):
        self._active_index = index
        self._refresh_active_styles()
        self.screen_changed.emit(index)

    def _refresh_active_styles(self):
        for i, btn in enumerate(self._buttons):
            btn.setProperty("active", str(i == self._active_index).lower())
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def enterEvent(self, event):
        self._animate_to(EXPANDED_WIDTH)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_to(COLLAPSED_WIDTH)
        super().leaveEvent(event)

    def _animate_to(self, width: int):
        self._animation.stop()
        self._animation.setStartValue(self.maximumWidth())
        self._animation.setEndValue(width)
        self._animation.start()

    @property
    def active_index(self) -> int:
        return self._active_index
