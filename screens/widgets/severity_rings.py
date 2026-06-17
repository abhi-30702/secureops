from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QRect, pyqtProperty
from PyQt6.QtWidgets import QWidget, QHBoxLayout
from PyQt6.QtGui import QPainter, QPen, QColor, QFont

from screens.widgets.theme import TXT, TXT3, BORDER, SEVERITY_COLORS

_SEVERITIES = ["critical", "high", "medium", "low"]
_SEVERITY_COLORS = SEVERITY_COLORS


class _RingWidget(QWidget):
    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self._severity = severity
        self._color = _SEVERITY_COLORS[severity]
        self._count = 0
        self._fill = 0.0
        self._animation: QPropertyAnimation | None = None
        self.setFixedSize(110, 130)

    def _get_fill(self) -> float:
        return self._fill

    def _set_fill(self, value: float):
        self._fill = value
        self.update()

    fill = pyqtProperty(float, _get_fill, _set_fill)

    def increment(self):
        self._count += 1
        new_fill = self._count / max(self._count, 10)
        if self._animation:
            self._animation.stop()
        self._animation = QPropertyAnimation(self, b"fill", self)
        self._animation.setDuration(300)
        self._animation.setStartValue(self._fill)
        self._animation.setEndValue(new_fill)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.start()

    def reset(self):
        if self._animation:
            self._animation.stop()
            self._animation = None
        self._count = 0
        self._fill = 0.0
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = QRect(15, 10, 80, 80)

        bg_pen = QPen(QColor(BORDER))
        bg_pen.setWidth(12)
        bg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(bg_pen)
        painter.drawArc(rect, 0, 360 * 16)

        if self._fill > 0:
            fg_pen = QPen(QColor(self._color))
            fg_pen.setWidth(12)
            fg_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            painter.setPen(fg_pen)
            start = 90 * 16
            span = -int(self._fill * 360 * 16)
            painter.drawArc(rect, start, span)

        painter.setPen(QColor(TXT))
        f = QFont()
        f.setBold(True)
        f.setPointSize(16)
        painter.setFont(f)
        painter.drawText(QRect(0, 10, 110, 80), Qt.AlignmentFlag.AlignCenter, str(self._count))

        painter.setPen(QColor(TXT3))
        f2 = QFont()
        f2.setPointSize(8)
        painter.setFont(f2)
        painter.drawText(QRect(0, 95, 110, 20), Qt.AlignmentFlag.AlignCenter, self._severity.upper())

    @property
    def count(self) -> int:
        return self._count


class SeverityRings(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rings: dict[str, _RingWidget] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)
        for sev in _SEVERITIES:
            ring = _RingWidget(sev)
            self._rings[sev] = ring
            layout.addWidget(ring)

    def add_finding(self, finding):
        if finding.severity in self._rings:
            self._rings[finding.severity].increment()

    def on_scan_complete(self, hosts: int, findings: int):
        pass  # intentionally empty — rings freeze on scan complete

    def reset(self):
        for ring in self._rings.values():
            ring.reset()
