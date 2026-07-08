"""SecureOps multi-morphism widget library.

Reusable, theme-driven components. Each morphism owns a semantic role
(see STYLE_GUIDE.md):

    glass → GlassPanel, GlassCard, TitleBar        (structure & surfaces)
    neu   → NeuButton, NeuLineEdit, NeuToggleTab    (interactive controls)
    clay  → ClayStatTile, ClaySeverityCard, SeverityBadge  (data callouts)
    skeu  → TerminalOutput, ToggleSwitch, StatusLED (physical elements)

QSS can't do backdrop-filter or box-shadow, so depth is produced with
QPainter (painted dual/soft shadows, gradients, scanlines, glow) and a single
shared QGraphicsDropShadowEffect per widget where a soft outer shadow suffices.
"""
from __future__ import annotations

from PyQt6.QtCore import (
    Qt, QRectF, QRect, QPoint, pyqtSignal, pyqtProperty,
    QPropertyAnimation, QVariantAnimation, QEasingCurve, QSize,
)
from PyQt6.QtGui import (
    QPainter, QColor, QLinearGradient, QRadialGradient, QPainterPath,
    QFont, QPen, QBrush,
)
from PyQt6.QtWidgets import (
    QWidget, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QPlainTextEdit, QGraphicsDropShadowEffect,
)

from screens.widgets import theme as T


# ── shared painting helpers ──────────────────────────────────────────────────
_NEU_MARGIN = 3  # small inset so controls breathe (flat theme — no shadow room needed)


def apply_elevation(widget: QWidget, name: str = "glass") -> QGraphicsDropShadowEffect:
    """Attach one soft drop shadow from a theme preset (reused, not hand-tuned)."""
    blur, dx, dy, rgba = T.elevation(name)
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    eff.setXOffset(dx)
    eff.setYOffset(dy)
    eff.setColor(QColor(*rgba))
    widget.setGraphicsEffect(eff)
    return eff


def _soft_shadow(p: QPainter, rect: QRectF, radius: float, rgba, dx, dy,
                 layers: int = 6, spread: float = 7.0):
    """Fake a Gaussian blur: stack translucent rounded rects fading outward."""
    r, g, b, a = rgba
    p.setPen(Qt.PenStyle.NoPen)
    for i in range(layers, 0, -1):
        frac = i / layers
        alpha = int(a * (1.0 - frac) ** 1.7)
        if alpha <= 0:
            continue
        grow = spread * frac
        p.setBrush(QColor(r, g, b, alpha))
        rr = QRectF(rect).adjusted(dx - grow, dy - grow, dx + grow, dy + grow)
        p.drawRoundedRect(rr, radius + grow, radius + grow)


def paint_neu(p: QPainter, rect: QRectF, radius: float, pressed: bool,
              active: bool = False):
    """Paint a flat control surface. `pressed`/`active` → filled graphite tint."""
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    on = pressed or active
    fill = QColor(T.ACCENT_SOFT if on else T.CARD)
    edge = QColor(T.ACCENT if on else T.BORDER_STRONG)
    p.setPen(QPen(edge, 1.4))
    p.setBrush(fill)
    p.drawRoundedRect(rect, radius, radius)


# ── skeuomorphic root background (mesh gradient) ──────────────────────────────
class RootBackground(QWidget):
    """Flat app background — a barely-there vertical light gradient."""

    def paintEvent(self, event):
        p = QPainter(self)
        rect = self.rect()
        grad = QLinearGradient(0, 0, 0, rect.height())
        for pos, hexc in T.MESH_STOPS:
            grad.setColorAt(pos, QColor(hexc))
        p.fillRect(rect, grad)


# ── glass (structure & surfaces) ─────────────────────────────────────────────
class GlassPanel(QFrame):
    """Flat surface: solid white fill + hairline border (structure role)."""

    def __init__(self, parent=None, strong: bool = False, radius: int = T.RADIUS_LG):
        super().__init__(parent)
        self.setObjectName("glassPanel")
        self._radius = radius
        fill = T.GLASS_FILL_STRONG if strong else T.GLASS_FILL
        self.setStyleSheet(
            f"#glassPanel {{ background: {fill};"
            f" border: 1px solid {T.GLASS_HAIRLINE};"
            f" border-radius: {radius}px; }}"
        )


class GlassCard(GlassPanel):
    """Glass panel with a vertical content layout + optional section title."""

    def __init__(self, title: str = "", parent=None, radius: int = T.RADIUS_LG):
        super().__init__(parent, radius=radius)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(T.SP_LG, T.SP_MD, T.SP_LG, T.SP_MD)
        self._layout.setSpacing(T.SP_SM)
        if title:
            lbl = QLabel(title.upper())
            lbl.setStyleSheet(T.overline(T.ACCENT, T.FS_TINY) + " background: transparent;")
            self._layout.addWidget(lbl)

    def body(self) -> QVBoxLayout:
        return self._layout

    def add(self, widget: QWidget, stretch: int = 0) -> None:
        self._layout.addWidget(widget, stretch)

    def add_layout(self, layout) -> None:
        self._layout.addLayout(layout)


# ── neumorphism (interactive controls) ───────────────────────────────────────
class NeuButton(QPushButton):
    """Soft extruded button; presses inset. Also works as a checkable tab."""

    def __init__(self, text: str = "", parent=None, accent: bool = False):
        super().__init__(text, parent)
        self._accent = accent
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(38 + _NEU_MARGIN)
        self.setFlat(True)

    def sizeHint(self) -> QSize:
        s = super().sizeHint()
        return QSize(s.width() + 2 * _NEU_MARGIN + 12, max(s.height() + 2 * _NEU_MARGIN, 40))

    def paintEvent(self, event):
        p = QPainter(self)
        rect = QRectF(self.rect()).adjusted(_NEU_MARGIN, _NEU_MARGIN,
                                            -_NEU_MARGIN, -_NEU_MARGIN)
        active = self.isChecked() or self._accent
        paint_neu(p, rect, T.RADIUS_MD, self.isDown(), active=active)

        p.setPen(QColor(T.ACCENT if active else T.TXT2))
        f = self.font(); f.setBold(True)
        p.setFont(f)
        p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.text())


class NeuLineEdit(QLineEdit):
    """Inset (carved-in) text field."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(38)
        self.setStyleSheet(
            f"QLineEdit {{ background: {T.INPUT}; border: 1px solid {T.BORDER};"
            f" border-radius: {T.RADIUS_MD}px; padding: 8px 12px;"
            f" color: {T.TXT}; selection-background-color: {T.ACCENT};"
            f" selection-color: #FFFFFF; }}"
            f"QLineEdit:focus {{ border: 1.5px solid {T.ACCENT}; }}"
        )


# ── claymorphism (key data callouts) ─────────────────────────────────────────
def _paint_clay(p: QPainter, rect: QRectF, radius: float, tint: QColor | None = None):
    """Flat card: solid white fill + hairline border (data-callout role)."""
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(QPen(QColor(T.BORDER), 1))
    p.setBrush(QColor(T.CARD))
    p.drawRoundedRect(rect, radius, radius)


class ClayStatTile(QFrame):
    """A pillowy metric tile: big value over an uppercase caption + accent bar."""

    def __init__(self, title: str, accent: str = T.ACCENT, parent=None):
        super().__init__(parent)
        self.title = title
        self._accent = accent
        self.setMinimumHeight(96)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_LG, T.SP_MD, T.SP_LG, T.SP_MD)
        layout.setSpacing(2)

        self._value_label = QLabel("0")
        self._value_label.setStyleSheet(
            f"color: {accent}; font-size: 32px; font-weight: bold; background: transparent;"
        )
        caption = QLabel(title.upper())
        caption.setStyleSheet(T.overline(T.TXT3, T.FS_TINY) + " background: transparent;")

        layout.addWidget(self._value_label)
        layout.addWidget(caption)

    def paintEvent(self, event):
        p = QPainter(self)
        rect = QRectF(self.rect()).adjusted(2, 2, -2, -2)
        _paint_clay(p, rect, T.RADIUS_LG, QColor(self._accent))
        # slim accent underline (kept — the one bit of colour on the tile)
        pen = QPen(QColor(self._accent)); pen.setWidth(2)
        p.setPen(pen)
        y = rect.bottom() - 12
        p.drawLine(int(rect.left() + 16), int(y), int(rect.left() + 40), int(y))

    def set_value(self, n) -> None:
        self._value_label.setText(str(n))


class ClaySeverityCard(QFrame):
    """Severity callout: coloured clay tile, animated count, share bar."""

    def __init__(self, severity: str, parent=None):
        super().__init__(parent)
        self._severity = severity
        self._color = T.SEVERITY_COLORS[severity]
        self._count = 0
        self._frac = 0.0
        self._anim: QVariantAnimation | None = None
        self.setFixedHeight(70)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 9, 14, 9)
        lay.setSpacing(6)

        top = QHBoxLayout(); top.setSpacing(6)
        self._name = QLabel(severity.upper())
        self._name.setStyleSheet(
            f"color: {T.TXT2}; font-size: {T.FS_TINY}px; font-weight: bold;"
            " letter-spacing: 1px; background: transparent;"
        )
        self._num = QLabel("0")
        self._num.setStyleSheet(
            f"color: {self._color}; font-size: 22px; font-weight: bold; background: transparent;"
        )
        self._num.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        top.addWidget(self._name); top.addStretch(1); top.addWidget(self._num)
        lay.addLayout(top)
        lay.addStretch(1)

    def paintEvent(self, event):
        p = QPainter(self)
        rect = QRectF(self.rect()).adjusted(2, 1, -2, -2)
        _paint_clay(p, rect, T.RADIUS_MD, QColor(self._color))
        # left coloured accent bar
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(self._color))
        p.drawRoundedRect(QRectF(rect.left() + 4, rect.top() + 8,
                                 3, rect.height() - 16), 1.5, 1.5)
        # share bar along the bottom
        track = QRectF(rect.left() + 14, rect.bottom() - 9, rect.width() - 28, 4)
        p.setBrush(QColor(0, 0, 0, 90)); p.drawRoundedRect(track, 2, 2)
        if self._frac > 0:
            fill = QRectF(track.left(), track.top(), track.width() * self._frac, track.height())
            p.setBrush(QColor(self._color)); p.drawRoundedRect(fill, 2, 2)

    @property
    def count(self) -> int:
        return self._count

    def increment(self):
        start = self._count
        self._count += 1
        if self._anim:
            self._anim.stop()
        anim = QVariantAnimation(self)
        anim.setStartValue(int(start)); anim.setEndValue(int(self._count))
        anim.setDuration(280); anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.valueChanged.connect(lambda v: self._num.setText(str(int(v))))
        anim.finished.connect(lambda: self._num.setText(str(self._count)))
        anim.start()
        self._anim = anim

    def set_proportion(self, frac: float):
        self._frac = max(0.0, min(1.0, frac))
        self.update()

    def reset(self):
        if self._anim:
            self._anim.stop(); self._anim = None
        self._count = 0
        self._frac = 0.0
        self._num.setText("0")
        self.update()


class SeverityBadge(QLabel):
    """A clay pill coloured by severity/intent."""

    def __init__(self, text: str, color: str = T.ACCENT, parent=None):
        super().__init__(text.upper(), parent)
        self.setStyleSheet(
            f"background: {color}; color: #FFFFFF; border-radius: {T.RADIUS_PILL}px;"
            f" padding: 2px 11px; font-size: {T.FS_TINY}px; font-weight: bold;"
            " letter-spacing: 1px;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


# ── skeuomorphism (physical elements) ────────────────────────────────────────
class _Scanlines(QWidget):
    """Transparent overlay that paints faint CRT scanlines over the terminal."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setPen(QColor(0, 0, 0, 26))
        h = self.height()
        y = 0
        while y < h:
            p.drawLine(0, y, self.width(), y)
            y += 3


class TerminalOutput(QFrame):
    """Skeuomorphic console: dark panel, prompt header, scanlines, mono output."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("termWrap")
        self.setStyleSheet(
            f"#termWrap {{ background: {T.TERMINAL_BG};"
            f" border: 1px solid {T.BORDER}; border-radius: {T.RADIUS_MD}px; }}"
        )
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        header = QWidget()
        header.setObjectName("termHeader")
        header.setFixedHeight(30)
        header.setStyleSheet(
            f"#termHeader {{ background: {T.TERMINAL_BG};"
            f" border-top-left-radius: {T.RADIUS_MD}px;"
            f" border-top-right-radius: {T.RADIUS_MD}px;"
            f" border-bottom: 1px solid {T.BORDER}; }}"
        )
        h = QHBoxLayout(header)
        h.setContentsMargins(14, 0, 14, 0); h.setSpacing(8)
        prompt = QLabel("❯")
        prompt.setStyleSheet(
            f"color: {T.SUCCESS}; font-family: {T.FONT_MONO};"
            f" font-size: {T.FS_BODY}px; font-weight: bold; background: transparent;"
        )
        title = QLabel("scan output")
        title.setStyleSheet(
            f"color: {T.TERMINAL_TXT}; font-family: {T.FONT_MONO};"
            f" font-size: {T.FS_SMALL}px; letter-spacing: 0.5px; background: transparent;"
        )
        tag = QLabel("LIVE OUTPUT")
        tag.setStyleSheet(
            f"color: {T.TXT3}; font-family: {T.FONT_MONO};"
            f" font-size: {T.FS_TINY}px; letter-spacing: 2px; background: transparent;"
        )
        h.addWidget(prompt); h.addWidget(title); h.addStretch(1); h.addWidget(tag)
        v.addWidget(header)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet(
            f"QPlainTextEdit {{ background: {T.TERMINAL_BG}; color: {T.TERMINAL_TXT};"
            f" font-family: {T.FONT_MONO}; font-size: {T.FS_SMALL}px;"
            f" border: none; padding: 8px; selection-background-color: {T.ACCENT}; }}"
            "QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }"
            "QScrollBar::handle:vertical { background: #3A3A40; border-radius: 4px;"
            " min-height: 24px; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        )
        v.addWidget(self.output, 1)

        self._scan = _Scanlines(self.output)
        self._scan.hide()  # subtle; enable via set_scanlines(True)

    def set_scanlines(self, on: bool):
        self._scan.setVisible(on)
        if on:
            self._scan.resize(self.output.size())
            self._scan.raise_()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._scan.isVisible():
            self._scan.resize(self.output.size())

    # convenience passthroughs
    def appendPlainText(self, text: str):
        self.output.appendPlainText(text)

    def clear(self):
        self.output.clear()


class ToggleSwitch(QWidget):
    """Skeuomorphic sliding switch with a glowing 'on' state."""

    toggled = pyqtSignal(bool)

    def __init__(self, checked: bool = False, parent=None):
        super().__init__(parent)
        self._checked = checked
        self._pos = 1.0 if checked else 0.0
        self._anim: QPropertyAnimation | None = None
        self.setFixedSize(48, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, val: bool):
        if val == self._checked:
            return
        self._checked = val
        self._animate()
        self.toggled.emit(val)

    def _get_pos(self) -> float:
        return self._pos

    def _set_pos(self, v: float):
        self._pos = v
        self.update()

    knob = pyqtProperty(float, _get_pos, _set_pos)

    def _animate(self):
        if self._anim:
            self._anim.stop()
        self._anim = QPropertyAnimation(self, b"knob", self)
        self._anim.setDuration(180)
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if self._checked else 0.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._anim.start()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
        super().mousePressEvent(event)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(1, 1, self.width() - 2, self.height() - 2)
        off = QColor(T.BORDER_STRONG)
        on = QColor(T.ACCENT)
        track = QColor(
            int(off.red() + (on.red() - off.red()) * self._pos),
            int(off.green() + (on.green() - off.green()) * self._pos),
            int(off.blue() + (on.blue() - off.blue()) * self._pos),
        )
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(track)
        p.drawRoundedRect(r, r.height() / 2, r.height() / 2)

        d = r.height() - 6
        x = r.left() + 3 + (r.width() - d - 6) * self._pos
        knob_rect = QRectF(x, r.top() + 3, d, d)
        p.setPen(QPen(QColor(T.BORDER), 1))
        p.setBrush(QColor("#FFFFFF"))
        p.drawEllipse(knob_rect)


class StatusLED(QLabel):
    """A glowing indicator dot. Keeps its colour in the stylesheet (test-safe)."""

    def __init__(self, color: str = T.LED_GREEN, parent=None):
        super().__init__("●", parent)
        self._glow: QGraphicsDropShadowEffect | None = None
        self.set_color(color)

    def set_color(self, color: str):
        self._color = color
        self.setStyleSheet(
            f"color: {color}; font-size: 12px; background: transparent; border: none;"
        )
        glow = QGraphicsDropShadowEffect(self)
        glow.setBlurRadius(9)
        glow.setOffset(0, 0)
        glow.setColor(QColor(color))
        self.setGraphicsEffect(glow)
        self._glow = glow

    def styleSheet(self) -> str:  # explicit — keep colour discoverable by tests
        return super().styleSheet()


# ── glass title bar (frameless window chrome) ────────────────────────────────
class _WinButton(QPushButton):
    def __init__(self, glyph: str, hover: str, hover_text: str = T.TXT, parent=None):
        super().__init__(glyph, parent)
        self._hover = hover
        self.setFixedSize(30, 26)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        # NOTE: reset padding/min-width explicitly. The global QSS `QPushButton`
        # rule sets `padding: 8px 16px`, which this widget's stylesheet would
        # otherwise inherit — with a fixed 30px width that squeezes the glyph out
        # of view, leaving an invisible (transparent) button.
        self.setStyleSheet(
            f"QPushButton {{ background: transparent; border: none; color: {T.TXT3};"
            f" font-size: 13px; font-weight: bold; padding: 0px; margin: 0px;"
            f" min-width: 0px; min-height: 0px; border-radius: {T.RADIUS_SM}px; }}"
            f"QPushButton:hover {{ background: {hover}; color: {hover_text}; }}"
            f"QPushButton:pressed {{ background: {hover}; }}"
        )


class TitleBar(GlassPanel):
    """Draggable frosted title bar with padlock brand + window controls."""

    def __init__(self, window: QWidget, title: str = "SecureOps", parent=None):
        super().__init__(parent, strong=True, radius=0)
        self._win = window
        self._drag_offset: QPoint | None = None
        self.setFixedHeight(44)
        self.setStyleSheet(
            f"#glassPanel {{ background: {T.GLASS_FILL_STRONG};"
            f" border: none; border-bottom: 1px solid {T.GLASS_HAIRLINE}; }}"
        )
        self.setGraphicsEffect(None)  # no shadow on the bar itself

        row = QHBoxLayout(self)
        row.setContentsMargins(14, 0, 8, 0)
        row.setSpacing(10)

        brand = QLabel("\U0001f512")
        brand.setStyleSheet(
            f"color: {T.ACCENT}; font-size: 15px; background: transparent;"
        )

        name = QLabel(title)
        name.setStyleSheet(
            f"color: {T.TXT}; font-size: {T.FS_TITLE}px; font-weight: bold;"
            " background: transparent; letter-spacing: 0.5px;"
        )
        tag = QLabel("SECURITY OPS CONSOLE")
        tag.setStyleSheet(T.overline(T.TXT3, T.FS_TINY) + " background: transparent;")

        row.addWidget(brand)
        row.addWidget(name)
        row.addSpacing(6)
        row.addWidget(tag)
        row.addStretch(1)

        self._min = _WinButton("–", T.HOVER, hover_text=T.TXT)
        self._max = _WinButton("□", T.HOVER, hover_text=T.TXT)
        self._close = _WinButton("✕", T.CRITICAL, hover_text="#FFFFFF")
        self._min.clicked.connect(self._win.showMinimized)
        self._max.clicked.connect(self._toggle_max)
        self._close.clicked.connect(self._win.close)
        row.addWidget(self._min)
        row.addWidget(self._max)
        row.addWidget(self._close)

    def _toggle_max(self):
        if self._win.isMaximized():
            self._win.showNormal()
        else:
            self._win.showMaximized()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_offset = (event.globalPosition().toPoint()
                                 - self._win.frameGeometry().topLeft())
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_offset is not None and not self._win.isMaximized():
            self._win.move(event.globalPosition().toPoint() - self._drag_offset)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_offset = None

    def mouseDoubleClickEvent(self, event):
        self._toggle_max()
