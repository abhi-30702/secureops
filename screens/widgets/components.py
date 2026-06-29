"""Reusable UI building blocks for a consistent, modern, accessible layout.

Every screen composes from these so spacing, typography, headers, cards and
buttons look identical everywhere. Colours/sizes come from theme tokens.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QFrame, QLabel, QVBoxLayout, QHBoxLayout, QPushButton,
    QGraphicsDropShadowEffect,
)
from PyQt6.QtGui import QColor

from screens.widgets import theme as T


class PageHeader(QWidget):
    """Standard page title + optional subtitle, left-aligned with actions on the right."""

    def __init__(self, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(T.SP_MD)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"color: {T.TXT}; font-size: {T.FS_DISPLAY}px; font-weight: bold;"
        )
        text_col.addWidget(title_lbl)
        if subtitle:
            sub = QLabel(subtitle)
            sub.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
            sub.setWordWrap(True)
            text_col.addWidget(sub)
        row.addLayout(text_col)
        row.addStretch()

        self._actions = QHBoxLayout()
        self._actions.setSpacing(T.SP_SM)
        row.addLayout(self._actions)

    def add_action(self, widget: QWidget) -> None:
        self._actions.addWidget(widget)


class Card(QFrame):
    """A white rounded panel with a soft shadow and a vertical content layout."""

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(T.SP_LG, T.SP_MD, T.SP_LG, T.SP_MD)
        self._layout.setSpacing(T.SP_SM)

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(18)
        shadow.setXOffset(0)
        shadow.setYOffset(2)
        shadow.setColor(QColor(15, 23, 41, 28))
        self.setGraphicsEffect(shadow)

        if title:
            self._layout.addWidget(SectionLabel(title))

    def body(self) -> QVBoxLayout:
        return self._layout

    def add(self, widget: QWidget, stretch: int = 0) -> None:
        self._layout.addWidget(widget, stretch)

    def add_layout(self, layout) -> None:
        self._layout.addLayout(layout)


class SectionLabel(QLabel):
    """Uppercase overline used as a card / section header."""

    def __init__(self, text: str, parent=None):
        super().__init__(text.upper(), parent)
        self.setStyleSheet(T.overline(T.ACCENT, T.FS_TINY))


class TitleLabel(QLabel):
    def __init__(self, text: str, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            f"color: {T.TXT}; font-size: {T.FS_TITLE}px; font-weight: bold;"
        )


def PrimaryButton(text: str, tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("primary")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(34)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def SecondaryButton(text: str, tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(34)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


def DangerButton(text: str, tooltip: str = "") -> QPushButton:
    btn = QPushButton(text)
    btn.setObjectName("danger")
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setMinimumHeight(34)
    if tooltip:
        btn.setToolTip(tooltip)
    return btn


class StatCard(QFrame):
    """A compact metric tile: large value over an uppercase caption."""

    def __init__(self, title: str, accent: str = T.ACCENT, parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.title = title
        self.setMinimumHeight(88)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_LG, T.SP_MD, T.SP_LG, T.SP_MD)
        layout.setSpacing(2)

        self._value_label = QLabel("0")
        self._value_label.setStyleSheet(
            f"color: {accent}; font-size: 30px; font-weight: bold;"
        )
        caption = QLabel(title.upper())
        caption.setStyleSheet(T.overline(T.TXT3, T.FS_TINY))

        layout.addWidget(self._value_label)
        layout.addWidget(caption)

    def set_value(self, n) -> None:
        self._value_label.setText(str(n))


class Badge(QLabel):
    """A small pill label coloured by intent."""

    def __init__(self, text: str, color: str = T.ACCENT, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            f"background: {color}; color: {T.CARD}; border-radius: {T.RADIUS_PILL}px; "
            f"padding: 2px 10px; font-size: {T.FS_TINY}px; font-weight: bold;"
        )
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)


def hline() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {T.BORDER}; background: {T.BORDER}; max-height: 1px;")
    return line
