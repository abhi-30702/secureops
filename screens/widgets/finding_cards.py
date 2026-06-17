from datetime import datetime, timezone
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QFrame, QLabel, QGraphicsOpacityEffect,
)

from screens.widgets.theme import TXT, TXT3, CARD, ACCENT, SEVERITY_COLORS

_MAX_CARDS = 200

_SEVERITY_COLORS = SEVERITY_COLORS


class _Card(QFrame):
    def __init__(self, title: str, tool: str, severity: str,
                 description: str, border_color: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setFixedHeight(70)
        self.setStyleSheet(
            f"QFrame {{ border-left: 4px solid {border_color};"
            f" background-color: {CARD}; border-radius: 4px; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        top = QLabel(f"{tool}  ·  {ts}")
        top.setStyleSheet(f"color: {TXT3}; font-size: 10px;")

        title_label = QLabel(title)
        title_label.setWordWrap(False)
        title_label.setStyleSheet(
            f"color: {TXT}; font-size: 13px; font-weight: bold;"
        )

        desc_label = QLabel(description or "")
        desc_label.setMaximumHeight(26)
        desc_label.setStyleSheet(f"color: {TXT3}; font-size: 11px;")
        desc_label.setWordWrap(True)

        layout.addWidget(top)
        layout.addWidget(title_label)
        layout.addWidget(desc_label)


class FindingCards(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list[_Card] = []
        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def add_finding(self, finding):
        self._trim_if_needed()
        color = _SEVERITY_COLORS.get(finding.severity, "#64748b")
        card = _Card(
            title=finding.title,
            tool=finding.tool,
            severity=finding.severity,
            description=finding.description,
            border_color=color,
        )
        card.setMaximumHeight(0)
        self._layout.insertWidget(0, card)
        self._cards.insert(0, card)

        effect = QGraphicsOpacityEffect(card)
        card.setGraphicsEffect(effect)
        effect.setOpacity(0.0)

        anim_h = QPropertyAnimation(card, b"maximumHeight", card)
        anim_h.setDuration(250)
        anim_h.setStartValue(0)
        anim_h.setEndValue(70)
        anim_h.setEasingCurve(QEasingCurve.Type.OutCubic)

        anim_o = QPropertyAnimation(effect, b"opacity", card)
        anim_o.setDuration(250)
        anim_o.setStartValue(0.0)
        anim_o.setEndValue(1.0)

        anim_h.start()
        anim_o.start()
        card._anim_h = anim_h
        card._anim_o = anim_o

        self.verticalScrollBar().setValue(0)

    def on_scan_complete(self, hosts: int, findings: int):
        card = _Card(
            title="Scan complete",
            tool="scan",
            severity="info",
            description=f"{hosts} hosts discovered, {findings} findings",
            border_color=ACCENT,
        )
        card.setMaximumHeight(70)
        self._layout.insertWidget(0, card)
        self._cards.insert(0, card)
        self.verticalScrollBar().setValue(0)

    def _delete_card(self, card: "_Card") -> None:
        if hasattr(card, "_anim_h"):
            card._anim_h.stop()
        if hasattr(card, "_anim_o"):
            card._anim_o.stop()
        self._layout.removeWidget(card)
        card.deleteLater()

    def reset(self):
        for card in self._cards:
            self._delete_card(card)
        self._cards.clear()

    def _trim_if_needed(self):
        if len(self._cards) >= _MAX_CARDS:
            oldest = self._cards.pop()
            self._delete_card(oldest)

    @property
    def card_count(self) -> int:
        return len(self._cards)
