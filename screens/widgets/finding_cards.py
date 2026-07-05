from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QGraphicsOpacityEffect,
)

from screens.widgets import theme as T
from screens.widgets.theme import TXT, TXT3, CARD, ACCENT, SEVERITY_COLORS

_MAX_CARDS = 200
_CARD_H = 84
_SEVERITY_COLORS = SEVERITY_COLORS


class _Card(QFrame):
    def __init__(self, title: str, tool: str, severity: str,
                 description: str, border_color: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("findCard")
        # Do NOT pin the minimum height here: add_finding animates maximumHeight
        # from 0 up for the reveal. If minimumHeight were fixed at _CARD_H, the
        # card would paint full height inside a shorter (still-animating) layout
        # slot and overlap the card below. Cap the max; lock to fixed on finish.
        self.setMinimumHeight(0)
        self.setMaximumHeight(_CARD_H)
        self.setStyleSheet(
            f"#findCard {{ background: {CARD}; border: 1px solid {T.BORDER};"
            f" border-left: 4px solid {border_color};"
            f" border-radius: {T.RADIUS_MD}px; }}"
            f"#findCard:hover {{ background: {T.BG_ALT};"
            f" border: 1px solid {T.BORDER_STRONG};"
            f" border-left: 4px solid {border_color}; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(6)
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        meta = QLabel(f"{tool}  ·  {ts}")
        meta.setStyleSheet(
            f"color: {TXT3}; font-size: {T.FS_TINY}px;"
            f" font-family: {T.FONT_MONO}; border: none;"
        )
        pill = QLabel(severity.upper())
        pill.setStyleSheet(
            f"color: #FFFFFF; background: {border_color};"
            f" border-radius: {T.RADIUS_SM}px; padding: 1px 8px;"
            f" font-size: {T.FS_TINY}px; font-weight: bold; letter-spacing: 1px;"
        )
        top.addWidget(meta)
        top.addStretch(1)
        top.addWidget(pill)
        layout.addLayout(top)

        title_label = QLabel(title)
        title_label.setWordWrap(False)
        title_label.setStyleSheet(
            f"color: {TXT}; font-size: 13px; font-weight: bold; border: none;"
        )
        layout.addWidget(title_label)

        desc_label = QLabel(description or "")
        desc_label.setMaximumHeight(26)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet(f"color: {TXT3}; font-size: 11px; border: none;")
        layout.addWidget(desc_label)


class FindingCards(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list[_Card] = []
        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(2, 2, 2, 2)
        self._layout.setSpacing(6)

        self._placeholder = QLabel("Findings will stream here as the scan runs.")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet(
            f"color: {TXT3}; font-size: {T.FS_BODY}px; font-style: italic;"
            " padding: 24px;"
        )
        self._layout.addWidget(self._placeholder)
        self._layout.addStretch()

        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet(
            "QScrollArea { border: none; background: transparent; }"
            "QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }"
            f"QScrollBar::handle:vertical {{ background: {T.BORDER_STRONG};"
            " border-radius: 4px; min-height: 24px; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }"
        )

    def add_finding(self, finding):
        self._placeholder.setVisible(False)
        self._trim_if_needed()
        color = _SEVERITY_COLORS.get(finding.severity, TXT3)
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
        anim_h.setDuration(260)
        anim_h.setStartValue(0)
        anim_h.setEndValue(_CARD_H)
        anim_h.setEasingCurve(QEasingCurve.Type.OutCubic)

        anim_o = QPropertyAnimation(effect, b"opacity", card)
        anim_o.setDuration(260)
        anim_o.setStartValue(0.0)
        anim_o.setEndValue(1.0)

        # Once revealed, lock to a stable uniform height (min == max == _CARD_H)
        # so the settled list never depends on the animation's transient state.
        anim_h.finished.connect(lambda c=card: c.setFixedHeight(_CARD_H))

        anim_h.start()
        anim_o.start()
        card._anim_h = anim_h
        card._anim_o = anim_o

        self.verticalScrollBar().setValue(0)

    def on_scan_complete(self, hosts: int, findings: int):
        self._placeholder.setVisible(False)
        card = _Card(
            title="Scan complete",
            tool="scan",
            severity="info",
            description=f"{hosts} hosts discovered, {findings} findings",
            border_color=ACCENT,
        )
        card.setFixedHeight(_CARD_H)
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
        self._placeholder.setVisible(True)

    def _trim_if_needed(self):
        if len(self._cards) >= _MAX_CARDS:
            oldest = self._cards.pop()
            self._delete_card(oldest)

    @property
    def card_count(self) -> int:
        return len(self._cards)
