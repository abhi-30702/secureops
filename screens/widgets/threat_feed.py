from PyQt6.QtWidgets import (
    QScrollArea, QWidget, QVBoxLayout, QFrame, QLabel,
)

from screens.widgets.theme import TXT, TXT3, CARD, SEVERITY_COLORS

_SEVERITY_COLORS = SEVERITY_COLORS
_LIMIT = 20


class ThreatFeed(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: list[QFrame] = []
        self._container = QWidget()
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(4)
        self._layout.addStretch()
        self.setWidget(self._container)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

    def refresh(self, db) -> None:
        self.clear()
        findings = db.query_recent_findings(limit=_LIMIT)
        for f in findings:
            color = _SEVERITY_COLORS.get(f.severity, TXT3)
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ border-left: 3px solid {color}; "
                f"background-color: {CARD}; border-radius: 3px; }}"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(10, 5, 10, 5)
            card_layout.setSpacing(1)
            title_lbl = QLabel(f.title)
            title_lbl.setWordWrap(False)
            title_lbl.setStyleSheet(
                f"color: {TXT}; font-size: 11px; font-weight: bold;"
            )
            meta_lbl = QLabel(f"{f.tool}  ·  {f.created_at[11:19]}")
            meta_lbl.setStyleSheet(f"color: {TXT3}; font-size: 9px;")
            card_layout.addWidget(title_lbl)
            card_layout.addWidget(meta_lbl)
            self._layout.insertWidget(0, card)
            self._cards.append(card)

    def clear(self) -> None:
        for card in self._cards:
            self._layout.removeWidget(card)
            card.deleteLater()
        self._cards.clear()

    @property
    def card_count(self) -> int:
        return len(self._cards)
