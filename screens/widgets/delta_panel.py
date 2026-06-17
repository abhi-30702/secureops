from PyQt6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QScrollArea, QFrame,
)
from PyQt6.QtCore import Qt

_MAX_CHIPS = 10


class DeltaPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._chips: list[QLabel] = []
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        hdr = QLabel("Delta:")
        hdr.setStyleSheet("color: #7a9bc4; font-size: 10px;")
        outer.addWidget(hdr)

        scroll = QScrollArea()
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setFixedHeight(28)

        self._inner = QWidget()
        self._row = QHBoxLayout(self._inner)
        self._row.setContentsMargins(0, 0, 0, 0)
        self._row.setSpacing(8)
        self._row.addStretch()
        scroll.setWidget(self._inner)
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll, 1)

    def add_delta(self, target: str, new_count: int, resolved_count: int) -> None:
        if new_count == 0 and resolved_count == 0:
            text = f"{target}  no change"
            color = "#3d5a7a"
        else:
            text = f"{target}  +{new_count} new  −{resolved_count} resolved"
            color = "#ffb300" if new_count > 0 else "#00ff88"

        chip = QLabel(text)
        chip.setStyleSheet(
            f"color: {color}; background: #0a1628; padding: 2px 8px; "
            f"border-radius: 3px; font-size: 10px;"
        )

        self._row.insertWidget(0, chip)
        self._chips.insert(0, chip)

        if len(self._chips) > _MAX_CHIPS:
            old = self._chips.pop()
            self._row.removeWidget(old)
            old.deleteLater()

    def clear(self) -> None:
        for chip in self._chips:
            self._row.removeWidget(chip)
            chip.deleteLater()
        self._chips.clear()
