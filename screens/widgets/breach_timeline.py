from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QScrollArea,
)
from screens.widgets.theme import BG, ACCENT, TXT as TEXT, CARD as SURFACE, ACCENT_H, CRITICAL, MEDIUM, TXT2

_EVENT_COLORS = {
    "entry":       CRITICAL,
    "lateral":     MEDIUM,
    "persistence": ACCENT,
    "exfil":       CRITICAL,
    "anomaly":     TXT2,
}


class BreachTimeline(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[dict] = []
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        header = QLabel("BREACH TIMELINE")
        header.setStyleSheet(
            f"color: {ACCENT}; font-size: 10px; letter-spacing: 1px; padding: 4px 8px;"
        )
        outer.addWidget(header)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {BG}; }}")

        self._container = QWidget()
        self._container.setStyleSheet(f"background: {BG};")
        self._layout = QVBoxLayout(self._container)
        self._layout.setContentsMargins(8, 4, 8, 4)
        self._layout.setSpacing(4)
        self._layout.addStretch()

        self._scroll.setWidget(self._container)
        outer.addWidget(self._scroll, stretch=1)

    def add_event(self, event: dict) -> None:
        self._rows.append(event)
        try:
            layout = object.__getattribute__(self, '_layout')
        except AttributeError:
            return  # called on a bare __new__ instance (tests only)
        row = self._make_row(event)
        layout.insertWidget(layout.count() - 1, row)
        self._scroll.verticalScrollBar().setValue(
            self._scroll.verticalScrollBar().maximum()
        )

    def reset(self) -> None:
        self._rows.clear()
        try:
            layout = object.__getattribute__(self, '_layout')
        except AttributeError:
            return
        while layout.count() > 1:
            item = layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

    def _make_row(self, event: dict) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet(
            f"QFrame {{ background: {SURFACE}; border: 1px solid {ACCENT_H};"
            " border-radius: 4px; }"
        )
        row_layout = QHBoxLayout(frame)
        row_layout.setContentsMargins(6, 4, 6, 4)
        row_layout.setSpacing(8)

        ts = event.get("timestamp", "")[:19].replace("T", " ")
        ts_label = QLabel(ts)
        ts_label.setStyleSheet(f"color: {TXT2}; font-family: monospace; font-size: 10px;")
        ts_label.setFixedWidth(130)
        row_layout.addWidget(ts_label)

        et = event.get("event_type", "anomaly")
        color = _EVENT_COLORS.get(et, TXT2)
        badge = QLabel(et.upper())
        badge.setStyleSheet(
            f"background: {color}; color: {BG}; border-radius: 3px;"
            " padding: 1px 6px; font-size: 9px; font-weight: bold;"
        )
        badge.setFixedWidth(80)
        row_layout.addWidget(badge)

        src = event.get("source_host", "")
        dst = event.get("dest_host", "")
        route = f"{src} → {dst}" if dst else src
        if route:
            route_label = QLabel(route)
            route_label.setStyleSheet(f"color: {TEXT}; font-size: 10px;")
            route_label.setFixedWidth(160)
            row_layout.addWidget(route_label)

        desc = event.get("description", "")
        desc_label = QLabel(desc)
        desc_label.setStyleSheet(f"color: {TEXT}; font-size: 10px;")
        desc_label.setWordWrap(True)
        row_layout.addWidget(desc_label, stretch=1)

        return frame
