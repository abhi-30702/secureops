from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
)
from tool_checker import is_critical_missing
from screens.widgets.threat_feed import ThreatFeed


class MetricCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("panel")
        self.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet(
            "color: #64748b; font-size: 11px; text-transform: uppercase;"
        )

        self._value_label = QLabel("0")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._value_label.setStyleSheet(
            "font-size: 28px; font-weight: bold; color: #e2e8f0;"
        )

        layout.addWidget(title_label)
        layout.addWidget(self._value_label)

    def set_value(self, n: int) -> None:
        self._value_label.setText(str(n))


class SeverityStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)
        for color, label in [
            ("#ff4444", "Critical"), ("#ff8800", "High"),
            ("#ffcc00", "Medium"), ("#4488ff", "Low"),
        ]:
            dot = QLabel(f"<span style='color:{color}'>●</span>  {label}  <b>0</b>")
            dot.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(dot)


def _placeholder_panel(label_text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(label_text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class DashboardScreen(QWidget):
    def __init__(self, tool_results: dict, db=None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._metric_cards: list[MetricCard] = []
        self._warning_banner: QLabel | None = None
        self._severity_strip: SeverityStrip | None = None
        self._threat_feed: ThreatFeed | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        self._warning_banner = QLabel("⚠  Critical tools missing — check Settings")
        self._warning_banner.setStyleSheet(
            "background-color: #3d2800; color: #ffaa00; "
            "padding: 6px 12px; border: 1px solid #ffaa00; border-radius: 4px;"
        )
        self._warning_banner.setVisible(is_critical_missing(self._tool_results))
        layout.addWidget(self._warning_banner)

        cards_row = QHBoxLayout()
        for title in ("Clients", "Scans", "Findings"):
            card = MetricCard(title)
            self._metric_cards.append(card)
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        middle_row = QHBoxLayout()
        middle_row.addWidget(
            _placeholder_panel("Attack Surface Graph\nLive in Phase 6"), stretch=1
        )
        self._threat_feed = ThreatFeed()
        middle_row.addWidget(self._threat_feed, stretch=1)
        layout.addLayout(middle_row)

        self._severity_strip = SeverityStrip()
        layout.addWidget(self._severity_strip)
        layout.addStretch()

        if self._db:
            self.refresh()

    def refresh(self) -> None:
        if not self._db:
            return
        clients = self._db.query_clients()
        n_clients = len(clients)
        null_scans = self._db.query_scans_by_client(None)
        client_scans = [
            s for cl in clients
            for s in self._db.query_scans_by_client(cl.id)
        ]
        n_scans = len(null_scans) + len(client_scans)
        n_findings = len(self._db.query_recent_findings(limit=99999))

        card_map = {c.title: c for c in self._metric_cards}
        if "Clients" in card_map:
            card_map["Clients"].set_value(n_clients)
        if "Scans" in card_map:
            card_map["Scans"].set_value(n_scans)
        if "Findings" in card_map:
            card_map["Findings"].set_value(n_findings)

        self._threat_feed.refresh(self._db)
