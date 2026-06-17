from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QTimer
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


class LiveSeverityStrip(QWidget):
    _COLORS = {
        "critical": "#ff3d57",
        "high":     "#ff8800",
        "medium":   "#ffb300",
        "low":      "#4488ff",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self._labels: dict[str, QLabel] = {}
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)
        for sev, color in self._COLORS.items():
            lbl = QLabel()
            lbl.setTextFormat(Qt.TextFormat.RichText)
            self._labels[sev] = lbl
            layout.addWidget(lbl)
        self._refresh_labels()

    def set_counts(self, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> None:
        self._counts = {"critical": critical, "high": high, "medium": medium, "low": low}
        self._refresh_labels()

    def _refresh_labels(self) -> None:
        for sev, lbl in self._labels.items():
            color = self._COLORS[sev]
            count = self._counts[sev]
            lbl.setText(f"<span style='color:{color}'>●</span>  {sev.capitalize()}  <b>{count}</b>")


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
        self._severity_strip: LiveSeverityStrip | None = None
        self._threat_feed: ThreatFeed | None = None
        self._schedule_panel = None
        self._delta_panel = None
        self._updated_label: QLabel | None = None
        self._timer: QTimer | None = None
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
        if self._db:
            from screens.widgets.schedule_panel import SchedulePanel
            self._schedule_panel = SchedulePanel(db=self._db)
            middle_row.addWidget(self._schedule_panel, stretch=1)
        else:
            middle_row.addWidget(
                _placeholder_panel("Scheduled Scans\n(DB not available)"), stretch=1
            )
        self._threat_feed = ThreatFeed()
        middle_row.addWidget(self._threat_feed, stretch=1)
        layout.addLayout(middle_row)

        self._severity_strip = LiveSeverityStrip()
        layout.addWidget(self._severity_strip)

        from screens.widgets.delta_panel import DeltaPanel
        self._delta_panel = DeltaPanel()
        layout.addWidget(self._delta_panel)

        self._updated_label = QLabel("")
        self._updated_label.setStyleSheet("color: #3d5a7a; font-size: 10px;")
        layout.addWidget(self._updated_label)

        layout.addStretch()

        if self._db:
            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(30_000)
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

        rows = self._db._conn.execute(
            "SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"
        ).fetchall()
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in rows:
            key = row["severity"]
            if key in sev_counts:
                sev_counts[key] = row["n"]
        if self._severity_strip:
            self._severity_strip.set_counts(**sev_counts)

        if self._schedule_panel:
            self._schedule_panel.refresh()

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if self._updated_label:
            self._updated_label.setText(f"Updated {ts}")
