from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
)
from tool_checker import is_critical_missing
from screens.widgets.threat_feed import ThreatFeed
from screens.widgets import theme as T
from screens.widgets.components import PageHeader, Card, StatCard, SectionLabel


# Retained for backwards compatibility with existing tests.
class MetricCard(StatCard):
    pass


class LiveSeverityStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        self._labels: dict[str, QLabel] = {}
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(T.SP_XL)
        for sev in ["critical", "high", "medium", "low"]:
            lbl = QLabel()
            lbl.setTextFormat(Qt.TextFormat.RichText)
            self._labels[sev] = lbl
            layout.addWidget(lbl)
        layout.addStretch()
        self._refresh_labels()

    def set_counts(self, critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> None:
        self._counts = {"critical": critical, "high": high, "medium": medium, "low": low}
        self._refresh_labels()

    def _refresh_labels(self) -> None:
        for sev, lbl in self._labels.items():
            color = T.SEVERITY_COLORS.get(sev, T.TXT3)
            count = self._counts[sev]
            lbl.setText(
                f"<span style='color:{color}; font-size:16px'>●</span>  "
                f"<span style='color:{T.TXT2}'>{sev.capitalize()}</span>  "
                f"<b style='color:{T.TXT}'>{count}</b>"
            )


class DashboardScreen(QWidget):
    def __init__(self, tool_results: dict, db=None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._metric_cards: list[StatCard] = []
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
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_LG)

        header = PageHeader("SOC Dashboard", "Live security posture overview")
        self._updated_label = QLabel("")
        self._updated_label.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_TINY}px;")
        header.add_action(self._updated_label)
        layout.addWidget(header)

        self._warning_banner = QLabel("⚠  Critical tools missing — open Settings to resolve")
        self._warning_banner.setStyleSheet(
            f"background-color: #FBEED6; color: {T.HIGH}; padding: 8px 14px; "
            f"border: 1px solid {T.HIGH}; border-radius: {T.RADIUS_SM}px; font-weight: 600;"
        )
        self._warning_banner.setVisible(is_critical_missing(self._tool_results))
        layout.addWidget(self._warning_banner)

        # Metric tiles
        cards_row = QHBoxLayout()
        cards_row.setSpacing(T.SP_LG)
        accents = {
            "Clients": T.ACCENT, "Scans": T.ACCENT,
            "Findings": T.MEDIUM, "Incidents": T.CRITICAL,
        }
        for title in ("Clients", "Scans", "Findings", "Incidents"):
            card = StatCard(title, accent=accents.get(title, T.ACCENT))
            self._metric_cards.append(card)
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # Severity overview card
        sev_card = Card("Open Findings by Severity")
        self._severity_strip = LiveSeverityStrip()
        sev_card.add(self._severity_strip)
        layout.addWidget(sev_card)

        # Middle: schedules + threat feed side by side
        middle_row = QHBoxLayout()
        middle_row.setSpacing(T.SP_LG)

        sched_card = Card("Scheduled Scans")
        if self._db:
            from screens.widgets.schedule_panel import SchedulePanel
            self._schedule_panel = SchedulePanel(db=self._db)
            sched_card.add(self._schedule_panel, stretch=1)
        else:
            ph = QLabel("DB not available")
            ph.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
            sched_card.add(ph)
        middle_row.addWidget(sched_card, stretch=1)

        feed_card = Card("Threat Feed")
        self._threat_feed = ThreatFeed()
        feed_card.add(self._threat_feed, stretch=1)
        middle_row.addWidget(feed_card, stretch=1)
        layout.addLayout(middle_row, stretch=1)

        # Delta alerts strip
        delta_card = Card("Changes Since Last Scan")
        from screens.widgets.delta_panel import DeltaPanel
        self._delta_panel = DeltaPanel()
        delta_card.add(self._delta_panel)
        layout.addWidget(delta_card)

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
        if "Incidents" in card_map:
            card_map["Incidents"].set_value(self._db.count_incident_events())

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
            self._updated_label.setText(f"Updated {ts} UTC")
