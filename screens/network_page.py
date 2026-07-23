"""Network Activity Monitor — live employee web-activity page (stack index 9).

Streams captured/synthetic network events into a sortable live table, raises
red-flag alerts when a destination matches the blocklist, and shows live
statistics. Reads exclusively from worker signals (which persist to SQLite
first), never from raw tool output — same contract as every other screen.
"""
from __future__ import annotations

from collections import Counter

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QBrush
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QSpinBox,
    QPushButton, QSplitter, QFrame, QScrollArea, QCheckBox, QSizePolicy,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
)

from db import DB
from blocklist_engine import BlocklistEngine
from workers.network_monitor_worker import NetworkMonitorWorker
from screens.widgets import theme as T
from screens.widgets.components import PageHeader, StatCard, PrimaryButton, SecondaryButton

_COLS = ["Timestamp", "Employee", "Domain", "Port", "Protocol", "Status", "Action"]

_SEV_COLOR = {
    "critical": T.CRITICAL,
    "high": T.HIGH,
    "medium": T.MEDIUM,
    "low": T.LOW,
    "info": T.INFO,
}


class _DistributionBar(QWidget):
    """A slim horizontal allowed(green)/blocked(red) proportion bar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._allowed = 0
        self._blocked = 0
        self.setFixedHeight(14)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_counts(self, allowed: int, blocked: int) -> None:
        self._allowed = max(0, allowed)
        self._blocked = max(0, blocked)
        self.update()

    def paintEvent(self, event):
        from PyQt6.QtGui import QPainter
        total = self._allowed + self._blocked
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.rect()
        p.setPen(Qt.PenStyle.NoPen)
        # track
        p.setBrush(QColor(T.BORDER))
        p.drawRoundedRect(r, 6, 6)
        if total > 0:
            w_blocked = int(r.width() * (self._blocked / total))
            if self._allowed:
                p.setBrush(QColor(T.SUCCESS))
                p.drawRoundedRect(r, 6, 6)
            if w_blocked > 0:
                p.setBrush(QColor(T.CRITICAL))
                blocked_rect = r.adjusted(r.width() - w_blocked, 0, 0, 0)
                p.drawRoundedRect(blocked_rect, 6, 6)
        p.end()


class NetworkPage(QWidget):
    """Live employee network-activity monitoring dashboard."""

    def __init__(self, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._db = db
        self._blocklist = BlocklistEngine()
        self._worker: NetworkMonitorWorker | None = None
        self._seeded = False

        # local counters (avoid a DB aggregate per event)
        self._total = 0
        self._blocked = 0
        self._employees: set[str] = set()
        self._top_blocked: Counter = Counter()
        self._rows_data: list[dict] = []  # aligned with table rows

        self._setup_ui()

    # ------------------------------------------------------------------ #
    # UI
    # ------------------------------------------------------------------ #
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(T.SP_XL, T.SP_XL, T.SP_XL, T.SP_XL)
        layout.setSpacing(T.SP_MD)

        layout.addWidget(PageHeader(
            "Network Activity Monitor",
            "Live employee web activity · blocklist matching · audit trail",
        ))

        layout.addLayout(self._build_controls())
        layout.addLayout(self._build_filters())

        # red-flag banner (hidden until a blocked event arrives)
        self._banner = QLabel("")
        self._banner.setStyleSheet(
            f"background: {T.CRITICAL}; color: #FFFFFF; font-weight: bold; "
            f"font-size: {T.FS_SMALL}px; padding: 6px 12px; "
            f"border-radius: {T.RADIUS_SM}px;"
        )
        self._banner.setVisible(False)
        layout.addWidget(self._banner)
        self._banner_timer = QTimer(self)
        self._banner_timer.setSingleShot(True)
        self._banner_timer.timeout.connect(lambda: self._banner.setVisible(False))

        # main split: live table | stats + alerts
        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._build_table())
        split.addWidget(self._build_side_panel())
        split.setSizes([820, 340])
        layout.addWidget(split, stretch=1)

        self._status = QLabel(self._idle_status_text())
        self._status.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
        layout.addWidget(self._status)

    def _build_controls(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(T.SP_SM)

        # Wireshark-style interface picker (live capture is the only mode).
        self._iface = QComboBox()
        self._iface.setMinimumWidth(200)
        self._iface.addItem("Default (all interfaces)", None)
        try:
            from workers.network_monitor_worker import list_interfaces
            for name in list_interfaces():
                self._iface.addItem(name, name)
        except Exception:
            pass

        self._start_btn = PrimaryButton("▶  Start Capture")
        self._start_btn.setEnabled(self._db is not None)
        self._start_btn.clicked.connect(self._on_start_stop)

        self._clear_btn = SecondaryButton("Clear")
        self._clear_btn.clicked.connect(self._on_clear)

        row.addWidget(QLabel("Interface:"))
        row.addWidget(self._iface)
        row.addStretch()
        row.addWidget(QLabel("Keep last:"))
        self._max_spin = QSpinBox()
        self._max_spin.setRange(50, 5000)
        self._max_spin.setValue(500)
        self._max_spin.setSingleStep(50)
        self._max_spin.setFixedWidth(90)
        row.addWidget(self._max_spin)
        row.addWidget(self._clear_btn)
        row.addWidget(self._start_btn)
        return row

    def _build_filters(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(T.SP_SM)

        self._f_ip = QLineEdit()
        self._f_ip.setPlaceholderText("filter employee / IP")
        self._f_ip.setFixedWidth(180)
        self._f_ip.textChanged.connect(self._apply_filters)

        self._f_domain = QLineEdit()
        self._f_domain.setPlaceholderText("filter domain")
        self._f_domain.setFixedWidth(200)
        self._f_domain.textChanged.connect(self._apply_filters)

        self._f_status = QComboBox()
        self._f_status.addItems(["All", "Allowed", "Blocked"])
        self._f_status.setFixedWidth(120)
        self._f_status.currentIndexChanged.connect(self._apply_filters)

        row.addWidget(QLabel("Filter:"))
        row.addWidget(self._f_ip)
        row.addWidget(self._f_domain)
        row.addWidget(self._f_status)
        row.addStretch()
        return row

    def _build_table(self) -> QWidget:
        self._table = QTableWidget(0, len(_COLS))
        self._table.setHorizontalHeaderLabels(_COLS)
        self._table.setObjectName("card")
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)      # Domain
        hdr.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)      # Action
        for c in (0, 1, 3, 4, 5):
            hdr.setSectionResizeMode(c, QHeaderView.ResizeMode.ResizeToContents)
        return self._table

    def _build_side_panel(self) -> QWidget:
        panel = QWidget()
        col = QVBoxLayout(panel)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(T.SP_MD)

        # --- stats ---
        stats = QFrame()
        stats.setObjectName("card")
        sv = QVBoxLayout(stats)
        sv.setContentsMargins(T.SP_MD, T.SP_MD, T.SP_MD, T.SP_MD)
        sv.setSpacing(T.SP_SM)

        tiles = QHBoxLayout()
        self._tile_total = StatCard("Requests", accent=T.ACCENT)
        self._tile_blocked = StatCard("Blocked", accent=T.CRITICAL)
        self._tile_emp = StatCard("Employees", accent=T.LOW)
        tiles.addWidget(self._tile_total)
        tiles.addWidget(self._tile_blocked)
        tiles.addWidget(self._tile_emp)
        sv.addLayout(tiles)

        self._dist = _DistributionBar()
        sv.addWidget(self._dist)
        self._dist_lbl = QLabel("No traffic yet")
        self._dist_lbl.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_TINY}px;")
        sv.addWidget(self._dist_lbl)

        top_hdr = QLabel("TOP BLOCKED DOMAINS")
        top_hdr.setStyleSheet(T.overline(T.TXT3, T.FS_TINY))
        sv.addWidget(top_hdr)
        self._top_list = QLabel("—")
        self._top_list.setStyleSheet(
            f"color: {T.TXT2}; font-family: {T.FONT_MONO}; font-size: {T.FS_SMALL}px;"
        )
        self._top_list.setWordWrap(True)
        sv.addWidget(self._top_list)
        col.addWidget(stats)

        col.addWidget(self._build_retention())

        # --- alerts ---
        alerts_box = QFrame()
        alerts_box.setObjectName("card")
        av = QVBoxLayout(alerts_box)
        av.setContentsMargins(T.SP_MD, T.SP_MD, T.SP_MD, T.SP_MD)
        av.setSpacing(T.SP_SM)
        ah = QLabel("RED-FLAG ALERTS")
        ah.setStyleSheet(T.overline(T.CRITICAL, T.FS_TINY))
        av.addWidget(ah)

        self._alert_scroll = QScrollArea()
        self._alert_scroll.setWidgetResizable(True)
        self._alert_scroll.setStyleSheet("QScrollArea { border: none; }")
        self._alert_container = QWidget()
        self._alert_layout = QVBoxLayout(self._alert_container)
        self._alert_layout.setContentsMargins(0, 0, 0, 0)
        self._alert_layout.setSpacing(4)
        self._alert_empty = QLabel("No blocked activity.")
        self._alert_empty.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")
        self._alert_layout.addWidget(self._alert_empty)
        self._alert_layout.addStretch()
        self._alert_scroll.setWidget(self._alert_container)
        av.addWidget(self._alert_scroll, stretch=1)
        col.addWidget(alerts_box, stretch=1)

        return panel

    def _build_retention(self) -> QWidget:
        """Retention/purge controls — bound the audit trail so the SQLite DB
        can't grow without limit under a long capture."""
        box = QFrame()
        box.setObjectName("card")
        v = QVBoxLayout(box)
        v.setContentsMargins(T.SP_MD, T.SP_MD, T.SP_MD, T.SP_MD)
        v.setSpacing(T.SP_SM)

        hdr = QLabel("RETENTION")
        hdr.setStyleSheet(T.overline(T.TXT3, T.FS_TINY))
        v.addWidget(hdr)

        policy = QHBoxLayout()
        policy.setSpacing(T.SP_SM)
        self._ret_mode = QComboBox()
        self._ret_mode.addItems(["Keep last N events", "Keep last N days"])
        self._ret_mode.currentIndexChanged.connect(self._on_ret_mode_changed)
        self._ret_value = QSpinBox()
        self._ret_value.setFixedWidth(96)
        self._ret_value.valueChanged.connect(self._on_ret_value_changed)
        policy.addWidget(self._ret_mode, stretch=1)
        policy.addWidget(self._ret_value)
        v.addLayout(policy)

        self._ret_auto = QCheckBox("Auto-purge during capture")
        self._ret_auto.setStyleSheet(f"color: {T.TXT2}; font-size: {T.FS_SMALL}px;")
        self._ret_auto.toggled.connect(lambda _=False: self._save_retention_settings())
        v.addWidget(self._ret_auto)

        foot = QHBoxLayout()
        self._storage_lbl = QLabel("Stored: —")
        self._storage_lbl.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_TINY}px;")
        self._purge_btn = SecondaryButton("Purge now")
        self._purge_btn.setEnabled(self._db is not None)
        self._purge_btn.clicked.connect(self._on_purge_now)
        foot.addWidget(self._storage_lbl, stretch=1)
        foot.addWidget(self._purge_btn)
        v.addLayout(foot)

        # periodic auto-purge / indicator refresh while a capture runs
        self._purge_timer = QTimer(self)
        self._purge_timer.setInterval(60_000)
        self._purge_timer.timeout.connect(self._on_purge_tick)

        self._load_retention_settings()
        return box

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def showEvent(self, event):
        super().showEvent(event)
        if not self._seeded and self._db is not None:
            self._seed_from_db()
            self._seeded = True
        self._update_storage_label()

    def _seed_from_db(self):
        """Populate the table + stats from the persisted audit trail."""
        try:
            events = self._db.query_network_events(limit=self._max_spin.value())
        except Exception:
            return
        for ev in reversed(events):  # oldest first so newest lands at the bottom
            self._append_row(ev, scroll=False)
            self._tally(ev)
        self._refresh_stats()
        self._update_storage_label()
        if events:
            self._table.scrollToBottom()

    @staticmethod
    def _is_root() -> bool:
        try:
            import os
            return hasattr(os, "geteuid") and os.geteuid() == 0
        except Exception:
            return False

    def _idle_status_text(self) -> str:
        if not self._is_root():
            return ("Idle — live capture needs root. Launch SecureOps with sudo, "
                    "then select an interface and press Start Capture.")
        return "Idle — select an interface and press Start Capture."

    # ------------------------------------------------------------------ #
    # start / stop
    # ------------------------------------------------------------------ #
    def _on_start_stop(self):
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._start_btn.setText("Stopping…")
            self._start_btn.setEnabled(False)
            return
        if self._db is None:
            return

        # Bound the audit trail before we start writing more to it.
        if self._ret_auto.isChecked():
            self._apply_retention()

        iface = self._iface.currentData()  # None → default (all interfaces)
        self._worker = NetworkMonitorWorker(
            db=self._db, blocklist=self._blocklist, iface=iface
        )
        self._worker.event_captured.connect(self._on_event)
        self._worker.alert_raised.connect(self._on_alert)
        self._worker.state_changed.connect(self._on_state)
        self._worker.error_occurred.connect(self._on_error)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()
        self._purge_timer.start()  # periodic auto-purge + indicator refresh

        self._start_btn.setText("■  Stop Capture")
        self._iface.setEnabled(False)
        self._status.setText("Starting live capture…")

    def _on_finished(self):
        self._purge_timer.stop()
        self._start_btn.setText("▶  Start Capture")
        self._start_btn.setEnabled(True)
        self._iface.setEnabled(True)
        self._update_storage_label()

    def _on_clear(self):
        if self._worker and self._worker.isRunning():
            return  # don't wipe under a live feed
        if self._db is not None:
            try:
                self._db.clear_network_data()
            except Exception:
                pass
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        self._table.setSortingEnabled(True)
        self._rows_data.clear()
        self._total = self._blocked = 0
        self._employees.clear()
        self._top_blocked.clear()
        # clear alerts
        while self._alert_layout.count() > 2:  # keep empty label + stretch
            item = self._alert_layout.takeAt(0)
            if item and item.widget() and item.widget() is not self._alert_empty:
                item.widget().deleteLater()
        self._alert_empty.setVisible(True)
        self._refresh_stats()
        self._update_storage_label()
        self._status.setText("Cleared.")

    # ------------------------------------------------------------------ #
    # retention / purge
    # ------------------------------------------------------------------ #
    _DEFAULTS = {"mode": "rows", "rows": 50000, "days": 30, "auto": True}

    def _load_retention_settings(self):
        """Restore persisted policy (or sensible defaults) into the widgets."""
        d = self._DEFAULTS
        rows, days, auto, mode = d["rows"], d["days"], d["auto"], d["mode"]
        if self._db is not None:
            try:
                rows = int(self._db.get_setting("net_retention_rows") or rows)
                days = int(self._db.get_setting("net_retention_days") or days)
                auto = (self._db.get_setting("net_retention_auto") or ("1" if auto else "0")) == "1"
                mode = self._db.get_setting("net_retention_mode") or mode
            except (ValueError, TypeError):
                pass
        self._ret_rows_val = max(500, rows)
        self._ret_days_val = max(1, days)
        self._ret_auto.blockSignals(True)
        self._ret_auto.setChecked(auto)
        self._ret_auto.blockSignals(False)
        self._ret_mode.blockSignals(True)
        self._ret_mode.setCurrentIndex(1 if mode == "days" else 0)
        self._ret_mode.blockSignals(False)
        self._sync_ret_spin()

    def _sync_ret_spin(self):
        """Point the spinbox at the value/range for the active policy."""
        self._ret_value.blockSignals(True)
        if self._ret_mode.currentIndex() == 1:  # days
            self._ret_value.setRange(1, 3650)
            self._ret_value.setSingleStep(1)
            self._ret_value.setSuffix(" d")
            self._ret_value.setValue(self._ret_days_val)
        else:  # rows
            self._ret_value.setRange(500, 5_000_000)
            self._ret_value.setSingleStep(1000)
            self._ret_value.setSuffix("")
            self._ret_value.setValue(self._ret_rows_val)
        self._ret_value.blockSignals(False)

    def _on_ret_mode_changed(self, _idx: int):
        self._sync_ret_spin()
        self._save_retention_settings()

    def _on_ret_value_changed(self, val: int):
        if self._ret_mode.currentIndex() == 1:
            self._ret_days_val = val
        else:
            self._ret_rows_val = val
        self._save_retention_settings()

    def _save_retention_settings(self):
        if self._db is None:
            return
        try:
            self._db.set_setting("net_retention_mode",
                                 "days" if self._ret_mode.currentIndex() == 1 else "rows")
            self._db.set_setting("net_retention_rows", str(self._ret_rows_val))
            self._db.set_setting("net_retention_days", str(self._ret_days_val))
            self._db.set_setting("net_retention_auto",
                                 "1" if self._ret_auto.isChecked() else "0")
        except Exception:
            pass

    def _apply_retention(self) -> int:
        """Run the configured purge. Returns events deleted."""
        if self._db is None:
            return 0
        try:
            if self._ret_mode.currentIndex() == 1:
                deleted = self._db.purge_network_events_older_than(self._ret_days_val)
            else:
                deleted = self._db.purge_network_events_keep_last(self._ret_rows_val)
        except Exception:
            deleted = 0
        self._update_storage_label()
        return deleted

    def _on_purge_tick(self):
        if self._ret_auto.isChecked():
            self._apply_retention()
        else:
            self._update_storage_label()

    def _on_purge_now(self):
        if self._db is None:
            return
        deleted = self._apply_retention()
        # Reclaim disk space only when idle — VACUUM would stall a live writer.
        if not (self._worker and self._worker.isRunning()):
            try:
                self._db.vacuum()
            except Exception:
                pass
        self._update_storage_label()
        self._status.setText(f"Purged {deleted:,} event(s) from the audit trail.")
        self._status.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")

    @staticmethod
    def _fmt_size(nbytes: int) -> str:
        size = float(nbytes)
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024 or unit == "GB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} GB"

    def _update_storage_label(self):
        if self._db is None:
            self._storage_lbl.setText("Stored: —")
            return
        try:
            count = self._db.network_event_count()
            size = self._db.db_size_bytes()
        except Exception:
            return
        suffix = f" · {self._fmt_size(size)}" if size else ""
        self._storage_lbl.setText(f"Stored: {count:,} events{suffix}")

    # ------------------------------------------------------------------ #
    # worker signals
    # ------------------------------------------------------------------ #
    def _on_event(self, event: dict):
        # cap table size
        max_rows = self._max_spin.value()
        while self._table.rowCount() >= max_rows:
            self._table.removeRow(0)
            if self._rows_data:
                self._rows_data.pop(0)
        self._append_row(event, scroll=True)
        self._tally(event)
        self._refresh_stats()

    def _on_alert(self, alert: dict):
        self._show_banner(alert)
        self._add_alert_row(alert)

    def _on_state(self, state: str, message: str):
        self._status.setText(message)
        if state == "error":
            self._status.setStyleSheet(f"color: {T.CRITICAL}; font-size: {T.FS_SMALL}px;")
        elif state == "running":
            self._status.setStyleSheet(f"color: {T.SUCCESS}; font-size: {T.FS_SMALL}px;")
        else:
            self._status.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_SMALL}px;")

    def _on_error(self, source: str, message: str):
        self._status.setText(f"[{source}] {message}")
        self._status.setStyleSheet(f"color: {T.CRITICAL}; font-size: {T.FS_SMALL}px;")

    # ------------------------------------------------------------------ #
    # table / stats helpers
    # ------------------------------------------------------------------ #
    def _append_row(self, ev: dict, scroll: bool):
        blocked = ev.get("status") == "blocked"
        self._table.setSortingEnabled(False)
        r = self._table.rowCount()
        self._table.insertRow(r)
        ts = str(ev.get("timestamp", ""))[:19].replace("T", " ")
        cells = [
            ts,
            str(ev.get("employee_name") or ev.get("src_ip", "")),
            str(ev.get("domain", "")),
            str(ev.get("port", "")),
            str(ev.get("protocol", "")),
            "BLOCKED" if blocked else "Allowed",
            str(ev.get("blocked_reason", "") if blocked else "permit"),
        ]
        for c, text in enumerate(cells):
            item = QTableWidgetItem(text)
            if blocked:
                item.setForeground(QBrush(QColor(T.CRITICAL)))
                item.setBackground(QBrush(QColor(220, 38, 38, 28)))
            if c == 5:  # status cell emphasis
                item.setForeground(QBrush(QColor(T.CRITICAL if blocked else T.SUCCESS)))
            self._table.setItem(r, c, item)
        self._rows_data.append(ev)
        self._table.setSortingEnabled(True)
        if scroll:
            self._table.scrollToBottom()
        self._apply_filters_to_row(r)

    def _tally(self, ev: dict):
        self._total += 1
        if ev.get("src_ip"):
            self._employees.add(ev["src_ip"])
        if ev.get("status") == "blocked":
            self._blocked += 1
            if ev.get("domain"):
                self._top_blocked[ev["domain"]] += 1

    def _refresh_stats(self):
        self._tile_total.set_value(self._total)
        self._tile_blocked.set_value(self._blocked)
        self._tile_emp.set_value(len(self._employees))
        self._dist.set_counts(self._total - self._blocked, self._blocked)
        if self._total:
            pct = 100.0 * self._blocked / self._total
            self._dist_lbl.setText(
                f"{self._total - self._blocked} allowed · {self._blocked} blocked "
                f"({pct:.1f}%)"
            )
        else:
            self._dist_lbl.setText("No traffic yet")
        if self._top_blocked:
            lines = [f"{n:>3}×  {d}" for d, n in self._top_blocked.most_common(5)]
            self._top_list.setText("\n".join(lines))
        else:
            self._top_list.setText("—")

    # ------------------------------------------------------------------ #
    # filters
    # ------------------------------------------------------------------ #
    def _row_matches(self, ev: dict) -> bool:
        ip_f = self._f_ip.text().strip().lower()
        dom_f = self._f_domain.text().strip().lower()
        status_f = self._f_status.currentText()
        if ip_f and ip_f not in f"{ev.get('employee_name','')} {ev.get('src_ip','')}".lower():
            return False
        if dom_f and dom_f not in str(ev.get("domain", "")).lower():
            return False
        if status_f == "Allowed" and ev.get("status") != "allowed":
            return False
        if status_f == "Blocked" and ev.get("status") != "blocked":
            return False
        return True

    def _apply_filters_to_row(self, r: int):
        if 0 <= r < len(self._rows_data):
            self._table.setRowHidden(r, not self._row_matches(self._rows_data[r]))

    def _apply_filters(self):
        for r, ev in enumerate(self._rows_data):
            self._table.setRowHidden(r, not self._row_matches(ev))

    # ------------------------------------------------------------------ #
    # alerts + banner
    # ------------------------------------------------------------------ #
    def _show_banner(self, alert: dict):
        sev = alert.get("severity", "medium").upper()
        self._banner.setText(
            f"⛔  BLOCKED [{sev}]  {alert.get('domain','')}  ←  "
            f"{alert.get('employee_name','')}   ·  {alert.get('notes','')}"
        )
        self._banner.setVisible(True)
        self._banner_timer.start(4500)

    def _add_alert_row(self, alert: dict):
        self._alert_empty.setVisible(False)
        row = QFrame()
        color = _SEV_COLOR.get(alert.get("severity", "medium"), T.MEDIUM)
        row.setStyleSheet(
            f"QFrame {{ background: {T.CARD}; border: 1px solid {color}; "
            f"border-left: 3px solid {color}; border-radius: {T.RADIUS_SM}px; }}"
        )
        rl = QVBoxLayout(row)
        rl.setContentsMargins(8, 5, 8, 5)
        rl.setSpacing(2)

        top = QHBoxLayout()
        badge = QLabel(alert.get("severity", "medium").upper())
        badge.setStyleSheet(
            f"background: {color}; color: #FFFFFF; border-radius: 3px; "
            f"padding: 0px 6px; font-size: {T.FS_TINY}px; font-weight: bold;"
        )
        ts = str(alert.get("created_at", ""))[:19].replace("T", " ")
        ts_lbl = QLabel(ts)
        ts_lbl.setStyleSheet(f"color: {T.TXT3}; font-family: {T.FONT_MONO}; font-size: {T.FS_TINY}px;")
        top.addWidget(badge)
        top.addStretch()
        top.addWidget(ts_lbl)
        rl.addLayout(top)

        dom = QLabel(f"<b>{alert.get('domain','')}</b> ← {alert.get('employee_name','')}")
        dom.setStyleSheet(f"color: {T.TXT}; font-size: {T.FS_SMALL}px;")
        dom.setWordWrap(True)
        rl.addWidget(dom)

        reason = QLabel(alert.get("notes", ""))
        reason.setStyleSheet(f"color: {T.TXT3}; font-size: {T.FS_TINY}px;")
        reason.setWordWrap(True)
        rl.addWidget(reason)

        ack = QCheckBox("Acknowledge")
        ack.setStyleSheet(f"color: {T.TXT2}; font-size: {T.FS_TINY}px;")
        alert_id = alert.get("id")
        ack.stateChanged.connect(
            lambda st, aid=alert_id: self._on_ack(aid, st == Qt.CheckState.Checked.value)
        )
        rl.addWidget(ack)

        # newest alert on top
        self._alert_layout.insertWidget(0, row)
        # cap alert rows
        while self._alert_layout.count() > 52:  # rows + empty + stretch
            item = self._alert_layout.takeAt(self._alert_layout.count() - 3)
            if item and item.widget():
                item.widget().deleteLater()

    def _on_ack(self, alert_id, acknowledged: bool):
        if alert_id is not None and self._db is not None:
            try:
                self._db.set_network_alert_ack(alert_id, acknowledged)
            except Exception:
                pass
