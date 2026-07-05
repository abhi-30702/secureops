from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget, QSizeGrip,
)
from sidebar import Sidebar
from status_bar import ToolStatusBar
from screens.widgets.morphism import RootBackground, TitleBar
from screens.dashboard import DashboardScreen
from screens.client_onboarding import ClientOnboardingScreen
from screens.scan_view import ScanViewScreen
from screens.report import ReportScreen
from screens.settings import SettingsScreen
from screens.internal_page import InternalPage
from screens.incident_page import IncidentPage
from screens.osint_page import OsintPage
from screens.history import HistoryScreen
from db import DB


class MainWindow(QMainWindow):
    def __init__(self, tool_results: dict, db: DB | None = None, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._db = db
        self._sidebar: Sidebar | None = None
        self._stack: QStackedWidget | None = None
        self._title_bar: TitleBar | None = None
        self._status_bar_widget: ToolStatusBar | None = None
        self._scan_view: ScanViewScreen | None = None
        self._report: ReportScreen | None = None
        self._dashboard: DashboardScreen | None = None
        self._history: HistoryScreen | None = None
        self._schedule_manager = None
        self._delta_workers: list = []
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("SecureOps")
        self.setMinimumSize(1200, 700)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        outer = RootBackground()
        self.setCentralWidget(outer)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self._title_bar = TitleBar(self, "SecureOps")
        outer_layout.addWidget(self._title_bar)

        content_row = QWidget()
        row_layout = QHBoxLayout(content_row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self._sidebar = Sidebar()
        self._stack = QStackedWidget()

        self._scan_view = ScanViewScreen(db=self._db)
        self._report = ReportScreen(db=self._db)
        self._dashboard = DashboardScreen(self._tool_results, db=self._db)
        self._stack.addWidget(self._dashboard)                            # 0
        self._stack.addWidget(ClientOnboardingScreen(db=self._db))        # 1
        self._stack.addWidget(self._scan_view)                            # 2
        self._stack.addWidget(self._report)                               # 3
        self._stack.addWidget(SettingsScreen(self._tool_results, db=self._db))  # 4
        self._internal = InternalPage(db=self._db)
        self._stack.addWidget(self._internal)                                   # 5
        self._internal.scan_ready.connect(self._on_scan_ready)
        self._incident = IncidentPage(db=self._db)
        self._stack.addWidget(self._incident)                                   # 6
        self._incident.scan_ready.connect(self._on_scan_ready)
        self._osint = OsintPage(db=self._db)
        self._stack.addWidget(self._osint)                                      # 7
        self._history = HistoryScreen(db=self._db)
        self._stack.addWidget(self._history)                                    # 8
        self._history.scan_selected.connect(self._on_history_open)

        row_layout.addWidget(self._sidebar)
        row_layout.addWidget(self._stack, stretch=1)
        outer_layout.addWidget(content_row, stretch=1)

        self._status_bar_widget = ToolStatusBar(self._tool_results)
        bottom = QWidget()
        bottom_row = QHBoxLayout(bottom)
        bottom_row.setContentsMargins(0, 0, 0, 0)
        bottom_row.setSpacing(0)
        bottom_row.addWidget(self._status_bar_widget, stretch=1)
        grip = QSizeGrip(bottom)
        bottom_row.addWidget(grip, 0, Qt.AlignmentFlag.AlignBottom | Qt.AlignmentFlag.AlignRight)
        outer_layout.addWidget(bottom)

        self._sidebar.screen_changed.connect(self._stack.setCurrentIndex)
        self._sidebar.screen_changed.connect(self._on_screen_changed)
        self._status_bar_widget.navigate_to_settings.connect(
            lambda: self._stack.setCurrentIndex(4)
        )
        self._scan_view.scan_ready.connect(self._on_scan_ready)

        if self._db:
            from scheduler.schedule_manager import ScheduleManager
            self._schedule_manager = ScheduleManager(db=self._db, parent=self)
            self._schedule_manager.scan_due.connect(self._on_scan_due)

    def _on_screen_changed(self, index: int):
        # Refresh history whenever the user opens it so new scans appear.
        if index == 8 and self._history:
            self._history.refresh()

    def _on_history_open(self, scan_id: int):
        self._report.load_scan(scan_id)
        self._stack.setCurrentIndex(3)

    def _on_scan_ready(self, scan_id: int):
        self._report.load_scan(scan_id)
        self._stack.setCurrentIndex(3)
        if self._dashboard:
            self._dashboard.refresh()
        if self._history:
            self._history.refresh()
        if self._db and self._dashboard and self._dashboard._delta_panel:
            from workers.delta_worker import DeltaWorker
            worker = DeltaWorker(scan_id=scan_id, db=self._db, parent=self)
            worker.delta_ready.connect(self._dashboard._delta_panel.add_delta)
            self._delta_workers.append(worker)
            worker.finished.connect(lambda: self._delta_workers.remove(worker) if worker in self._delta_workers else None)
            worker.start()

    def _on_scan_due(self, target: str):
        self._stack.setCurrentIndex(2)
        self._scan_view.start_scan(target)
