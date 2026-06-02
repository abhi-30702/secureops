from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
)
from sidebar import Sidebar
from status_bar import ToolStatusBar
from screens.dashboard import DashboardScreen
from screens.client_onboarding import ClientOnboardingScreen
from screens.scan_view import ScanViewScreen
from screens.report import ReportScreen
from screens.settings import SettingsScreen


class MainWindow(QMainWindow):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._sidebar: Sidebar | None = None
        self._stack: QStackedWidget | None = None
        self._status_bar_widget: ToolStatusBar | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("SecureOps")
        self.setMinimumSize(1200, 700)

        outer = QWidget()
        self.setCentralWidget(outer)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        content_row = QWidget()
        row_layout = QHBoxLayout(content_row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self._sidebar = Sidebar()
        self._stack = QStackedWidget()

        self._stack.addWidget(DashboardScreen(self._tool_results))        # 0
        self._stack.addWidget(ClientOnboardingScreen())                    # 1
        self._stack.addWidget(ScanViewScreen())                            # 2
        self._stack.addWidget(ReportScreen())                              # 3
        self._stack.addWidget(SettingsScreen(self._tool_results))          # 4

        row_layout.addWidget(self._sidebar)
        row_layout.addWidget(self._stack, stretch=1)
        outer_layout.addWidget(content_row, stretch=1)

        self._status_bar_widget = ToolStatusBar(self._tool_results)
        outer_layout.addWidget(self._status_bar_widget)

        self._sidebar.screen_changed.connect(self._stack.setCurrentIndex)
        self._status_bar_widget.navigate_to_settings.connect(
            lambda: self._stack.setCurrentIndex(4)
        )
