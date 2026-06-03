from tool_checker import TOOLS
from main_window import MainWindow


def _all_present():
    return {t: True for t in TOOLS}


def test_main_window_stack_has_five_screens(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._stack.count() == 5


def test_main_window_default_screen_is_dashboard(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._stack.currentIndex() == 0


def test_main_window_sidebar_signal_changes_screen(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    win._sidebar.screen_changed.emit(3)
    assert win._stack.currentIndex() == 3


def test_main_window_status_bar_signal_navigates_to_settings(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    win._status_bar_widget.navigate_to_settings.emit()
    assert win._stack.currentIndex() == 4


def test_main_window_has_status_bar_widget(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._status_bar_widget is not None


def test_main_window_report_screen_has_db(qtbot):
    from screens.report import ReportScreen
    from db import DB

    def _make_db():
        return DB(":memory:")

    db = _make_db()
    win = MainWindow(tool_results={}, db=db)
    qtbot.addWidget(win)
    report = win._stack.widget(3)
    assert isinstance(report, ReportScreen)
    assert report._db is db


def test_main_window_dashboard_has_db(qtbot):
    from screens.dashboard import DashboardScreen
    from db import DB
    db = DB(":memory:")
    win = MainWindow(tool_results={}, db=db)
    qtbot.addWidget(win)
    dashboard = win._stack.widget(0)
    assert isinstance(dashboard, DashboardScreen)
    assert dashboard._db is db
