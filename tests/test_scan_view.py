import gc
import pytest
from unittest.mock import patch
from PyQt6.QtCore import Qt
from screens.scan_view import ScanViewScreen


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def test_scan_view_has_mode_toggle_buttons(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert view._scan_mode_btn is not None
    assert view._log_mode_btn is not None


def test_scan_view_default_mode_is_scan(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert view._mode == "scan"


def test_switching_to_log_mode_shows_browse_button(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    assert not view._browse_btn.isVisible()
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    assert view._browse_btn.isVisible()
    assert view._mode == "logs"


def test_switching_back_to_scan_mode_hides_browse_button(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    qtbot.mouseClick(view._scan_mode_btn, Qt.MouseButton.LeftButton)
    assert not view._browse_btn.isVisible()
    assert view._mode == "scan"


def test_log_mode_creates_log_analyzer_worker(qtbot, db, tmp_path):
    from workers.log_analyzer import LogAnalyzerWorker
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jun  5 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4\n")
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    view._target_input.setText(str(log_file))

    with patch.object(LogAnalyzerWorker, "start"):
        view._on_start_cancel()

    assert isinstance(view._worker, LogAnalyzerWorker)


def test_scan_mode_creates_scan_worker(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view._target_input.setText("example.com")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()

    assert isinstance(view._worker, ScanWorker)
