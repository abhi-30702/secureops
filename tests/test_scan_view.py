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


def test_scan_view_has_ip_mode_button(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert view._ip_mode_btn is not None


def test_switching_to_ip_mode_hides_browse_and_shows_pipeline(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    qtbot.mouseClick(view._ip_mode_btn, Qt.MouseButton.LeftButton)
    assert view._mode == "ip"
    assert not view._browse_btn.isVisible()
    assert view._pipeline_panel.isVisible()
    assert view._start_btn.text() == "▶  Scan IP"


def test_ip_mode_with_valid_ip_creates_scan_worker(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    qtbot.mouseClick(view._ip_mode_btn, Qt.MouseButton.LeftButton)
    view._target_input.setText("192.168.1.10")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()

    assert isinstance(view._worker, ScanWorker)


def test_ip_mode_rejects_invalid_ip(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    qtbot.mouseClick(view._ip_mode_btn, Qt.MouseButton.LeftButton)
    view._target_input.setText("example.com")

    view._on_start_cancel()

    assert view._worker is None
    assert "not a valid IP" in view._status_label.text()


def test_starting_scan_shows_running_indicators(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    view._target_input.setText("example.com")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()

    assert view._elapsed_timer.isActive()
    assert view._busy_bar.isVisible()
    assert view._pulse_dot.isVisible()
    assert view._timer_label.text() == "⏱  00:00"


def test_scan_complete_stops_running_indicators(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    view._target_input.setText("example.com")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()
    view._on_scan_complete(3, 5)

    assert not view._elapsed_timer.isActive()
    assert not view._busy_bar.isVisible()
    assert not view._pulse_dot.isVisible()


def test_scan_failed_stops_running_indicators(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view.show()
    view._target_input.setText("example.com")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()
    view._on_scan_failed("boom")

    assert not view._elapsed_timer.isActive()
    assert not view._busy_bar.isVisible()


def test_elapsed_tick_formats_mm_ss(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)

    view._elapsed_secs = 0
    view._on_elapsed_tick()
    assert view._timer_label.text() == "⏱  00:01"

    view._elapsed_secs = 74
    view._on_elapsed_tick()
    assert view._timer_label.text() == "⏱  01:15"


def test_elapsed_tick_formats_hours(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)

    view._elapsed_secs = 3661  # tick → 3662 = 1h 1m 2s
    view._on_elapsed_tick()
    assert view._timer_label.text() == "⏱  1:01:02"
