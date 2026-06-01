import pytest
from PyQt6.QtCore import Qt
from tool_checker import TOOLS
from status_bar import ToolStatusBar


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def _non_critical_missing():
    results = {t: True for t in TOOLS}
    results["dnsx"] = False
    return results


def test_status_bar_shows_ready_count_all_present(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    assert f"{len(TOOLS)}/{len(TOOLS)}" in bar._label.text()


def test_status_bar_shows_partial_count(qtbot):
    results = _all_present()
    results["dnsx"] = False
    bar = ToolStatusBar(results)
    qtbot.addWidget(bar)
    assert f"{len(TOOLS) - 1}/{len(TOOLS)}" in bar._label.text()


def test_status_bar_dot_green_when_all_present(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    assert "#00ff88" in bar._dot.styleSheet()


def test_status_bar_dot_red_when_critical_missing(qtbot):
    bar = ToolStatusBar(_critical_missing())
    qtbot.addWidget(bar)
    assert "#ff4444" in bar._dot.styleSheet()


def test_status_bar_dot_amber_when_non_critical_missing(qtbot):
    bar = ToolStatusBar(_non_critical_missing())
    qtbot.addWidget(bar)
    assert "#ffaa00" in bar._dot.styleSheet()


def test_status_bar_emits_navigate_on_click(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    bar.show()

    with qtbot.waitSignal(bar.navigate_to_settings, timeout=1000):
        qtbot.mouseClick(bar, Qt.MouseButton.LeftButton)
