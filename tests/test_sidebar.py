import pytest
from PyQt6.QtCore import Qt
from sidebar import Sidebar, COLLAPSED_WIDTH, EXPANDED_WIDTH


def test_sidebar_has_seven_nav_buttons(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert len(sidebar._buttons) == 7


def test_sidebar_starts_collapsed(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert sidebar.maximumWidth() == COLLAPSED_WIDTH


def test_sidebar_emits_screen_changed_on_click(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    sidebar.show()

    with qtbot.waitSignal(sidebar.screen_changed, timeout=1000) as blocker:
        qtbot.mouseClick(sidebar._buttons[2], Qt.MouseButton.LeftButton)

    assert blocker.args == [2]


def test_sidebar_tracks_active_index(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    sidebar.show()

    qtbot.mouseClick(sidebar._buttons[3], Qt.MouseButton.LeftButton)
    assert sidebar.active_index == 3


def test_sidebar_default_active_index_is_zero(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert sidebar.active_index == 0
