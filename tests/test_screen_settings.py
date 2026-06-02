from tool_checker import TOOLS, CRITICAL_TOOLS
from screens.settings import SettingsScreen


def _all_present():
    return {t: True for t in TOOLS}


def _some_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    results["dnsx"] = False
    return results


def test_settings_has_row_for_every_tool(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._tool_rows) == len(TOOLS)


def test_settings_tool_rows_keyed_by_tool_name(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in TOOLS:
        assert tool in screen._tool_rows


def test_settings_critical_tools_marked(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in CRITICAL_TOOLS:
        row = screen._tool_rows[tool]
        assert row["is_critical"] is True


def test_settings_non_critical_not_marked(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in TOOLS:
        if tool not in CRITICAL_TOOLS:
            assert screen._tool_rows[tool]["is_critical"] is False


def test_settings_missing_tool_shows_false_status(qtbot):
    results = _some_missing()
    screen = SettingsScreen(results)
    qtbot.addWidget(screen)
    assert screen._tool_rows["nmap"]["present"] is False
    assert screen._tool_rows["dnsx"]["present"] is False


def test_settings_present_tool_shows_true_status(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._tool_rows["subfinder"]["present"] is True
