from tool_checker import TOOLS
from screens.dashboard import DashboardScreen


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def test_dashboard_has_three_metric_cards(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._metric_cards) == 3


def test_dashboard_metric_card_labels(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    titles = [c.title for c in screen._metric_cards]
    assert "Clients" in titles
    assert "Scans" in titles
    assert "Findings" in titles


def test_dashboard_warning_banner_hidden_when_tools_ok(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._warning_banner.isVisible()


def test_dashboard_warning_banner_shown_when_critical_missing(qtbot):
    screen = DashboardScreen(_critical_missing())
    qtbot.addWidget(screen)
    screen.show()
    assert screen._warning_banner.isVisible()


def test_dashboard_has_severity_strip(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._severity_strip is not None
