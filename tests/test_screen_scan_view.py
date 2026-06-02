from screens.scan_view import ScanViewScreen


def test_scan_view_has_target_input(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._target_input is not None


def test_scan_view_start_button_disabled(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert not screen._start_btn.isEnabled()


def test_scan_view_has_pipeline_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._pipeline_panel is not None


def test_scan_view_has_attack_graph_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._attack_graph_panel is not None


def test_scan_view_has_severity_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._severity_panel is not None


def test_scan_view_has_finding_cards_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._finding_cards_panel is not None


def test_scan_view_has_terminal_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._terminal_panel is not None
