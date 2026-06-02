from screens.report import ReportScreen


def test_report_has_export_button(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._export_btn is not None


def test_report_export_button_disabled(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert not screen._export_btn.isEnabled()


def test_report_has_placeholder_label(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._placeholder_label is not None
