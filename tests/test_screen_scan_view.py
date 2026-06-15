import gc
import pytest
from screens.scan_view import ScanViewScreen


@pytest.fixture(autouse=True)
def _gc_after_each():
    """Force Python GC after every test in this file.

    ScanViewScreen embeds an AttackGraph (pyqtgraph PlotWidget). Without
    explicit collection, accumulated pyqtgraph C++ objects across the ~25
    tests in this file exhaust internal pyqtgraph state and trigger a
    segfault mid-suite. gc.collect() destroys each PlotWidget promptly
    so the next test starts from a clean slate.
    """
    yield
    gc.collect()


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


from db import DB


def _make_db():
    return DB(":memory:")


def test_scan_view_start_button_enabled_with_db(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert screen._start_btn.isEnabled()


def test_scan_view_has_status_label(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._status_label is not None


def test_scan_view_terminal_panel_is_plain_text_edit(qtbot):
    from PyQt6.QtWidgets import QPlainTextEdit
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._terminal_panel, QPlainTextEdit)


def test_scan_view_start_button_still_disabled_without_db(qtbot):
    screen = ScanViewScreen(db=None)
    qtbot.addWidget(screen)
    assert not screen._start_btn.isEnabled()


from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards


def test_scan_view_pipeline_panel_is_pipeline_tracker(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._pipeline_panel, PipelineTracker)


def test_scan_view_attack_graph_panel_is_attack_graph(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._attack_graph_panel, AttackGraph)


def test_scan_view_severity_panel_is_severity_rings(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._severity_panel, SeverityRings)


def test_scan_view_finding_cards_panel_is_finding_cards(qtbot):
    screen = ScanViewScreen(db=_make_db())
    qtbot.addWidget(screen)
    assert isinstance(screen._finding_cards_panel, FindingCards)


def test_scan_view_has_scan_ready_signal(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert hasattr(screen, "scan_ready")


def test_scan_view_start_scan_sets_target(qtbot):
    from db import DB
    db = DB(":memory:")
    screen = ScanViewScreen(db=db)
    qtbot.addWidget(screen)
    screen.start_scan("example.com")
    assert screen._target_input.text() == "example.com"
