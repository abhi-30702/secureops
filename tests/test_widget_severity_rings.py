from models import Finding
from screens.widgets.severity_rings import SeverityRings


def _finding(severity: str) -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool="nuclei",
                   severity=severity, title="Test", description="",
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_severity_rings_has_four_rings(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    assert len(rings._rings) == 4


def test_severity_rings_counts_start_at_zero(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    for ring in rings._rings.values():
        assert ring.count == 0


def test_severity_rings_critical_increments_on_finding(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("critical"))
    assert rings._rings["critical"].count == 1


def test_severity_rings_high_increments_on_finding(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("high"))
    assert rings._rings["high"].count == 1
    assert rings._rings["critical"].count == 0


def test_severity_rings_reset_zeroes_all_counts(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("critical"))
    rings.add_finding(_finding("medium"))
    rings.reset()
    for ring in rings._rings.values():
        assert ring.count == 0


def test_severity_rings_ignores_unknown_severity(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("info"))
    total = sum(r.count for r in rings._rings.values())
    assert total == 0


def test_severity_rings_medium_and_low_increment(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("medium"))
    rings.add_finding(_finding("low"))
    assert rings._rings["medium"].count == 1
    assert rings._rings["low"].count == 1


def test_severity_rings_scan_complete_does_not_change_counts(qtbot):
    rings = SeverityRings()
    qtbot.addWidget(rings)
    rings.add_finding(_finding("critical"))
    rings.on_scan_complete(5, 1)
    assert rings._rings["critical"].count == 1
