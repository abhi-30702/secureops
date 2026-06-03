from models import Finding
from screens.widgets.finding_cards import FindingCards


def _finding(tool: str = "nuclei", severity: str = "critical",
             title: str = "Test Finding", description: str = "desc") -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool=tool,
                   severity=severity, title=title, description=description,
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_finding_cards_starts_empty(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    assert fc.card_count == 0


def test_finding_cards_add_finding_increments_count(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding())
    assert fc.card_count == 1


def test_finding_cards_newest_at_top(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding(title="First"))
    fc.add_finding(_finding(title="Second"))
    assert fc._cards[0].title == "Second"
    assert fc._cards[1].title == "First"


def test_finding_cards_capped_at_200(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    for i in range(205):
        fc.add_finding(_finding(title=f"Finding {i}"))
    assert fc.card_count == 200


def test_finding_cards_scan_complete_adds_summary(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.on_scan_complete(47, 12)
    assert fc.card_count == 1
    assert fc._cards[0].title == "Scan complete"


def test_finding_cards_reset_clears_all(qtbot):
    fc = FindingCards()
    qtbot.addWidget(fc)
    fc.add_finding(_finding())
    fc.add_finding(_finding())
    fc.reset()
    assert fc.card_count == 0
