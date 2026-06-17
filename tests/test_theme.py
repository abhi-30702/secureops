import re
import pytest


def test_all_constants_are_valid_hex():
    from screens.widgets.theme import (
        BG, CARD, INPUT, ACCENT, ACCENT_H, TXT, TXT2, TXT3,
        BORDER, CRITICAL, HIGH, MEDIUM, LOW, INFO, SUCCESS,
    )
    colors = [BG, CARD, INPUT, ACCENT, ACCENT_H, TXT, TXT2, TXT3,
              BORDER, CRITICAL, HIGH, MEDIUM, LOW, INFO, SUCCESS]
    pattern = re.compile(r'^#[0-9A-Fa-f]{6}$')
    for c in colors:
        assert pattern.match(c), f"{c!r} is not a valid #RRGGBB hex"


def test_severity_colors_has_all_keys():
    from screens.widgets.theme import SEVERITY_COLORS
    assert set(SEVERITY_COLORS.keys()) == {"critical", "high", "medium", "low", "info"}


def test_severity_colors_values_match_constants():
    from screens.widgets.theme import SEVERITY_COLORS, CRITICAL, HIGH, MEDIUM, LOW, INFO
    assert SEVERITY_COLORS["critical"] == CRITICAL
    assert SEVERITY_COLORS["high"] == HIGH
    assert SEVERITY_COLORS["medium"] == MEDIUM
    assert SEVERITY_COLORS["low"] == LOW
    assert SEVERITY_COLORS["info"] == INFO
