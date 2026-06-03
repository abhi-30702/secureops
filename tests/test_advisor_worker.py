from advisor.worker import parse_advisor_response


_VALID = """\
IMMEDIATE:
1. Patch OpenSSL immediately
2. Disable SSLv3 and TLS 1.0
SHORT_TERM:
1. Review firewall rules for port 443
PREVENTIVE:
1. Enable automated dependency scanning
"""

_MISSING_PREVENTIVE = """\
IMMEDIATE:
1. Do something
SHORT_TERM:
1. Do something else
"""

_EMPTY = ""


def test_parse_valid_response_count():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert len(items) == 4


def test_parse_valid_response_tiers():
    items = parse_advisor_response(_VALID, scan_id=1)
    tiers = {i.tier for i in items}
    assert tiers == {"immediate", "short_term", "preventive"}


def test_parse_valid_response_scan_id():
    items = parse_advisor_response(_VALID, scan_id=7)
    assert all(i.scan_id == 7 for i in items)


def test_parse_valid_response_not_accepted():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert all(i.accepted is False for i in items)


def test_parse_valid_response_no_id():
    items = parse_advisor_response(_VALID, scan_id=1)
    assert all(i.id is None for i in items)


def test_parse_immediate_text():
    items = parse_advisor_response(_VALID, scan_id=1)
    immediate = [i for i in items if i.tier == "immediate"]
    assert any("OpenSSL" in i.text for i in immediate)


def test_parse_missing_tier_returns_empty():
    assert parse_advisor_response(_MISSING_PREVENTIVE, scan_id=1) == []


def test_parse_empty_response_returns_empty():
    assert parse_advisor_response(_EMPTY, scan_id=1) == []
