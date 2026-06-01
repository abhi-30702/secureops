from unittest.mock import patch
from tool_checker import check_tools, is_critical_missing, ready_count, TOOLS, CRITICAL_TOOLS


def test_check_tools_returns_dict_with_all_tools():
    with patch("tool_checker.shutil.which", return_value="/usr/bin/tool"):
        result = check_tools()
    assert set(result.keys()) == set(TOOLS)


def test_check_tools_true_when_tool_found():
    with patch("tool_checker.shutil.which", return_value="/usr/bin/subfinder"):
        result = check_tools()
    assert result["subfinder"] is True


def test_check_tools_false_when_tool_missing():
    with patch("tool_checker.shutil.which", return_value=None):
        result = check_tools()
    assert result["subfinder"] is False


def test_is_critical_missing_false_when_all_present():
    results = {t: True for t in TOOLS}
    assert is_critical_missing(results) is False


def test_is_critical_missing_true_when_nmap_absent():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    assert is_critical_missing(results) is True


def test_ready_count_all_present():
    results = {t: True for t in TOOLS}
    assert ready_count(results) == len(TOOLS)


def test_ready_count_partial():
    results = {t: True for t in TOOLS}
    results["dnsx"] = False
    results["katana"] = False
    assert ready_count(results) == len(TOOLS) - 2
