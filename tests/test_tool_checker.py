import sys
import shutil as _shutil
from unittest.mock import patch
from tool_checker import _tool_path, check_tools, is_critical_missing, ready_count, TOOLS, CRITICAL_TOOLS


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


def test_tool_path_not_frozen_uses_which(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: f'/usr/bin/{name}')
    assert _tool_path('nmap') == '/usr/bin/nmap'


def test_tool_path_not_frozen_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: None)
    assert _tool_path('missing_tool') is None


def test_tool_path_frozen_returns_bundled_when_exists(tmp_path, monkeypatch):
    tools_dir = tmp_path / 'tools'
    tools_dir.mkdir()
    bundled = tools_dir / 'subfinder'
    bundled.write_text('binary')
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    assert _tool_path('subfinder') == str(bundled)


def test_tool_path_frozen_falls_back_to_which_when_not_bundled(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: f'/usr/bin/{name}')
    assert _tool_path('nmap') == '/usr/bin/nmap'


def test_tool_path_frozen_returns_none_when_not_found_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: None)
    assert _tool_path('nonexistent') is None


def test_check_tools_uses_tool_path(monkeypatch):
    monkeypatch.setattr('tool_checker._tool_path', lambda name: '/fake' if name == 'nmap' else None)
    from tool_checker import check_tools
    results = check_tools()
    assert results['nmap'] is True
    assert results['subfinder'] is False
