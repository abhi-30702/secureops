import threading
from unittest.mock import patch, MagicMock
from workers.base_tool import ToolRunner, ToolError, CancelledError


def _make_runner(cancel_event=None):
    return ToolRunner(cancel_event or threading.Event())


def test_run_yields_stdout_lines():
    mock_proc = MagicMock()
    mock_proc.stdout.__iter__ = MagicMock(return_value=iter(["line1\n", "line2\n"]))
    mock_proc.returncode = 0
    mock_proc.wait = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc):
        runner = _make_runner()
        lines = list(runner.run(["echo", "test"]))

    assert lines == ["line1", "line2"]


def test_run_raises_tool_error_on_nonzero_exit():
    mock_proc = MagicMock()
    mock_proc.stdout.__iter__ = MagicMock(return_value=iter([]))
    mock_proc.returncode = 1
    mock_proc.wait = MagicMock()

    with patch("subprocess.Popen", return_value=mock_proc):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError):
            list(runner.run(["false"]))


def test_run_raises_tool_error_on_missing_binary():
    with patch("subprocess.Popen", side_effect=FileNotFoundError):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError, match="not found"):
            list(runner.run(["nonexistent_binary"]))


def test_run_raises_cancelled_error_when_event_set():
    cancel = threading.Event()
    cancel.set()

    runner = ToolRunner(cancel)
    import pytest
    with pytest.raises(CancelledError):
        list(runner.run(["echo", "test"]))


def test_run_buffered_returns_stdout():
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = '{"key": "value"}'

    with patch("subprocess.run", return_value=mock_result):
        runner = _make_runner()
        output = runner.run_buffered(["nmap", "-oX", "-"])

    assert output == '{"key": "value"}'


def test_run_buffered_raises_tool_error_on_nonzero():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""

    with patch("subprocess.run", return_value=mock_result):
        runner = _make_runner()
        import pytest
        with pytest.raises(ToolError):
            runner.run_buffered(["nmap", "-oX", "-"])
