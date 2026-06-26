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


def test_run_resolves_cmd0_through_tool_path(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None
        return mock_proc

    monkeypatch.setattr('workers.base_tool._tool_path',
                        lambda name: f'/opt/secureops/tools/{name}',
                        raising=False)
    with patch('subprocess.Popen', fake_popen):
        list(runner.run(['subfinder', '-d', 'example.com']))

    assert captured['cmd'][0] == '/opt/secureops/tools/subfinder'
    assert captured['cmd'][1:] == ['-d', 'example.com']


def test_run_buffered_resolves_cmd0_through_tool_path(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ''
        return mock_result

    monkeypatch.setattr('workers.base_tool._tool_path',
                        lambda name: f'/opt/secureops/tools/{name}',
                        raising=False)
    with patch('subprocess.run', fake_run):
        runner.run_buffered(['nmap', '-sV', '10.0.0.1'])

    assert captured['cmd'][0] == '/opt/secureops/tools/nmap'
    assert captured['cmd'][1:] == ['-sV', '10.0.0.1']


def test_run_falls_back_to_original_name_when_tool_path_returns_none(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None
        return mock_proc

    monkeypatch.setattr('workers.base_tool._tool_path', lambda name: None, raising=False)
    with patch('subprocess.Popen', fake_popen):
        list(runner.run(['subfinder', '-d', 'example.com']))

    assert captured['cmd'][0] == 'subfinder'


# --- Reliability: streaming run() must enforce timeout, drain stderr, surface it ---

def test_run_kills_and_raises_on_timeout(monkeypatch):
    """A tool that hangs with no output must be killed and reported, not block forever."""
    import pytest
    monkeypatch.setattr('workers.base_tool._tool_path', lambda name: None, raising=False)
    runner = _make_runner()
    with pytest.raises(ToolError, match="timed out"):
        list(runner.run(["sleep", "10"], timeout=1))


def test_run_surfaces_stderr_in_error_message(monkeypatch):
    """On non-zero exit, the error should include the tool's stderr, not just the code."""
    import pytest
    monkeypatch.setattr('workers.base_tool._tool_path', lambda name: None, raising=False)
    runner = _make_runner()
    with pytest.raises(ToolError, match="distinctive-failure-reason"):
        list(runner.run(["sh", "-c", "echo distinctive-failure-reason >&2; exit 3"]))


def test_run_does_not_deadlock_on_large_stderr(monkeypatch):
    """Heavy stderr output must not block stdout streaming (pipe-buffer deadlock)."""
    monkeypatch.setattr('workers.base_tool._tool_path', lambda name: None, raising=False)
    runner = _make_runner()
    script = "for i in $(seq 1 20000); do echo noise >&2; done; echo finished"
    lines = list(runner.run(["sh", "-c", script], timeout=30))
    assert "finished" in lines
