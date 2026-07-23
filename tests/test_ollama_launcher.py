"""Tests for the AI-Advisor Ollama launcher worker."""
from advisor import ollama_launcher
from advisor.ollama_launcher import OllamaLauncher, server_up


def test_server_up_false_when_unreachable(monkeypatch):
    def _boom(*a, **k):
        raise OSError("connection refused")
    monkeypatch.setattr(ollama_launcher.urllib.request, "urlopen", _boom)
    assert server_up(timeout=0.1) is False


def test_launcher_defaults_model(qtbot):
    w = OllamaLauncher(model="")
    assert w._model == "llama3"
    w2 = OllamaLauncher(model="llama3.2:1b")
    assert w2._model == "llama3.2:1b"


def test_warm_model_reports_missing_model(qtbot, monkeypatch):
    import urllib.error

    def _raise_404(*a, **k):
        raise urllib.error.HTTPError(
            url="x", code=404, msg="not found", hdrs=None,
            fp=_FakeFP(b'{"error":"model not found"}'),
        )
    monkeypatch.setattr(ollama_launcher.urllib.request, "urlopen", _raise_404)
    ok, msg = OllamaLauncher(model="ghost:9b")._warm_model()
    assert ok is False and "ollama pull ghost:9b" in msg


def test_warm_model_success(qtbot, monkeypatch):
    class _Resp:
        status = 200
        def read(self): return b'{"response":"ok","done":true}'
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(ollama_launcher.urllib.request, "urlopen", lambda *a, **k: _Resp())
    ok, msg = OllamaLauncher(model="llama3.2:1b")._warm_model()
    assert ok is True and msg == ""


class _FakeFP:
    def __init__(self, data: bytes): self._d = data
    def read(self, *a): return self._d
    def close(self): pass
