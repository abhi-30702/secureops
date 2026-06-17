import json
import pytest
from unittest.mock import patch, MagicMock
from advisor.ollama_client import OllamaClient


def _mock_response(body: dict):
    mock = MagicMock()
    mock.__enter__ = lambda s: s
    mock.__exit__ = MagicMock(return_value=False)
    mock.read.return_value = json.dumps(body).encode()
    return mock


def test_ollama_client_returns_text():
    resp = _mock_response({"response": "patch immediately"})
    with patch("urllib.request.urlopen", return_value=resp):
        result = OllamaClient(model="llama3").generate("prompt")
    assert result == "patch immediately"


def test_ollama_client_raises_on_http_error():
    import urllib.error
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
        with pytest.raises(RuntimeError, match="Ollama"):
            OllamaClient(model="llama3").generate("prompt")


def test_ollama_client_raises_on_missing_response_key():
    resp = _mock_response({"error": "model not found"})
    with patch("urllib.request.urlopen", return_value=resp):
        with pytest.raises(RuntimeError):
            OllamaClient(model="llama3").generate("prompt")
