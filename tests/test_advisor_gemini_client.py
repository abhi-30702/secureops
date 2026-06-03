import sys
from unittest.mock import MagicMock
import pytest


def _mock_genai(response_text: str = "response") -> MagicMock:
    m = MagicMock()
    m.GenerativeModel.return_value.generate_content.return_value.text = response_text
    return m


def test_gemini_client_returns_text(monkeypatch):
    mock_genai = _mock_genai("hello")
    mock_google = MagicMock()
    mock_google.generativeai = mock_genai
    monkeypatch.setitem(sys.modules, "google", mock_google)
    monkeypatch.setitem(sys.modules, "google.generativeai", mock_genai)
    from advisor.gemini_client import GeminiClient
    assert GeminiClient("key").generate("prompt") == "hello"


def test_gemini_client_configures_api_key(monkeypatch):
    mock_genai = _mock_genai()
    mock_google = MagicMock()
    mock_google.generativeai = mock_genai
    monkeypatch.setitem(sys.modules, "google", mock_google)
    monkeypatch.setitem(sys.modules, "google.generativeai", mock_genai)
    from advisor.gemini_client import GeminiClient
    GeminiClient("my-secret-key").generate("prompt")
    mock_genai.configure.assert_called_once_with(api_key="my-secret-key")


def test_gemini_client_wraps_api_error(monkeypatch):
    mock_genai = MagicMock()
    mock_genai.GenerativeModel.return_value.generate_content.side_effect = Exception("quota")
    mock_google = MagicMock()
    mock_google.generativeai = mock_genai
    monkeypatch.setitem(sys.modules, "google", mock_google)
    monkeypatch.setitem(sys.modules, "google.generativeai", mock_genai)
    from advisor.gemini_client import GeminiClient
    with pytest.raises(RuntimeError, match="quota"):
        GeminiClient("key").generate("prompt")
