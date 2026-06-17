import json
import urllib.request
import urllib.error

_OLLAMA_URL = "http://localhost:11434/api/generate"


class OllamaClient:
    def __init__(self, model: str = "llama3"):
        self._model = model

    def generate(self, prompt: str) -> str:
        payload = json.dumps({
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            _OLLAMA_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Ollama unreachable: {exc.reason}") from exc
        except Exception as exc:
            raise RuntimeError(str(exc)) from exc

        if "response" not in data:
            raise RuntimeError(f"Ollama returned unexpected payload: {data}")
        return data["response"]
