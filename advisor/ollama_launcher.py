"""Start and warm the local Ollama runtime for the AI Advisor, off the UI thread.

The "Start Ollama" button in Settings runs this on a QThread so the window never
blocks (Rule #1). It ensures the local Ollama server is up (starting it if not)
and then loads the configured model into memory, so the first real advisory call
doesn't pay the cold-load cost.

Everything is local — this never talks to any third party.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request

from PyQt6.QtCore import QThread, pyqtSignal

_BASE = "http://localhost:11434"


def server_up(timeout: float = 2.0) -> bool:
    """True if a local Ollama server answers on :11434."""
    try:
        with urllib.request.urlopen(f"{_BASE}/api/tags", timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


class OllamaLauncher(QThread):
    """Ensures the Ollama server is running and the model is loaded.

    Emits ``status(state, message)`` with state in
    {"starting", "running", "error"}.
    """

    status = pyqtSignal(str, str)

    def __init__(self, model: str, parent=None):
        super().__init__(parent)
        self._model = model or "llama3"

    # -- QThread entry ------------------------------------------------- #
    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:  # never crash the app
            self.status.emit("error", f"Ollama start failed: {exc}")

    def _run(self) -> None:
        if not server_up():
            if shutil.which("ollama") is None:
                self.status.emit(
                    "error",
                    "Ollama is not installed. Install it, then try again.",
                )
                return
            self.status.emit("starting", "Starting Ollama server…")
            self._start_server()
            for _ in range(40):  # wait up to ~20s for the port to bind
                if server_up():
                    break
                time.sleep(0.5)
            else:
                self.status.emit(
                    "error",
                    "Ollama server did not start. Try: sudo systemctl start ollama",
                )
                return

        self.status.emit("starting", f"Loading model '{self._model}' into memory…")
        ok, msg = self._warm_model()
        if ok:
            self.status.emit("running", f"Ollama running — model '{self._model}' ready.")
        else:
            self.status.emit("error", msg)

    # -- helpers ------------------------------------------------------- #
    def _start_server(self) -> None:
        """Prefer the systemd service; fall back to a detached ``ollama serve``."""
        try:
            subprocess.run(
                ["systemctl", "start", "ollama"],
                timeout=8, capture_output=True,
            )
        except Exception:
            pass
        if server_up():
            return
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception:
            pass

    def _warm_model(self) -> tuple[bool, str]:
        """Load the model with a trivial 1-token generation."""
        payload = json.dumps({
            "model": self._model,
            "prompt": "ok",
            "stream": False,
            "options": {"num_predict": 1},
        }).encode()
        req = urllib.request.Request(
            f"{_BASE}/api/generate", data=payload,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read())
            if data.get("error"):
                return False, f"Ollama: {data['error']}"
            return True, ""
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "ignore")[:200].lower()
            if "not found" in body or "no such model" in body:
                return False, (
                    f"Model '{self._model}' is not pulled. "
                    f"Run: ollama pull {self._model}"
                )
            return False, f"Ollama error ({exc.code}): {body}"
        except Exception as exc:
            return False, f"Ollama unreachable: {exc}"
