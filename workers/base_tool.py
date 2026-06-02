import os
import subprocess
import tempfile
import threading
from typing import Iterator


class ToolError(Exception):
    pass


class CancelledError(Exception):
    pass


def _write_tmpfile(lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="secureops_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return path


class ToolRunner:
    def __init__(self, cancel_event: threading.Event):
        self._cancel = cancel_event

    def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
        if self._cancel.is_set():
            raise CancelledError()
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")

        for line in proc.stdout:
            if self._cancel.is_set():
                proc.kill()
                proc.wait()
                raise CancelledError()
            stripped = line.rstrip()
            if stripped:
                yield stripped

        proc.wait()
        if proc.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {proc.returncode}")

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        if self._cancel.is_set():
            raise CancelledError()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")
        except subprocess.TimeoutExpired:
            raise ToolError(f"{cmd[0]}: timed out after {timeout}s")
        if self._cancel.is_set():
            raise CancelledError()
        if result.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {result.returncode}")
        return result.stdout
