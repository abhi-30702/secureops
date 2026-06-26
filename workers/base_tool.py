import os
import subprocess
import tempfile
import threading
from typing import Iterator

from tool_checker import _tool_path


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
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        try:
            proc = subprocess.Popen(
                resolved,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")

        # Drain stderr on a background thread so a chatty tool can never fill the
        # OS pipe buffer and deadlock against our stdout read (classic subprocess
        # trap). The captured text also gives us a real reason on failure.
        stderr_chunks: list[str] = []

        def _drain_stderr() -> None:
            try:
                for err_line in proc.stderr:
                    stderr_chunks.append(err_line)
            except Exception:
                pass

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        # Watchdog: a tool that stalls with no output would otherwise block the
        # stdout iterator forever. Kill it after `timeout` seconds; the killed
        # process closes stdout, the loop ends, and we report the timeout.
        timed_out = threading.Event()

        def _watchdog() -> None:
            timed_out.set()
            proc.kill()

        timer = threading.Timer(timeout, _watchdog)
        timer.start()

        try:
            for line in proc.stdout:
                if self._cancel.is_set():
                    proc.kill()
                    proc.wait()
                    raise CancelledError()
                stripped = line.rstrip()
                if stripped:
                    yield stripped
        finally:
            timer.cancel()
            proc.wait()
            stderr_thread.join(timeout=1)

        if timed_out.is_set():
            raise ToolError(f"{cmd[0]}: timed out after {timeout}s")
        if proc.returncode != 0:
            msg = f"{cmd[0]}: exited with code {proc.returncode}"
            detail = "".join(stderr_chunks).strip().splitlines()
            if detail:
                msg += f" ({detail[-1][:200]})"
            raise ToolError(msg)

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        if self._cancel.is_set():
            raise CancelledError()
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        try:
            result = subprocess.run(
                resolved,
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
