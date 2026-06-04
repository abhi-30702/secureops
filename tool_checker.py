import shutil
import sys
from pathlib import Path

TOOLS = [
    "subfinder", "dnsx", "naabu", "httpx", "katana",
    "nuclei", "nmap", "nikto", "testssl.sh",
]

CRITICAL_TOOLS = {"subfinder", "nuclei", "nmap"}


def _tool_path(name: str) -> str | None:
    if getattr(sys, 'frozen', False):
        bundled = Path(sys.executable).parent / "tools" / name
        if bundled.is_file():
            return str(bundled)
    return shutil.which(name)


def check_tools() -> dict:
    return {tool: _tool_path(tool) is not None for tool in TOOLS}


def is_critical_missing(results: dict) -> bool:
    return any(not results.get(t, False) for t in CRITICAL_TOOLS)


def ready_count(results: dict) -> int:
    return sum(1 for v in results.values() if v)
