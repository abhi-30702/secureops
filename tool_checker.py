import shutil
import sys
from pathlib import Path

TOOLS = [
    "subfinder", "dnsx", "naabu", "httpx", "katana",
    "nuclei", "nmap", "nikto", "testssl.sh",
]

CRITICAL_TOOLS = {"subfinder", "nuclei", "nmap"}

# Some ProjectDiscovery tools ship under a different binary name on Kali to avoid
# colliding with an unrelated package. The classic case: `python3-httpx` owns
# /usr/bin/httpx (an HTTP client CLI that does NOT speak our -json/-silent flags),
# while PD's httpx is installed as `httpx-toolkit`. Prefer the real one, in order.
_TOOL_ALIASES = {
    "httpx": ["httpx-toolkit", "httpx"],
}


def _tool_path(name: str) -> str | None:
    if getattr(sys, 'frozen', False):
        bundled = Path(sys.executable).parent / "tools" / name
        if bundled.is_file():
            return str(bundled)
    for candidate in _TOOL_ALIASES.get(name, [name]):
        found = shutil.which(candidate)
        if found:
            return found
    return None


def check_tools() -> dict:
    return {tool: _tool_path(tool) is not None for tool in TOOLS}


def is_critical_missing(results: dict) -> bool:
    return any(not results.get(t, False) for t in CRITICAL_TOOLS)


def ready_count(results: dict) -> int:
    return sum(1 for v in results.values() if v)
