import shutil

TOOLS = [
    "subfinder", "dnsx", "naabu", "httpx", "katana",
    "nuclei", "nmap", "nikto", "testssl.sh",
]

CRITICAL_TOOLS = {"subfinder", "nuclei", "nmap"}


def check_tools() -> dict:
    return {tool: shutil.which(tool) is not None for tool in TOOLS}


def is_critical_missing(results: dict) -> bool:
    return any(not results.get(t, False) for t in CRITICAL_TOOLS)


def ready_count(results: dict) -> int:
    return sum(1 for v in results.values() if v)
