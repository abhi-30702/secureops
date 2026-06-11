import os

FIXED_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/run"]

BUILTIN_RULES = r"""
rule Webshell_PHP_Eval {
    strings:
        $a = /eval\s*\(\s*base64_decode/ nocase
    condition:
        $a
}
rule Reverse_Shell_Bash {
    strings:
        $a = "bash -i >& /dev/tcp/" nocase
    condition:
        $a
}
rule Meterpreter_Artifact {
    strings:
        $a = "meterpreter" nocase
        $b = "ReflectiveDll" nocase
    condition:
        any of them
}
"""


def run(extra_path: str = "") -> list[dict]:
    """Scan FIXED_PATHS + extra_path with built-in YARA rules.

    Returns list of dicts: {file, rule, severity, description}.
    Returns [] if yara-python is not installed or rules fail to compile.
    """
    try:
        import yara
    except ImportError:
        return []

    try:
        rules = yara.compile(source=BUILTIN_RULES)
    except Exception:
        return []

    paths_to_scan: list[str] = []
    for p in FIXED_PATHS:
        if os.path.isdir(p):
            paths_to_scan.append(p)
    if extra_path and os.path.exists(extra_path):
        paths_to_scan.append(extra_path)

    results: list[dict] = []
    for base in paths_to_scan:
        if os.path.isfile(base):
            _scan_file(base, rules, results)
        else:
            for root, _, files in os.walk(base):
                for fname in files:
                    _scan_file(os.path.join(root, fname), rules, results)
    return results


def _scan_file(filepath: str, rules, results: list[dict]) -> None:
    try:
        matches = rules.match(filepath=filepath)
        for m in matches:
            results.append({
                "file": filepath,
                "rule": m.rule,
                "severity": "high",
                "description": f"YARA rule '{m.rule}' matched in {filepath}",
            })
    except Exception:
        pass
