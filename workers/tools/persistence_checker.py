import glob
import os
import subprocess
import time
from pathlib import Path

_CRON_DIRS = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron/crontabs",
]

_CRON_FILES = ["/etc/crontab"]

_MAX_AGE_SECONDS = 7 * 86400

KNOWN_GOOD_SUID = {
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/su",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
}


def run() -> list[dict]:
    """Run all three persistence sub-checks. Returns list of finding dicts."""
    results: list[dict] = []
    results.extend(_check_cron())
    results.extend(_check_authorized_keys())
    results.extend(_check_suid())
    return results


def _check_cron(cron_dirs: list[str] | None = None) -> list[dict]:
    now = time.time()
    cutoff = now - _MAX_AGE_SECONDS
    dirs = cron_dirs if cron_dirs is not None else _CRON_DIRS
    findings: list[dict] = []

    candidates: list[str] = list(_CRON_FILES) if cron_dirs is None else []
    for d in dirs:
        if os.path.isdir(d):
            for entry in os.listdir(d):
                candidates.append(os.path.join(d, entry))

    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime >= cutoff:
            findings.append({
                "check": "cron",
                "path": path,
                "detail": f"Modified {int((now - mtime) / 3600)}h ago",
                "severity": "high",
            })
    return findings


def _check_authorized_keys(home_dirs: list[str] | None = None) -> list[dict]:
    findings: list[dict] = []
    if home_dirs is None:
        search_roots = list(Path("/home").glob("*")) + [Path("/root")]
    else:
        search_roots = [Path(d) for d in home_dirs]

    for home in search_roots:
        ak_path = home / ".ssh" / "authorized_keys"
        if not ak_path.is_file():
            continue
        try:
            text = ak_path.read_text(errors="replace")
        except OSError:
            continue
        keys = [
            ln for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if len(keys) >= 2:
            findings.append({
                "check": "authorized_keys",
                "path": str(ak_path),
                "detail": f"{len(keys)} keys present (threshold: 1)",
                "severity": "medium",
            })
    return findings


def _check_suid() -> list[dict]:
    findings: list[dict] = []
    try:
        proc = subprocess.run(
            ["find", "/usr", "/bin", "/sbin", "/usr/local",
             "-perm", "-4000", "-type", "f"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in proc.stdout.splitlines():
            path = line.strip()
            if path and path not in KNOWN_GOOD_SUID:
                findings.append({
                    "check": "suid",
                    "path": path,
                    "detail": "SUID binary not in known-good baseline",
                    "severity": "high",
                })
    except Exception:
        pass
    return findings
