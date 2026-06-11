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
    # Core user/auth utilities
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/su",
    # Filesystem / mount
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount3",
    "/usr/bin/ntfs-3g",
    "/usr/sbin/mount.cifs",
    "/usr/sbin/mount.nfs",
    # PolicyKit / D-Bus / SSH / X11
    "/usr/bin/pkexec",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/xorg/Xorg.wrap",
    # Chromium sandbox
    "/usr/lib/chromium/chrome-sandbox",
    # Kismet wireless capture helpers (Kali)
    "/usr/bin/kismet_cap_hak5_wifi_coconut",
    "/usr/bin/kismet_cap_linux_bluetooth",
    "/usr/bin/kismet_cap_linux_wifi",
    "/usr/bin/kismet_cap_nrf_51822",
    "/usr/bin/kismet_cap_nrf_52840",
    "/usr/bin/kismet_cap_nrf_mousejack",
    "/usr/bin/kismet_cap_nxp_kw41z",
    "/usr/bin/kismet_cap_rz_killerbee",
    "/usr/bin/kismet_cap_ti_cc_2531",
    "/usr/bin/kismet_cap_ti_cc_2540",
    "/usr/bin/kismet_cap_ubertooth_one",
    # Remote shell (rsh-redone package)
    "/usr/bin/rsh-redone-rlogin",
    "/usr/bin/rsh-redone-rsh",
    # PPP
    "/usr/sbin/pppd",
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
        # find exits 1 on permission errors for subtrees but still returns output
        if proc.returncode not in (0, 1):
            return findings
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
