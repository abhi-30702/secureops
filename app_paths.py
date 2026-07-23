"""Resolve SecureOps' on-disk data location consistently across launch modes.

The app needs root for live packet capture (``sudo python3 main.py``) but runs as
the normal user otherwise. ``Path.home()`` therefore points at ``/root`` under sudo
and ``/home/<user>`` normally — which would split the SQLite DB (and every setting,
finding, and captured event) across two files.

These helpers pin the data dir to the *invoking* user's home even under sudo
(via ``SUDO_USER``), and chown files back to that user when we created them as
root, so a later non-root launch can still read and write them.
"""
from __future__ import annotations

import os
from pathlib import Path

try:
    import pwd  # Unix only (SecureOps targets Kali/Linux)
except ImportError:  # pragma: no cover
    pwd = None  # type: ignore


def _invoking_user() -> tuple[str, int, int] | None:
    """(name, uid, gid) of the real user when launched via sudo, else None."""
    if pwd is None:
        return None
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or sudo_user == "root":
        return None
    try:
        pw = pwd.getpwnam(sudo_user)
        return sudo_user, pw.pw_uid, pw.pw_gid
    except KeyError:
        return None


def resolve_data_dir() -> Path:
    """``~/.secureops`` for the invoking user — stable whether launched directly
    or through sudo, so both modes share one database."""
    info = _invoking_user()
    if info is not None and pwd is not None:
        try:
            return Path(pwd.getpwnam(info[0]).pw_dir) / ".secureops"
        except KeyError:
            pass
    return Path.home() / ".secureops"


def resolve_db_path() -> Path:
    return resolve_data_dir() / "secureops.db"


def fix_ownership(data_dir: Path) -> None:
    """If running as root via sudo, chown the data dir + DB files back to the
    invoking user so a subsequent non-root launch can still write them.

    No-op when not root or not under sudo. Never raises."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    info = _invoking_user()
    if info is None:
        return
    _, uid, gid = info
    try:
        os.chown(data_dir, uid, gid)
    except OSError:
        return
    for p in data_dir.glob("secureops.db*"):  # db + -wal + -shm
        try:
            os.chown(p, uid, gid)
        except OSError:
            pass
