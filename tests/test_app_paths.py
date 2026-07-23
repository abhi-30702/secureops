"""Tests for the launch-mode-stable data-dir resolver (root/user DB split fix)."""
import os
from pathlib import Path

import app_paths


def test_normal_user_uses_home(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(app_paths.Path, "home", classmethod(lambda cls: Path("/home/kaelix")))
    assert app_paths.resolve_data_dir() == Path("/home/kaelix/.secureops")
    assert app_paths.resolve_db_path() == Path("/home/kaelix/.secureops/secureops.db")


def test_sudo_resolves_invoking_user_home(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "kaelix")

    class _PW:
        pw_uid, pw_gid, pw_dir = 1000, 1000, "/home/kaelix"

    monkeypatch.setattr(app_paths.pwd, "getpwnam", lambda name: _PW())
    # even though "home" would be /root under sudo, we use the invoking user's home
    monkeypatch.setattr(app_paths.Path, "home", classmethod(lambda cls: Path("/root")))
    assert app_paths.resolve_data_dir() == Path("/home/kaelix/.secureops")


def test_sudo_user_root_falls_back_to_home(monkeypatch):
    monkeypatch.setenv("SUDO_USER", "root")
    monkeypatch.setattr(app_paths.Path, "home", classmethod(lambda cls: Path("/root")))
    assert app_paths.resolve_data_dir() == Path("/root/.secureops")


def test_invoking_user_none_without_sudo(monkeypatch):
    monkeypatch.delenv("SUDO_USER", raising=False)
    assert app_paths._invoking_user() is None


def test_fix_ownership_noop_when_not_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **k: called.append(a))
    app_paths.fix_ownership(tmp_path)
    assert called == []  # never chowns when not root


def test_fix_ownership_chowns_db_files_as_root(monkeypatch, tmp_path):
    (tmp_path / "secureops.db").write_text("x")
    (tmp_path / "secureops.db-wal").write_text("y")
    (tmp_path / "other.txt").write_text("z")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_USER", "kaelix")

    class _PW:
        pw_uid, pw_gid, pw_dir = 1000, 1000, "/home/kaelix"

    monkeypatch.setattr(app_paths.pwd, "getpwnam", lambda name: _PW())
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append(str(p)))
    app_paths.fix_ownership(tmp_path)
    names = {Path(p).name for p in chowned}
    assert "secureops.db" in names and "secureops.db-wal" in names
    assert "other.txt" not in names  # only touches secureops.db*
