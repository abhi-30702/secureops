import os
import time
import tempfile
import pytest
from unittest.mock import patch, MagicMock


def test_cron_recent_mtime_emits_finding(tmp_path):
    """A cron file modified within the last 7 days triggers a finding."""
    cron_file = tmp_path / "suspicious_job"
    cron_file.write_text("*/5 * * * * /tmp/backdoor.sh\n")
    # Set mtime to 1 hour ago (within 7-day window)
    recent = time.time() - 3600
    os.utime(str(cron_file), (recent, recent))

    from workers.tools.persistence_checker import _check_cron
    results = _check_cron(cron_dirs=[str(tmp_path)])
    assert len(results) == 1
    assert results[0]["check"] == "cron"
    assert results[0]["severity"] == "high"


def test_cron_old_mtime_no_finding(tmp_path):
    """A cron file last modified 30 days ago is not flagged."""
    cron_file = tmp_path / "old_job"
    cron_file.write_text("0 2 * * * /usr/bin/backup.sh\n")
    old = time.time() - (30 * 86400)
    os.utime(str(cron_file), (old, old))

    from workers.tools.persistence_checker import _check_cron
    results = _check_cron(cron_dirs=[str(tmp_path)])
    assert results == []


def test_authorized_keys_two_keys_emits_finding(tmp_path):
    """authorized_keys with 2 or more keys triggers a finding."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    auth_keys = ssh_dir / "authorized_keys"
    auth_keys.write_text(
        "ssh-rsa AAAA...key1== user1@host\n"
        "ssh-rsa BBBB...key2== attacker@evil\n"
    )

    from workers.tools.persistence_checker import _check_authorized_keys
    results = _check_authorized_keys(home_dirs=[str(tmp_path)])
    assert len(results) == 1
    assert results[0]["check"] == "authorized_keys"
    assert results[0]["severity"] == "medium"


def test_authorized_keys_one_key_no_finding(tmp_path):
    """authorized_keys with exactly 1 key is not flagged."""
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "authorized_keys").write_text("ssh-rsa AAAA...key1== admin@corp\n")

    from workers.tools.persistence_checker import _check_authorized_keys
    results = _check_authorized_keys(home_dirs=[str(tmp_path)])
    assert results == []


def test_suid_unknown_binary_emits_finding():
    """A SUID binary not in the known-good set triggers a finding."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "/usr/bin/sudo\n/tmp/evil_suid\n"

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import persistence_checker
        # Reload to ensure fresh import
        import importlib
        importlib.reload(persistence_checker)
        results = persistence_checker._check_suid()

    assert len(results) == 1
    assert results[0]["check"] == "suid"
    assert "/tmp/evil_suid" in results[0]["path"]
    assert results[0]["severity"] == "high"


def test_suid_only_known_good_no_finding():
    """Only known-good SUID binaries → no findings."""
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "/usr/bin/sudo\n/usr/bin/passwd\n"

    with patch("subprocess.run", return_value=mock_proc):
        from workers.tools import persistence_checker
        import importlib
        importlib.reload(persistence_checker)
        results = persistence_checker._check_suid()

    assert results == []


def test_run_returns_combined_results(tmp_path):
    """run() aggregates results from all three sub-checks."""
    from workers.tools.persistence_checker import run

    with patch("workers.tools.persistence_checker._check_cron", return_value=[{"check": "cron", "path": "x", "detail": "y", "severity": "high"}]), \
         patch("workers.tools.persistence_checker._check_authorized_keys", return_value=[]), \
         patch("workers.tools.persistence_checker._check_suid", return_value=[{"check": "suid", "path": "/tmp/evil", "detail": "not in baseline", "severity": "high"}]):
        results = run()

    assert len(results) == 2
    checks = {r["check"] for r in results}
    assert checks == {"cron", "suid"}
