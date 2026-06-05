import re
from workers.log_rules import LogRule, detect_format, RULES


# ── format detection ────────────────────────────────────────────────────────

def test_detect_format_auth():
    lines = [
        "Jun  5 10:01:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "Jun  5 10:01:02 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2",
    ]
    assert detect_format(lines) == "auth"


def test_detect_format_nginx():
    lines = [
        '1.2.3.4 - - [05/Jun/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '1.2.3.4 - - [05/Jun/2026:10:00:01 +0000] "POST /login HTTP/1.1" 401 200',
    ]
    assert detect_format(lines) == "nginx"


def test_detect_format_firewall():
    lines = [
        "Jun  5 10:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1",
    ]
    assert detect_format(lines) == "firewall"


def test_detect_format_syslog():
    lines = [
        "Jun  5 10:00:00 myhost systemd[1]: Started Some Service.",
        "Jun  5 10:00:01 myhost kernel: Initializing cgroup subsys cpuset",
    ]
    assert detect_format(lines) == "syslog"


def test_detect_format_unknown():
    lines = ["random line with no pattern", "another random line"]
    assert detect_format(lines) == "unknown"


# ── rule matching ────────────────────────────────────────────────────────────

def test_ssh_brute_force_rule_matches():
    rule = next(r for r in RULES if r.name == "ssh_brute_force")
    line = "Jun  5 10:01:01 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert rule.pattern.search(line) is not None


def test_root_sudo_rule_matches():
    rule = next(r for r in RULES if r.name == "root_sudo")
    line = "Jun  5 10:01:01 host sudo:    user : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
    assert rule.pattern.search(line) is not None


def test_user_account_change_rule_matches():
    rule = next(r for r in RULES if r.name == "user_account_change")
    assert rule.pattern.search("useradd newuser") is not None
    assert rule.pattern.search("usermod -aG sudo newuser") is not None
    assert rule.pattern.search("userdel baduser") is not None


def test_sqli_attempt_rule_matches():
    rule = next(r for r in RULES if r.name == "sqli_attempt")
    line = '1.2.3.4 - - [05/Jun/2026] "GET /page?id=1 UNION SELECT 1,2,3 HTTP/1.1" 200 500'
    assert rule.pattern.search(line) is not None


def test_scanner_ua_rule_matches():
    rule = next(r for r in RULES if r.name == "scanner_ua")
    line = '1.2.3.4 - - [05/Jun/2026] "GET / HTTP/1.1" 200 100 "-" "sqlmap/1.7"'
    assert rule.pattern.search(line) is not None


def test_port_scan_rule_matches():
    rule = next(r for r in RULES if r.name == "port_scan")
    line = "Jun  5 10:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 DST=10.0.0.1 DPT=22"
    assert rule.pattern.search(line) is not None


def test_oom_killer_rule_matches():
    rule = next(r for r in RULES if r.name == "oom_killer")
    line = "Jun  5 10:00:00 host kernel: Out of memory: Kill process 1234 (python3)"
    assert rule.pattern.search(line) is not None


def test_log_rule_has_required_fields():
    for rule in RULES:
        assert isinstance(rule.name, str) and rule.name
        assert isinstance(rule.pattern, type(re.compile("")))
        assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert isinstance(rule.description, str) and rule.description
        assert isinstance(rule.formats, list) and rule.formats
