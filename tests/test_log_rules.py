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


def test_detect_format_windows():
    lines = [
        "2026-06-20 00:00:00 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 "
        "An account failed to log on. Account Name: oracle Source Network Address: 1.2.3.4",
        "2026-06-20 00:00:04 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4624 "
        "An account was successfully logged on. Account Name: alice Logon Type: 2",
    ]
    assert detect_format(lines) == "windows"


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


def test_windows_failed_logon_rule_matches_and_captures_ip():
    rule = next(r for r in RULES if r.name == "windows_failed_logon")
    line = ("2026-06-20 00:00:00 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4625 "
            "An account failed to log on. Account Name: oracle Logon Type: 3 "
            "Source Network Address: 45.83.64.1 Failure Reason: bad password")
    m = rule.pattern.search(line)
    assert m is not None and m.group(1) == "45.83.64.1"


def test_windows_kerberos_preauth_fail_rule_matches():
    rule = next(r for r in RULES if r.name == "windows_kerberos_preauth_fail")
    line = ("2026-06-20 00:00:00 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4771 "
            "Kerberos pre-authentication failed. Account Name: mysql Client Address: 1.2.3.4 "
            "Failure Code: 0x18")
    m = rule.pattern.search(line)
    assert m is not None and m.group(1) == "1.2.3.4"


def test_windows_account_created_rule_matches():
    rule = next(r for r in RULES if r.name == "windows_account_created")
    assert rule.pattern.search("... EventID=4720 A user account was created. New Account Name: bkdoor1")


def test_windows_admin_group_add_rule_matches():
    rule = next(r for r in RULES if r.name == "windows_admin_group_add")
    assert rule.pattern.search("... EventID=4732 A member was added to Administrators")
    assert rule.pattern.search("... EventID=4728 A member was added to Domain Admins")


def test_windows_rdp_logon_rule_matches_only_type_10():
    rule = next(r for r in RULES if r.name == "windows_rdp_logon")
    rdp = "... EventID=4624 An account was successfully logged on. Account Name: root Logon Type: 10"
    local = "... EventID=4624 An account was successfully logged on. Account Name: alice Logon Type: 2"
    assert rule.pattern.search(rdp) is not None
    assert rule.pattern.search(local) is None


def test_windows_rules_do_not_match_clean_logon_events():
    # A clean successful interactive logon must not trip any attack rule.
    clean = ("2026-06-20 00:00:00 WIN-DC01 Microsoft-Windows-Security-Auditing EventID=4624 "
             "An account was successfully logged on. Account Name: CORP\\alice Logon Type: 2 "
             "Source Network Address: 10.0.0.5")
    win_rules = [r for r in RULES if r.name.startswith("windows_")]
    assert win_rules  # sanity
    assert all(r.pattern.search(clean) is None for r in win_rules)


def test_log_rule_has_required_fields():
    for rule in RULES:
        assert isinstance(rule.name, str) and rule.name
        assert isinstance(rule.pattern, type(re.compile("")))
        assert rule.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert isinstance(rule.description, str) and rule.description
        assert isinstance(rule.formats, list) and rule.formats
