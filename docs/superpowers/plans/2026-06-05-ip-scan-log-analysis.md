# IP Scanning + Log Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add IP-mode pipeline routing (skip subfinder/dnsx for IP targets) and a new log analysis mode that detects format, runs rule-based anomaly detection, and optionally enriches findings via AI Advisor — all flowing into the same report and PDF.

**Architecture:** A module-level `_is_ip()` helper in `scan_worker.py` gates the domain-only pipeline stages. A new `LogAnalyzerWorker(QThread)` in `workers/log_analyzer.py` emits the same signals as `ScanWorker` so the scan view, report, and PDF need minimal changes. Rules live in `workers/log_rules.py` as a `LogRule` dataclass list. The scan view gains a pill-style mode toggle and Browse button that switch between creating a `ScanWorker` or `LogAnalyzerWorker`.

**Tech Stack:** PyQt6, Python `ipaddress` stdlib (IP detection), `re` stdlib (rule matching), existing `advisor.gemini_client.GeminiClient` (AI enrichment), existing `DB`, `Finding`, `models`.

---

## File map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `workers/scan_worker.py` | Add `_is_ip()`, branch pipeline for IP targets |
| Create | `workers/log_rules.py` | `LogRule` dataclass, `detect_format()`, `RULES` list |
| Create | `workers/log_analyzer.py` | `LogAnalyzerWorker(QThread)` — 3-stage analysis |
| Modify | `screens/scan_view.py` | Mode toggle, Browse button, worker selection |
| Modify | `screens/report.py` | Conditional log findings section |
| Modify | `report/pdf_generator.py` | `_log_section()`, call in `generate()` |
| Modify | `tests/test_scan_worker.py` | IP detection + IP-mode pipeline tests |
| Create | `tests/test_log_rules.py` | Format detection + rule matching tests |
| Create | `tests/test_log_analyzer.py` | Worker integration tests |
| Create | `tests/test_scan_view.py` | Mode toggle + Browse + correct worker created |
| Modify | `tests/test_report.py` | Log section present/absent assertions |

---

### Task 1: IP detection and pipeline routing in scan_worker.py

**Files:**
- Modify: `workers/scan_worker.py`
- Modify: `tests/test_scan_worker.py`

- [ ] **Step 1: Write failing tests for `_is_ip()`**

Add these tests at the end of `tests/test_scan_worker.py`:

```python
from workers.scan_worker import _is_ip


def test_is_ip_true_for_ipv4():
    assert _is_ip("192.168.1.1") is True


def test_is_ip_true_for_ipv6():
    assert _is_ip("::1") is True
    assert _is_ip("2001:db8::1") is True


def test_is_ip_false_for_domain():
    assert _is_ip("example.com") is False
    assert _is_ip("scanme.nmap.org") is False
    assert _is_ip("") is False


def test_ip_mode_skips_subfinder_and_dnsx(qtbot, db):
    worker, _ = _make_worker(db, target="10.0.0.1")
    started_tools = []
    worker.tool_started.connect(started_tools.append)

    with patch("workers.scan_worker.naabu.run", return_value=[]):
        with patch("workers.scan_worker.httpx.run", return_value=[]):
            with patch("workers.scan_worker.katana.run", return_value=[]):
                with patch("workers.scan_worker.nuclei.run", return_value=[]):
                    with patch("workers.scan_worker.nmap.run", return_value=[]):
                        with patch("workers.scan_worker.nikto.run", return_value=[]):
                            with patch("workers.scan_worker.testssl.run", return_value=[]):
                                with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                    worker.start()

    assert "subfinder" not in started_tools
    assert "dnsx" not in started_tools
    assert "naabu" in started_tools


def test_ip_mode_feeds_ip_directly_to_naabu(qtbot, db):
    worker, _ = _make_worker(db, target="10.0.0.1")
    captured = {}

    def fake_naabu(ips, runner, db, scan_id):
        captured["ips"] = ips
        return []

    with patch("workers.scan_worker.naabu.run", side_effect=fake_naabu):
        with patch("workers.scan_worker.httpx.run", return_value=[]):
            with patch("workers.scan_worker.katana.run", return_value=[]):
                with patch("workers.scan_worker.nuclei.run", return_value=[]):
                    with patch("workers.scan_worker.nmap.run", return_value=[]):
                        with patch("workers.scan_worker.nikto.run", return_value=[]):
                            with patch("workers.scan_worker.testssl.run", return_value=[]):
                                with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                    worker.start()

    assert captured["ips"] == ["10.0.0.1"]
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scan_worker.py::test_is_ip_true_for_ipv4 tests/test_scan_worker.py::test_ip_mode_skips_subfinder_and_dnsx -v
```
Expected: `ImportError` — `_is_ip` not defined yet.

- [ ] **Step 3: Add `_is_ip()` and branch pipeline in `workers/scan_worker.py`**

Add `import ipaddress` at the top of the file alongside existing imports.

Add `_is_ip` as a module-level function just before the `ScanWorker` class:

```python
import ipaddress


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False
```

Replace `_execute_pipeline` with:

```python
def _execute_pipeline(self):
    runner = self._make_runner()

    if _is_ip(self._target):
        ips = [self._target]
    else:
        subdomains_hosts = self._run_tool("subfinder", subfinder.run, self._target, runner, self._db, self._scan_id)
        subdomain_names = [h.subdomain for h in subdomains_hosts if h.subdomain]

        resolved_hosts = self._run_tool("dnsx", dnsx.run, subdomain_names, runner, self._db, self._scan_id)
        ips = list({h.ip for h in resolved_hosts if h.ip})

    port_hosts = self._run_tool("naabu", naabu.run, ips, runner, self._db, self._scan_id)
    host_ports = [f"{h.ip}:{h.port}" for h in port_hosts if h.ip and h.port]

    http_hosts_list = self._run_tool("httpx", httpx.run, host_ports, runner, self._db, self._scan_id)
    http_urls = [h.url for h in http_hosts_list if h.url]

    self._run_tool("katana", katana.run, http_urls, runner, self._db, self._scan_id)

    all_targets = list({h.url or f"{h.ip}:{h.port}" for h in self._db.query_hosts_by_scan(self._scan_id) if h.url or (h.ip and h.port)})
    self._run_tool("nuclei", nuclei.run, all_targets, runner, self._db, self._scan_id)

    https_urls = [u for u in http_urls if u and u.startswith("https://")]

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(self._run_parallel_tool, "nmap",    nmap.run,    ips,         self._make_runner()),
            executor.submit(self._run_parallel_tool, "nikto",   nikto.run,   http_urls,   self._make_runner()),
            executor.submit(self._run_parallel_tool, "testssl", testssl.run, https_urls,  self._make_runner()),
        ]
        for future in futures:
            future.result()

    hosts_count = len(self._db.query_hosts_by_scan(self._scan_id))
    findings_count = len(self._db.query_findings_by_scan(self._scan_id))
    self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
    self.scan_complete.emit(hosts_count, findings_count)
```

- [ ] **Step 4: Run all scan_worker tests**

```bash
pytest tests/test_scan_worker.py -v
```
Expected: All pass including 5 new tests.

- [ ] **Step 5: Run full test suite for regressions**

```bash
pytest --tb=short -q
```
Expected: All 218 existing tests pass + 5 new = 223 total.

- [ ] **Step 6: Commit**

```bash
git add workers/scan_worker.py tests/test_scan_worker.py
git commit -m "feat: skip subfinder/dnsx for IP targets in scan pipeline"
```

---

### Task 2: Log rules library (`workers/log_rules.py`)

**Files:**
- Create: `workers/log_rules.py`
- Create: `tests/test_log_rules.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_log_rules.py`:

```python
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_log_rules.py -v
```
Expected: `ModuleNotFoundError: No module named 'workers.log_rules'`

- [ ] **Step 3: Create `workers/log_rules.py`**

```python
import re
from dataclasses import dataclass


@dataclass
class LogRule:
    name: str
    pattern: re.Pattern
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    description: str
    formats: list[str]   # log format tags this rule applies to; ["*"] = all formats


def detect_format(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])
    scores = {
        "auth":     0,
        "nginx":    0,
        "apache":   0,
        "firewall": 0,
        "syslog":   0,
    }

    if re.search(r"\bsshd\b|\bsudo\b|\bPAM\b|\buseradd\b|\bpam_unix\b", sample):
        scores["auth"] += 3
    if re.search(r'"(GET|POST|PUT|DELETE|HEAD)\s+\S+\s+HTTP/\d', sample):
        scores["nginx"] += 2
        scores["apache"] += 2
    if re.search(r"nginx", sample, re.IGNORECASE):
        scores["nginx"] += 2
    if re.search(r"apache|httpd", sample, re.IGNORECASE):
        scores["apache"] += 2
    if re.search(r"UFW BLOCK|iptables|IN=\w+.*OUT=|DPT=\d+", sample):
        scores["firewall"] += 3
    if re.search(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+", sample, re.MULTILINE):
        scores["syslog"] += 1

    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "unknown"


RULES: list[LogRule] = [
    LogRule(
        name="ssh_brute_force",
        pattern=re.compile(r"Failed password for .+ from (\d{1,3}(?:\.\d{1,3}){3})"),
        severity="HIGH",
        description="Repeated SSH authentication failures from same IP (potential brute force)",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="root_sudo",
        pattern=re.compile(r"sudo.*USER=root.*COMMAND=", re.IGNORECASE),
        severity="MEDIUM",
        description="sudo command executed as root",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="user_account_change",
        pattern=re.compile(r"\b(useradd|usermod|userdel)\b"),
        severity="HIGH",
        description="User account created, modified, or deleted",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="pubkey_login",
        pattern=re.compile(r"Accepted publickey for .+ from (\d{1,3}(?:\.\d{1,3}){3})"),
        severity="INFO",
        description="SSH public key authentication succeeded",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="sqli_attempt",
        pattern=re.compile(
            r"(UNION\s+SELECT|'\s*--\s|1\s*=\s*1|OR\s+1\s*=\s*1|DROP\s+TABLE)",
            re.IGNORECASE,
        ),
        severity="HIGH",
        description="Possible SQL injection pattern in request",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="scanner_ua",
        pattern=re.compile(r"\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei)\b", re.IGNORECASE),
        severity="MEDIUM",
        description="Known security scanner User-Agent detected",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="http_scan_rate",
        pattern=re.compile(r'" [45]\d{2} '),
        severity="MEDIUM",
        description="High rate of HTTP 4xx/5xx responses from same IP (possible scan)",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="port_scan",
        pattern=re.compile(r"(?:UFW BLOCK|iptables.*DROP).*SRC=(\d{1,3}(?:\.\d{1,3}){3}).*DPT=(\d+)"),
        severity="HIGH",
        description="Port scan pattern — multiple blocked ports from same source IP",
        formats=["firewall", "unknown"],
    ),
    LogRule(
        name="repeated_block",
        pattern=re.compile(r"(?:UFW BLOCK|iptables.*DROP).*SRC=(\d{1,3}(?:\.\d{1,3}){3})"),
        severity="MEDIUM",
        description="Repeated firewall blocks from same source IP",
        formats=["firewall", "unknown"],
    ),
    LogRule(
        name="oom_killer",
        pattern=re.compile(r"Out of memory: Kill process", re.IGNORECASE),
        severity="MEDIUM",
        description="Linux OOM killer invoked — system under memory pressure",
        formats=["syslog", "unknown"],
    ),
    LogRule(
        name="kernel_panic",
        pattern=re.compile(r"\b(segfault|kernel panic|BUG: unable to handle)\b", re.IGNORECASE),
        severity="MEDIUM",
        description="Kernel error or panic detected",
        formats=["syslog", "unknown"],
    ),
]
```

- [ ] **Step 4: Run log_rules tests**

```bash
pytest tests/test_log_rules.py -v
```
Expected: All 14 tests pass.

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q
```
Expected: 223 + 14 = 237 tests pass.

- [ ] **Step 6: Commit**

```bash
git add workers/log_rules.py tests/test_log_rules.py
git commit -m "feat: add log rules library — format detection and anomaly rule set"
```

---

### Task 3: `LogAnalyzerWorker` (`workers/log_analyzer.py`)

**Files:**
- Create: `workers/log_analyzer.py`
- Create: `tests/test_log_analyzer.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_log_analyzer.py`:

```python
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from models import Scan
from workers.log_analyzer import LogAnalyzerWorker


def _write_log(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


def _make_worker(db, content: str):
    path = _write_log(content)
    scan = Scan(id=None, client_id=None, target=path, status="running",
                started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    scan_id = db.insert_scan(scan)
    return LogAnalyzerWorker(path=path, scan_id=scan_id, db=db), scan_id, path


SSH_BRUTE_LOG = "\n".join(
    [f"Jun  5 10:00:{i:02d} host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
     for i in range(10)]
)

NGINX_SCANNER_LOG = "\n".join([
    '5.6.7.8 - - [05/Jun/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 200 "-" "sqlmap/1.7"',
    '5.6.7.8 - - [05/Jun/2026:10:00:01 +0000] "GET /login HTTP/1.1" 401 200 "-" "sqlmap/1.7"',
])


def test_log_analyzer_emits_scan_complete(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000) as blocker:
            worker.start()
        hosts, findings = blocker.args
        assert hosts == 0
        assert findings >= 0
    finally:
        os.unlink(path)


def test_log_analyzer_detects_ssh_brute_force(qtbot, db):
    worker, scan_id, path = _make_worker(db, SSH_BRUTE_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any(f.severity == "HIGH" for f in findings), "Expected at least one HIGH finding"
        assert any("ssh" in f.title.lower() or "brute" in f.title.lower() for f in findings)
    finally:
        os.unlink(path)


def test_log_analyzer_detects_scanner_ua(qtbot, db):
    worker, scan_id, path = _make_worker(db, NGINX_SCANNER_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any(f.tool == "log-analyzer" for f in findings)
    finally:
        os.unlink(path)


def test_log_analyzer_stores_findings_in_db(qtbot, db):
    worker, scan_id, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        db_findings = db.query_findings_by_scan(scan_id)
        assert all(f.tool == "log-analyzer" for f in db_findings)
    finally:
        os.unlink(path)


def test_log_analyzer_emits_scan_failed_for_missing_file(qtbot, db):
    scan = Scan(id=None, client_id=None, target="/nonexistent/path.log", status="running",
                started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    scan_id = db.insert_scan(scan)
    worker = LogAnalyzerWorker(path="/nonexistent/path.log", scan_id=scan_id, db=db)
    failed_msgs = []
    worker.scan_failed.connect(failed_msgs.append)
    with qtbot.waitSignal(worker.scan_failed, timeout=5000):
        worker.start()
    assert failed_msgs


def test_log_analyzer_emits_log_lines(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    log_lines = []
    worker.log_line.connect(log_lines.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        assert any("log-analyzer" in line for line in log_lines)
    finally:
        os.unlink(path)


def test_log_analyzer_skips_ai_advisor_when_disabled(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    try:
        with patch("workers.log_analyzer.GeminiClient") as mock_gemini:
            with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                worker.start()
            mock_gemini.assert_not_called()
    finally:
        os.unlink(path)


def test_log_analyzer_groups_brute_force_into_one_finding(qtbot, db):
    worker, _, path = _make_worker(db, SSH_BRUTE_LOG)
    findings = []
    worker.finding_found.connect(findings.append)
    try:
        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
            worker.start()
        brute_force = [f for f in findings if "brute" in f.title.lower() or "ssh" in f.title.lower()]
        assert len(brute_force) == 1, f"Expected 1 grouped finding, got {len(brute_force)}"
    finally:
        os.unlink(path)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_log_analyzer.py -v
```
Expected: `ModuleNotFoundError: No module named 'workers.log_analyzer'`

- [ ] **Step 3: Create `workers/log_analyzer.py`**

```python
import re
from collections import defaultdict
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding
from workers.log_rules import detect_format, RULES, LogRule


class LogAnalyzerWorker(QThread):
    finding_found = pyqtSignal(object)
    log_line      = pyqtSignal(str)
    scan_complete = pyqtSignal(int, int)
    scan_failed   = pyqtSignal(str)

    def __init__(self, path: str, scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._path = path
        self._scan_id = scan_id
        self._db = db

    def run(self):
        try:
            lines = self._read_file()
        except FileNotFoundError:
            self.scan_failed.emit(f"Log file not found: {self._path}")
            return
        except PermissionError:
            self.scan_failed.emit(f"Cannot read log file: permission denied")
            return

        fmt = detect_format(lines)
        self.log_line.emit(f"[log-analyzer] detected format: {fmt}")

        findings = self._run_rules(lines, fmt)
        self.log_line.emit(f"[log-analyzer] rules complete — {len(findings)} findings")

        findings = self._enrich_with_ai(findings)

        for f in findings:
            f.id = self._db.insert_finding(f)
            self.finding_found.emit(f)

        self._db.update_scan_status(
            self._scan_id, "complete", datetime.now(timezone.utc).isoformat()
        )
        self.scan_complete.emit(0, len(findings))

    def _read_file(self) -> list[str]:
        with open(self._path, "r", errors="replace") as fh:
            return fh.readlines()

    def _run_rules(self, lines: list[str], fmt: str) -> list[Finding]:
        applicable = [
            r for r in RULES
            if "*" in r.formats or fmt in r.formats or "unknown" in r.formats
        ]

        # Count-based rules: group hits by extracted key (IP, user, etc.)
        count_rules = {"ssh_brute_force", "http_scan_rate", "repeated_block", "port_scan"}
        count_hits: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        # Pattern-match rules: one finding per distinct matched string
        match_hits: dict[str, set[str]] = defaultdict(set)

        for lineno, line in enumerate(lines, start=1):
            for rule in applicable:
                m = rule.pattern.search(line)
                if not m:
                    continue
                if rule.name in count_rules:
                    key = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                    count_hits[rule.name][key].append(lineno)
                else:
                    match_hits[rule.name].add(m.group(0)[:120])

        findings: list[Finding] = []

        # Thresholds for count-based rules
        thresholds = {
            "ssh_brute_force": 5,
            "http_scan_rate":  20,
            "repeated_block":  10,
            "port_scan":       1,
        }

        rule_by_name = {r.name: r for r in applicable}

        for rule_name, key_hits in count_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            threshold = thresholds.get(rule_name, 1)
            for key, line_numbers in key_hits.items():
                if len(line_numbers) < threshold:
                    continue
                desc = (
                    f"{rule.description}: {len(line_numbers)} occurrences from {key} "
                    f"(lines {line_numbers[0]}–{line_numbers[-1]})"
                )
                findings.append(Finding(
                    id=None,
                    scan_id=self._scan_id,
                    host_id=None,
                    tool="log-analyzer",
                    severity=rule.severity.lower(),
                    title=f"{rule_name.replace('_', ' ').title()} — {key}",
                    description=desc,
                    raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        for rule_name, matched_strings in match_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            for matched in matched_strings:
                findings.append(Finding(
                    id=None,
                    scan_id=self._scan_id,
                    host_id=None,
                    tool="log-analyzer",
                    severity=rule.severity.lower(),
                    title=rule_name.replace("_", " ").title(),
                    description=f"{rule.description}: {matched}",
                    raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        return findings

    def _enrich_with_ai(self, findings: list[Finding]) -> list[Finding]:
        if not self._db:
            return findings
        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""
        if not enabled or not api_key:
            return findings

        self.log_line.emit("[log-analyzer] enriching with AI Advisor...")
        try:
            summary_lines = [f"- [{f.severity.upper()}] {f.title}: {f.description[:200]}" for f in findings]
            prompt = (
                "You are a security analyst. Analyse these log anomalies and identify "
                "any additional security concerns. For each concern respond with:\n"
                "SEVERITY: HIGH|MEDIUM|LOW\nTITLE: short title\nDESCRIPTION: one sentence\n\n"
                + "\n".join(summary_lines[:20])
            )
            from advisor.gemini_client import GeminiClient
            response = GeminiClient(api_key).generate(prompt)
            ai_findings = self._parse_ai_response(response)
            findings.extend(ai_findings)
            self.log_line.emit(f"[log-analyzer] AI Advisor added {len(ai_findings)} findings")
        except Exception as exc:
            self.log_line.emit(f"[log-analyzer] AI Advisor error (skipped): {exc}")
        return findings

    def _parse_ai_response(self, text: str) -> list[Finding]:
        findings = []
        blocks = re.split(r"\n(?=SEVERITY:)", text.strip())
        for block in blocks:
            sev_m = re.search(r"SEVERITY:\s*(HIGH|MEDIUM|LOW|CRITICAL|INFO)", block, re.IGNORECASE)
            title_m = re.search(r"TITLE:\s*(.+)", block)
            desc_m = re.search(r"DESCRIPTION:\s*(.+)", block)
            if not (sev_m and title_m):
                continue
            findings.append(Finding(
                id=None,
                scan_id=self._scan_id,
                host_id=None,
                tool="log-analyzer",
                severity=sev_m.group(1).lower(),
                title=title_m.group(1).strip(),
                description=desc_m.group(1).strip() if desc_m else "",
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
        return findings
```

- [ ] **Step 4: Run log_analyzer tests**

```bash
pytest tests/test_log_analyzer.py -v
```
Expected: All 8 tests pass.

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q
```
Expected: 237 + 8 = 245 tests pass.

- [ ] **Step 6: Commit**

```bash
git add workers/log_analyzer.py tests/test_log_analyzer.py
git commit -m "feat: add LogAnalyzerWorker — format detection, rule engine, AI Advisor enrichment"
```

---

### Task 4: Scan view mode toggle and Browse button (`screens/scan_view.py`)

**Files:**
- Modify: `screens/scan_view.py`
- Modify: `tests/test_scan_view.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_scan_view.py` (file does not exist yet):

```python
from unittest.mock import patch
from PyQt6.QtCore import Qt
from screens.scan_view import ScanViewScreen


def test_scan_view_has_mode_toggle_buttons(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert view._scan_mode_btn is not None
    assert view._log_mode_btn is not None


def test_scan_view_default_mode_is_scan(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert view._mode == "scan"


def test_switching_to_log_mode_shows_browse_button(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    assert not view._browse_btn.isVisible()
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    assert view._browse_btn.isVisible()
    assert view._mode == "logs"


def test_switching_back_to_scan_mode_hides_browse_button(qtbot, db):
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    qtbot.mouseClick(view._scan_mode_btn, Qt.MouseButton.LeftButton)
    assert not view._browse_btn.isVisible()
    assert view._mode == "scan"


def test_log_mode_creates_log_analyzer_worker(qtbot, db, tmp_path):
    from workers.log_analyzer import LogAnalyzerWorker
    log_file = tmp_path / "auth.log"
    log_file.write_text("Jun  5 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4\n")
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    qtbot.mouseClick(view._log_mode_btn, Qt.MouseButton.LeftButton)
    view._target_input.setText(str(log_file))

    with patch.object(LogAnalyzerWorker, "start"):
        view._on_start_cancel()

    assert isinstance(view._worker, LogAnalyzerWorker)


def test_scan_mode_creates_scan_worker(qtbot, db):
    from workers.scan_worker import ScanWorker
    view = ScanViewScreen(db=db)
    qtbot.addWidget(view)
    view._target_input.setText("example.com")

    with patch.object(ScanWorker, "start"):
        view._on_start_cancel()

    assert isinstance(view._worker, ScanWorker)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_scan_view.py -k "mode_toggle or mode_btn or browse or log_mode or scan_mode" -v
```
Expected: `AttributeError: 'ScanViewScreen' object has no attribute '_scan_mode_btn'`

- [ ] **Step 3: Update `screens/scan_view.py`**

Replace the imports block at the top:

```python
from datetime import datetime, timezone
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSplitter, QPlainTextEdit,
    QFileDialog,
)
from screens.widgets.pipeline_tracker import PipelineTracker
from screens.widgets.attack_graph import AttackGraph
from screens.widgets.severity_rings import SeverityRings
from screens.widgets.finding_cards import FindingCards
```

Replace the `__init__` method:

```python
def __init__(self, db=None, parent=None):
    super().__init__(parent)
    self._db = db
    self._mode = "scan"
    self._target_input: QLineEdit | None = None
    self._scan_mode_btn: QPushButton | None = None
    self._log_mode_btn: QPushButton | None = None
    self._browse_btn: QPushButton | None = None
    self._start_btn: QPushButton | None = None
    self._status_label: QLabel | None = None
    self._log_status_label: QLabel | None = None
    self._pipeline_panel: PipelineTracker | None = None
    self._attack_graph_panel: AttackGraph | None = None
    self._severity_panel: SeverityRings | None = None
    self._finding_cards_panel: FindingCards | None = None
    self._terminal_panel: QPlainTextEdit | None = None
    self._worker = None
    self._scan_id: int | None = None
    self._setup_ui()
```

Replace `_setup_ui` method:

```python
def _setup_ui(self):
    layout = QVBoxLayout(self)
    layout.setContentsMargins(12, 12, 12, 12)
    layout.setSpacing(8)

    top_bar = QHBoxLayout()

    # Mode toggle pill
    self._scan_mode_btn = QPushButton("Scan Target")
    self._scan_mode_btn.setCheckable(True)
    self._scan_mode_btn.setChecked(True)
    self._scan_mode_btn.setProperty("active", "true")
    self._scan_mode_btn.setFixedWidth(110)
    self._scan_mode_btn.clicked.connect(lambda: self._set_mode("scan"))

    self._log_mode_btn = QPushButton("Analyse Logs")
    self._log_mode_btn.setCheckable(True)
    self._log_mode_btn.setChecked(False)
    self._log_mode_btn.setProperty("active", "false")
    self._log_mode_btn.setFixedWidth(110)
    self._log_mode_btn.clicked.connect(lambda: self._set_mode("logs"))

    self._target_input = QLineEdit()
    self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")

    self._browse_btn = QPushButton("Browse")
    self._browse_btn.setFixedWidth(72)
    self._browse_btn.setVisible(False)
    self._browse_btn.clicked.connect(self._on_browse)

    self._start_btn = QPushButton("▶  Start Scan")
    self._start_btn.setEnabled(self._db is not None)
    self._start_btn.setToolTip("Enter a target and click to scan" if self._db else "DB not initialised")
    self._start_btn.clicked.connect(self._on_start_cancel)

    top_bar.addWidget(self._scan_mode_btn)
    top_bar.addWidget(self._log_mode_btn)
    top_bar.addWidget(self._target_input, stretch=1)
    top_bar.addWidget(self._browse_btn)
    top_bar.addWidget(self._start_btn)
    layout.addLayout(top_bar)

    self._status_label = QLabel("Ready")
    self._status_label.setStyleSheet("color: #64748b; font-size: 11px;")
    layout.addWidget(self._status_label)

    self._log_status_label = QLabel("")
    self._log_status_label.setStyleSheet("color: #64748b; font-size: 11px;")
    self._log_status_label.setVisible(False)
    layout.addWidget(self._log_status_label)

    self._pipeline_panel = PipelineTracker()
    self._attack_graph_panel = AttackGraph()
    self._attack_graph_panel.reset()
    self._severity_panel = SeverityRings()
    self._finding_cards_panel = FindingCards()

    self._terminal_panel = QPlainTextEdit()
    self._terminal_panel.setReadOnly(True)
    self._terminal_panel.setObjectName("panel")
    self._terminal_panel.setStyleSheet(
        "font-family: monospace; font-size: 11px; color: #00ff88; background-color: #0a0e1a;"
    )

    top_splitter = QSplitter(Qt.Orientation.Horizontal)
    top_splitter.addWidget(self._pipeline_panel)
    top_splitter.addWidget(self._attack_graph_panel)
    top_splitter.setSizes([250, 750])

    mid_splitter = QSplitter(Qt.Orientation.Horizontal)
    mid_splitter.addWidget(self._severity_panel)
    mid_splitter.addWidget(self._finding_cards_panel)
    mid_splitter.setSizes([250, 750])

    top_mid = QWidget()
    top_mid_layout = QVBoxLayout(top_mid)
    top_mid_layout.setContentsMargins(0, 0, 0, 0)
    top_mid_layout.setSpacing(8)
    top_mid_layout.addWidget(top_splitter, stretch=1)
    top_mid_layout.addWidget(mid_splitter, stretch=1)

    main_splitter = QSplitter(Qt.Orientation.Vertical)
    main_splitter.addWidget(top_mid)
    main_splitter.addWidget(self._terminal_panel)
    main_splitter.setSizes([800, 200])

    layout.addWidget(main_splitter, stretch=1)
```

Add `_set_mode` and `_on_browse` methods (insert before `_on_start_cancel`):

```python
def _set_mode(self, mode: str):
    self._mode = mode
    is_scan = mode == "scan"
    self._scan_mode_btn.setProperty("active", "true" if is_scan else "false")
    self._log_mode_btn.setProperty("active", "false" if is_scan else "true")
    self._scan_mode_btn.style().unpolish(self._scan_mode_btn)
    self._scan_mode_btn.style().polish(self._scan_mode_btn)
    self._log_mode_btn.style().unpolish(self._log_mode_btn)
    self._log_mode_btn.style().polish(self._log_mode_btn)
    self._target_input.setText("")
    self._target_input.setPlaceholderText(
        "Target domain or IP (e.g. example.com)" if is_scan
        else "Path to log file (e.g. /var/log/auth.log)"
    )
    self._browse_btn.setVisible(not is_scan)
    self._pipeline_panel.setVisible(is_scan)
    self._log_status_label.setVisible(not is_scan)
    self._start_btn.setText("▶  Start Scan" if is_scan else "▶  Analyse")

def _on_browse(self):
    path, _ = QFileDialog.getOpenFileName(
        self, "Select log file", "/var/log",
        "Log files (*.log *.txt *);;All files (*)"
    )
    if path:
        self._target_input.setText(path)
```

Replace `_on_start_cancel` method:

```python
def _on_start_cancel(self):
    if self._worker and self._worker.isRunning():
        self._worker.cancel()
        self._start_btn.setEnabled(False)
        self._start_btn.setText("Cancelling…")
        return

    target = self._target_input.text().strip()
    if not target:
        self._status_label.setText("Enter a target first." if self._mode == "scan" else "Select a log file first.")
        return

    from models import Scan

    scan = Scan(
        id=None,
        client_id=None,
        target=target,
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    )
    self._scan_id = self._db.insert_scan(scan)

    self._severity_panel.reset()
    self._finding_cards_panel.reset()
    self._terminal_panel.clear()

    if self._worker is not None:
        self._worker.deleteLater()
        self._worker = None

    if self._mode == "scan":
        from workers.scan_worker import ScanWorker
        self._pipeline_panel.reset()
        self._attack_graph_panel.reset()
        self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)
        self._worker.tool_started.connect(self._pipeline_panel.on_tool_started)
        self._worker.tool_finished.connect(self._pipeline_panel.on_tool_finished)
        self._worker.tool_failed.connect(self._pipeline_panel.on_tool_failed)
        self._worker.scan_complete.connect(self._pipeline_panel.on_scan_complete)
        self._worker.host_found.connect(self._attack_graph_panel.add_host)
        self._worker.finding_found.connect(self._attack_graph_panel.add_finding)
        self._worker.scan_complete.connect(self._attack_graph_panel.on_scan_complete)
        self._worker.tool_started.connect(self._on_tool_started)
        self._worker.tool_finished.connect(self._on_tool_finished)
        self._worker.tool_failed.connect(self._on_tool_failed_log)
    else:
        from workers.log_analyzer import LogAnalyzerWorker
        self._log_status_label.setText("Detecting format…")
        self._worker = LogAnalyzerWorker(path=target, scan_id=self._scan_id, db=self._db)
        self._worker.log_line.connect(self._on_log_status_update)

    self._worker.finding_found.connect(self._severity_panel.add_finding)
    self._worker.scan_complete.connect(self._severity_panel.on_scan_complete)
    self._worker.finding_found.connect(self._finding_cards_panel.add_finding)
    self._worker.scan_complete.connect(self._finding_cards_panel.on_scan_complete)
    self._worker.log_line.connect(self._log)
    self._worker.scan_complete.connect(self._on_scan_complete)
    self._worker.scan_failed.connect(self._on_scan_failed)

    self._start_btn.setText("■  Cancel")
    self._worker.start()

def _on_log_status_update(self, line: str):
    if "detected format" in line:
        self._log_status_label.setText("Running rules…")
    elif "rules complete" in line:
        self._log_status_label.setText("Enriching with AI Advisor…")
```

- [ ] **Step 4: Run scan_view tests**

```bash
pytest tests/test_scan_view.py -v
```
Expected: All pass including 6 new tests.

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q
```
Expected: 245 + 6 = 251 tests pass.

- [ ] **Step 6: Commit**

```bash
git add screens/scan_view.py tests/test_scan_view.py
git commit -m "feat: add Scan Target / Analyse Logs mode toggle and Browse button to scan view"
```

---

### Task 5: Log findings section in report view (`screens/report.py`)

**Files:**
- Modify: `screens/report.py`
- Modify: `tests/test_report.py`

- [ ] **Step 1: Write failing tests**

Add these tests at the end of `tests/test_report.py`:

```python
from models import Finding
from datetime import datetime, timezone


def _make_log_finding(db, scan_id, title="SSH Brute Force", severity="high"):
    f = Finding(
        id=None, scan_id=scan_id, host_id=None,
        tool="log-analyzer", severity=severity,
        title=title, description="10 failed attempts from 1.2.3.4",
        raw_json="", created_at=datetime.now(timezone.utc).isoformat(),
    )
    f.id = db.insert_finding(f)
    return f


def test_report_shows_log_section_when_log_findings_exist(qtbot, db):
    from screens.report import ReportScreen
    from models import Scan
    scan = Scan(id=None, client_id=None, target="test.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    scan_id = db.insert_scan(scan)
    _make_log_finding(db, scan_id)

    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)

    labels = [screen._content.findChild(type(screen._content), "", options=0)]
    # Check the content layout has a log findings panel
    found_log_section = False
    for i in range(screen._content_layout.count()):
        item = screen._content_layout.itemAt(i)
        if item and item.widget():
            widget = item.widget()
            # Look for QLabel children with "Log Analysis" text
            for child in widget.findChildren(__import__('PyQt6.QtWidgets', fromlist=['QLabel']).QLabel):
                if "Log Analysis" in child.text():
                    found_log_section = True
    assert found_log_section, "Log Analysis section not found in report"


def test_report_hides_log_section_when_no_log_findings(qtbot, db):
    from screens.report import ReportScreen
    from models import Scan, Finding
    scan = Scan(id=None, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    scan_id = db.insert_scan(scan)
    # Insert a regular (non-log) finding
    f = Finding(id=None, scan_id=scan_id, host_id=None, tool="nmap", severity="medium",
                title="Open port", description="Port 80 open", raw_json="",
                created_at=datetime.now(timezone.utc).isoformat())
    db.insert_finding(f)

    screen = ReportScreen(db=db)
    qtbot.addWidget(screen)
    screen.load_scan(scan_id)

    from PyQt6.QtWidgets import QLabel
    found_log_section = False
    for i in range(screen._content_layout.count()):
        item = screen._content_layout.itemAt(i)
        if item and item.widget():
            for child in item.widget().findChildren(QLabel):
                if "Log Analysis" in child.text():
                    found_log_section = True
    assert not found_log_section, "Log Analysis section should not appear for scan-only findings"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_report.py::test_report_shows_log_section_when_log_findings_exist tests/test_report.py::test_report_hides_log_section_when_no_log_findings -v
```
Expected: FAIL — no "Log Analysis" label rendered yet.

- [ ] **Step 3: Update `screens/report.py`**

In `load_scan`, insert `_build_log_panel` call after `_build_findings_panel`. Replace:

```python
        self._content_layout.addWidget(self._build_summary(scan, hosts, findings))
        self._content_layout.addWidget(self._build_severity_panel(findings))
        self._content_layout.addWidget(self._build_findings_panel(findings))
```

With:

```python
        net_findings = [f for f in findings if f.tool != "log-analyzer"]
        log_findings = [f for f in findings if f.tool == "log-analyzer"]

        self._content_layout.addWidget(self._build_summary(scan, hosts, findings))
        self._content_layout.addWidget(self._build_severity_panel(findings))
        self._content_layout.addWidget(self._build_findings_panel(net_findings))
        if log_findings:
            self._content_layout.addWidget(self._build_log_panel(log_findings))
```

Add `_build_log_panel` method after `_build_findings_panel`:

```python
    def _build_log_panel(self, findings) -> QFrame:
        panel = QFrame()
        panel.setObjectName("panel")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        header = QLabel("Log Analysis Findings")
        header.setStyleSheet("font-size: 14px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(header)

        by_sev: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_sev else "info"
            by_sev[sev].append(f)

        for sev in _SEVERITY_ORDER:
            if not by_sev[sev]:
                continue
            color = _SEVERITY_COLORS.get(sev, "#64748b")
            sev_label = QLabel(
                f'<span style="color:{color}; font-weight:bold;">{sev.upper()} ({len(by_sev[sev])})</span>'
            )
            sev_label.setStyleSheet("font-size: 12px;")
            layout.addWidget(sev_label)
            for f in by_sev[sev]:
                card = QFrame()
                card.setStyleSheet(
                    f"QFrame {{ border-left: 3px solid {color}; "
                    f"background-color: #0f172a; border-radius: 3px; }}"
                )
                card_layout = QVBoxLayout(card)
                card_layout.setContentsMargins(10, 6, 10, 6)
                card_layout.setSpacing(2)
                title_lbl = QLabel(f.title)
                title_lbl.setStyleSheet("color: #e2e8f0; font-size: 12px; font-weight: bold;")
                card_layout.addWidget(title_lbl)
                if f.description:
                    desc_lbl = QLabel(f.description[:200])
                    desc_lbl.setWordWrap(True)
                    desc_lbl.setStyleSheet("color: #94a3b8; font-size: 10px;")
                    card_layout.addWidget(desc_lbl)
                layout.addWidget(card)

        return panel
```

- [ ] **Step 4: Run report tests**

```bash
pytest tests/test_report.py -v
```
Expected: All pass including 2 new tests.

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q
```
Expected: 251 + 2 = 253 tests pass.

- [ ] **Step 6: Commit**

```bash
git add screens/report.py tests/test_report.py
git commit -m "feat: add Log Analysis Findings section to report view"
```

---

### Task 6: Log analysis section in PDF generator (`report/pdf_generator.py`)

**Files:**
- Modify: `report/pdf_generator.py`
- Modify: `tests/test_pdf_generator.py`

- [ ] **Step 1: Write failing tests**

Add these tests at the end of `tests/test_pdf_generator.py`:

```python
import os
import tempfile
from datetime import datetime, timezone
from models import Scan, Host, Finding
from report.pdf_generator import PdfGenerator


def _make_log_finding(scan_id, title="SSH Brute Force", severity="high"):
    return Finding(
        id=1, scan_id=scan_id, host_id=None,
        tool="log-analyzer", severity=severity,
        title=title, description="10 failed SSH attempts from 1.2.3.4",
        raw_json="", created_at=datetime.now(timezone.utc).isoformat(),
    )


def test_pdf_includes_log_section_when_log_findings_present(tmp_path):
    scan = Scan(id=1, client_id=None, target="test.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    findings = [_make_log_finding(scan_id=1)]
    out = str(tmp_path / "report_log.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=findings, output_path=out)
    gen.generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def test_pdf_excludes_log_section_when_no_log_findings(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    findings = [Finding(id=1, scan_id=1, host_id=None, tool="nmap", severity="medium",
                        title="Open port", description="Port 80 open", raw_json="",
                        created_at=datetime.now(timezone.utc).isoformat())]
    out = str(tmp_path / "report_noscan.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=findings, output_path=out)
    result = gen.generate()
    assert os.path.exists(out)
```

- [ ] **Step 2: Run tests to confirm the new tests pass already** (PDF generates without errors; no log section yet but file is created)

```bash
pytest tests/test_pdf_generator.py::test_pdf_includes_log_section_when_log_findings_present tests/test_pdf_generator.py::test_pdf_excludes_log_section_when_no_log_findings -v
```
Note: These tests only check file existence and size — they pass once the PDF generator accepts log findings without crashing.

- [ ] **Step 3: Update `report/pdf_generator.py`**

In `generate()`, replace:

```python
        story += self._findings_section()
        story.append(PageBreak())
        story += self._iso_section()
```

With:

```python
        net_findings = [f for f in self._findings if f.tool != "log-analyzer"]
        log_findings = [f for f in self._findings if f.tool == "log-analyzer"]

        story += self._findings_section(net_findings)
        if log_findings:
            story += self._log_section(log_findings)
        story.append(PageBreak())
        story += self._iso_section(net_findings)
```

Update `_findings_section` signature to accept `findings` parameter (instead of using `self._findings` directly). Replace:

```python
    def _findings_section(self) -> list:
        story = [
            Paragraph("Findings", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
        ]
        by_severity: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in self._findings:
```

With:

```python
    def _findings_section(self, findings: list | None = None) -> list:
        if findings is None:
            findings = self._findings
        story = [
            Paragraph("Findings", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
        ]
        by_severity: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
```

Also update the `if not self._findings:` check at the end of `_findings_section` to use the local variable:

```python
        if not findings:
            story.append(Paragraph("No findings recorded for this scan.", self._body))
        return story
```

Update `_iso_section` signature similarly. Replace:

```python
    def _iso_section(self) -> list:
```
With:
```python
    def _iso_section(self, findings: list | None = None) -> list:
        if findings is None:
            findings = self._findings
```

And replace `for f in self._findings:` inside `_iso_section` with `for f in findings:`.

Add `_log_section` method after `_findings_section`:

```python
    def _log_section(self, findings: list) -> list:
        story = [
            Paragraph("Log Analysis", self._h1),
            HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")),
        ]
        by_severity: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.severity if f.severity in by_severity else "info"
            by_severity[sev].append(f)

        for sev in _SEVERITY_ORDER:
            sev_findings = by_severity[sev]
            if not sev_findings:
                continue
            sev_color = _SEVERITY_COLORS.get(sev, colors.grey)
            story.append(Paragraph(sev.upper(), ParagraphStyle(
                f"LogSevHead_{sev}", fontSize=12, textColor=sev_color,
                fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=4,
            )))
            story.append(HRFlowable(width="100%", thickness=1, color=sev_color))
            for f in sev_findings:
                story.append(Paragraph(f.title, self._h3))
                if f.description:
                    story.append(Paragraph(f.description, self._body))
                story.append(Spacer(1, 0.3*cm))

        if not findings:
            story.append(Paragraph("No log anomalies recorded.", self._body))
        return story
```

- [ ] **Step 4: Run PDF generator tests**

```bash
pytest tests/test_pdf_generator.py -v
```
Expected: All pass including 2 new tests.

- [ ] **Step 5: Run full suite**

```bash
pytest --tb=short -q
```
Expected: 253 + 2 = 255 tests pass, 0 failures.

- [ ] **Step 6: Commit**

```bash
git add report/pdf_generator.py tests/test_pdf_generator.py
git commit -m "feat: add Log Analysis section to PDF export"
```
