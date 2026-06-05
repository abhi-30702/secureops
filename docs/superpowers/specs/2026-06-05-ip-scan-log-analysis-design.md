# IP Scanning + Log Analysis — Design

**Date:** 2026-06-05
**Status:** Approved
**Scope:** Two related features: (1) smart IP vs domain pipeline routing in the scan engine, and (2) a new log analysis mode with rule-based anomaly detection and optional AI Advisor enrichment.

---

## 1. Goals

- When an IP address is entered as the target, skip domain-only tools (subfinder, dnsx) and feed the IP directly into the port-scanning stage onward
- Add a "Scan Target / Analyse Logs" mode toggle to the scan view
- Log analysis reads any local log file, auto-detects its format, applies rule-based anomaly detection, and optionally enriches findings via AI Advisor (when enabled in Settings)
- Log findings flow into the same Security Report and PDF as network scan findings, rendered in a dedicated "Log Analysis" section
- Everything works fully offline; AI Advisor enrichment is additive and optional

## 2. Non-goals

- Live log tailing / watching a log file for new entries
- Windows log formats (EVT/EVTX)
- Log ingestion from remote hosts via SSH or syslog
- Statistical/ML-based anomaly detection (rule-based only for v1)
- Changing the DB schema

---

## 3. Architecture overview

Two independent `QThread` workers share the same signal interface. The scan view creates one or the other depending on mode:

```
ScanViewScreen
├── mode = "scan"  → ScanWorker (existing, extended with IP detection)
└── mode = "logs"  → LogAnalyzerWorker (new)
        ├── FormatDetector
        ├── RuleEngine  ←  log_rules.py
        └── AI Advisor enrichment (optional)

Both workers emit:
    finding_found(Finding)
    log_line(str)
    scan_complete(int, int)
    scan_failed(str)

Downstream (unchanged):
    SeverityRings, FindingCards, TerminalPanel, ReportScreen, PDFGenerator
```

---

## 4. Feature 1 — IP vs Domain detection

### 4.1 Detection

`scan_worker.py` gains a module-level helper:

```python
import ipaddress

def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False
```

`ipaddress.ip_address()` handles both IPv4 and IPv6. No regex needed.

### 4.2 Pipeline routing

`_execute_pipeline()` branches at the top:

```python
if _is_ip(self._target):
    ips = [self._target]
    # skip subfinder and dnsx
else:
    subdomains_hosts = self._run_tool("subfinder", ...)
    subdomain_names = [h.subdomain for h in subdomains_hosts if h.subdomain]
    resolved_hosts = self._run_tool("dnsx", ...)
    ips = list({h.ip for h in resolved_hosts if h.ip})
```

From naabu onwards, both paths are identical. Subfinder and dnsx cards in the pipeline tracker show as skipped (zero items) for IP targets — no UI change needed.

### 4.3 Files changed

| File | Change |
|------|--------|
| `workers/scan_worker.py` | Add `_is_ip()`, branch in `_execute_pipeline()` |
| `tests/test_scan_worker.py` | Tests for IP detection and IP-mode pipeline routing |

---

## 5. Feature 2 — Log analysis

### 5.1 New files

| File | Purpose |
|------|---------|
| `workers/log_analyzer.py` | `LogAnalyzerWorker(QThread)` — orchestrates the three stages |
| `workers/log_rules.py` | `LogRule` dataclass + all format-specific rule sets |
| `tests/test_log_analyzer.py` | Unit tests for format detection, rule matching, finding grouping |

### 5.2 `LogRule` dataclass (`workers/log_rules.py`)

```python
@dataclass
class LogRule:
    name: str
    pattern: re.Pattern
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    description: str
    formats: list[str]   # which log formats this rule applies to; ["*"] = all
```

Rules are grouped into a `RULES: list[LogRule]` constant. All patterns are pre-compiled at import time.

### 5.3 Format detection

Reads the first 20 lines, scores each format, returns the highest-scoring one:

| Format tag | Detection signature |
|------------|-------------------|
| `auth` | contains `sshd`, `sudo`, `PAM`, or `useradd` |
| `syslog` | matches `^[A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2}` |
| `nginx` | contains `"GET ` or `"POST ` with HTTP status code |
| `apache` | same pattern as nginx (combined log format is identical) |
| `firewall` | contains `UFW BLOCK`, `iptables`, or `IN=` `OUT=` |
| `unknown` | fallback — generic rules only |

### 5.4 Rule library (initial set)

| Format | Rule name | Trigger | Severity |
|--------|-----------|---------|----------|
| `auth` | ssh_brute_force | ≥5 `Failed password` from same IP | HIGH |
| `auth` | root_sudo | `sudo.*session opened.*root` | MEDIUM |
| `auth` | user_account_change | `useradd\|usermod\|userdel` | HIGH |
| `auth` | pubkey_login | `Accepted publickey` | INFO |
| `nginx`,`apache` | http_scan_rate | ≥20 4xx from same IP | MEDIUM |
| `nginx`,`apache` | sqli_attempt | `UNION.*SELECT\|'\s*--\|1=1` in URL | HIGH |
| `nginx`,`apache` | scanner_ua | `sqlmap\|nikto\|nmap\|masscan` in User-Agent | MEDIUM |
| `firewall` | repeated_block | ≥10 blocks from same source IP | MEDIUM |
| `firewall` | port_scan | ≥5 distinct destination ports from same source IP | HIGH |
| `syslog` | oom_killer | `Out of memory: Kill process` | MEDIUM |
| `syslog` | kernel_panic | `segfault\|kernel panic` | MEDIUM |
| `*` | generic_sqli | SQL injection patterns (any format) | HIGH |

### 5.5 `LogAnalyzerWorker` stages

**Stage 1 — Format detection**
Reads up to the first 20 lines, runs `detect_format()`, emits `log_line("[log-analyzer] detected format: auth")`.

**Stage 2 — Rule engine**
Iterates all lines, collects matches per rule. Groups hits by source IP/identifier before creating `Finding` objects — so 200 failed SSH attempts from one IP = one `HIGH` finding, not 200. Each `Finding` uses `tool="log-analyzer"`, severity from the rule, and `description` containing a summary (e.g. "SSH brute force: 247 failed attempts from 192.168.1.10").

**Stage 3 — AI Advisor enrichment (conditional)**
If `db.get_setting("ai_advisor_enabled") == "1"` and `db.get_setting("gemini_api_key")` is non-empty: builds a compact plain-text summary of all rule hits (≤ 2000 chars) and sends it to `GeminiClient` with the prompt "Analyse these log anomalies and identify any additional security concerns." Any `Finding` objects returned are emitted with `tool="log-analyzer"`.

**Completion**
Emits `scan_complete(0, findings_count)` — hosts is always 0 for log analysis.

### 5.6 Finding grouping algorithm

For count-based rules (SSH brute force, HTTP scan rate, repeated blocks, port scan):
- Collect all matching lines
- Group by extracted key (source IP, user, etc.)
- Emit one `Finding` per group that meets the threshold
- Finding description: `"{rule_name}: {count} occurrences from {key} (lines {first}–{last})"`

For pattern-match rules (SQLi, scanner UA, user account changes):
- Each distinct match (deduplicated by matched string) emits one `Finding`

### 5.7 Error handling

- File not found → `scan_failed.emit("Log file not found: {path}")`
- Permission denied → `scan_failed.emit("Cannot read log file: permission denied")`
- Unknown format with zero rule hits → `scan_complete.emit(0, 0)` with a log line noting no anomalies found
- AI Advisor failure → log the error, proceed without enrichment (non-fatal)

---

## 6. UI changes (`screens/scan_view.py`)

### 6.1 Mode toggle

Two `QPushButton`s styled as a pill selector, inserted to the left of the input field:

```
[ Scan Target | Analyse Logs ]  [ input / path field ............ ] [Browse] [Start Scan]
```

- Only one button is "active" at a time (CSS `active` property, same pattern as sidebar)
- Browse button hidden in Scan Target mode; visible in Analyse Logs mode
- Browse opens `QFileDialog.getOpenFileName()` filtered to `"Log files (*.log *.txt *)"` + "All files"

### 6.2 Pipeline tracker visibility

- **Scan Target mode**: pipeline tracker visible (existing behaviour)
- **Analyse Logs mode**: pipeline tracker hidden; replaced by a `QLabel` showing the current stage ("Detecting format…", "Running rules…", "Enriching with AI Advisor…")

### 6.3 Worker selection on Start

```python
if self._mode == "scan":
    self._worker = ScanWorker(target=target, scan_id=self._scan_id, db=self._db)
else:
    self._worker = LogAnalyzerWorker(path=log_path, scan_id=self._scan_id, db=self._db)

# Signal connections are identical for both workers
self._worker.finding_found.connect(...)
self._worker.log_line.connect(...)
self._worker.scan_complete.connect(...)
self._worker.scan_failed.connect(...)
```

### 6.4 Files changed

| File | Change |
|------|--------|
| `screens/scan_view.py` | Mode toggle buttons, Browse button, worker selection, tracker visibility |
| `tests/test_scan_view.py` | Mode switching, Browse button populates field, correct worker created per mode |

---

## 7. Report & PDF changes

### 7.1 Report view (`screens/report.py`)

After the existing Findings section, a new "Log Analysis Findings" group box is rendered when `tool == "log-analyzer"` findings are present. Absent entirely for scan-only runs. Same card style as network findings.

### 7.2 PDF generator (`report/pdf_generator.py`)

A new `_build_log_section(findings)` method, called after `_build_findings_section()`. Included in the PDF only when log findings exist. Header: "Log Analysis" with the same section styling.

### 7.3 Files changed

| File | Change |
|------|--------|
| `screens/report.py` | Conditional log findings section |
| `report/pdf_generator.py` | `_build_log_section()` method |
| `tests/test_report.py` | Log section present/absent assertions |

---

## 8. Acceptance criteria

1. Entering an IPv4 or IPv6 address runs the scan starting from naabu — subfinder and dnsx cards show as skipped
2. Entering a domain runs the full existing pipeline unchanged
3. The mode toggle switches between Scan Target and Analyse Logs; Browse button appears/disappears correctly
4. Log analysis on `/var/log/auth.log` detects SSH brute-force attempts and emits at least one HIGH finding
5. Log analysis on an nginx access log detects scanner User-Agents and emits findings
6. Rule hits are grouped — 200 failed SSH attempts from one IP = one finding, not 200
7. When AI Advisor is disabled, log analysis completes without errors
8. Log findings appear in the Security Report under "Log Analysis Findings"
9. Log findings appear in the exported PDF under "Log Analysis"
10. All new tests pass; no regressions in existing 218 tests

---

## 9. File map

| Action | Path |
|--------|------|
| Modify | `workers/scan_worker.py` |
| Create | `workers/log_analyzer.py` |
| Create | `workers/log_rules.py` |
| Modify | `screens/scan_view.py` |
| Modify | `screens/report.py` |
| Modify | `report/pdf_generator.py` |
| Modify | `tests/test_scan_worker.py` |
| Create | `tests/test_log_analyzer.py` |
| Modify | `tests/test_scan_view.py` |
| Modify | `tests/test_report.py` |
