# Phase 5 — Incident Response Design Spec

**Date:** 2026-06-11  
**Owner:** Abhishek K — Fidelitus Corp  
**Status:** Approved — ready for implementation plan

---

## Goal

Add a dedicated Incident Response page that runs a unified three-stage scan from a single trigger: log file analysis, YARA scanning of suspicious directories, and a persistence mechanism checker. Results stream into `FindingCards`, `SeverityRings`, and a new `BreachTimeline` widget. A new `IncidentWorker` is created alongside the existing `LogAnalyzerWorker` (which is kept unchanged for `scan_view.py`). `IncidentWorker` reuses the same log analysis logic as Stage 1 and adds two new stages.

---

## Architecture

`IncidentWorker` (QThread) runs three stages in sequence:

1. **Stage 1 — Log Analysis**: reads a user-selected log file, detects format (auth/nginx/apache/firewall/syslog/unknown), runs 11 rule-based detections, optionally enriches with Gemini AI (if enabled). All existing `LogAnalyzerWorker` logic, zero changes.
2. **Stage 2 — YARA Scan**: scans fixed suspicious directories (`/tmp`, `/var/tmp`, `/dev/shm`, `/run`) plus one user-configurable extra path. Uses a built-in YARA ruleset (webshells, reverse shells, meterpreter artifacts). Emits one `Finding` per match.
3. **Stage 3 — Persistence Check**: three sub-checks — unexpected cron entries, SSH `authorized_keys` with more than one key per user, SUID binaries not in the known-good baseline. Emits one `Finding` per anomaly.

Each stage is isolated: a failure in one stage emits a `log_line` warning and skips to the next. Only `CancelledError` halts the pipeline.

---

## Components

| File | Action | Purpose |
|------|--------|---------|
| `workers/incident_worker.py` | **Create** | `IncidentWorker` QThread — 3 stages, cancel, all signals |
| `workers/log_rules.py` | Keep | Rule engine unchanged |
| `workers/tools/yara_scanner.py` | **Create** | `run(paths, extra_path) → list[dict]` — wraps `yara-python` |
| `workers/tools/persistence_checker.py` | **Create** | `run() → list[dict]` — cron + authorized_keys + SUID |
| `screens/incident_page.py` | **Create** | Full incident UI |
| `screens/widgets/breach_timeline.py` | **Create** | Chronological event list widget |
| `db.py` | **Modify** | Add `incident_events` table; add `get_incident_events(scan_id)` |
| `sidebar.py` | **Modify** | Add 🔥 Incident at nav index 6 |
| `main_window.py` | **Modify** | Add `IncidentPage` to stack at index 6 |
| `workers/log_analyzer.py` | Keep | Unchanged — still used by `scan_view.py` for external scan log analysis |
| `screens/scan_view.py` | Keep | No changes — continues to import `LogAnalyzerWorker` |
| `tests/test_incident_worker.py` | **Create** | Stage 1/2/3 unit tests |
| `tests/test_breach_timeline.py` | **Create** | Timeline data model tests |

---

## Signal Contract

All workers in SecureOps emit this standard set:

```python
finding_found  = pyqtSignal(object)        # Finding written to DB; UI appends card
tool_progress  = pyqtSignal(str, int, str) # stage_name, count, status
log_line       = pyqtSignal(str)           # raw output line → terminal
scan_complete  = pyqtSignal(int, int)      # total_findings, 0
scan_failed    = pyqtSignal(str)           # error message
error_occurred = pyqtSignal(str, str)      # tool_name, error_message
```

---

## Data Flow

1. User selects log file path + optional extra YARA path on `IncidentPage`, clicks **▶ Start Scan**
2. `IncidentPage._on_start()` creates `Scan` record in DB, instantiates `IncidentWorker`, connects signals, calls `.start()`
3. `IncidentWorker.run()` executes stages in order:
   - Stage 1: `_stage1_log_analysis(runner)` — reused from `LogAnalyzerWorker`
   - Stage 2: `_stage2_yara_scan(runner)` — calls `yara_scanner.run()`
   - Stage 3: `_stage3_persistence(runner)` — calls `persistence_checker.run()`
4. Each finding: `db.insert_finding(f)` → `finding_found.emit(f)` → UI updates cards/rings
5. Each log entry/lateral/persistence finding also writes a row to `incident_events`
6. On `scan_complete`: `IncidentPage` calls `db.get_incident_events(scan_id)` and populates `BreachTimeline`

---

## Database Changes

Add to `db.py` `_SCHEMA`:

```sql
CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER,
    timestamp   TEXT,
    event_type  TEXT,   -- 'entry' | 'lateral' | 'persistence' | 'exfil' | 'anomaly'
    source_host TEXT,
    dest_host   TEXT,
    description TEXT,
    evidence    TEXT
);
```

Add method `get_incident_events(scan_id: int) -> list[dict]`.

Findings from Stage 1 that match entry/lateral/exfil patterns (SSH login, HTTP 4xx burst, data transfer indicators) get a corresponding `incident_events` row. All Stage 3 persistence findings get an `incident_events` row with `event_type="persistence"`.

---

## YARA Scanner (`workers/tools/yara_scanner.py`)

```python
FIXED_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/run"]

BUILTIN_RULES = """
rule Webshell_PHP_Eval {
    strings: $a = /eval\s*\(\s*base64_decode/ nocase
    condition: $a
}
rule Reverse_Shell_Bash {
    strings: $a = "bash -i >& /dev/tcp/" nocase
    condition: $a
}
rule Meterpreter_Artifact {
    strings: $a = "meterpreter" nocase $b = "ReflectiveDll" nocase
    condition: any of them
}
"""

def run(extra_path: str | None = None) -> list[dict]:
    """Compile built-in rules, scan FIXED_PATHS + extra_path. Returns list of match dicts."""
```

Returns: `[{"file": path, "rule": rule_name, "severity": "high", "description": "..."}]`

If `yara-python` is not installed or rules fail to compile, returns `[]` and logs a warning — does not raise.

---

## Persistence Checker (`workers/tools/persistence_checker.py`)

Three sub-checks:

**Cron check:** reads `/etc/cron*/**` and `/var/spool/cron/crontabs/*`. Flags any file with mtime within the last 7 days (relative to scan time). Returns finding with the cron file path and entry text.

**authorized_keys check:** walks all user home directories under `/home` and `/root`. For each `~/.ssh/authorized_keys` found, flags if it contains more than 1 key (threshold: configurable, default 1).

**SUID check:** runs `find /usr /bin /sbin /usr/local -perm -4000 -type f` via subprocess. Flags any result not in the hardcoded known-good set:

```python
KNOWN_GOOD_SUID = {
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/chsh", "/usr/bin/chfn",
    "/usr/bin/su", "/usr/bin/mount", "/usr/bin/umount",
    "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
}
```

Returns: `[{"check": "cron"|"authorized_keys"|"suid", "path": ..., "detail": ..., "severity": "high"|"medium"}]`

---

## BreachTimeline Widget (`screens/widgets/breach_timeline.py`)

A `QScrollArea` containing a `QVBoxLayout` of event rows. Each row is a `QFrame` with:
- Timestamp pill (left, monospace, muted)
- Event type badge: coloured by type — entry=#C94A62, lateral=#B38B00, persistence=#5F4A8B, exfil=#C94A62, anomaly=#5A7A9B
- Source → Dest (if present)
- Description text

Public API:
- `add_event(event: dict)` — appends event at bottom (oldest-first chronological order); auto-scrolls to bottom
- `reset()` — clears all rows

---

## IncidentPage UI (`screens/incident_page.py`)

Layout (top to bottom):
1. **Top bar**: log file path input + Browse button + optional YARA path input + Start/Stop button
2. **Status label**: idle / scanning / done / error
3. **Body splitter** (horizontal):
   - Left: `BreachTimeline` (takes 60% width)
   - Right: `SeverityRings` + `FindingCards` stacked vertically
4. **Terminal** (bottom strip, collapsible): raw `log_line` output

`showEvent` loads saved `internal_subnets` — no, wrong page. `showEvent` is a no-op here (no persisted state to restore on this page).

---

## Colour Palette

Reuse Phase 4 palette:
- Background: `#FEFACD` (Lemon Chiffon)
- Accent: `#5F4A8B` (Ultra Violet)  
- Dark text: `#2A1F45` (Deep Violet)
- Hover: `#8B75C2` (Soft Violet)
- Card surface: `#FFFEF2` (Pale Chiffon)

Event type badge colours follow device-type conventions from `TopologyGraph`.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| Log file not found | `scan_failed` emitted, scan status → "failed" |
| Log file permission denied | `scan_failed` emitted, scan status → "failed" |
| `yara-python` not installed | Stage 2 skipped, `log_line` warning emitted, Stage 3 continues |
| YARA compile error | Stage 2 skipped with warning, Stage 3 continues |
| SUID `find` command not found | Sub-check skipped, `log_line` warning |
| Persistence check permission error | Sub-check skipped, `log_line` warning |
| Cancel during any stage | DB status → "cancelled", pipeline halts |
| Unexpected exception in any stage | `except Exception` in `run()` → DB "failed" + `scan_failed` |

---

## Testing

### `tests/test_incident_worker.py`
- Stage 1: file not found → `scan_failed`; SSH brute force fixture → finding emitted + written to DB; format detection returns correct tag
- Stage 2: YARA match on fixture file → finding emitted; YARA import error → stage skipped gracefully; no matches → count 0
- Stage 3: fake crontab mtime within 7 days → finding emitted; `authorized_keys` with 2 keys → finding emitted; unexpected SUID binary → finding emitted
- Cancel mid-scan → DB status "cancelled"

### `tests/test_breach_timeline.py`
- `add_event` × 1 → row count 1
- `add_event` × 3 → rows in insertion order
- `reset()` → row count 0

### Regression
- All 283 existing tests pass after `log_analyzer.py` deletion and `scan_view.py` import update
