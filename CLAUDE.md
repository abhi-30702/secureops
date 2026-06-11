# SecureOps — Claude Code Instructions

**Owner:** Abhishek K — Fidelitus Corp internal security team
**Platform:** Kali Linux (native desktop app)
**Stack:** PyQt6 + pyqtgraph + SQLite + ReportLab + Python subprocess wrappers
**Status:** Building Phase by Phase — do not skip phases or build ahead

---

## What this project is

A standalone PyQt6 desktop penetration-testing and security-audit platform for Kali Linux.
It scans Fidelitus Corp's 9 subsidiary companies — external web, internal LAN, cloud (AWS/GCP),
OSINT, and incident response — all from one interface. Findings stream into a live report as
scanning runs. When the scan finishes, the view settles into a professional PDF-exportable report.

**Full PRD:** `SecureOps_PRD (1).md` — read it for full context before any session.

---

## Absolute rules — never break these

1. **UI never blocks.** Every scan, file read, and network call runs on a QThread worker.
   The main thread handles only UI. Use Qt signals to pass data back. No exceptions.

2. **Tool failures are isolated.** Each tool wrapper has its own try/except. One tool
   failing must never stop the pipeline or crash the app.

3. **Detection and reporting only.** No exploitation code, no payload generation,
   no credential attacks, no C2. If a feature crosses that line, refuse it.

4. **Findings write to SQLite immediately** — not at the end of a scan. Incremental
   persistence means a crash mid-scan loses nothing.

5. **Never log or print cloud credentials (AWS keys, GCP service accounts).** Store
   them in encrypted config only. Strip from all scan output.

6. **AI Advisor is opt-in, OFF by default.** Never send data externally without an
   explicit consent confirmation from the user in the UI.

7. **Test before moving to the next phase.** Each phase must run without errors on
   Kali before Phase N+1 begins.

---

## Project structure (actual layout on disk)

```
secureops/                         # repo root
├── main.py                        # App entry point
├── main_window.py                 # MainWindow + QStackedWidget
├── sidebar.py                     # Sidebar navigation widget
├── app.py                         # App-level wiring
├── db.py                          # SQLite schema + DB class
├── models.py                      # Client, Scan, Host, Finding, Schedule dataclasses
├── tool_checker.py                # Startup tool verification
├── workers/                       # QThread workers
│   ├── scan_worker.py             # External scan pipeline (subfinder→nuclei + nmap/nikto/testssl)
│   ├── log_analyzer.py            # Log analysis worker (format detect, rules, AI enrichment)
│   ├── log_rules.py               # LogRule dataclass + RULES list
│   ├── base_tool.py               # Shared subprocess helper
│   └── tools/                     # One file per tool — run() → list[dict]
│       ├── subfinder.py
│       ├── dnsx.py
│       ├── naabu.py
│       ├── httpx.py
│       ├── katana.py
│       ├── nuclei.py
│       ├── nmap.py
│       ├── nikto.py
│       └── testssl.py
├── screens/                       # One QWidget per screen
│   ├── scan_view.py               # Unified live scan + log analysis view
│   ├── report.py                  # Settled report + PDF export
│   ├── dashboard.py               # SOC live monitoring (partial)
│   ├── client_onboarding.py       # Client / company registration
│   ├── settings.py                # Tool paths, API keys, scan config
│   └── widgets/                   # Reusable visual components
│       ├── attack_graph.py        # Attack-surface + topology graph
│       ├── severity_rings.py      # Animated severity counters
│       ├── pipeline_tracker.py    # Tool pipeline status nodes
│       ├── finding_cards.py       # Streaming finding cards
│       └── threat_feed.py         # SOC threat feed
├── report/
│   └── pdf_generator.py           # ReportLab PDF export
├── advisor/                       # AI Advisor (Gemini / Ollama)
│   ├── gemini_client.py
│   ├── prompt_builder.py
│   └── worker.py
├── scheduler/                     # Scan scheduling
├── packaging/                     # .deb DEBIAN control files
├── docs/                          # Design specs + implementation plans
├── tests/                         # pytest test suite
├── build.sh                       # PyInstaller → .deb + .AppImage
├── secureops.spec                 # PyInstaller spec
├── requirements.txt
└── THIRD-PARTY-LICENSES

# Workers to add in upcoming phases:
# workers/internal_worker.py      Phase 4 — subnet sweep + device fingerprint
# workers/incident_worker.py      Phase 5 — YARA + persistence checker (promote log_analyzer)
# workers/cloud_worker.py         Phase 6 — AWS + GCP audit
# workers/osint_worker.py         Phase 6 — theHarvester
# screens/internal_page.py        Phase 4
# screens/incident_page.py        Phase 5
# screens/cloud_page.py           Phase 6
# screens/osint_page.py           Phase 6
# workers/tools/theharvester.py   Phase 6
# workers/tools/yara_scanner.py   Phase 5
# workers/tools/aws_auditor.py    Phase 6
# workers/tools/gcp_auditor.py    Phase 6
```

---

## Build phases — build in this order, one at a time

| Phase | What to build | Status |
|-------|--------------|--------|
| **1** | main.py entry point, MainWindow, dark QSS theme, sidebar navigation, QStackedWidget page shell, startup tool checker with clear error messages | ✅ Done |
| **2** | All tool wrappers (workers/tools/*.py), ScanWorker QThread, chained external pipeline (subfinder→dnsx→naabu→httpx→katana→nuclei + nmap/nikto/testssl), SQLite schema + db.py | ✅ Done |
| **3** | Live visuals: PipelineTracker widget, SeverityRings widget, attack_graph widget, FindingCards widget, ScanView page wiring it all together | ✅ Done |
| **4** | InternalWorker + nmap for subnet sweep, device fingerprinting, topology map in attack_graph, InternalPage UI | 🔲 **Current** |
| **5** | IncidentWorker, LogAnalyser (dedicated incident_page.py), YaraScanner, persistence checker, breach timeline | ⚠️ Partial (log_analyzer in scan_view; no incident_page, no YARA, no persistence checker) |
| **6** | CloudWorker (boto3 AWS + google-cloud GCP), OsintWorker (theHarvester), CloudPage, OsintPage | 🔲 Not started |
| **7** | Multi-target: 9-company registry in client_onboarding.py, sequential/parallel scan orchestration, per-company + consolidated findings | 🔲 Not started |
| **8** | ReportPage settled view, ReportLab PDF export (light corporate theme), per-company sections | ✅ Done |
| **9** | SOC dashboard: live metrics, scheduling, delta alerts between scans | ⚠️ Partial (dashboard.py shell exists) |
| **10** | AI Advisor: advisor/worker.py, consent flow UI, Ollama local option, labelled output | ⚠️ Partial (Gemini integration in advisor/) |
| **11** | PyInstaller spec, .deb + .AppImage build, bundled binaries, THIRD-PARTY-LICENSES | ✅ Done (build.sh, secureops.spec) |

**Current phase: Phase 4 — Internal Network Scanning**
Always confirm which phase we are on at the start of each session.

---

## Scanning tools — installed on Kali

All tools installed via the Kali setup guide. Verify with:
```bash
for t in subfinder dnsx naabu httpx katana nuclei nmap nikto theharvester; do
  printf "%-14s " "$t"; command -v $t || echo "MISSING"
done
```

| Tool | Command | Output format | Notes |
|------|---------|--------------|-------|
| subfinder | `subfinder -d <domain> -json` | JSON lines | |
| dnsx | `dnsx -l <file> -json` | JSON lines | Takes subfinder output |
| naabu | `naabu -host <host> -json` | JSON lines | CONNECT mode (no root) |
| httpx | `httpx -l <file> -json` | JSON lines | Takes naabu output |
| katana | `katana -u <url> -json` | JSON lines | Headless needs CGO |
| nuclei | `nuclei -l <file> -json` | JSON lines | Run last; use -severity |
| nmap | `nmap -sV -sC --open -oX -` | XML | Parse with python-nmap |
| nikto | `nikto -h <url> -Format json` | JSON | |
| testssl.sh | `testssl.sh --jsonfile /tmp/ssl.json <host>:443` | JSON file | |
| theHarvester | `theHarvester -d <domain> -b all -f /tmp/harvest.json` | JSON file | |

---

## Theme constants (always use these — never hardcode colours)

```python
# In secureops/widgets/theme.py
BG0    = "#020810"   # Deepest background
BG1    = "#060f1e"   # Card / panel background
BG2    = "#0a1628"   # Input fields
BG3    = "#0f1f35"   # Subtle containers
CYAN   = "#00e5ff"   # Primary accent
GREEN  = "#00ff88"   # Success / safe
AMBER  = "#ffb300"   # Warning
RED    = "#ff3d57"   # Critical / danger
TXT    = "#e2eaf4"   # Primary text
TXT2   = "#7a9bc4"   # Secondary text
TXT3   = "#3d5a7a"   # Muted text
BORDER = "#0d2440"   # Subtle border
MONO   = "Space Mono"
SANS   = "DM Sans"
```

---

## Qt signals every worker must emit

```python
# All workers inherit from QThread and emit these signals:
finding_discovered = pyqtSignal(dict)   # New finding → DB + graph + card
tool_progress      = pyqtSignal(str, int, str)  # tool_name, count, status
tool_log           = pyqtSignal(str)    # Raw output line → terminal
scan_complete      = pyqtSignal(dict)   # Summary dict → settle report view
error_occurred     = pyqtSignal(str, str)  # tool_name, error_message
```

---

## Database schema (SQLite — db.py)

The live schema is defined in `db.py`. The v2.0 PRD target schema (needed for Phases 4–7) adds `companies` and `incident_events`. When extending the DB for those phases, add columns/tables to the existing `_SCHEMA` string in `db.py`.

**Current tables (implemented):** `clients`, `scans`, `hosts`, `findings`, `schedules`, `advisory_items`, `app_settings`

**Target tables to add in Phase 4–7:**

```sql
-- Fidelitus Corp subsidiaries (Phase 7)
CREATE TABLE companies (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    domains TEXT,          -- JSON array
    ip_ranges TEXT,        -- JSON array e.g. ["192.168.1.0/24"]
    aws_profile TEXT,
    gcp_project TEXT,
    firewall_type TEXT,
    created_at TEXT
);

-- Incident events (Phase 5)
CREATE TABLE incident_events (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER,
    timestamp TEXT,
    event_type TEXT,       -- 'entry','lateral','persistence','exfil'
    source_host TEXT,
    dest_host TEXT,
    description TEXT,
    evidence TEXT
);
```

---

## Python environment

```bash
# Always activate before running
source ~/secureops/venv/bin/activate

# Install / verify
pip install PyQt6 pyqtgraph reportlab yara-python python-nmap \
            boto3 google-cloud-storage anthropic --break-system-packages

# Run the app
cd ~/secureops
python main.py
```

---

## Key constraints — remind Claude Code of these every session

- **PyQt6 only** — not PySide6, not PyQt5
- **QThread for everything async** — no asyncio, no threading.Thread
- **One tool wrapper per file** — each exposes a single `run()` function returning `list[dict]`
- **All findings go to SQLite first** — UI reads from DB via signals, not directly from tool output
- **No root assumed** — default to non-privileged scan modes; prompt only when required
- **9 companies in scope** — every feature must handle multi-company data cleanly
- **Scope: Fidelitus Corp internal use** — no exploitation, strictly detection + reporting

---

## Start of every Claude Code session — checklist

1. State which **Phase** we are building
2. Run the tool verification loop above to confirm the environment
3. Confirm the venv is activated
4. Read any existing files in the relevant phase before writing new ones
5. After writing each file, run `python -c "import secureops.<module>"` to verify no import errors
6. After completing a phase, run `python main.py` and confirm it launches cleanly before moving on

---

*SecureOps · Owner: Abhishek K · Fidelitus Corp · Kali Linux*
