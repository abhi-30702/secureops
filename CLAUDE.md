# SecureOps — Claude Code Instructions

**Owner:** Abhishek K — the organisation internal security team
**Platform:** Kali Linux (native desktop app)
**Stack:** PyQt6 + pyqtgraph + SQLite + ReportLab + Python subprocess wrappers
**Status:** All 11 phases complete (399 tests passing). Now in **post-phase polish** —
feature adds + a UI overhaul. See "Recent work" below.
**UI design system:** light "Graphite" black-and-white theme — flat/minimal depth,
graphite `#18181B` accent, flattened morphism library — see `STYLE_GUIDE.md` and
`screens/widgets/morphism.py`.

---

## What this project is

A standalone PyQt6 desktop penetration-testing and security-audit platform for Kali Linux.
It scans companies you register — external web, internal LAN, OSINT, and incident
response — all from one interface. Findings stream into a live report as scanning runs.
When the scan finishes, the view settles into a professional PDF-exportable report.

**Project documentation:** `DOCUMENTATIONCLAUDE.md` — read it for full context before any session.

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

5. **Never log or print secrets (e.g. the AI Advisor API key).** Store them in
   config only. Strip from all scan output.

6. **AI Advisor is opt-in, OFF by default.** Never send data externally without an
   explicit consent confirmation from the user in the UI.

7. **Test before moving to the next phase.** Each phase must run without errors on
   Kali before Phase N+1 begins.

---

## Project structure (actual layout on disk)

```
secureops/                         # repo root — on disk at /home/kaelix/Desktop/secureops
├── main.py                        # App entry point
├── main_window.py                 # Frameless MainWindow: RootBackground + glass TitleBar + QStackedWidget
├── sidebar.py                     # Sidebar navigation widget (glass)
├── status_bar.py                  # Tool-status bar + StatusLED (Tools n/n)
├── app.py                         # QApplication + global QSS (COOL_QSS, @TOKEN@ substitution)
├── db.py                          # SQLite schema + DB class
├── models.py                      # Client, Scan, Host, Finding, Schedule dataclasses
├── tool_checker.py                # Startup tool verification
├── workers/                       # QThread workers
│   ├── scan_worker.py             # External pipeline (subfinder→nuclei + nmap/nikto/testssl); bare IP skips subdomain enum
│   ├── batch_scan_worker.py       # Sequential multi-company scan
│   ├── internal_worker.py         # Phase 4 — subnet sweep + device fingerprint
│   ├── incident_worker.py         # Phase 5 — incident response
│   ├── osint_worker.py            # Phase 6 — theHarvester
│   ├── delta_worker.py            # Phase 9 — delta alerts between scans
│   ├── log_analyzer.py            # Log analysis worker (format detect, rules, AI enrichment)
│   ├── log_rules.py               # LogRule dataclass + RULES (auth/nginx/apache/firewall/syslog/windows)
│   ├── base_tool.py               # Shared subprocess helper (ToolRunner + cancel)
│   └── tools/                     # One file per tool — run() → list[dict]
│       ├── subfinder.py  dnsx.py  naabu.py  httpx.py  katana.py  nuclei.py
│       ├── nmap.py  nikto.py  testssl.py  theharvester.py
│       └── yara_scanner.py  persistence_checker.py
├── screens/                       # One QWidget per screen (8 in the QStackedWidget)
│   ├── dashboard.py               # SOC live monitoring (metrics, threat feed, schedule, delta)
│   ├── client_onboarding.py       # Company registration
│   ├── scan_view.py               # Live scan + log analysis (3 modes: Scan Target / Scan IP / Analyse Logs)
│   ├── report.py                  # Settled report + PDF export
│   ├── settings.py                # Tool paths, API keys, scan config
│   ├── internal_page.py           # Phase 4
│   ├── incident_page.py           # Phase 5
│   ├── osint_page.py              # Phase 6
│   └── widgets/                   # Reusable visual components
│       ├── theme.py               # ★ design tokens (light Graphite B&W + morphism scales) — SOURCE OF TRUTH
│       ├── morphism.py            # ★ morphism widget library (glass/neu/clay/skeu — flattened for light theme)
│       ├── components.py          # PageHeader, GlassCard/Card, StatCard(=ClayStatTile), Badge, buttons
│       ├── severity_rings.py      # Severity column (ClaySeverityCard rows)
│       ├── finding_cards.py       # Streaming finding cards
│       ├── pipeline_tracker.py    # Tool pipeline status nodes
│       ├── attack_graph.py        # Attack-surface graph
│       ├── topology_graph.py      # Internal topology map
│       ├── threat_feed.py         # SOC threat feed
│       ├── breach_timeline.py     # Incident breach timeline
│       ├── company_selector.py    # Company dropdown
│       ├── schedule_panel.py      # Scan scheduling panel
│       └── delta_panel.py         # Delta-alert panel
├── report/pdf_generator.py        # ReportLab PDF export (own LIGHT palette — decoupled from theme)
├── advisor/                       # AI Advisor: gemini_client.py, ollama_client.py, prompt_builder.py, worker.py
├── scheduler/schedule_manager.py  # Scan scheduling
├── packaging/                     # .deb DEBIAN control files
├── docs/                          # Design specs + implementation plans
├── tests/                         # pytest suite (399 passing)
├── STYLE_GUIDE.md                 # ★ morphism roles + token reference
├── build.sh · secureops.spec · requirements.txt · THIRD-PARTY-LICENSES
└── Error/ · Non-Error/ · Huge-Logs/  # UNTRACKED test-log fixtures (see Recent work)
```

---

## Build phases — build in this order, one at a time

| Phase | What to build | Status |
|-------|--------------|--------|
| **1** | main.py entry point, MainWindow, dark QSS theme, sidebar navigation, QStackedWidget page shell, startup tool checker with clear error messages | ✅ Done |
| **2** | All tool wrappers (workers/tools/*.py), ScanWorker QThread, chained external pipeline (subfinder→dnsx→naabu→httpx→katana→nuclei + nmap/nikto/testssl), SQLite schema + db.py | ✅ Done |
| **3** | Live visuals: PipelineTracker widget, SeverityRings widget, attack_graph widget, FindingCards widget, ScanView page wiring it all together | ✅ Done |
| **4** | InternalWorker + nmap for subnet sweep, device fingerprinting, topology map in attack_graph, InternalPage UI | ✅ Done |
| **5** | IncidentWorker, LogAnalyser (dedicated incident_page.py), YaraScanner, persistence checker, breach timeline | ✅ Done (incident_page, yara_scanner, persistence_checker, breach_timeline; breach timeline in PDF) |
| **6** | OsintWorker (theHarvester), OsintPage | ✅ Done (OSINT page + worker; OSINT section in PDF) |
| **7** | Multi-target: 9-company registry in client_onboarding.py, sequential/parallel scan orchestration, per-company + consolidated findings | ✅ Done (sequential BatchScanWorker, consolidated PDF + cross-company correlation; parallel mode deferred per PRD §12) |
| **8** | ReportPage settled view, ReportLab PDF export (light corporate theme), per-company sections | ✅ Done |
| **9** | SOC dashboard: live metrics, scheduling, delta alerts between scans | ✅ Done (metrics inc. Incidents card, schedule add/delete, DeltaWorker delta alerts) |
| **10** | AI Advisor: advisor/worker.py, consent flow UI, Ollama local option, labelled output | ✅ Done (Gemini + Ollama, backend-aware consent flow, redaction option) |
| **11** | PyInstaller spec, .deb + .AppImage build, bundled binaries, THIRD-PARTY-LICENSES | ✅ Done (build.sh, secureops.spec) |

**Current status: all 11 phases complete.** Test suite: **399 passing**.
Work is now post-phase polish (see "Recent work"), not phase-gated.

---

## Recent work (post-phase — 2026-07)

Not phase-gated; these are feature/UX changes on top of the completed 11 phases.

- **Single-IP scan mode** — a third toggle in `scan_view.py` ("Scan IP") that validates
  an IPv4/IPv6 and reuses `ScanWorker` (which already skips subdomain enum for a bare IP).
  *Committed* (`6f29d89`).
- **Live scan indicators** — `scan_view.py` shows an elapsed ⏱ timer, a pulsing dot, and an
  indeterminate busy bar while any scan/log analysis runs (start/stop on complete/fail/batch).
- **Windows log rules** — `log_rules.py` detects the `windows` format (EventID=NNNN) and adds
  5 rules (4625 brute-force, 4771 Kerberos, 4720 account created, 4732/4728/4756 admin-group,
  4624 Type-10 RDP); two are IP-aggregating count-rules in `log_analyzer.py`. *Uncommitted.*
- **Test-log corpus (untracked):** `Error/` (compromised) + `Non-Error/` (clean baseline),
  10 files × 12k lines; `Huge-Logs/` = 2 large nginx logs (~20s and ~40–50s scans) for
  exercising the live timer. Do not commit these.
- **UI overhaul** — started as a dark multi-morphism pass, then re-scoped to a clean
  light **"Graphite" black-and-white** theme (`theme.py`) with flat/minimal depth. The
  `morphism.py` widget library is retained but flattened (hairline borders, whisper
  shadows — no glows/gradients); frameless window + flat `TitleBar` + light `RootBackground`
  (`main_window.py`), global QSS (`app.py`), and `STYLE_GUIDE.md`. Console stays dark. First
  pass done, 399 tests green, **uncommitted** (awaiting approval to commit).

Always confirm what we're working on at the start of each session.

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

## Theme & UI design system (never hardcode colours — use tokens)

**Source of truth:** `screens/widgets/theme.py` (tokens) + `screens/widgets/morphism.py`
(widgets) + `STYLE_GUIDE.md` (roles). Global QSS is built in `app.py` from `@TOKEN@`
substitution and exported as `COOL_QSS`.

**"Graphite" light palette** (current values — always import, never inline a hex):

```python
# screens/widgets/theme.py — key tokens (names are stable; values may retune)
BG "#F7F7F9"  BG_ALT "#EFEFF2"  CARD "#FFFFFF"  INPUT  HOVER  # near-white base + white cards
ACCENT "#18181B"  ACCENT_H "#2E2E33"  ACCENT_D "#0A0A0C"      # graphite accent (flat, no glow)
ACCENT_SOFT "#ECECEF"  ACCENT_GLOW (compat)  WARM             # tinted grey chips
TXT "#111114"  TXT2  TXT3 "#71717A"  BORDER "#E4E4E7"  BORDER_STRONG  FOCUS  # near-black text/hairlines (WCAG-AA on white)
CRITICAL HIGH MEDIUM LOW INFO SUCCESS                       # severity — PRESERVED (red/orange/amber/blue)
TERMINAL_BG "#0E0E11"  TERMINAL_TXT  FONT_SANS FONT_MONO    # console stays dark + fonts
# scales: SP_* (4pt) · RADIUS_SM/MD/LG/CLAY/PILL · FS_* · ELEVATION presets (flattened) · glass/neu/clay tokens
```

**Morphism → semantic role (do not mix):**
- **Glass** = structure/surfaces → `GlassPanel`, `GlassCard`, `TitleBar`, `#card`/`#panel`/`#sidebar`.
- **Neu** = interactive controls → `NeuButton`, `NeuLineEdit` (scan mode toggles, inputs).
- **Clay** = data callouts → `ClayStatTile`(=`StatCard`), `ClaySeverityCard`, `SeverityBadge`, `Badge`.
- **Skeu** = physical elements → `TerminalOutput`, `ToggleSwitch`, `StatusLED`, padlock brand, `RootBackground` mesh.

**QSS reality:** Qt QSS ignores `backdrop-filter`/`box-shadow`, and `QGraphicsDropShadowEffect`
is single-shadow only. So depth is *painted* — `paint_neu()` (dual/inset), `_paint_clay()`,
`_soft_shadow()` (layered-rect fake blur), mesh `paintEvent`. Reuse `ELEVATION` presets via
`apply_elevation()`; don't stack a fresh shadow per child (perf).

**PDF export keeps its own light palette** (`report/pdf_generator.py` hardcodes hex) — the dark
theme flip must not touch it.

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
-- Registered companies (Phase 7)
CREATE TABLE companies (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    domains TEXT,          -- JSON array
    ip_ranges TEXT,        -- JSON array e.g. ["192.168.1.0/24"]
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

Repo lives at `/home/kaelix/Desktop/secureops`. **No venv is active** — system Python 3.13
with packages installed via `pip --break-system-packages` (PyQt6, pyqtgraph, reportlab,
yara-python, python-nmap, pytest-qt, …).

```bash
cd /home/kaelix/Desktop/secureops

# Run the GUI — DISPLAY varies per boot; check the X socket, don't assume.
ls /tmp/.X11-unix/            # e.g. X0 → :0
DISPLAY=:0 python3 main.py

# Run the test suite headless
QT_QPA_PLATFORM=offscreen python3 -m pytest -q      # 399 passing

# Safely kill a running app (avoid pkill matching the tool's own shell)
pgrep -f "[m]ain.py" | xargs -r kill
```

Modules are top-level (no `secureops.` package prefix), e.g. `python3 -c "import screens.scan_view"`.
`sudo` password is `kaelix` (NOT passwordless).

---

## Key constraints — remind Claude Code of these every session

- **PyQt6 only** — not PySide6, not PyQt5
- **QThread for everything async** — no asyncio, no threading.Thread
- **One tool wrapper per file** — each exposes a single `run()` function returning `list[dict]`
- **All findings go to SQLite first** — UI reads from DB via signals, not directly from tool output
- **No root assumed** — default to non-privileged scan modes; prompt only when required
- **Multi-company** — the registry is empty by default (post-rescope: no Cloud, no Fidelitus);
  every feature must still handle multiple registered companies cleanly
- **Scope: the organisation internal use** — no exploitation, strictly detection + reporting

---

## Start of every Claude Code session — checklist

1. Confirm what we're working on (phases are done; likely a feature/UX task or the UI overhaul)
2. Run the tool verification loop above to confirm the environment
3. Read existing files (esp. `theme.py`, `morphism.py`, `STYLE_GUIDE.md`) before writing new ones
4. After writing each file, run `python3 -c "import <module>"` (top-level, e.g. `screens.scan_view`) to verify imports
5. Run `QT_QPA_PLATFORM=offscreen python3 -m pytest -q` — keep 399 green
6. Relaunch `DISPLAY=:0 python3 main.py` and confirm it launches cleanly before wrapping up
7. **Commit only when the user asks.** Much current work is intentionally uncommitted.

---

*SecureOps · Owner: Abhishek K · the organisation · Kali Linux*
