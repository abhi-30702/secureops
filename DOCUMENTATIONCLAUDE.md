# SecureOps — Project Documentation (Source of Truth)

> **Purpose of this file.** This is the single, self-contained content source for the
> SecureOps project report. A Claude Code session reads this file and converts it into a
> formatted Microsoft Word (`.docx`) document by following `INSTRUCTIONDOCUMENT.md`.
> Do **not** invent facts beyond what is written here; everything below reflects the
> actual implemented system (PyQt6 desktop app, ~395 passing automated tests, 11 build
> phases complete). All diagrams are given in ASCII so they can be reproduced faithfully.

**Project:** SecureOps — A Unified Desktop Penetration-Testing, Incident-Response & Security-Audit Platform
**Organisation:** the organisation (internal security team) · **Platform:** Kali Linux · **Version:** 1.2

---

## Table of Contents

1. Abstract
2. Introduction (Problem, Description, Objectives, Scope)
3. Hardware and Software Requirements
4. Overview of Technologies Used
5. Proposed System
6. Feasibility Study (Technical / Economic / Operational)
7. System Design and Development (Architecture, ER Diagram, Threading & Persistence)
8. Detailed Design (DFD-1, DFD-2, Module Design)
9. Activity Diagram
10. Implementation and Coding (Language/Framework, Algorithmic Approach, Pseudocode, Code Snippets, Key Functionalities)
11. Software Testing (Strategies: Unit, Integration, System)
12. Results and Discussion (Experimental Setup, Hardware/Software Setup, Results)
13. Conclusion and Future Enhancements (Conclusion, Limitations, Future Scope)

---

## 1. Abstract

SecureOps is a standalone PyQt6 desktop application that consolidates the full
security-assessment lifecycle — external attack-surface scanning, internal network
discovery, OSINT harvesting, and incident-response investigation — into a single
operator interface for Kali Linux. It orchestrates an
industry-standard toolchain (subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto,
testssl.sh, theHarvester, YARA) through background `QThread` workers, persists every
finding to a local SQLite database the instant it is discovered, and assembles results
into a live, animated report that "settles" into a professional, ReportLab-generated PDF
on completion. Built to audit multiple registered companies from one console, it
supports multi-target orchestration with both per-company and consolidated cross-company
reporting, continuous SOC monitoring with scheduled re-scans and delta alerting, and an
opt-in AI Advisor (Google Gemini cloud or local Ollama) that produces plain-language,
defensive-only remediation guidance with consent and data-redaction safeguards. The
platform is strictly a **detection and reporting** tool — it contains no exploitation,
payload, or command-and-control capability — making it appropriate for authorised
internal use.

---

## 2. Introduction

### 2.1 Project Overview

#### 2.1.1 Statement of the Problem
a typical organisation operates several companies, each with public web domains and
internal LAN infrastructure (DMZ, firewalls, routers, switches, servers, end-user
devices). There is confirmed evidence of a breach: an attacker
compromised a firewall and subsequently a server, with malware potentially resident in
applications, operating systems, or network devices. The security team has **no unified
tool** to audit this full stack. Running each tool manually, correlating output by hand,
and authoring reports from scratch is slow, error-prone, and inconsistent — and breaches
go undetected between periodic audits.

#### 2.1.2 Brief Description of the Project
SecureOps is a single PyQt6 desktop application, running inside the organisation's network on
Kali Linux, that runs the complete external scan pipeline against all registered companies,
performs internal subnet discovery and device fingerprinting, conducts incident response
(log analysis, IOC/YARA scanning, breach-trail reconstruction, persistence detection),
harvests public OSINT, visualises the attack surface and network topology live, and
exports compliance-grade PDF reports.

#### 2.1.3 Objectives of the Project
1. Provide a unified single-screen experience where the scan view assembles into the report in real time.
2. Run the full external pipeline across all registered companies from one interface.
3. Discover and fingerprint internal hosts and map network topology.
4. Reconstruct breach timelines and detect IOCs and persistence mechanisms.
5. Harvest public OSINT across the registered companies.
6. Provide continuous SOC monitoring with scheduled re-scans and delta alerts.
7. Generate professional, ISO-27001-mapped PDF reports (per-company and consolidated).
8. Guarantee reliability: the UI never freezes; a single tool failure never crashes the app.
9. Offer an optional, opt-in, privacy-preserving AI Advisor for defensive guidance.

#### 2.1.4 Scope of the Project
**In scope:** detection, reconnaissance, incident-response analysis, and reporting for
authorised internal use across the registered companies; offline operation for core scanning;
local data storage. **Out of scope:** active exploitation, payload delivery, credential
attacks, command-and-control; multi-user or server deployment; Windows/macOS support;
offensive AI automation.

---

## 3. Hardware and Software Requirements

### 3.1 Hardware
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | Dual-core x86-64 | Quad-core x86-64 |
| RAM | 4 GB | 8 GB+ (large subnet/multi-company scans) |
| Storage | 2 GB free (binaries + SQLite DB) | 10 GB+ |
| Display | 1280×720 | 1920×1080 |
| Network | LAN access to targets | Wired LAN to internal segments |

### 3.2 Software
| Layer | Technology |
|-------|-----------|
| OS | Kali Linux (native) |
| Language | Python 3.11+ |
| GUI | PyQt6 |
| Charts/graphs | pyqtgraph |
| Database | SQLite (built-in `sqlite3`) |
| PDF | ReportLab |
| IOC scanning | yara-python |
| Internal scan | python-nmap / nmap |
| AI Advisor | Gemini SDK (cloud) **or** Ollama API (local) |
| Bundled CLI tools | subfinder, dnsx, naabu, httpx, katana, nuclei (ProjectDiscovery); nmap, nikto, testssl.sh, theHarvester (Kali-native) |
| Testing | pytest, pytest-qt (offscreen Qt platform) |
| Packaging | PyInstaller → `.deb` / `.AppImage` |

---

## 4. Overview of Technologies Used

- **PyQt6** — desktop framework; all async work runs on `QThread` workers communicating
  with the main thread via Qt signals (`finding_discovered`, `tool_progress`, `tool_log`,
  `scan_complete`, `error_occurred`).
- **pyqtgraph** — force-directed attack-surface graph and live network topology map
  (`GraphItem` + scatter plot).
- **SQLite** — local, file-based persistence; findings are written incrementally so a
  mid-scan crash loses nothing.
- **subprocess wrappers** — one wrapper per tool, each returning `list[dict]`, isolated by
  its own try/except so one tool failing never stops the pipeline.
- **ReportLab** — light, corporate PDF generation (executive summary, severity breakdown,
  findings, ISO-27001 gap table, breach timeline, OSINT, consolidated multi-company sections).
- **YARA** — IOC pattern matching against files/configs.
- **Gemini / Ollama** — optional AI enrichment; opt-in, OFF by default, with consent gating
  and an optional redaction pass.
- **A unified design system** — a single theme-token module (`screens/widgets/theme.py`)
  plus a global Qt stylesheet and reusable component widgets (`components.py`) give every
  screen consistent, accessible, modern styling (light corporate theme).

---

## 5. Proposed System

The proposed system replaces fragmented, manual tooling with an integrated orchestrator. A
user selects a target (single domain, subnet, log file, or "scan all companies"); the
appropriate `QThread` worker drives the relevant tool chain; findings
stream live into the database and the UI (pipeline tracker, severity rings,
attack/topology graph, streaming finding cards, terminal feed); on completion the view
settles into an exportable report. Continuous monitoring schedules re-scans and surfaces
deltas; the AI Advisor optionally interprets results.

**Key differentiators:** full-stack coverage (external + internal + OSINT + incident) in
one tool; live report assembly; signature animated attack-surface/topology graph;
multi-target orchestration with consolidated reporting; built-in incident response;
compliance-grade output; opt-in privacy-preserving AI Advisor; fully offline core
operation.

---

## 6. Feasibility Study

### 6.1 Technical Feasibility
All core technologies are mature, open-source, and proven on Kali. PyQt6's threading model
cleanly separates UI from blocking I/O; SQLite requires no server; the scanning tools are
already standard in the security domain. The architecture has been implemented and
validated across all eleven build phases with an automated test suite (~395 passing tests)
and verified headless launches. **Conclusion: technically feasible and demonstrated.**

### 6.2 Economic Feasibility
The stack is entirely free/open-source (no licensing cost). It runs on existing Kali
workstations — no new hardware or cloud spend for core operation. The only optional
recurring cost is the cloud AI Advisor (Gemini API usage), which is opt-in and avoidable
via the local Ollama backend. Development reuses in-house effort. **Conclusion:
economically feasible; near-zero marginal cost.**

### 6.3 Operational Feasibility
The tool targets a Kali-literate internal security team and consolidates workflows they
already perform manually, reducing effort and error. The unified UI, live feedback, and
one-click PDF export lower operational friction; startup tool-verification and actionable
error messages ease setup. Reports are designed for non-technical C-suite consumption.
Strict detection-only scope keeps it within organisational authorisation. **Conclusion:
operationally feasible and beneficial.**

---

## 7. System Design and Development

### 7.1 Architecture (layered)
```
┌──────────────────────────────────────────────────────────────┐
│  PRESENTATION (PyQt6 main thread)                              │
│  MainWindow · Sidebar · QStackedWidget                         │
│  Screens: Dashboard · Onboarding · ScanView · Internal ·       │
│           Incident · OSINT · Report · Settings                 │
│  Widgets: PipelineTracker · SeverityRings · AttackGraph ·      │
│           TopologyGraph · FindingCards · BreachTimeline        │
│  Design system: theme tokens · global QSS · components         │
└───────────────▲───────────────────────────────┬──────────────┘
                │ Qt signals (thread-safe)        │ user actions
┌───────────────┴───────────────────────────────▼──────────────┐
│  WORKER LAYER (QThread)                                         │
│  ScanWorker · InternalWorker · IncidentWorker · OsintWorker ·  │
│  BatchScanWorker · DeltaWorker · AdvisorWorker                 │
└───────────────▲───────────────────────────────┬──────────────┘
                │ run()→list[dict] (isolated)     │
┌───────────────┴──────────┐   ┌─────────────────▼──────────────┐
│  TOOL WRAPPERS            │   │  DATA LAYER                    │
│  subfinder dnsx naabu     │   │  db.py (SQLite)               │
│  httpx katana nuclei nmap │   │  models.py (dataclasses)      │
│  nikto testssl theHarv.   │   │  report/ (ReportLab PDF)      │
│  yara scanner             │   │  advisor/ (Gemini/Ollama)     │
└───────────────────────────┘   └────────────────────────────────┘
```

### 7.2 ER Diagram (text notation)
```
              ┌──────────────┐
              │   COMPANIES  │   (user-registered companies)
              │──────────────│
              │ PK id        │
              │ name         │
              │ domains[]    │
              │ ip_ranges[]  │
              │ firewall_type│
              └──────┬───────┘
                     │ 1
        client_id    │            ┌──────────────┐
                     │            │   CLIENTS    │
                     │            │ PK id        │
                     │            │ name/domain  │
                     │            │ firewall     │
                     │            └──────┬───────┘
                     │                   │ 1
                     ▼  N                ▼  N
              ┌────────────────────────────────┐
              │            SCANS               │
              │────────────────────────────────│
              │ PK id                          │
              │ FK client_id (→clients/companies)
              │ target · status                │
              │ started_at · finished_at       │
              └───┬───────────┬────────────┬───┘
              1   │       1   │        1   │
          N       ▼      N    ▼      N     ▼
   ┌──────────┐ ┌──────────────┐ ┌────────────────┐ ┌──────────────┐
   │  HOSTS   │ │   FINDINGS   │ │ INCIDENT_EVENTS│ │ OSINT_ITEMS  │
   │──────────│ │──────────────│ │────────────────│ │──────────────│
   │ PK id    │ │ PK id        │ │ PK id          │ │ PK id        │
   │ FK scan  │ │ FK scan_id   │ │ FK scan_id     │ │ FK scan_id   │
   │ subdomain│ │ FK host_id ──┼─┤ timestamp      │ │ domain       │
   │ ip/port  │ │ tool         │ │ event_type     │ │ item_type    │
   │ service  │ │ severity     │ │ source/dest    │ │ value        │
   │ url      │ │ title/desc   │ │ description    │ │ source       │
   └──────────┘ │ raw_json     │ │ evidence       │ └──────────────┘
        ▲       └──────┬───────┘ └────────────────┘
        │ host_id      │ 1
        └──────────────┘ ▼ N
                  ┌──────────────────┐      ┌──────────────┐   ┌──────────────┐
                  │ ADVISORY_ITEMS   │      │  SCHEDULES   │   │ APP_SETTINGS │
                  │──────────────────│      │──────────────│   │──────────────│
                  │ PK id            │      │ PK id        │   │ PK key       │
                  │ FK scan_id       │      │ target(uniq) │   │ value        │
                  │ tier             │      │ interval_h   │   └──────────────┘
                  │ text · accepted  │      │ enabled      │
                  └──────────────────┘      │ last_run     │
                                            └──────────────┘
```
**Relationships:** A company/client has many scans (1:N). A scan has many hosts, findings,
incident_events, and osint_items (1:N). A host has many findings (1:N, via `host_id`). A
scan has many advisory_items (1:N). Schedules and app_settings are standalone
configuration tables.

### 7.3 Threading & Persistence Model
Every scan runs on a dedicated `QThread`. Workers never touch widgets directly; they emit
signals consumed on the main thread. Each tool wrapper is wrapped in try/except (failure
isolation). Findings are inserted into SQLite the moment they are parsed, then emitted to
the UI — guaranteeing crash-safe incremental persistence.

---

## 8. Detailed Design

### 8.1 Data Flow Diagram — Level 1 (DFD-1): External Scan Pipeline
```
                       ┌─────────────┐
   target domain ─────▶│  1.0        │
   (user input)        │  Validate & │────▶ scans row ──▶ [D1 SQLite: scans]
                       │  Init Scan  │
                       └──────┬──────┘
                              │ scan_id, target
                              ▼
                       ┌─────────────┐
                       │  2.0        │   subfinder → dnsx → naabu →
                       │  Run        │   httpx → katana → nuclei
                       │  Pipeline   │   (+ nmap / nikto / testssl
                       │  (QThread)  │      on live hosts)
                       └──┬───────┬──┘
              hosts/      │       │  findings (parsed dict)
              subdomains  │       │
                          ▼       ▼
        [D2 hosts] ◀──────┤       ├──────▶ [D3 findings]
                          │       │
                          ▼       ▼
                       ┌─────────────┐
                       │  3.0        │  finding_discovered,
                       │  Stream to  │  tool_progress, tool_log
                       │  UI (signals)│
                       └──────┬──────┘
                              ▼
              ┌───────────────────────────────┐
              │ Pipeline tracker · severity    │
              │ rings · attack graph · cards · │
              │ terminal feed                  │
              └──────┬─────────────────────────┘
                     │ scan_complete
                     ▼
              ┌─────────────┐
              │  4.0        │
              │  Settle &   │──▶ ReportLab ──▶ PDF file
              │  Export     │
              └─────────────┘
```

### 8.2 Data Flow Diagram — Level 2 (DFD-2): Incident-Response Sub-Process (Process 2.0 expanded)
```
   log file + target host
          │
          ▼
   ┌──────────────┐   parsed timeline events
   │ 2.1 Parse &  │──────────────────────────▶ [D4 incident_events]
   │ Detect Format│
   └──────┬───────┘
          │ lines, format
          ▼
   ┌──────────────┐   rule hits (severity, title)
   │ 2.2 Apply    │──────────────────────────▶ [D3 findings]
   │ Log Rules    │
   └──────┬───────┘
          ▼
   ┌──────────────┐   IOC matches (file, rule)
   │ 2.3 YARA     │──────────────────────────▶ [D3 findings] + [D4 events]
   │ IOC Scan     │
   └──────┬───────┘
          ▼
   ┌──────────────┐   cron/authkeys/SUID anomalies
   │ 2.4 Persist. │──────────────────────────▶ [D3 findings] + [D4 events]
   │ Checker      │
   └──────┬───────┘
          ▼
   ┌──────────────┐   (optional, opt-in + consent)
   │ 2.5 AI       │──────────────────────────▶ [D5 advisory_items]
   │ Enrichment   │   (redaction pass if enabled)
   └──────┬───────┘
          ▼
   finding_found / log_line / scan_complete  ──▶ Breach Timeline + Finding Cards
```

### 8.3 Detailed Module Design (selected)
- **ScanWorker** — chained external pipeline; per-tool isolation; emits standard signals.
- **InternalWorker** — Stage 1 nmap ping sweep → live IPs; Stage 2 service scan → device
  fingerprinting (router/workstation/printer/IoT/server by open-port heuristics); feeds TopologyGraph.
- **IncidentWorker** — three-stage log analysis + YARA + persistence checks (DFD-2 above).
- **OsintWorker / BatchScanWorker / DeltaWorker** — OSINT harvesting; sequential
  multi-company orchestration with consolidated reporting; new/resolved finding deltas vs.
  previous scan.
- **AdvisorWorker** — backend-aware (Gemini/Ollama); tiered output
  (immediate/short-term/preventive); consent + optional redaction of company names,
  hostnames, IPs.

---

## 9. Activity Diagram — End-to-End Scan & Report

```
        ( Start )
            │
            ▼
   [Launch app] ──▶ <Tool checker: all present?>
            │                 │ No
            │ Yes             ▼
            │        [Show actionable warning / Settings]
            ▼
   [Select mode / target]
            │
            ▼
   <Mode?>──────────────────────────────────────────────┐
   │ External   │ Internal   │ Incident   │ OSINT      │ Multi-company
   ▼            ▼            ▼            ▼            ▼
 [Run        [Subnet      [Load logs   [Run the-    [For each company:
  pipeline]   sweep +      + YARA +     Harvester]   run pipeline]
              fingerprint] persistence]
   │            │            │            │            │
   └────────────┴─────┬──────┴────────────┴────────────┘
                      ▼
            ┌───────────────────────────┐
            │  FORK (concurrent)         │
            │  ├─ Write finding→SQLite   │  ◀── every finding, immediately
            │  └─ Emit signal→UI update  │
            └─────────────┬─────────────┘
                          │  (loop until tools finish)
                          ▼
              <Any tool error?> ──Yes──▶ [Log + isolate; continue] ─┐
                          │ No                                      │
                          ◀──────────────────────────────────────────┘
                          ▼
                   [scan_complete: settle view]
                          │
                          ▼
              <AI Advisor enabled & opted-in?>
                   │ Yes                    │ No
                   ▼                        │
        [Show consent notice]               │
              │                             │
        <User confirms?>──No────────────────┤
              │ Yes                          │
              ▼                              │
        [Redact (if on) → call backend       │
         → store advisory_items]             │
              │                              │
              └──────────────┬───────────────┘
                             ▼
                   [Enable PDF export]
                             │
                             ▼
                <Export requested?>──Yes──▶ [Generate ReportLab PDF
                             │                (per-company / consolidated)]
                             │ No                      │
                             ▼                         ▼
                        ( End ) ◀──────────────────────┘
```

---

## 10. Implementation and Coding

### 10.1 Programming Language and Framework
- **Language:** Python 3.11+ (developed and tested on Python 3.13, Kali Linux).
- **GUI framework:** PyQt6 (chosen over PySide6/PyQt5 for native Qt6 widgets and licensing
  clarity). The UI runs on the main thread only; every blocking operation is delegated to a
  `QThread` worker.
- **Concurrency model:** Qt's `QThread` + signals/slots — chosen over `asyncio` or raw
  `threading.Thread` because Qt signals are inherently thread-safe for marshalling data back
  to the GUI thread.
- **Persistence:** Python's built-in `sqlite3` (no external DB server).
- **Reporting:** ReportLab (programmatic PDF) — light corporate theme.
- **Supporting libraries:** pyqtgraph (graphs), yara-python (IOC), python-nmap/nmap
  (internal scan), Gemini/Ollama clients (AI Advisor).
- **Testing:** pytest + pytest-qt (with `QT_QPA_PLATFORM=offscreen` for headless CI).
- **Packaging:** PyInstaller → `.deb` / `.AppImage`.

### 10.2 Algorithmic Approach

The system is built around five core algorithms. Each is presented below as pseudocode.

#### 10.2.1 Chained External Scan Pipeline
The external pipeline feeds each tool's output into the next, isolating every tool so one
failure cannot abort the chain, and persisting findings as they appear.

```
ALGORITHM ExternalPipeline(target, scan_id, db)
    runner ← ToolRunner(cancel_event)
    subdomains ← isolate( subfinder.run(target) )        # returns [] on failure
    resolved   ← isolate( dnsx.run(subdomains) )
    open_ports ← isolate( naabu.run(resolved) )
    live_urls  ← isolate( httpx.run(open_ports) )
    endpoints  ← isolate( katana.run(live_urls) )
    FOR each url IN live_urls:                            # depth scanners
        isolate( nmap.run(url) ); isolate( nikto.run(url) ); isolate( testssl.run(url) )
    findings   ← isolate( nuclei.run(live_urls + endpoints) )
    FOR each f IN all_parsed_findings:
        db.insert_finding(f)        # persist immediately
        EMIT finding_discovered(f)  # update UI
    EMIT scan_complete(summary)

FUNCTION isolate(call)              # Absolute Rule #2: failure isolation
    TRY: RETURN call()
    EXCEPT ToolError as e: EMIT error_occurred(tool, e); RETURN []
```

#### 10.2.2 Internal Sweep + Device Fingerprinting
Two nmap stages; devices are classified from their open-port signature with a fixed
priority order.

```
ALGORITHM InternalSweep(subnets, scan_id, db)
    live_ips ← parse_xml( nmap("-sn -T4 -oX -", subnets) )      # Stage 1: ping sweep
    IF live_ips is empty: EMIT scan_complete(0,0); RETURN
    xml ← nmap("-sV -T4 --open -oX -", live_ips)                # Stage 2: service scan
    FOR each host IN parse_xml(xml):
        open_ports ← collect open <port> ids
        device_type ← Classify(open_ports)
        f ← Finding(tool="nmap-internal", severity="info",
                    title=device_type + " — " + host.ip,
                    description="Open ports: " + join(open_ports))
        db.insert_finding(f); EMIT finding_found(f)             # → TopologyGraph

FUNCTION Classify(ports)            # first matching class wins (priority order)
    IF ports ∩ {53,23,179}   ≠ ∅: RETURN "router"
    IF ports ∩ {3389,445}    ≠ ∅: RETURN "workstation"
    IF ports ∩ {515,631,9100}≠ ∅: RETURN "printer"
    IF ports ∩ {1883,8883,102}≠∅: RETURN "iot"
    IF ports ∩ {80,443,22,8080,8443}≠∅: RETURN "server"
    RETURN "unknown"
```

#### 10.2.3 Delta Detection (SOC Monitoring)
Compares the current scan against the previous completed scan of the same target.

```
ALGORITHM DeltaDetect(scan_id, db)
    target ← db.target_of(scan_id)
    curr   ← { (f.tool, f.title, f.description) for f in db.findings(scan_id) }
    prev_id← db.previous_complete_scan(target, before=scan_id)
    IF prev_id is NULL: EMIT delta_ready(target, |curr|, 0); RETURN
    prev   ← { (f.tool, f.title, f.description) for f in db.findings(prev_id) }
    new      ← | curr − prev |       # appeared since last scan
    resolved ← | prev − curr |       # fixed since last scan
    EMIT delta_ready(target, new, resolved)
```

#### 10.2.4 Cross-Company Correlation (Consolidated Report)
Surfaces weaknesses shared by two or more companies.

```
ALGORITHM Correlate(per_company)        # per_company = list of (name, findings)
    groups ← {}                         # key → {title, worst_severity, companies:set}
    FOR each (name, findings) IN per_company:
        FOR each f IN findings:
            key ← normalize(f.title)    # strip " — host" suffix, lowercase
            g ← groups[key] (create if absent)
            g.companies.add(name)
            g.severity ← worse_of(g.severity, f.severity)
    shared ← [ g FOR g IN groups IF |g.companies| ≥ 2 ]
    SORT shared BY (descending company-count, title)
    RETURN shared
```

#### 10.2.5 AI Advisor Redaction (Privacy Safeguard)
Strips identifying data before it leaves the machine; order matters (hostnames before bare IPs).

```
ALGORITHM Redact(text, hosts, client, target)
    identifiers ← [h.subdomain for h in hosts] + [target]
    FOR ident IN sort(identifiers, by_length_desc):     # longest first
        text ← replace(text, ident, "[HOST]")
    IF client.name: text ← replace_caseless(text, client.name, "[COMPANY]")
    text ← regex_replace(text, IPv4_PATTERN, "[IP]")
    RETURN text
```

### 10.3 Code Snippets and Explanation

#### 10.3.1 Crash-safe streaming subprocess runner (`workers/base_tool.py`)
The shared `ToolRunner` drains stderr on a background thread (so a chatty tool can't
deadlock the stdout pipe) and uses a watchdog timer to kill a stalled tool. This is the
backbone of Absolute Rule #1 (UI never blocks) and #2 (failures isolated).

```python
def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
    if self._cancel.is_set():
        raise CancelledError()
    resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
    try:
        proc = subprocess.Popen(resolved, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError:
        raise ToolError(f"{cmd[0]}: not found")

    # Drain stderr on a thread so the OS pipe buffer can never fill and deadlock.
    stderr_chunks: list[str] = []
    def _drain_stderr():
        for err_line in proc.stderr: stderr_chunks.append(err_line)
    threading.Thread(target=_drain_stderr, daemon=True).start()

    # Watchdog: kill a tool that stalls with no output past `timeout`.
    timed_out = threading.Event()
    timer = threading.Timer(timeout, lambda: (timed_out.set(), proc.kill()))
    timer.start()
    try:
        for line in proc.stdout:
            if self._cancel.is_set():
                proc.kill(); proc.wait(); raise CancelledError()
            if line.rstrip(): yield line.rstrip()
    finally:
        timer.cancel(); proc.wait()
    if timed_out.is_set():
        raise ToolError(f"{cmd[0]}: timed out after {timeout}s")
```

#### 10.3.2 Device fingerprinting by port signature (`workers/internal_worker.py`)
```python
_ROUTER_PORTS      = {53, 23, 179}
_WORKSTATION_PORTS = {3389, 445}
_PRINTER_PORTS     = {515, 631, 9100}
_IOT_PORTS         = {1883, 8883, 102}
_SERVER_PORTS      = {80, 443, 22, 8080, 8443}

def _classify_device(ports: list[int]) -> str:
    port_set = set(ports)
    if port_set & _ROUTER_PORTS:      return "router"
    if port_set & _WORKSTATION_PORTS: return "workstation"
    if port_set & _PRINTER_PORTS:     return "printer"
    if port_set & _IOT_PORTS:         return "iot"
    if port_set & _SERVER_PORTS:      return "server"
    return "unknown"
```
**Explanation:** classification is deterministic and order-sensitive — a host exposing both
`53` (DNS) and `80` (HTTP) is classified as a *router* because routing/infra ports take
priority over generic web ports. This avoids mislabelling network gear as servers.

#### 10.3.3 Incremental persistence + UI signal (worker pattern)
```python
finding = Finding(id=None, scan_id=self._scan_id, host_id=None,
                  tool="nmap-internal", severity="info",
                  title=f"{device_type} — {ip}",
                  description=f"Open ports: {ports_str}",
                  raw_json="", created_at=datetime.now(timezone.utc).isoformat())
finding.id = self._db.insert_finding(finding)   # persist FIRST (crash-safe)
self.finding_found.emit(finding)                 # THEN update the UI
```
**Explanation:** the database write precedes the UI signal so that a crash between the two
never loses a discovered finding (Absolute Rule #4).

#### 10.3.4 Backend-aware AI Advisor with consent (`screens/report.py` + `advisor/worker.py`)
```python
backend = db.get_setting("advisor_backend") or "gemini"
redact  = db.get_setting("advisor_redact") == "1"
if backend == "ollama":
    # Local model — nothing leaves the machine, so no external-transmission consent.
    confirm("Run local AI Advisor?", "Analysed locally by Ollama. No data leaves your machine.")
else:
    # Cloud model — explicit consent, with redaction state disclosed.
    confirm("Send data to Gemini?", "Findings will be sent to Google Gemini …"
            + ("Identifying details will be redacted." if redact else "… will leave your machine."))
```
**Explanation:** the consent dialog is *backend-aware* — the local Ollama path correctly
states that no data leaves the machine, satisfying FR-52/FR-54, while the cloud path
discloses whether redaction is active.

### 10.4 Key Functionalities
1. **Unified scan view** — pipeline tracker, severity rings, animated attack-surface graph,
   streaming finding cards, and a live terminal feed, all updating in real time.
2. **External pipeline** — subfinder → dnsx → naabu → httpx → katana → nuclei, with
   nmap/nikto/testssl on live hosts.
3. **Internal network module** — subnet sweep, device fingerprinting, live topology map.
4. **Incident response** — log-format detection, rule-based timeline reconstruction, YARA
   IOC scanning, and persistence checks (cron, authorized_keys, SUID).
5. **OSINT** — theHarvester-driven harvesting of emails, subdomains, IPs, and URLs.
6. **Multi-company orchestration** — sequential scanning of all registered companies with
   per-company isolation and a consolidated cross-company report + correlation.
7. **SOC dashboard** — live metrics (clients, scans, findings, incidents), scheduled
   re-scans, and delta alerting.
8. **Reporting** — live-assembled, then settled ReportLab PDF with executive summary,
   severity breakdown, findings, ISO-27001 gap table, breach timeline, OSINT section, and
   consolidated multi-company sections.
9. **AI Advisor** — opt-in, OFF by default; Gemini or local Ollama; tiered defensive
   guidance; consent gating; optional redaction.

---

## 11. Software Testing

### 11.1 Testing Strategies
Testing uses **pytest** with the **pytest-qt** plugin, running Qt headlessly via
`QT_QPA_PLATFORM=offscreen`. The suite comprises **~395 automated tests** spanning unit,
integration, and system levels. A shared `conftest.py` provides an in-memory SQLite
fixture and an autouse teardown that drains the Qt event loop and joins any lingering
`QThread` workers — eliminating cross-test interference and thread-teardown races. Tests
run on every change; a phase is not considered complete until the suite is green and the
app launches cleanly.

### 11.2 Unit Testing
Validates individual functions/classes in isolation (often with mocked subprocesses so no
real network/tool is needed). Examples:
- **Tool wrappers** — feed canned JSON/XML to each parser (`subfinder`, `httpx`, `nuclei`,
  `nmap`, etc.) and assert the produced `list[dict]`/`Finding` objects.
- **Device classifier** — `_classify_device([53]) == "router"`, `[3389,443] == "workstation"`,
  priority rules, and the empty-ports → "unknown" case.
- **Cross-company correlation** — shared weakness detection, same-company de-duplication,
  worst-severity roll-up, and ordering by breadth of impact.
- **Redaction** — strips company names, hostnames, subdomains, and IPv4 addresses while
  preserving security content (severities, vulnerability titles).
- **Log rules / prompt builder / theme tokens / DB methods** — each tested directly.

### 11.3 Integration Testing
Validates that components work together across the worker → DB → signal → UI boundary:
- **Worker pipelines** — start a `QThread` worker, wait on its completion signal
  (`qtbot.waitSignal`), then assert findings were written to the in-memory DB and the
  correct signals fired (e.g., `scan_complete`, `delta_ready`, `finding_found`).
- **Failure isolation** — inject a failing company/tool into a batch run and assert the
  batch still completes and the remaining companies are scanned (Absolute Rule #2).
- **Screen wiring** — construct each screen with a DB and assert widgets, signals, and
  refresh logic behave (e.g., dashboard metric cards update; settings persist/restore
  schedules and advisor settings).
- **PDF generation** — build `PdfGenerator`/`ConsolidatedPdfGenerator` with sample data and
  assert the output `.pdf` is produced and non-trivial, and that conditional sections
  (breach timeline, OSINT, per-company) appear only when data exists.

### 11.4 System Testing
Validates the assembled application end-to-end:
- **Headless launch & navigation** — build the main window, iterate through all eight
  screens in the `QStackedWidget`, pump the event loop, and assert no crashes or
  stylesheet errors.
- **End-to-end report** — generate a real PDF (single-scan and consolidated multi-company)
  and confirm structure and size.
- **Visual verification** — render screens offscreen to PNG and review layout, contrast,
  and consistency of the design system.

### 11.5 Representative Test Cases (sample)
| # | Level | Test | Expected Result |
|---|-------|------|-----------------|
| 1 | Unit | `_classify_device([53, 80])` | `"router"` (priority over server) |
| 2 | Unit | `correlate_cross_company` with a shared finding in 2 companies | weakness listed with both company names |
| 3 | Unit | `redact()` on text containing company/host/IP | all three replaced; `CRITICAL` preserved |
| 4 | Integration | Batch scan where one company raises | batch completes; other companies scanned; error surfaced |
| 5 | Integration | DeltaWorker vs previous scan | correct new/resolved counts emitted |
| 6 | Integration | Dashboard refresh after inserting incidents | "Incidents" metric shows correct count |
| 7 | System | Launch app, navigate all 9 screens | no crash; all screens construct |
| 8 | System | Export consolidated PDF for 3 companies | valid PDF; correlation section present |

---

## 12. Results and Discussion

### 12.1 Experimental Setup
Development and validation were performed on a native Kali Linux workstation. The
application and its automated suite are executed from the project root; the GUI is rendered
both interactively and headlessly (offscreen) for verification.

### 12.2 Hardware / Software Setup
| Item | Value |
|------|-------|
| OS | Kali Linux (rolling) |
| Python | 3.11+ (validated on 3.13) |
| GUI | PyQt6 / Qt 6.x |
| Test runner | pytest + pytest-qt, `QT_QPA_PLATFORM=offscreen` |
| Scanning tools | subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl.sh, theHarvester |
| Optional | yara-python, Gemini/Ollama |

### 12.3 Results
- **Functional completeness:** all build phases implemented — external scanning,
  live visuals, internal network module, incident response, OSINT, multi-company
  orchestration, settled PDF report, SOC dashboard, AI Advisor, and packaging.
- **Test outcomes:** the automated suite of **~395 tests passes** consistently across
  repeated runs (unit, integration, and system levels).
- **Reliability:** failure-isolation tests confirm that a single failing tool or company
  never aborts the pipeline/batch; the UI remains responsive because all scanning runs on
  `QThread` workers.
- **Reporting:** single-scan and consolidated multi-company PDFs are generated successfully,
  including conditional breach-timeline and OSINT sections and ISO-27001 control mapping.
- **Usability/UI:** a unified design system (theme tokens + global stylesheet + reusable
  components) yields consistent, accessible, modern screens; headless screenshots confirm
  layout and contrast across the dashboard, onboarding, and audit screens.
- **Privacy:** the AI Advisor is opt-in and OFF by default; the redaction pass removes
  company names, hostnames, and IPs before any cloud call, and the local Ollama backend
  keeps data on-device.

### 12.4 Discussion
The results demonstrate that consolidating the assessment lifecycle into one operator
tool is both feasible and beneficial: it removes manual tool-stitching, enforces
incremental crash-safe persistence, and produces consistent compliance-grade output. The
strict detection-only scope keeps the tool within authorised internal use. The principal
engineering trade-off was favouring **sequential** multi-company scanning by default for
predictability and resource safety, with configurable parallelism deferred (see
Limitations).

---

## 13. Conclusion and Future Enhancements

### 13.1 Conclusion
SecureOps successfully unifies external scanning, internal discovery, OSINT, and
incident response into a single, reliable, offline-capable Kali Linux desktop
application. It satisfies its objectives: a non-blocking UI with live report assembly,
full multi-company coverage with consolidated reporting, crash-safe incremental persistence,
compliance-grade PDF output, and an opt-in, privacy-preserving AI Advisor — all within a
strict detection-and-reporting scope. The implementation is validated by a comprehensive
automated test suite and verified application launches.

### 13.2 Limitations of the Project
1. **Sequential multi-company scans** — parallel scanning is deferred; large multi-company
   runs are processed one company at a time by default.
2. **SOC monitoring while app is open** — scheduled re-scans run only while the application
   is running; there is no background OS service (v1 scope).
3. **Platform** — Kali Linux only; no Windows/macOS build of the application itself.
4. **YARA ruleset** — ships a baseline rule set; advanced/custom rule management is limited.
5. **AI Advisor dependency** — cloud interpretation depends on an external API (mitigated by
   the local Ollama option and opt-in/OFF default).

### 13.3 Scope for Future Enhancements
1. **Configurable parallel orchestration** for multi-company scans.
2. **Background scheduling service** so SOC re-scans run when the app is closed.
3. **Custom YARA rule import/management** and threat-intel feed integration.
4. **Branded/templated PDF reports** (per-organisation logos, themes).
5. **Role-based multi-user mode** and optional centralised result aggregation.
6. **Richer correlation** (CVE ↔ host ↔ OSINT linkage in the attack graph).
7. **Cross-platform packaging** (Windows/macOS) for the operator UI.

---

*End of documentation source. Diagrams above are ASCII and map 1:1 to standard ER /
DFD / activity-diagram notation; they may be recreated in draw.io, Lucidchart, or
PlantUML, or embedded as monospaced text blocks per `INSTRUCTIONDOCUMENT.md`.*
