# SecureOps — Product Requirements Document

**Version:** 2.0
**Status:** Approved — ready to build
**Owner:** Abhishek K
**Organisation:** Fidelitus Corp
**Last updated:** 9 June 2026
**Document type:** PRD (Product Requirements Document)

---

## 1. Overview

### 1.1 Product summary

SecureOps is a standalone desktop penetration-testing, incident-response, and security-audit platform for Kali Linux. It is built for internal use at Fidelitus Corp — a parent organisation with 9 subsidiary companies — to conduct regular security audits, respond to active or historical breaches, and maintain continuous SOC monitoring across all subsidiaries and their shared infrastructure.

The platform orchestrates a full toolchain (external scanning, internal network discovery, cloud audit, OSINT, malware detection, log analysis) through a single unified interface, assembles findings into a live report as the scan runs, and exports a professional, compliance-grade PDF on completion.

### 1.2 Context — Fidelitus Corp

Fidelitus Corp operates 9 subsidiary companies. Each company has:
- One or more public websites and domains
- Social/professional presence (LinkedIn and other platforms)
- Cloud-hosted applications on AWS and GCP
- A shared or company-specific network infrastructure comprising:
  - DMZ (public-facing segment)
  - Firewall (one has been confirmed compromised)
  - Internal LAN with multiple subnets
  - Routers, switches, WiFi access points
  - End-user and server devices

There is confirmed evidence of a breach: an attacker cracked a firewall and subsequently cracked a server. Logs confirm the attack path. Malware may be present in applications, operating systems, routers, or firewalls. SecureOps must address both the ongoing audit mandate and the breach investigation in one integrated platform.

### 1.3 Problem statement

Fidelitus Corp has 9 companies, multiple IP ranges, AWS and GCP footprints, an active breach history, and no unified tool to audit the full stack. Running tools manually, correlating output by hand, and writing reports from scratch wastes significant time and produces inconsistent results. Breaches go undetected between audits.

### 1.4 Solution

A single PyQt6 desktop application, running on Kali Linux inside the Fidelitus Corp network, that:
- Runs the full external scan pipeline against all 9 companies' domains and cloud footprints.
- Performs internal network discovery and device enumeration across all subnet ranges.
- Conducts incident response: log analysis, malware/IOC detection, breach trail reconstruction.
- Audits AWS and GCP for misconfigurations.
- Harvests public OSINT across all 9 companies.
- Visualises the attack surface live as scanning runs, including a real-time network topology map.
- Assembles findings into a live report continuously, settled into a professional PDF on completion.
- Supports scheduled continuous monitoring so new threats are caught between planned audits.

### 1.5 Scope boundary

SecureOps is a **detection, reconnaissance, incident-response, and reporting** platform. It explicitly does **not** include an exploitation or weaponisation layer. No automated exploit chaining, payload delivery, credential attacks, or command-and-control. This keeps it appropriate for an internal security team operating under organisational authorisation.

---

## 2. Goals and non-goals

### 2.1 Goals

1. Unified single-screen experience where the scan view assembles into the report live.
2. Full external scan pipeline across all 9 Fidelitus subsidiaries from one interface.
3. Internal network discovery: subnet sweeps, device fingerprinting, network topology mapping.
4. Incident response capability: log analysis, IOC/malware detection, lateral movement tracking, breach trail reconstruction.
5. Cloud audit: AWS and GCP misconfiguration detection.
6. OSINT harvesting across all 9 companies' public digital footprint.
7. Continuous SOC monitoring with scheduled re-scans and new-finding alerts.
8. Professional, compliance-grade PDF reports (ISO 27001 control mapping included).
9. Fully offline operation once installed — no external dependencies for core scanning.
10. Optional AI Advisor agent (opt-in) for plain-language scan interpretation and precaution recommendations.
11. Top-class reliability: UI never freezes, single tool failure never crashes the app.

### 2.2 Non-goals (this release)

1. Active exploitation of vulnerabilities.
2. Cloud-hosted or multi-user server deployment.
3. Windows or macOS support (Kali Linux only for v1).
4. Real-time collaboration or external ticketing integrations.
5. AI-driven offensive automation of any kind (AI Advisor is strictly defensive).

---

## 3. Target users

### 3.1 Primary — Internal security team (Abhishek K, Fidelitus Corp)

Runs regular audits and incident investigations across all 9 subsidiaries. Works from a Kali Linux machine connected to the Fidelitus internal network. Needs a tool that handles the full stack — external, internal, cloud, and incident — without stitching tools together manually.

### 3.2 Secondary — Fidelitus Corp management (report consumer)

Non-technical stakeholders (CTO, CISO, compliance officers) across the group who read the PDF reports. Never touch the app; the report's clarity and professional presentation directly affect the audit's credibility.

---

## 4. User experience and design

### 4.1 Design principles

1. **Unified flow** — the scan view and report are one surface; the scan settles into the report.
2. **Live assembly** — the report builds continuously as findings arrive, not at the end.
3. **Motion with meaning** — animations communicate discovery and progress, never decoration.
4. **Dark workspace, light deliverable** — dark cyberpunk app theme; light professional PDF.
5. **Reliability is visible** — tool status, network state, and errors are always surfaced clearly.
6. **Multi-target clarity** — when scanning 9 companies, progress and findings are clearly segmented per company but visible in aggregate.

### 4.2 Visual theme

- **Application:** Dark cyberpunk. Deep navy (`#020810`), cyan (`#00e5ff`) and green (`#00ff88`) accents, Space Mono + DM Sans typeface pairing, scanline overlay, glow effects.
- **Exported PDF:** Light, professional, corporate. White background, restrained accent colour, clean typography. Suitable for printing and C-suite distribution.

### 4.3 Primary screens

| Screen | Purpose |
|--------|---------|
| SOC Dashboard | Live monitoring: threat feed, metrics, system health, geo attack map |
| Client / Org Onboarding | Register Fidelitus Corp and each of the 9 subsidiaries with their assets |
| Scan (Unified View) | Core experience — live scan that assembles into the report in real time |
| Incident Response | Log analysis, IOC scan, breach trail, lateral movement map |
| Internal Network | Subnet discovery, device inventory, network topology map |
| Cloud Audit | AWS and GCP misconfiguration findings |
| OSINT | Public digital footprint per company |
| Report | Settled final report with PDF export |
| Settings | Tool paths, API keys, scan schedules, subnet ranges |

### 4.4 The unified scan view (core experience)

While a scan runs, this single screen shows:

1. **Pipeline tracker** — tools rendered as connected nodes; each pulses while active, glows green on completion, shows live counts.
2. **Attack-surface network graph (signature visual)** — the target at centre; subdomains, hosts, ports, and vulnerabilities branch outward in real time. Animated, force-directed layout. For internal scans, this becomes the network topology map: subnets, devices, services, and relationships.
3. **Severity rings** — animated counters for Critical / High / Medium / Low growing as findings arrive.
4. **Streaming finding cards** — each finding slides in, colour-coded by severity, newest on top.
5. **Terminal feed** — raw tool output for transparency and debugging.
6. **Per-company tabs** — when running a multi-company scan, findings are segmented per subsidiary with an aggregate view.

On completion, the view settles: graph completes, counters lock, PDF export enables.

### 4.5 Scan trigger modes

- **Quick scan:** One click runs the full chained external pipeline against a target with sensible defaults.
- **Advanced mode:** User selects tools, sets per-tool flags, defines scope, chooses subnet ranges.
- **Multi-target mode:** Select multiple Fidelitus subsidiaries and run the pipeline across all of them in sequence, with a consolidated report.
- **Internal sweep mode:** Target a subnet range for device discovery, fingerprinting, and topology mapping.
- **Incident response mode:** Feed logs and specify a host for breach trail reconstruction and IOC scanning.

---

## 5. Functional requirements

### 5.1 External scanning engine

| ID | Requirement |
|----|-------------|
| FR-1 | The engine shall run the following tools: subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl.sh, theHarvester. |
| FR-2 | Tools shall run in a chained pipeline: subfinder → dnsx → naabu → httpx → katana → nuclei, with nmap/nikto/testssl run against discovered live hosts. |
| FR-3 | Every tool shall run on a QThread background worker; the UI shall remain fully responsive at all times. |
| FR-4 | A failure in any single tool shall be logged and shall not stop the pipeline or crash the app. |
| FR-5 | The engine shall parse each tool's JSON output into a structured findings model. |
| FR-6 | Each finding shall be written to the local database the moment it is discovered. |
| FR-7 | The engine shall default to non-privileged modes; elevation shall only be requested when required, with a clear prompt. |
| FR-8 | On startup, the app shall verify all required tools are present and display actionable messages for any that are missing. |

### 5.2 Multi-target orchestration

| ID | Requirement |
|----|-------------|
| FR-9 | The app shall maintain a registry of all 9 Fidelitus subsidiaries, each with their domains, IP ranges, cloud accounts, and asset inventory. |
| FR-10 | The app shall support running the full scan pipeline against multiple subsidiaries in a single session, sequentially or in configurable parallel. |
| FR-11 | Multi-target scans shall produce both per-company findings and an aggregated cross-company report. |
| FR-12 | The app shall surface findings that span multiple subsidiaries (e.g. a shared infrastructure weakness affecting several companies). |

### 5.3 Internal network scanning

| ID | Requirement |
|----|-------------|
| FR-13 | The app shall support internal network sweeps across one or more defined subnet ranges (e.g. 192.168.x.0/24, 10.x.x.0/24). |
| FR-14 | The internal sweep shall discover all live hosts, open ports, and services using nmap. |
| FR-15 | The app shall fingerprint device types: servers, workstations, routers, switches, WiFi access points, IoT devices. |
| FR-16 | The internal sweep shall produce a network topology map showing subnet structure, device relationships, and services. |
| FR-17 | The topology map shall be visualised in the attack-surface graph with device-type icons and relationship edges. |
| FR-18 | Internal scan subnet ranges shall be configurable per company in Settings. |

### 5.4 Incident response

| ID | Requirement |
|----|-------------|
| FR-19 | The app shall accept firewall and server log files as input for breach trail analysis. |
| FR-20 | The log analyser shall reconstruct the attacker's timeline: entry point, lateral movement, affected systems, actions taken. |
| FR-21 | The app shall run IOC (Indicator of Compromise) detection using YARA rules against accessible file systems, running process lists, and config files. |
| FR-22 | The app shall check for common persistence mechanisms: new user accounts, modified cron jobs, new scheduled tasks, backdoor services, modified sudoers. |
| FR-23 | The app shall scan router and firewall configs for known backdoor indicators and unauthorised rule changes. |
| FR-24 | Incident findings shall be timestamped and stored separately from audit findings in the database. |
| FR-25 | The breach trail shall be visualised as an annotated timeline in the report. |

### 5.5 Cloud audit

| ID | Requirement |
|----|-------------|
| FR-26 | The app shall audit AWS environments using nuclei cloud templates and configurable AWS credentials. |
| FR-27 | AWS checks shall include: public S3 buckets, overly permissive IAM policies, exposed access keys, unencrypted resources, unrestricted security groups. |
| FR-28 | The app shall audit GCP environments using configurable service account credentials. |
| FR-29 | GCP checks shall include: public storage buckets, weak service accounts, exposed APIs, audit log gaps. |
| FR-30 | Cloud credentials shall be stored in the local encrypted config and never written to scan output or logs. |

### 5.6 OSINT module

| ID | Requirement |
|----|-------------|
| FR-31 | The app shall run theHarvester against each company's domains to collect emails, subdomains, hosts, and employee names from public sources. |
| FR-32 | The OSINT module shall collect publicly visible information from LinkedIn, social media, Shodan (if API key configured), and certificate transparency logs. |
| FR-33 | OSINT findings shall be correlated with scan findings (e.g. a harvested email that matches a credential in a data breach). |

### 5.7 Correlation engine

| ID | Requirement |
|----|-------------|
| FR-34 | The engine shall correlate findings across tools: associate CVEs with specific hosts and subdomains, link OSINT data with scan findings, and connect cloud misconfigs with internal network findings. |
| FR-35 | The attack-surface graph shall reflect correlated relationships: target → subdomain → host → port → vulnerability → remediation. |
| FR-36 | Cross-company correlations shall be highlighted when a weakness affects multiple Fidelitus subsidiaries. |

### 5.8 Live report assembly

| ID | Requirement |
|----|-------------|
| FR-37 | The report view shall update in real time as findings are written to the database. |
| FR-38 | Severity counts, charts, and the network graph shall animate to reflect new findings as they arrive. |
| FR-39 | On scan completion, the report shall transition to a settled final state and enable PDF export. |

### 5.9 Reporting and export

| ID | Requirement |
|----|-------------|
| FR-40 | The app shall generate a professional PDF using ReportLab with a light, corporate theme. |
| FR-41 | The report shall include: executive summary, overall risk rating, findings by severity with descriptions and remediation steps, attack-surface/topology map, ISO 27001 control gap table, breach timeline (incident mode), severity/category/per-company charts. |
| FR-42 | Multi-company reports shall include a per-subsidiary section and a consolidated group-level summary. |
| FR-43 | The report shall be self-contained and suitable for direct C-suite distribution. |

### 5.10 Continuous monitoring (SOC)

| ID | Requirement |
|----|-------------|
| FR-44 | The app shall support scheduled re-scans on a configurable interval per company. |
| FR-45 | The SOC dashboard shall surface newly discovered findings since the last scan, with delta highlighting. |
| FR-46 | The dashboard shall show live metrics: threat count, blocked/flagged activity, open incidents, system health per company. |

### 5.11 AI Advisor Agent

The AI Advisor is an optional, opt-in agent that reads a completed scan and produces plain-language precautions and recommendations. It is an enrichment layer — all scanning and reporting work fully offline without it.

| ID | Requirement |
|----|-------------|
| FR-47 | The AI Advisor shall, after scan completion, produce: a plain-language explanation of findings, prioritised precautions at three urgency tiers (immediate, short-term, preventive), and an overall risk interpretation. |
| FR-48 | The AI Advisor shall map findings to ISO 27001 controls and recommend specific remediation tailored to the client's known stack. |
| FR-49 | The AI Advisor shall run on a QThread worker so the UI never freezes during analysis. |
| FR-50 | AI output shall be clearly labelled "AI-generated — review before distributing" and require explicit consultant sign-off. |
| FR-51 | The AI Advisor shall be opt-in and OFF by default. It shall be togglable per company and per scan. |
| FR-52 | A clear consent notice shall be shown before any data is sent externally. The user must confirm before proceeding. |
| FR-53 | A redaction option shall strip identifying details (company names, hostnames, IPs) from data sent to the AI service. |
| FR-54 | A local-LLM backend (Ollama) shall be supported as an alternative so sensitive data never leaves the machine. |
| FR-55 | The AI Advisor shall never recommend or generate exploitation steps. Its scope is strictly defensive precautions and remediation guidance. |

---

## 6. Non-functional requirements

### 6.1 Performance

- UI shall maintain 60fps animation responsiveness during active scans.
- Tool orchestration shall run concurrently where the pipeline allows.
- Internal subnet sweeps shall handle Class C networks (254 hosts) without lag.
- Multi-company scans shall not degrade UI performance regardless of the number of targets.

### 6.2 Reliability

- No single tool failure shall crash the application.
- The database shall persist findings incrementally — a crash mid-scan loses no completed work.
- The app shall recover gracefully and resume displaying prior state on restart.
- Internal network scans shall time out cleanly on unresponsive hosts rather than hanging.

### 6.3 Security and privacy

- The app shall run without root privileges for normal operation.
- All scan data, findings, and client records shall be stored in a local SQLite database.
- Cloud credentials (AWS keys, GCP service accounts) shall be stored in an encrypted local config file, never logged or included in reports.
- The app shall not transmit any data externally except when the AI Advisor is explicitly enabled and the user has confirmed the consent notice.
- Bundled third-party tools shall be accompanied by their license notices (all are MIT).

### 6.4 Usability

- A user familiar with Kali Linux shall be able to run a quick scan within 5 minutes of installation.
- Error states shall be clear and actionable (e.g. "subfinder not found — run: pdtm -install subfinder").
- Subnet range configuration shall validate input and reject malformed ranges.

### 6.5 Packaging

- Distributed as a `.deb` package and an `.AppImage`.
- All ProjectDiscovery Go binaries bundled inside the package.
- `.deb` declares Kali-native dependencies (nmap, nikto, testssl.sh, theharvester).
- A `THIRD-PARTY-LICENSES` file bundled for MIT compliance.

---

## 7. Technical architecture

### 7.1 Stack

| Layer | Technology |
|-------|-----------|
| Desktop framework | PyQt6 |
| Charts / live graphs | pyqtgraph |
| Network topology graph | pyqtgraph GraphItem + custom force-directed layout |
| Threading | QThread workers with Qt signals/slots |
| Scan orchestration | Python subprocess wrappers (one per tool) |
| Internal network scanning | nmap Python wrapper (python-nmap) |
| IOC / malware detection | YARA Python bindings |
| Log analysis | Custom Python parser (regex + timeline reconstruction) |
| Cloud audit | boto3 (AWS) + google-cloud Python SDK (GCP) |
| OSINT | theHarvester subprocess wrapper |
| Database | SQLite via Python built-in sqlite3 |
| PDF generation | ReportLab |
| AI Advisor (optional) | anthropic SDK (cloud) or Ollama API (local) |
| Packaging | PyInstaller → .deb / .AppImage |

### 7.2 Tool inventory

| Tool | Role | Source | License |
|------|------|--------|---------|
| subfinder | Subdomain enumeration | ProjectDiscovery | MIT |
| dnsx | DNS resolution + validation | ProjectDiscovery | MIT |
| naabu | Fast port scanning | ProjectDiscovery | MIT |
| httpx | HTTP probing + fingerprinting | ProjectDiscovery | MIT |
| katana | Web crawling + endpoint discovery | ProjectDiscovery | MIT |
| nuclei | Vulnerability detection (9,000+ templates) | ProjectDiscovery | MIT |
| nmap | Service / version / OS scanning, internal sweep | Kali native | GPL (declared dep) |
| nikto | Web server misconfiguration | Kali native | GPL (declared dep) |
| testssl.sh | TLS / SSL analysis | Kali native | GPL (declared dep) |
| theHarvester | OSINT: emails, names, subdomains | Kali native | GPL (declared dep) |
| YARA | IOC pattern matching | pip: yara-python | MIT |
| python-nmap | nmap Python API for internal sweeps | pip | GPL |
| boto3 | AWS SDK for cloud audit | pip | Apache 2.0 |
| google-cloud | GCP SDK for cloud audit | pip | Apache 2.0 |

### 7.3 Project directory structure

```
secureops/
├── main.py                        # App entry point
├── secureops/
│   ├── core/
│   │   ├── database.py            # SQLite models + queries
│   │   ├── config.py              # Settings, encrypted credentials
│   │   └── tool_checker.py        # Startup tool verification
│   ├── workers/
│   │   ├── pipeline_worker.py     # External scan orchestrator (QThread)
│   │   ├── internal_worker.py     # Internal network sweep (QThread)
│   │   ├── incident_worker.py     # Log analysis + IOC scan (QThread)
│   │   ├── cloud_worker.py        # AWS + GCP audit (QThread)
│   │   ├── osint_worker.py        # theHarvester + OSINT (QThread)
│   │   └── ai_worker.py           # AI Advisor (QThread)
│   ├── tools/
│   │   ├── subfinder.py           # Tool wrapper
│   │   ├── dnsx.py
│   │   ├── naabu.py
│   │   ├── httpx.py
│   │   ├── katana.py
│   │   ├── nuclei.py
│   │   ├── nmap_wrapper.py
│   │   ├── nikto.py
│   │   ├── testssl.py
│   │   ├── theharvester.py
│   │   ├── yara_scanner.py
│   │   ├── log_analyser.py
│   │   ├── aws_auditor.py
│   │   └── gcp_auditor.py
│   ├── pages/
│   │   ├── soc_dashboard.py       # SOC live monitoring
│   │   ├── onboarding.py          # Company + asset registration
│   │   ├── scan_view.py           # Unified live scan + report assembly
│   │   ├── incident_page.py       # Incident response
│   │   ├── internal_page.py       # Internal network scan
│   │   ├── cloud_page.py          # Cloud audit
│   │   ├── osint_page.py          # OSINT harvesting
│   │   ├── report_page.py         # Final settled report + PDF export
│   │   └── settings_page.py       # Config: tools, subnets, credentials
│   └── widgets/
│       ├── graph_widget.py        # Attack-surface + topology graph
│       ├── severity_rings.py      # Animated severity counters
│       ├── pipeline_tracker.py    # Tool pipeline status nodes
│       ├── finding_card.py        # Individual finding widget
│       ├── terminal_widget.py     # Streaming terminal feed
│       └── theme.py               # QSS dark theme constants
├── resources/
│   ├── bins/                      # Bundled Go binaries
│   ├── yara_rules/                # YARA rule sets
│   └── nuclei_templates/          # Pinned nuclei template snapshot
├── THIRD-PARTY-LICENSES
└── requirements.txt
```

### 7.4 Threading model

Every scan module runs on a dedicated `QThread` worker. Workers emit Qt signals to update the UI — the main thread never performs blocking I/O. Signal types:
- `finding_discovered(finding: dict)` → updates DB, triggers graph update + finding card animation
- `tool_progress(tool: str, count: int, status: str)` → updates pipeline tracker
- `tool_log(line: str)` → appends to terminal feed
- `scan_complete(summary: dict)` → settles the report view, enables PDF export

### 7.5 Data flow — external scan

```
User triggers scan (one or more companies)
        ↓
PipelineWorker (QThread)
        ↓
subfinder → dnsx → naabu → httpx → katana → nuclei
        ↓                            ↓
        nmap / nikto / testssl (against discovered live hosts)
        ↓
Each finding: parse JSON → write to SQLite → emit finding_discovered signal
        ↓
UI: graph node added, finding card animates in, severity ring increments
        ↓
Scan complete → report settles → PDF export enabled
```

### 7.6 Data flow — internal network scan

```
User sets subnet range(s) and triggers internal sweep
        ↓
InternalWorker (QThread)
        ↓
nmap ping sweep → live host list
        ↓
nmap service/version scan per host → device fingerprinting
        ↓
Device type classified → topology edges built
        ↓
Each device/service → write to SQLite → emit finding_discovered
        ↓
UI: topology map node added, network graph updates live
```

### 7.7 Data flow — incident response

```
User loads log files + specifies target host
        ↓
IncidentWorker (QThread)
        ↓
Log parser → timeline events extracted
        ↓
YARA scanner → IOC matches against files/configs
        ↓
Persistence checker → new accounts, cron, services
        ↓
Lateral movement mapper → which hosts were accessed post-breach
        ↓
Each finding → write to SQLite (incident table) → emit signal
        ↓
UI: breach timeline animates, affected hosts highlighted on topology map
```

---

## 8. Build phases

| Phase | Deliverable | Key files |
|-------|-------------|-----------|
| 1 | App skeleton — main window, dark theme, sidebar navigation, page shell, tool verification on startup | main.py, theme.py, tool_checker.py |
| 2 | Scan engine — all tool wrappers, external pipeline, SQLite persistence, QThread workers | tools/*.py, workers/pipeline_worker.py, core/database.py |
| 3 | Live visuals — pipeline tracker, severity rings, attack-surface graph, streaming cards, terminal feed | widgets/*.py, pages/scan_view.py |
| 4 | Internal network module — subnet sweep, device fingerprinting, topology map | workers/internal_worker.py, tools/nmap_wrapper.py, pages/internal_page.py |
| 5 | Incident response module — log analyser, YARA IOC scan, persistence checker, breach timeline | workers/incident_worker.py, tools/yara_scanner.py, tools/log_analyser.py, pages/incident_page.py |
| 6 | Cloud audit + OSINT — AWS/GCP checks, theHarvester, public footprint | workers/cloud_worker.py, workers/osint_worker.py, tools/aws_auditor.py, tools/gcp_auditor.py, tools/theharvester.py |
| 7 | Multi-target orchestration — 9-company registry, sequential/parallel scans, consolidated report | pages/onboarding.py, workers/pipeline_worker.py multi-target mode |
| 8 | Final report + professional PDF — settled report view, ReportLab light-theme export, per-company sections | pages/report_page.py |
| 9 | SOC dashboard + continuous monitoring — live metrics, scheduling, delta alerts | pages/soc_dashboard.py |
| 10 | AI Advisor agent — scan interpretation, precaution tiers, ISO mapping, consent flow, Ollama local option | workers/ai_worker.py |
| 11 | Packaging — PyInstaller spec, .deb + .AppImage, bundled binaries, license file | build scripts |

---

## 9. Differentiators

1. **Full-stack internal + external** — one tool covers external web, internal LAN, cloud, OSINT, and incident response together. Nothing else does all of this without a server stack.
2. **Live report assembly** — the report builds itself as the scan runs; the scan view *is* the report.
3. **Signature attack-surface + topology graph** — animated force-directed graph covering both external attack surface and internal network topology, built live.
4. **9-company multi-target orchestration** — scan all Fidelitus subsidiaries in one session with consolidated and per-company views.
5. **Incident response built in** — log analysis, YARA IOC scanning, breach trail reconstruction, persistence detection — not a separate tool.
6. **Cloud audit integrated** — AWS and GCP misconfigurations surfaced in the same report as network and web findings.
7. **Compliance-grade output** — ISO 27001 control mapping, professional C-suite PDF.
8. **AI Advisor** — optional, opt-in agent for plain-language findings interpretation and prioritised precautions.
9. **Offline, single-binary** — no Docker, no server, no internet required for core operation.

---

## 10. Success metrics

1. A full external scan of one Fidelitus subsidiary completes end-to-end with all tools producing parsed findings.
2. An internal subnet sweep discovers and fingerprints all live hosts on a /24 network without UI lag.
3. Incident response mode correctly reconstructs a breach timeline from sample firewall and server logs.
4. A multi-company scan of all 9 subsidiaries runs sequentially and produces a consolidated PDF report.
5. No crash or freeze occurs when any single tool fails mid-scan.
6. The generated PDF is accepted by Fidelitus Corp management as a client-ready deliverable.
7. The app installs and runs fully offline from the `.deb` on a clean Kali machine.

---

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Tool output format changes between versions | Parsing breaks | Pin bundled tool versions; isolate parsers per tool with try/except |
| Long multi-company scans freeze UI | Poor UX | All scans on QThread workers; progress streamed via signals |
| Internal subnet too large (Class B or larger) | Sweep takes hours | Cap default sweep depth; allow user to narrow range; show live progress |
| Cloud credentials handled insecurely | Data breach risk | Encrypt at rest; never log; strip from all output |
| YARA rules outdated | IOC misses | Ship a curated baseline ruleset; allow custom rule import |
| Log format varies by firewall/OS vendor | Parser fails | Modular parsers per format (FortiGate, iptables, Windows Event Log); graceful fallback |
| Network graph performance with 100+ nodes (large internal scan) | Lag | Level-of-detail rendering; cluster nodes by subnet; cap rendered edges |
| Missing Kali-native tools on fresh install | Scan fails silently | Startup verification with exact install commands displayed |
| AI Advisor sends client data externally | Privacy / legal | Opt-in only, OFF by default; consent notice; redaction option; local-LLM alternative |
| AI output incorrect | Bad advice in report | All AI output labelled; mandatory consultant sign-off; easy accept/edit/discard |
| Build environment cannot render GUI | Visual issues found late | Build runs on Kali; iterate with user feedback |

---

## 12. Open questions (resolved)

| Question | Resolution |
|----------|-----------|
| SOC re-scans when app is closed? | v1: only while app is open. Background service in v2. |
| Quick scan scope? | Domain + all discovered subdomains. |
| PDF branding (logo, colours)? | v2. v1 uses standard Fidelitus-neutral professional template. |
| Parallel vs sequential multi-company scans? | Sequential by default; configurable parallelism in Settings. |
| Internal scan needs root for SYN mode? | Default to CONNECT mode (no root). User can opt into SYN with sudo prompt. |

---

*End of document. Version 2.0 — approved for build.*
