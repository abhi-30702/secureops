# SecureOps — Product Requirements Document

**Version:** 1.0
**Status:** Draft for approval
**Owner:** Abhishek K
**Last updated:** 29 May 2026
**Document type:** PRD (Product Requirements Document)

---

## 1. Overview

### 1.1 Product summary

SecureOps is a standalone desktop penetration-testing and security-audit application for Kali Linux. It orchestrates a suite of best-in-class open-source scanning tools through a single unified interface, assembles findings into a live report as the scan runs, and exports a professional, client-ready PDF on completion. The product is designed for security consultants delivering ISO 27001 audits, vulnerability assessments, and continuous SOC monitoring.

### 1.2 Problem statement

Security consultants today stitch together a dozen command-line tools by hand, manually parse inconsistent output, and spend hours converting raw findings into client-presentable reports. Existing all-in-one platforms (e.g. reNgine) are heavy, server-based, Docker-dependent, and require significant infrastructure. There is no lightweight, reliable, offline-capable desktop application that runs the modern scanning toolchain, correlates results intelligently, and produces compliance-grade reporting out of the box.

### 1.3 Solution

A single PyQt6 desktop application that:
- Runs a chained pipeline of eight industry-standard scanning tools with one click.
- Visualizes the scan live, including a signature animated attack-surface network graph.
- Assembles the report continuously as findings arrive.
- Exports a polished, professional PDF suitable for clients and auditors.
- Runs fully offline, with all tools bundled inside the installer.

### 1.4 Scope boundary (important)

SecureOps is a **detection, reconnaissance, and reporting** platform. It identifies and reports security weaknesses. It explicitly does **not** include an exploitation or weaponization layer (no automated exploit chaining, payload delivery, credential attacks, or command-and-control). This keeps the product legal to distribute and aligned with compliance-audit use cases.

---

## 2. Goals and non-goals

### 2.1 Goals

1. Deliver a unified, single-screen experience where the scan view *is* the report, assembled live.
2. Provide both a one-click "quick scan" and an advanced manual mode for power users.
3. Achieve top-class reliability: the UI must never freeze, and a single tool failure must never crash the app or stop the pipeline.
4. Produce a professional, compliance-grade PDF report including ISO 27001 control mapping.
5. Run fully offline once installed.
6. Provide an optional, opt-in AI Advisor agent that interprets completed scans and recommends defensive precautions, while preserving the offline, local-first guarantees of the core product.

### 2.2 Non-goals (this release)

1. Active exploitation of vulnerabilities.
2. Cloud-hosted or multi-user server deployment.
3. Windows or macOS support (Linux/Kali only for v1).
4. Real-time collaboration or ticketing integrations.
5. AI-driven exploitation or offensive automation of any kind (the AI Advisor is strictly defensive — see FR-32).

---

## 3. Target users and personas

### 3.1 Primary persona — Security Consultant

A penetration tester or ISO 27001 auditor who runs assessments on client infrastructure. Comfortable with Kali Linux and command-line tools but wants to save time on orchestration and reporting. Needs deliverables that look professional to non-technical client stakeholders.

### 3.2 Secondary persona — SOC Analyst

Monitors client environments on an ongoing basis. Needs continuous re-scanning and a live dashboard that surfaces new threats over time.

### 3.3 Tertiary persona — Consulting Client (report consumer)

A non-technical stakeholder (CTO, compliance officer) who reads the final PDF. Never touches the app, but the report's clarity and polish directly affect the consultant's reputation.

---

## 4. User experience and design

### 4.1 Design principles

1. **Unified flow** — no jarring page jumps. The scan view and the report are the same surface; the scan settles into the report.
2. **Live assembly** — the report fills in as findings arrive, not at the end.
3. **Motion with meaning** — animations communicate progress and discovery, never decoration for its own sake.
4. **Dark workspace, light deliverable** — the app uses a dark cyberpunk theme; the exported PDF uses a clean, light, corporate theme.
5. **Reliability is visible** — tool status, connection state, and errors are always clearly surfaced.

### 4.2 Visual theme

- **Application:** Dark cyberpunk. Deep navy backgrounds, cyan and green accents, monospace + sans pairing, subtle scanline and glow effects.
- **Exported PDF:** Light, professional, corporate. White background, restrained accent colour, clean typography, suitable for printing and client distribution.

### 4.3 Primary screens

| Screen | Purpose |
|--------|---------|
| Dashboard / SOC | Live monitoring overview: metrics, threat feed, system health |
| Client Onboarding | Capture client profile, domain, firewall type, asset inventory |
| Scan (Unified View) | The core experience — live scan that assembles into the report |
| Report | The settled final report with PDF export |
| Settings | Tool paths, scan defaults, (later) API key for AI |

### 4.4 The unified scan view (core experience)

While a scan runs, this single screen shows:

1. **Pipeline tracker** — the eight tools rendered as connected nodes. Each node pulses while active, glows green on completion, and shows a live count (e.g. "subfinder: 23 subdomains").
2. **Attack-surface network graph (signature visual)** — the target sits at the center; subdomains, hosts, ports, and vulnerabilities branch outward in real time as they are discovered. Animated, force-directed layout.
3. **Severity rings** — animated counters for Critical / High / Medium / Low that grow as findings arrive.
4. **Streaming finding cards** — each finding slides in, colour-coded by severity, newest on top.
5. **Terminal feed** — raw tool output for transparency and debugging.

On completion, the same view animates into a settled state: the network graph completes, counters lock, and PDF export is enabled.

### 4.5 Scan trigger modes

- **Quick scan:** One click runs the full chained pipeline with sensible defaults.
- **Advanced mode:** The user selects which tools to run, configures per-tool flags, and defines scope.

---

## 5. Functional requirements

### 5.1 Scanning engine

| ID | Requirement |
|----|-------------|
| FR-1 | The engine shall run eight scanning tools: subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl.sh. |
| FR-2 | The engine shall run tools in a chained pipeline where each tool's output feeds the next (subfinder → dnsx → naabu → httpx → katana → nuclei), with nmap/nikto/testssl run against discovered hosts. |
| FR-3 | Every tool shall run on a background thread; the UI shall remain fully responsive during scans. |
| FR-4 | A failure in any single tool shall be logged and shall not stop the pipeline or crash the app. |
| FR-5 | The engine shall parse each tool's JSON output (where available) into a structured findings model. |
| FR-6 | Each finding shall be written to the local database the moment it is discovered. |
| FR-7 | The engine shall default to non-privileged tool modes; elevation shall only be requested when strictly required, with a clear prompt. |
| FR-8 | On startup, the app shall verify each required tool is present and display a clear message if any is missing. |

### 5.2 Correlation

| ID | Requirement |
|----|-------------|
| FR-9 | The engine shall correlate findings across tools (e.g. associate a discovered CVE with the specific host and subdomain it affects). |
| FR-10 | The attack-surface graph shall reflect correlated relationships (target → subdomain → host → port → vulnerability). |

### 5.3 Live report assembly

| ID | Requirement |
|----|-------------|
| FR-11 | The report view shall update in real time as findings are written to the database. |
| FR-12 | Severity counts and charts shall animate to reflect new findings as they arrive. |
| FR-13 | On scan completion, the report shall transition to a settled final state and enable PDF export. |

### 5.4 Reporting and export

| ID | Requirement |
|----|-------------|
| FR-14 | The app shall generate a professional PDF report using a light, corporate theme. |
| FR-15 | The report shall include: executive summary, overall risk rating, findings grouped by severity with descriptions and remediation, the attack-surface map, an ISO 27001 control gap table, and severity/category charts. |
| FR-16 | The report shall be self-contained and suitable for direct client distribution. |

### 5.5 Client and data management

| ID | Requirement |
|----|-------------|
| FR-17 | The app shall persist clients, scans, and findings in a local SQLite database. |
| FR-18 | The app shall allow onboarding a client with company profile, domain, firewall type, and asset inventory. |
| FR-19 | Scan history shall be retrievable per client. |
| FR-20 | All data shall remain local; nothing shall leave the machine (until AI features are explicitly enabled in a later release). |

### 5.6 Continuous monitoring (SOC)

| ID | Requirement |
|----|-------------|
| FR-21 | The app shall support scheduled re-scans of a target. |
| FR-22 | The dashboard shall surface newly discovered threats since the previous scan. |

### 5.7 AI Advisor Agent

The AI Advisor is an optional, toggleable agent that reads a completed scan, interprets the findings, and produces plain-language precautions and recommendations. It is an **enrichment layer**, never a core dependency: all scanning and reporting work fully offline without it.

| ID | Requirement |
|----|-------------|
| FR-23 | The app shall provide an AI Advisor Agent that, once a scan completes, analyzes the structured findings and produces: (a) a plain-language explanation of what the scan found, (b) prioritized precautions and recommended actions, and (c) an overall risk interpretation. |
| FR-24 | The AI Advisor shall map findings to recommended precautions at three urgency tiers: immediate, short-term, and preventive. |
| FR-25 | The AI Advisor shall run on a background thread (QThread) so the UI never freezes during analysis. |
| FR-26 | The AI Advisor shall be strictly advisory. Its output shall be clearly labelled as AI-generated and shall require human (consultant) review before inclusion in any client deliverable. |
| FR-27 | The AI Advisor shall be opt-in and toggleable per client and per scan. It shall be OFF by default. |
| FR-28 | When the AI Advisor is disabled or unavailable (no API key, no connection), the app shall function fully and the report shall be complete without it. |
| FR-29 | Before any data is sent to an external AI service, the app shall display a clear consent notice stating that finding data will leave the machine, and shall proceed only on explicit user confirmation. |
| FR-30 | The app shall offer a redaction option to strip client-identifying details (company name, specific hostnames, IPs) from data sent to the AI service. |
| FR-31 | The architecture shall support a local-LLM backend (e.g. Ollama) as an alternative to the cloud API, for sensitive engagements where data must not leave the machine. |
| FR-32 | The AI Advisor shall never recommend or generate exploitation steps. Its scope is limited to defensive precautions and remediation guidance. |

#### 5.7.1 AI Advisor behaviour

The agent consumes the same structured findings written to the database, not raw tool dumps. For each scan it produces a structured advisory containing:

- **Summary** — what the scan covered and the headline risk in plain language.
- **Key concerns** — the findings that matter most, with why they matter (business impact, not just technical detail).
- **Precautions by urgency** — immediate (do now), short-term (within days), preventive (ongoing hygiene).
- **Per-finding guidance** — for each significant finding, a recommended remediation tailored where possible to the client's known stack (e.g. firewall type captured at onboarding).
- **ISO 27001 mapping** — which controls each concern relates to.

#### 5.7.2 Safeguards

- Output is always marked **"AI-generated — review before sending to client."**
- The consultant remains the signing authority on all deliverables (consistent with the human-sign-off principle elsewhere in this document).
- AI output can be confidently wrong; the UI shall make it easy to edit, accept, or discard each AI recommendation.
- No AI feature shall weaken the offline, local-first guarantees of the core product.

---

## 6. Non-functional requirements

### 6.1 Performance

- The UI shall maintain responsive interaction (target 60fps for animations) during active scans.
- Tool orchestration shall run tools concurrently where the pipeline allows, to minimize total scan time.

### 6.2 Reliability

- No single tool failure shall crash the application.
- The database shall persist findings incrementally so a crash mid-scan does not lose completed work.
- The app shall recover gracefully and resume display of prior state on restart.

### 6.3 Security and privacy

- The app shall run without root privileges for normal operation.
- All scan data shall be stored locally.
- Bundled third-party tools shall be accompanied by their license notices (all are MIT).
- The app shall not transmit any client data externally unless the AI Advisor is explicitly enabled by the user, and then only after a clear consent notice (see FR-29). Core scanning and reporting transmit nothing.

### 6.4 Usability

- A new user shall be able to run a quick scan within minutes of installation.
- Error states shall be clear and actionable (e.g. "nmap not found — install with apt").

### 6.5 Portability and packaging

- The app shall be distributed as a `.deb` package and an `.AppImage`.
- All scanning binaries shall be bundled for fully offline operation.
- The `.deb` shall declare Kali-native dependencies (nmap, nikto, testssl.sh).

---

## 7. Technical architecture

### 7.1 Stack

| Layer | Technology |
|-------|-----------|
| Desktop framework | PyQt6 |
| Charts / live graphs | pyqtgraph |
| Threading | QThread workers with Qt signals |
| Scan orchestration | Python subprocess wrappers |
| Database | SQLite (Python built-in sqlite3) |
| PDF generation | ReportLab |
| Packaging | PyInstaller → .deb / .AppImage |
| AI Advisor (optional) | Anthropic Claude SDK (cloud) or Ollama (local) |

### 7.2 Bundled scanning tools

| Tool | Role | Source | License |
|------|------|--------|---------|
| subfinder | Subdomain enumeration | ProjectDiscovery (GitHub) | MIT |
| dnsx | DNS resolution | ProjectDiscovery (GitHub) | MIT |
| naabu | Port scanning | ProjectDiscovery (GitHub) | MIT |
| httpx | HTTP probing / fingerprinting | ProjectDiscovery (GitHub) | MIT |
| katana | Web crawling | ProjectDiscovery (GitHub) | MIT |
| nuclei | Vulnerability detection | ProjectDiscovery (GitHub) | MIT |
| nmap | Service / version scanning | Kali native | (declared dependency) |
| nikto | Web server misconfiguration | Kali native | (declared dependency) |
| testssl.sh | TLS / SSL analysis | Kali native | (declared dependency) |

### 7.3 Threading model

All scans execute on `QThread` worker objects. Workers communicate progress and findings back to the UI exclusively via Qt signals, ensuring the main thread (UI) is never blocked. Each tool wrapper is isolated in its own try/except boundary so failures are contained.

### 7.4 Data flow

```
User triggers scan
        ↓
Pipeline orchestrator (worker thread)
        ↓
subfinder → dnsx → naabu → httpx → katana → nuclei
        ↓                    ↓
   nmap / nikto / testssl (against discovered hosts)
        ↓
Each finding parsed → written to SQLite immediately
        ↓
UI binds to DB → live report assembly + graph update (Qt signals)
        ↓
Scan completes → report settles → PDF export enabled
```

---

## 8. Differentiators

What makes SecureOps stand out from a generic scanner script:

1. **Chained-intelligence pipeline** — tools feed each other and findings are correlated, not run in isolation.
2. **Live report assembly** — the report builds itself in real time; the scan view *is* the report.
3. **Signature attack-surface network graph** — an animated, force-directed visualization of the discovered attack surface.
4. **Dark workspace, light professional PDF** — a striking app plus a client-ready deliverable.
5. **Compliance-grade output** — ISO 27001 control mapping built in.
6. **AI Advisor agent** — an optional, opt-in agent that reads the scan, explains it in plain language, and recommends defensive precautions by urgency tier, with full consent and review safeguards.
7. **Offline, single-binary reliability** — no Docker, no server, no internet required.

---

## 9. Release plan

### 9.1 Build phases

| Phase | Deliverable |
|-------|-------------|
| 1 | App skeleton — main window, dark theme, navigation, unified-view shell |
| 2 | Scan engine — eight threaded tool wrappers, chaining, SQLite persistence |
| 3 | Live visuals — pipeline tracker, severity rings, attack-surface graph, streaming cards |
| 4 | Final report + professional PDF export |
| 5 | Continuous monitoring (SOC) and scheduling |
| 6 | AI Advisor agent — scan interpretation and precaution recommendations (opt-in, with consent, redaction, and review safeguards; cloud + local-LLM backends) |
| 7 | Packaging — PyInstaller spec, .deb and .AppImage, bundled tools, license file |

### 9.2 Later releases

- AI Advisor enhancements: deeper attack-path reasoning, false-positive triage, stack-specific remediation playbooks.
- Additional export formats (DOCX, HTML).
- Cross-platform support.

---

## 10. Success metrics

1. A quick scan completes end to end with at least seven of nine tools producing parsed findings on a typical target.
2. The UI remains responsive (no freeze) throughout a full scan.
3. No crash occurs when a tool is missing or fails mid-scan.
4. A professional PDF is produced that a consultant would send to a client without manual editing.
5. The app installs and runs fully offline from the `.deb`.

---

## 11. Risks and mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Scan tool output format changes | Parsing breaks | Pin bundled tool versions; isolate parsers per tool |
| Long scans freeze UI | Poor UX | All scans on QThread workers; never block main thread |
| Missing native tools (nmap, etc.) | Scan fails | Startup verification + clear install guidance; declared .deb deps |
| Network graph performance with large surfaces | Lag | Cap rendered nodes; level-of-detail rendering; pyqtgraph optimization |
| Privilege requirements (SYN scan, headless crawl) | Failures or prompts | Default to non-privileged modes; prompt only when required |
| Large package size from bundled binaries | Slower distribution | Accepted trade-off for offline reliability; provide AppImage alternative |
| AI Advisor sends client data to external service | Privacy / legal exposure | Opt-in only, OFF by default; explicit consent notice; redaction option; local-LLM alternative for sensitive clients |
| AI Advisor produces confident but wrong guidance | Bad advice in deliverable | Output clearly labelled AI-generated; mandatory consultant review; easy edit/accept/discard per item |
| Build environment cannot preview GUI | Visual issues found late | Build to run on Kali; iterate on visuals with user feedback |

---

## 12. Open questions

1. Should scheduled SOC re-scans run while the app is closed (background service), or only while the app is open? (Current assumption: only while open in v1.)
2. What is the default scope for a quick scan — single domain only, or domain plus discovered subdomains? (Current assumption: domain plus discovered subdomains.)
3. Should the PDF be customizable with the consultancy's logo and branding in v1, or a later release? (Current assumption: later release.)

---

*End of document.*
