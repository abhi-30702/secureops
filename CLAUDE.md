# SecureOps — Claude Working Context

## Project summary

SecureOps is a standalone PyQt6 desktop penetration-testing and security-audit application for Kali Linux. It orchestrates 9 open-source scanning tools (subfinder, dnsx, naabu, httpx, katana, nuclei, nmap, nikto, testssl.sh) through a single UI, assembles findings into a live report, and exports a professional PDF.

**Owner:** Abhishek K  
**PRD:** `PRD.md`  
**Stack:** PyQt6, pyqtgraph, QThread workers, SQLite, ReportLab, PyInstaller → .deb / .AppImage  
**Optional:** AI Advisor via Anthropic Claude SDK or Ollama (opt-in, OFF by default)

## Build phases

| # | Phase | Status |
|---|-------|--------|
| 1 | App skeleton — main window, dark theme, navigation, unified-view shell | Complete |
| 2 | Scan engine — 8 threaded tool wrappers, chaining, SQLite persistence | Complete |
| 3 | Live visuals — pipeline tracker, severity rings, attack-surface graph, streaming cards | Complete |
| 4 | Final report + professional PDF export | Complete |
| 5 | Continuous monitoring (SOC) and scheduling | Complete |
| 6 | AI Advisor agent (opt-in, consent, redaction, local-LLM alt) | Complete |
| 7 | Packaging — .deb and .AppImage, bundled tools | Not started |

## Key constraints (never violate)

- UI must never freeze — all scans on QThread
- Single tool failure must never crash the app or stop the pipeline
- Fully offline by default — nothing leaves the machine unless AI Advisor explicitly enabled
- No exploitation features — detection, recon, and reporting only
- AI Advisor is strictly defensive (no exploit suggestions), opt-in, with explicit consent notice

## Deferred tasks ("let's do it later" log)

| Date | What was deferred | Context / notes |
|------|-------------------|-----------------|
| 2026-06-02 | ~~Phase 3 subagent-driven implementation~~ | Completed 2026-06-03. |
| 2026-06-03 | ~~Phases 6 & 7 implementation~~ | Phase 6 completed 2026-06-03. Phase 7 still pending. |
| 2026-06-03 | AI Advisor: redaction option (FR-30) | Strip client-identifying details before sending to Gemini. Explicitly out-of-scope for Phase 6. |
| 2026-06-03 | AI Advisor: local-LLM backend (FR-31) | Ollama support as offline alternative to Gemini. Explicitly out-of-scope for Phase 6. |
| 2026-06-03 | ~~Phase 7 implementation~~ | Tasks 1-3 completed 2026-06-04. Tasks 4-6 deferred. |
| 2026-06-04 | Phase 7 Tasks 4-6 (packaging files + build.sh + .gitignore) | Tasks 1 (tool_checker.py), 2 (base_tool.py), 3 (requirements.txt + secureops.spec) done. Remaining: Task 4 (packaging/ metadata + test_packaging.py), Task 5 (build.sh), Task 6 (.gitignore). Resume with superpowers:subagent-driven-development from Task 4. |

---

## "Let's do it later" instruction

Whenever the user types **"let's do it later"**, immediately:
1. Identify what we were actively working on or discussing.
2. Append it to the **Deferred tasks** table above with today's date.
3. Confirm in one sentence what was saved.

Format for deferred entries:
| Date | What was deferred | Context / notes |
|------|-------------------|-----------------|
| YYYY-MM-DD | Short description | Any relevant detail |
