# Phase 1 Design — App Skeleton

**Date:** 2026-06-01  
**Status:** Approved  
**Phase:** 1 of 7 — App skeleton: main window, dark theme, navigation, unified-view shell

---

## 1. Goal

Deliver a runnable PyQt6 application with a complete visual shell: collapsible sidebar navigation, dark cyberpunk theme, five screen placeholders, and a persistent tool-health status bar. No scan engine, no database, no network calls. Every panel that Phase 3+ will populate is represented as a labelled placeholder frame so layout is designed once.

---

## 2. Project structure

```
secureops/
├── main.py                  # entry point: python -m secureops (or python main.py)
├── app.py                   # QApplication setup, global QSS dark theme
├── main_window.py           # QMainWindow — sidebar + QStackedWidget + status bar
├── sidebar.py               # collapsible icon-only sidebar, expands on hover
├── status_bar.py            # bottom strip — tool health pill
├── tool_checker.py          # shutil.which() check for all 9 tools on startup
└── screens/
    ├── __init__.py
    ├── dashboard.py          # metric cards + placeholder panels
    ├── client_onboarding.py  # client form shell
    ├── scan_view.py          # 5-panel grid skeleton + target input
    ├── report.py             # placeholder report surface + disabled PDF export
    └── settings.py           # tool status detail panel + path overrides
```

---

## 3. Theme

Applied as a single `QSS` stylesheet at `QApplication` level in `app.py`.

| Token | Value | Use |
|-------|-------|-----|
| Background | `#0a0e1a` | Main window, panels |
| Surface | `#111827` | Cards, sidebar |
| Border | `#1e2d40` | Panel outlines |
| Accent cyan | `#00d4ff` | Active nav, highlights |
| Accent green | `#00ff88` | Success, tool OK |
| Accent amber | `#ffaa00` | Warning, partial tools |
| Accent red | `#ff4444` | Error, critical tools missing |
| Text primary | `#e2e8f0` | Body copy |
| Text muted | `#64748b` | Placeholders, labels |
| Font UI | `Inter` / system sans | Navigation, labels |
| Font mono | `JetBrains Mono` / `monospace` | Terminal feed, data |

Subtle `1px` cyan border on all placeholder `QFrame` panels. No scanline/glow effects in Phase 1 — those come with Phase 3 live visuals.

---

## 4. Sidebar

**File:** `sidebar.py`  
**Class:** `Sidebar(QWidget)`

- Collapsed width: **52px** (icon only)
- Expanded width: **180px** (icon + label)
- Expands on `enterEvent`, collapses on `leaveEvent`
- Animation: `QPropertyAnimation` on `maximumWidth`, 150ms, `InOutQuad` easing

**Signal:** `screen_changed = pyqtSignal(int)` — emitted on nav button click, connected to `QStackedWidget.setCurrentIndex()` in `main_window.py`.

**Nav items (top to bottom):**

| Icon | Label | Stack index |
|------|-------|-------------|
| `⊞` | Dashboard | 0 |
| `+` | New Client | 1 |
| `⚡` | Scan | 2 |
| `📄` | Report | 3 |
| `⚙` | Settings | 4 |

- Active item: cyan left border (`3px`) + darkened background
- Tooltip on each button showing screen name (visible when collapsed)
- Logo/wordmark at top: icon-only when collapsed, `SECUREOPS` wordmark when expanded
- Version label (`v0.1.0`) pinned to bottom

---

## 5. Screen shells

### 5.1 Dashboard (`screens/dashboard.py`)

**Top row — 3 metric cards:**
```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Clients    │  │   Scans     │  │  Findings   │
│     0       │  │     0       │  │     0       │
└─────────────┘  └─────────────┘  └─────────────┘
```

**Middle row — 2-column layout:**
- Left: Attack Surface Graph placeholder (`QFrame`, label: `"Attack Surface Graph — live in Phase 3"`)
- Right: Threat Feed placeholder (`QFrame`, label: `"Threat Feed — live in Phase 3"`)

**Bottom row — severity strip:**
```
● Critical  0    ● High  0    ● Medium  0    ● Low  0
```
Coloured dots (red / orange / yellow / blue), counts as `QLabel`.

**Conditional banner** (shown only when critical tools missing):
```
⚠  Critical tools missing — check Settings
```
Non-blocking `QLabel` strip between metric cards and middle row, amber background.

---

### 5.2 Client Onboarding (`screens/client_onboarding.py`)

Form shell — no database wiring in Phase 1.

Fields:
- Company Name (`QLineEdit`)
- Domain (`QLineEdit`, placeholder: `example.com`)
- Firewall Type (`QComboBox`: None, pfSense, Cisco ASA, Fortinet, Other)
- Notes (`QTextEdit`, 3 rows)

`Save Client` button — in Phase 1 shows a temporary `"Client saved (not persisted yet)"` label for 2 seconds, then clears.

---

### 5.3 Scan — Unified View (`screens/scan_view.py`)

**Top bar:** Target input (`QLineEdit`) + `Start Scan` button (disabled in Phase 1, enabled in Phase 2).

**5-panel grid skeleton:**

```
┌──────────────────┬───────────────────────────────┐
│  Pipeline        │                               │
│  Tracker         │   Attack Surface Graph        │
│  (Phase 3)       │   (Phase 3)                   │
├────┬─────────────┴───────────────────────────────┤
│Sev │                                             │
│Ring│   Finding Cards stream (Phase 3)            │
│(P3)│                                             │
├────┴─────────────────────────────────────────────┤
│  Terminal Feed (Phase 3)                         │
└──────────────────────────────────────────────────┘
```

Each panel is a `QFrame` with a `1px` cyan border and a centered muted label naming the panel and its phase. Grid implemented with `QSplitter` (vertical + horizontal) so panels are resizable. Initial size ratios: top row 40% height / bottom terminal 20% height / middle row 40% height; left column (pipeline + severity) 25% width / right column 75% width.

---

### 5.4 Report (`screens/report.py`)

Single placeholder panel:
- Label: `"Report assembles here during scan — Phase 4"`
- `Export PDF` button — permanently disabled in Phase 1, enabled in Phase 4
- Muted subtitle: `"Run a scan to generate a report"`

---

### 5.5 Settings (`screens/settings.py`)

**Tool status panel** — 9 rows, one per tool:

| Tool | Status |
|------|--------|
| subfinder | ✓ / ✗ |
| dnsx | ✓ / ✗ |
| naabu | ✓ / ✗ |
| httpx | ✓ / ✗ |
| katana | ✓ / ✗ |
| nuclei | ✓ / ✗ |
| nmap | ✓ / ✗ |
| nikto | ✓ / ✗ |
| testssl.sh | ✓ / ✗ |

Critical tools (subfinder, nuclei, nmap) flagged with `[CRITICAL]` label. Each row has a path override `QLineEdit` pre-populated from `shutil.which()` result. `Save Paths` button at the bottom (no-op in Phase 1, wired in Phase 2).

---

## 6. Status bar

**File:** `status_bar.py`  
**Class:** `ToolStatusBar(QWidget)`

Persistent strip pinned to the bottom of `QMainWindow`.

Content: `Tools: N/9 ready  ●`

| State | Dot colour | Condition |
|-------|-----------|-----------|
| All ready | Green `#00ff88` | All 9 tools found |
| Partial | Amber `#ffaa00` | Some non-critical tools missing |
| Critical missing | Red `#ff4444` | Any of subfinder / nuclei / nmap missing |

Clicking the status bar navigates directly to Settings (index 4).

---

## 7. Tool checker

**File:** `tool_checker.py`  
**Function:** `check_tools() -> dict[str, bool]`

Runs synchronously at startup before the main window is shown. Uses `shutil.which()` for each of the 9 tools. Fast — no threads needed.

Returns:
```python
{
    "subfinder": True,
    "dnsx": False,
    ...
}
```

Result dict passed as constructor argument to `MainWindow`, which forwards it to `ToolStatusBar` and `SettingsScreen`.

---

## 8. Error handling

The only failure surface in Phase 1 is the tool check. All 9 failures are handled by the status bar + settings panel. The app always launches regardless of tool availability. No other error handling needed — no scan engine, no I/O, no network.

---

## 9. Out of scope for Phase 1

- Any real scan execution
- Database (SQLite wired in Phase 2)
- Signal/slot wiring between screens (Phase 2+)
- Animations on panels beyond sidebar hover (Phase 3)
- PDF export (Phase 4)
- AI Advisor (Phase 6)
