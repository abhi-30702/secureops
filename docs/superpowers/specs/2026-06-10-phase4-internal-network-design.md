# Phase 4 — Internal Network Scanning Design

**Date:** 2026-06-10
**Status:** Approved
**Scope:** Internal subnet sweep, device fingerprinting, topology map, dedicated Internal page

---

## 1. Goals

- Sweep one or more subnet ranges for live hosts using nmap (non-privileged)
- Fingerprint each host's device type from its open ports and services
- Visualise the discovered network as a subnet-grouped topology map
- Integrate findings into the existing report and PDF pipeline
- Allow subnet ranges to be pre-configured in Settings or typed ad-hoc on the Internal page

## 2. Non-goals

- OS detection via nmap `-O` (requires root — deferred)
- Lateral movement tracking or breach trail (Phase 5)
- SNMP or CDP/LLDP neighbour discovery
- Authenticated scanning (SSH/WMI)
- Scheduled internal sweeps (Phase 9)

---

## 3. Architecture overview

```
InternalPage (screens/internal_page.py)
├── subnet chip bar   ← pre-filled from Settings, editable inline
├── Start / Stop button
├── TopologyGraph     ← screens/widgets/topology_graph.py  (new)
├── SeverityRings     ← reused as-is
├── FindingCards      ← reused as-is
└── terminal strip    ← QPlainTextEdit, collapsible

InternalWorker (workers/internal_worker.py)   QThread
├── Stage 1: nmap -sn -T4 <subnets>  →  list[str] live IPs
└── Stage 2: nmap -sV -T4 --open -oX - <all live IPs>
            → parse XML
            → _classify_device(open_ports) → device_type str
            → emit finding_found(Finding) per host
            → emit scan_complete(hosts, findings) when done

Sidebar: new nav item "Internal" at index 5
MainWindow: InternalPage at stack index 5
```

### Signal contract

`InternalWorker` emits the same four signals as `ScanWorker` and `LogAnalyzerWorker`:

```python
finding_found = pyqtSignal(object)   # Finding per discovered host
log_line      = pyqtSignal(str)      # raw nmap output line → terminal
scan_complete = pyqtSignal(int, int) # hosts_found, findings_count
scan_failed   = pyqtSignal(str)      # fatal error message
```

---

## 4. `InternalWorker`

**File:** `workers/internal_worker.py`

### Stage 1 — ping sweep

```
nmap -sn -T4 -oX - <subnet1> [<subnet2> ...]
```

Parses XML: collects all `<host>` elements where `<status state="up"/>`, extracts IPv4 address. Emits one `log_line` per live host: `"[internal] live: 192.168.1.42"`. If zero hosts found, emits `scan_complete(0, 0)` and returns.

### Stage 2 — service scan

Runs a single nmap command against all live IPs:

```
nmap -sV -T4 --open -oX - <ip1> <ip2> ...
```

For each host in XML output:
1. Collect all open port numbers
2. Call `_classify_device(open_ports)` → device type string
3. Build one `Finding` with:
   - `tool = "nmap-internal"`
   - `severity = "info"`
   - `title = "{device_type} — {ip}"`
   - `description = "Open ports: {comma-separated port/service list}"`
4. Write to SQLite via `db.insert_finding(finding)`
5. Emit `finding_found(finding)`
6. Emit `log_line`: `"[internal] 192.168.1.42 — server (22/ssh, 80/http, 443/https)"`

On completion: `scan_complete(len(live_ips), len(findings))`.

### Device classification — `_classify_device(ports: list[int]) -> str`

Evaluated in priority order (first match wins):

| Ports present | Device type |
|---------------|-------------|
| 53 or 23 or 179 | `router` |
| 3389 or 445 | `workstation` |
| 515 or 631 or 9100 | `printer` |
| 1883 or 8883 or 102 | `iot` |
| 80 or 443 (with or without 22) | `server` |
| 22 only | `server` |
| _(no match)_ | `unknown` |

### Cancellation

`stop()` sets `self._cancelled = True` and calls `.kill()` on the running subprocess. Worker checks `_cancelled` between stages and after nmap completes.

### Error handling

| Condition | Behaviour |
|-----------|-----------|
| nmap not found | `scan_failed.emit("nmap not found — install with: apt install nmap")` |
| Stage 1 produces no XML | `scan_complete(0, 0)` with log line |
| Stage 2 nmap fails on parse | log error, treat as zero findings for that batch |
| Stage 2 subprocess error | `scan_failed.emit(...)` |

---

## 5. `TopologyGraph` widget

**File:** `screens/widgets/topology_graph.py`

### Layout model

- Subnet anchor nodes placed in a fixed ring around the canvas centre, evenly spaced by angle
- Device nodes orbit their subnet anchor at a fixed radius, evenly spaced by angle
- A light edge connects each device node to its subnet anchor
- Positions are recomputed geometrically on every `add_host()` call — no simulation, no timer

### Node appearance

| Type | Colour | Size |
|------|--------|------|
| subnet | `#00e5ff` (CYAN) | 18 |
| router | `#ffb300` (AMBER) | 14 |
| server | `#00ff88` (GREEN) | 12 |
| workstation | `#4488ff` | 10 |
| printer | `#7a9bc4` | 9 |
| iot | `#ff3d57` (RED) | 9 |
| unknown | `#3d5a7a` | 8 |

Colours defined as module-level constants inline (same pattern as `attack_graph.py` — no external import needed).

### Public API

```python
def reset(self) -> None
def add_host(self, ip: str, device_type: str, ports: list[int]) -> None
```

`add_host` derives the /24 subnet key from `ip` (`".".join(ip.split(".")[:3]) + ".0/24"`), creates a subnet anchor node if this is the first host in that subnet, then adds the device node and edge.

### Tooltips

Hovering a node shows `"{ip}\\n{device_type}\\nPorts: {port list}"` via `pg.ScatterPlotItem` mouse-hover event.

---

## 6. `InternalPage` UI

**File:** `screens/internal_page.py`

### Layout

```
┌─ top bar ─────────────────────────────────────────────────────┐
│  [192.168.1.0/24        ] [+ Add]        [Start Sweep]        │
│  chips: [192.168.1.0/24 ×]  [10.0.0.0/24 ×]                 │
│  status label (idle / sweeping / N hosts, M findings)         │
└───────────────────────────────────────────────────────────────┘
┌─ left 60% ──────────────────┐  ┌─ right 40% ─────────────────┐
│  TopologyGraph               │  │  SeverityRings              │
│                              │  │  ────────────               │
│                              │  │  FindingCards               │
└──────────────────────────────┘  └─────────────────────────────┘
┌─ terminal strip (QPlainTextEdit, read-only) ──────────────────┐
```

### Subnet chip bar

- Text input + "Add" button; pressing Enter also adds
- Each chip is a `QPushButton` with "×" that removes it from the list
- On init: reads `db.get_setting("internal_subnets")` (comma-separated), creates chips for each non-empty entry
- Validation on Start: each range passed through `ipaddress.ip_network(range, strict=False)`; invalid ranges shown with a red status label, Start blocked

### Start / Stop behaviour

- **Start:** validates ranges, creates a `Scan` record in SQLite, starts `InternalWorker`
- Button label changes to "Stop Sweep" while running
- **Stop:** calls `worker.stop()`, updates scan status to `"cancelled"` in DB
- On `scan_complete`: button reverts to "Start Sweep", status label shows summary, `scan_ready` signal emitted

### `scan_ready` signal

```python
scan_ready = pyqtSignal(int)   # scan_id → MainWindow navigates to Report
```

Same pattern as `ScanViewScreen`.

---

## 7. Sidebar + MainWindow wiring

**`sidebar.py`** — append to `_NAV_ITEMS`:
```python
("⬡", "Internal", 5),
```

**`main_window.py`** — add import and stack entry:
```python
from screens.internal_page import InternalPage
...
self._internal = InternalPage(db=self._db)
self._stack.addWidget(self._internal)   # index 5
self._internal.scan_ready.connect(self._on_scan_ready)
```

---

## 8. Settings integration

**`screens/settings.py`** — add a "Subnet Ranges" row to the existing settings form:
- `QLineEdit` labelled "Internal subnet ranges (comma-separated)"
- Reads from / saves to `db.get_setting("internal_subnets")` / `db.save_setting("internal_subnets", value)`
- Placeholder: `"192.168.1.0/24, 10.0.0.0/24"`

`InternalPage` reads this setting at init and again each time the page is shown (via `showEvent`).

---

## 9. Testing

**`tests/test_internal_worker.py`**
- `_classify_device` unit tests: port 53 → router, port 3389 → workstation, port 1883 → iot, ports 80+443 → server, empty ports → unknown, mixed ports (priority order correct)
- Stage 1 zero-hosts: worker emits `scan_complete(0, 0)` without running Stage 2
- `stop()` sets cancelled flag before stage 2 starts
- Worker emits `finding_found` for each host in Stage 2 output
- `scan_failed` emitted when nmap binary missing

**`tests/test_topology_graph.py`** (no Qt runtime — test geometry logic only)
- `add_host` with two IPs in same /24 → one subnet anchor, two device nodes
- `add_host` with IPs in different /24s → two subnet anchors
- `reset()` clears all nodes
- Subnet key derivation: `"192.168.1.42"` → `"192.168.1.0/24"`

---

## 10. File map

| Action | Path |
|--------|------|
| Create | `workers/internal_worker.py` |
| Create | `screens/internal_page.py` |
| Create | `screens/widgets/topology_graph.py` |
| Modify | `sidebar.py` — add Internal nav item |
| Modify | `main_window.py` — add InternalPage at index 5 |
| Modify | `screens/settings.py` — add subnet ranges field |
| Create | `tests/test_internal_worker.py` |
| Create | `tests/test_topology_graph.py` |

---

## 11. Acceptance criteria

1. Entering `192.168.x.0/24` and clicking Start Sweep discovers all live hosts on that subnet
2. Each host appears as a node in `TopologyGraph` grouped under its subnet anchor
3. Device types are correctly classified from open ports (router, server, workstation, printer, iot, unknown)
4. Findings write to SQLite immediately as each host is scanned
5. When sweep completes, Report screen loads showing all internal findings
6. Stop button cancels the sweep cleanly — no hanging subprocess
7. Invalid subnet format shows red error label and blocks Start
8. Subnet ranges pre-fill from Settings; changes on the Internal page do not overwrite Settings
9. All new tests pass; no regressions in existing test suite
