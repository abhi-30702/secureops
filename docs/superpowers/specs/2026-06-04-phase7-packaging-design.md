# Phase 7 — Packaging Design

**Date:** 2026-06-04  
**Status:** Approved  
**Scope:** `.deb` and `.AppImage` distribution packages for SecureOps on Kali Linux (amd64)

---

## 1. Goals

- Produce a `secureops_VERSION_amd64.deb` installable on Kali Linux via `dpkg -i`
- Produce a `SecureOps-VERSION-x86_64.AppImage` runnable on any x86-64 Linux without installation
- Bundle the six ProjectDiscovery Go tools (subfinder, dnsx, naabu, httpx, katana, nuclei) at pinned versions for fully offline operation
- Declare nmap, nikto, and testssl.sh as `.deb` dependencies (Kali-native); detect them from PATH at runtime for the AppImage
- Version number has a single source of truth: `app.py` (`setApplicationVersion`)

## 2. Non-goals

- arm64 or any architecture other than amd64
- Windows or macOS packaging
- Bundling nmap, nikto, or testssl.sh inside the AppImage
- CI/CD pipeline (local build only for v1)
- Auto-update mechanism

---

## 3. Repository layout

New files added to the repo:

```
secureops/
├── build.sh                        # Main build orchestration script
├── secureops.spec                  # PyInstaller spec file
├── packaging/
│   ├── tool_versions.sh            # Pinned Go tool versions (sourced by build.sh)
│   ├── deb/
│   │   └── DEBIAN/
│   │       ├── control             # .deb metadata template
│   │       ├── postinst            # Post-install chmod script
│   │       └── copyright           # License notice
│   └── appimage/
│       ├── AppRun                  # AppImage entry script
│       ├── secureops.desktop       # .desktop file (shared for both formats)
│       └── secureops.svg           # App icon
└── dist/                           # Build output — gitignored
```

`dist/` is added to `.gitignore`.

---

## 4. Build script stages

`build.sh` runs four sequential stages. Usage: `./build.sh`

### Stage 1 — Fetch Go tools

Sources `packaging/tool_versions.sh`. For each of the six tools, downloads the amd64 zip from:
```
https://github.com/projectdiscovery/{tool}/releases/download/v{VERSION}/{tool}_{VERSION}_linux_amd64.zip
```
Extracts the binary to `dist/tools/`, makes it executable. Skips if the binary already exists (incremental rebuild). Deletes the zip after extraction.

### Stage 2 — PyInstaller

Runs `pyinstaller secureops.spec --noconfirm`, producing `dist/secureops/` (onedir). Then copies `dist/tools/` into `dist/secureops/tools/`.

### Stage 3 — Build .deb

Assembles a staging tree under `dist/deb-staging/`:
```
dist/deb-staging/
├── DEBIAN/            ← control, postinst, copyright
├── opt/secureops/     ← PyInstaller onedir output
└── usr/
    ├── local/bin/secureops         ← thin shell launcher
    └── share/
        ├── applications/secureops.desktop
        └── pixmaps/secureops.svg
```
Runs `dpkg-deb --build --root-owner-group dist/deb-staging dist/secureops_VERSION_amd64.deb`.

### Stage 4 — Build .AppImage

Downloads `appimagetool` into `dist/` once if not cached. Assembles `dist/AppDir/`:
```
dist/AppDir/
├── AppRun
├── secureops.desktop
├── secureops.svg
└── usr/bin/
    ├── secureops
    ├── _internal/
    └── tools/
```
Runs `ARCH=x86_64 dist/appimagetool dist/AppDir dist/SecureOps-VERSION-x86_64.AppImage`.

---

## 5. Tool version pinning

`packaging/tool_versions.sh`:

```bash
SUBFINDER_VERSION="2.6.6"
DNSX_VERSION="1.2.0"
NAABU_VERSION="2.3.1"
HTTPX_VERSION="1.6.10"
KATANA_VERSION="1.1.2"
NUCLEI_VERSION="3.3.9"
```

To upgrade a tool: bump the version here and delete the cached binary from `dist/tools/`.

---

## 6. PyInstaller spec (`secureops.spec`)

- **Mode:** `--onedir` (not onefile) — faster startup, transparent layout, `tools/` sits cleanly beside the executable
- **Entry point:** `main.py`
- **Hidden imports:**
  - `PyQt6.QtSvg`, `PyQt6.sip`
  - `pyqtgraph`
  - `reportlab.graphics`, `reportlab.platypus`
  - `google.generativeai`, `google.auth`, `google.auth.transport` (lazy import — must be explicit)
- **Datas:** none — the SQLite DB is user data at `~/.secureops/secureops.db`
- **Qt plugins:** handled automatically by `pyinstaller-hooks-contrib`

Output layout:
```
dist/secureops/
├── secureops           ← launcher executable
├── _internal/          ← Python runtime + .so libs
└── tools/
    ├── subfinder
    ├── dnsx
    ├── naabu
    ├── httpx
    ├── katana
    └── nuclei
```

---

## 7. Source code change — `tool_checker.py` and `base_tool.py`

The only source code change in Phase 7: teach the app to find bundled tools when frozen.

**`tool_checker.py`** — add `_tool_path()` helper:

```python
def _tool_path(name: str) -> str | None:
    if getattr(sys, 'frozen', False):
        bundled = Path(sys.executable).parent / "tools" / name
        if bundled.is_file():
            return str(bundled)
    return shutil.which(name)

def check_tools() -> dict:
    return {tool: _tool_path(tool) is not None for tool in TOOLS}
```

**`workers/base_tool.py`** — resolve `cmd[0]` through `_tool_path()` at the top of `run()` and `run_buffered()`, so all 9 tool wrappers get bundled-path resolution without touching each file individually:

```python
from tool_checker import _tool_path

class ToolRunner:
    def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        # ... rest of method uses resolved instead of cmd

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        # ... rest of method uses resolved instead of cmd
```

No changes needed to any individual tool file (subfinder.py, dnsx.py, etc.).

---

## 8. .deb package metadata

`DEBIAN/control`:
```
Package: secureops
Version: {VERSION}
Architecture: amd64
Maintainer: Abhishek K <abhi30702@gmail.com>
Depends: nmap, nikto, testssl.sh
Section: net
Priority: optional
Description: SecureOps — penetration testing and security audit platform
 Orchestrates subfinder, dnsx, naabu, httpx, katana, nuclei, nmap,
 nikto, and testssl.sh through a single PyQt6 UI with live reporting
 and professional PDF export.
```

Install paths:
- App: `/opt/secureops/`
- CLI launcher: `/usr/local/bin/secureops` → `exec /opt/secureops/secureops "$@"`
- Desktop entry: `/usr/share/applications/secureops.desktop`
- Icon: `/usr/share/pixmaps/secureops.svg`

`DEBIAN/postinst` sets executable bits on the app binary and bundled tools after install.

---

## 9. .AppImage structure

`AppRun`:
```bash
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/secureops" "$@"
```

`secureops.desktop`:
```ini
[Desktop Entry]
Name=SecureOps
Comment=Penetration testing and security audit platform
Exec=secureops
Icon=secureops
Type=Application
Categories=Network;Security;
```

The AppImage is a single self-contained file. Users `chmod +x SecureOps-*.AppImage && ./SecureOps-*.AppImage`. nmap, nikto, and testssl.sh must be present on the system; the app reports missing tools at startup via the existing `tool_checker.py` mechanism.

---

## 10. Acceptance criteria

1. `./build.sh` completes without errors on Kali Linux (amd64) with `curl`, `unzip`, `dpkg-deb`, and an internet connection
2. `dpkg -i secureops_VERSION_amd64.deb` installs cleanly; `secureops` launches from terminal and application menu
3. `./SecureOps-VERSION-x86_64.AppImage` runs directly after `chmod +x`
4. Both packages launch the app, pass `tool_checker.py` startup checks, and complete a full scan end-to-end
5. The bundled Go binaries are used (not system PATH versions) when the app is frozen
6. Removing the package (`dpkg -r secureops`) leaves no files outside `/opt/secureops/` and `/usr/`
