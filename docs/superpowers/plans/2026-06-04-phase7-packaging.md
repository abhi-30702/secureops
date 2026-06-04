# Phase 7 — Packaging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a `secureops_VERSION_amd64.deb` and a `SecureOps-VERSION-x86_64.AppImage` from a single `./build.sh` command, bundling the six ProjectDiscovery Go tools at pinned versions for fully offline operation.

**Architecture:** PyInstaller (onedir mode) bundles the Python app and all Python deps into `dist/secureops/`. `build.sh` downloads pinned Go binaries, runs PyInstaller, then assembles both package formats from the same output. Two source files (`tool_checker.py`, `workers/base_tool.py`) are modified to resolve bundled tool paths when the app is running frozen.

**Tech Stack:** PyInstaller 6.x, dpkg-deb (Kali-native), appimagetool (downloaded once), bash, curl, unzip.

---

## File map

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `tool_checker.py` | Add `_tool_path()` — bundled path lookup when frozen |
| Modify | `workers/base_tool.py` | Import `_tool_path`, resolve `cmd[0]` before subprocess |
| Modify | `requirements.txt` | Add `pyqtgraph` and `reportlab` (missing runtime deps) |
| Create | `secureops.spec` | PyInstaller build spec |
| Create | `packaging/tool_versions.sh` | Pinned Go tool versions |
| Create | `packaging/deb/DEBIAN/control` | .deb package metadata template |
| Create | `packaging/deb/DEBIAN/postinst` | Post-install chmod script |
| Create | `packaging/deb/DEBIAN/copyright` | License notice |
| Create | `packaging/appimage/AppRun` | AppImage entry script |
| Create | `packaging/appimage/secureops.desktop` | Desktop integration (shared by both formats) |
| Create | `packaging/appimage/secureops.svg` | App icon |
| Create | `build.sh` | Main build orchestration script |
| Create | `.gitignore` | Exclude `dist/` and build artifacts |
| Create | `tests/test_packaging.py` | Infrastructure tests for packaging files |
| Modify | `tests/test_tool_checker.py` | Tests for `_tool_path()` |
| Modify | `tests/test_base_tool.py` | Tests for resolved subprocess cmd |

---

### Task 1: Update tool_checker.py — bundled path resolution

**Files:**
- Modify: `tool_checker.py`
- Modify: `tests/test_tool_checker.py`

- [ ] **Step 1: Establish baseline test count**

Run: `pytest tests/test_tool_checker.py -v`
Note the number of passing tests.

- [ ] **Step 2: Write failing tests for `_tool_path()`**

Open `tests/test_tool_checker.py`. Make three changes:

**a)** Replace the existing import at line 1-2:
```python
from unittest.mock import patch
from tool_checker import check_tools, is_critical_missing, ready_count, TOOLS, CRITICAL_TOOLS
```
with:
```python
import sys
import shutil as _shutil
from unittest.mock import patch
from tool_checker import _tool_path, check_tools, is_critical_missing, ready_count, TOOLS, CRITICAL_TOOLS
```

**b)** Add these tests at the end of the file (after existing tests):

```python
def test_tool_path_not_frozen_uses_which(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: f'/usr/bin/{name}')
    assert _tool_path('nmap') == '/usr/bin/nmap'


def test_tool_path_not_frozen_returns_none_when_missing(monkeypatch):
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: None)
    assert _tool_path('missing_tool') is None


def test_tool_path_frozen_returns_bundled_when_exists(tmp_path, monkeypatch):
    tools_dir = tmp_path / 'tools'
    tools_dir.mkdir()
    bundled = tools_dir / 'subfinder'
    bundled.write_text('binary')
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    assert _tool_path('subfinder') == str(bundled)


def test_tool_path_frozen_falls_back_to_which_when_not_bundled(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: f'/usr/bin/{name}')
    assert _tool_path('nmap') == '/usr/bin/nmap'


def test_tool_path_frozen_returns_none_when_not_found_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(tmp_path / 'secureops'), raising=False)
    monkeypatch.setattr(_shutil, 'which', lambda name: None)
    assert _tool_path('nonexistent') is None


def test_check_tools_uses_tool_path(monkeypatch):
    monkeypatch.setattr('tool_checker._tool_path', lambda name: '/fake' if name == 'nmap' else None)
    from tool_checker import check_tools
    results = check_tools()
    assert results['nmap'] is True
    assert results['subfinder'] is False
```

- [ ] **Step 3: Run tests to confirm they fail**

Run: `pytest tests/test_tool_checker.py -v`
Expected: ALL tests in the file fail — `ImportError: cannot import name '_tool_path' from 'tool_checker'` (the import at line 4 fails, which prevents the entire module from loading)

- [ ] **Step 4: Implement `_tool_path()` in tool_checker.py**

Replace the entire content of `tool_checker.py` with:

```python
import shutil
import sys
from pathlib import Path

TOOLS = [
    "subfinder", "dnsx", "naabu", "httpx", "katana",
    "nuclei", "nmap", "nikto", "testssl.sh",
]

CRITICAL_TOOLS = {"subfinder", "nuclei", "nmap"}


def _tool_path(name: str) -> str | None:
    if getattr(sys, 'frozen', False):
        bundled = Path(sys.executable).parent / "tools" / name
        if bundled.is_file():
            return str(bundled)
    return shutil.which(name)


def check_tools() -> dict:
    return {tool: _tool_path(tool) is not None for tool in TOOLS}


def is_critical_missing(results: dict) -> bool:
    return any(not results.get(t, False) for t in CRITICAL_TOOLS)


def ready_count(results: dict) -> int:
    return sum(1 for v in results.values() if v)
```

- [ ] **Step 5: Run all tool_checker tests**

Run: `pytest tests/test_tool_checker.py -v`
Expected: All pass (baseline count + 6 new tests)

- [ ] **Step 6: Run full test suite to check for regressions**

Run: `pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add tool_checker.py tests/test_tool_checker.py
git commit -m "feat: resolve bundled tool paths when app is frozen (PyInstaller)"
```

---

### Task 2: Update workers/base_tool.py — use bundled tool paths

**Files:**
- Modify: `workers/base_tool.py`
- Modify: `tests/test_base_tool.py`

- [ ] **Step 1: Establish baseline test count**

Run: `pytest tests/test_base_tool.py -v`
Note the number of passing tests.

- [ ] **Step 2: Write failing tests**

Open `tests/test_base_tool.py`. Add these tests at the end of the file (the file already imports `threading`, `MagicMock`, `ToolRunner`, `ToolError`):

```python
def test_run_resolves_cmd0_through_tool_path(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None
        return mock_proc

    monkeypatch.setattr('workers.base_tool._tool_path',
                        lambda name: f'/opt/secureops/tools/{name}',
                        raising=False)
    with patch('subprocess.Popen', fake_popen):
        list(runner.run(['subfinder', '-d', 'example.com']))

    assert captured['cmd'][0] == '/opt/secureops/tools/subfinder'
    assert captured['cmd'][1:] == ['-d', 'example.com']


def test_run_buffered_resolves_cmd0_through_tool_path(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_run(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ''
        return mock_result

    monkeypatch.setattr('workers.base_tool._tool_path',
                        lambda name: f'/opt/secureops/tools/{name}',
                        raising=False)
    with patch('subprocess.run', fake_run):
        runner.run_buffered(['nmap', '-sV', '10.0.0.1'])

    assert captured['cmd'][0] == '/opt/secureops/tools/nmap'
    assert captured['cmd'][1:] == ['-sV', '10.0.0.1']


def test_run_falls_back_to_original_name_when_tool_path_returns_none(monkeypatch):
    cancel = threading.Event()
    runner = ToolRunner(cancel)
    captured = {}

    def fake_popen(cmd, **kwargs):
        captured['cmd'] = cmd
        mock_proc = MagicMock()
        mock_proc.stdout = iter([])
        mock_proc.returncode = 0
        mock_proc.wait.return_value = None
        return mock_proc

    monkeypatch.setattr('workers.base_tool._tool_path', lambda name: None, raising=False)
    with patch('subprocess.Popen', fake_popen):
        list(runner.run(['subfinder', '-d', 'example.com']))

    assert captured['cmd'][0] == 'subfinder'
```

- [ ] **Step 3: Run new tests to confirm they fail**

Run: `pytest tests/test_base_tool.py -k "resolves_cmd or falls_back" -v`
Expected: FAIL — AssertionError on `captured['cmd'][0]` (the unmodified `run()` passes the raw tool name, not the resolved path)

- [ ] **Step 4: Update workers/base_tool.py**

Replace the entire content of `workers/base_tool.py` with:

```python
import os
import subprocess
import tempfile
import threading
from typing import Iterator

from tool_checker import _tool_path


class ToolError(Exception):
    pass


class CancelledError(Exception):
    pass


def _write_tmpfile(lines: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="secureops_")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return path


class ToolRunner:
    def __init__(self, cancel_event: threading.Event):
        self._cancel = cancel_event

    def run(self, cmd: list[str], timeout: int = 300) -> Iterator[str]:
        if self._cancel.is_set():
            raise CancelledError()
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        try:
            proc = subprocess.Popen(
                resolved,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")

        for line in proc.stdout:
            if self._cancel.is_set():
                proc.kill()
                proc.wait()
                raise CancelledError()
            stripped = line.rstrip()
            if stripped:
                yield stripped

        proc.wait()
        if proc.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {proc.returncode}")

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        if self._cancel.is_set():
            raise CancelledError()
        resolved = [_tool_path(cmd[0]) or cmd[0]] + cmd[1:]
        try:
            result = subprocess.run(
                resolved,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            raise ToolError(f"{cmd[0]}: not found")
        except subprocess.TimeoutExpired:
            raise ToolError(f"{cmd[0]}: timed out after {timeout}s")
        if self._cancel.is_set():
            raise CancelledError()
        if result.returncode != 0:
            raise ToolError(f"{cmd[0]}: exited with code {result.returncode}")
        return result.stdout
```

- [ ] **Step 5: Run all base_tool tests**

Run: `pytest tests/test_base_tool.py -v`
Expected: All pass (baseline count + 3 new tests)

- [ ] **Step 6: Run full test suite**

Run: `pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add workers/base_tool.py tests/test_base_tool.py
git commit -m "feat: resolve bundled tool paths in ToolRunner subprocess calls"
```

---

### Task 3: Update requirements.txt and write secureops.spec

**Files:**
- Modify: `requirements.txt`
- Create: `secureops.spec`

- [ ] **Step 1: Add missing runtime dependencies to requirements.txt**

`pyqtgraph` (used for attack surface graph) and `reportlab` (used for PDF export) are runtime dependencies missing from `requirements.txt`. Replace the file content with:

```
PyQt6>=6.6.0
pyqtgraph>=0.13.0
reportlab>=4.0.0
pytest>=8.0.0
pytest-qt>=4.4.0
google-generativeai>=0.8.0
```

- [ ] **Step 2: Install updated requirements**

Run: `pip install -r requirements.txt`
Expected: Installs pyqtgraph and reportlab (or confirms already installed)

- [ ] **Step 3: Run full test suite to confirm no regressions**

Run: `pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 4: Create secureops.spec in the repo root**

```python
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'PyQt6.QtSvg',
        'PyQt6.sip',
        'pyqtgraph',
        'pyqtgraph.graphicsItems',
        'pyqtgraph.widgets',
        'reportlab',
        'reportlab.graphics',
        'reportlab.graphics.renderPDF',
        'reportlab.lib',
        'reportlab.lib.colors',
        'reportlab.lib.pagesizes',
        'reportlab.lib.styles',
        'reportlab.lib.units',
        'reportlab.platypus',
        'google.generativeai',
        'google.auth',
        'google.auth.transport',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['pytest', '_pytest', 'pytest_qt'],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='secureops',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='secureops',
)
```

- [ ] **Step 5: Verify spec file is valid Python**

Run: `python3 -c "import ast; ast.parse(open('secureops.spec').read()); print('OK')"`
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add requirements.txt secureops.spec
git commit -m "chore: add pyqtgraph/reportlab to requirements, add PyInstaller spec"
```

---

### Task 4: Write packaging metadata files and infrastructure tests

**Files:**
- Create: `packaging/tool_versions.sh`
- Create: `packaging/deb/DEBIAN/control`
- Create: `packaging/deb/DEBIAN/postinst`
- Create: `packaging/deb/DEBIAN/copyright`
- Create: `packaging/appimage/AppRun`
- Create: `packaging/appimage/secureops.desktop`
- Create: `packaging/appimage/secureops.svg`
- Create: `tests/test_packaging.py`

- [ ] **Step 1: Write failing infrastructure tests**

Create `tests/test_packaging.py`:

```python
import ast
import os
import subprocess
from pathlib import Path


def test_build_script_exists_and_is_executable():
    p = Path('build.sh')
    assert p.exists(), "build.sh not found"
    assert os.access(p, os.X_OK), "build.sh not executable"


def test_build_script_syntax():
    result = subprocess.run(['bash', '-n', 'build.sh'], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed:\n{result.stderr}"


def test_tool_versions_defines_all_tools():
    content = Path('packaging/tool_versions.sh').read_text()
    for tool in ['SUBFINDER', 'DNSX', 'NAABU', 'HTTPX', 'KATANA', 'NUCLEI']:
        assert f'{tool}_VERSION=' in content, f"{tool}_VERSION missing"


def test_deb_control_has_required_fields():
    content = Path('packaging/deb/DEBIAN/control').read_text()
    assert 'Package: secureops' in content
    assert 'Architecture: amd64' in content
    assert 'Depends:' in content
    for dep in ['nmap', 'nikto', 'testssl.sh']:
        assert dep in content, f"Depends missing: {dep}"


def test_deb_postinst_is_shell_script():
    content = Path('packaging/deb/DEBIAN/postinst').read_text()
    assert content.startswith('#!/bin/sh')
    assert 'chmod' in content


def test_apprun_is_shell_script_that_launches_secureops():
    content = Path('packaging/appimage/AppRun').read_text()
    assert content.startswith('#!/bin/sh')
    assert 'secureops' in content


def test_desktop_file_has_required_fields():
    content = Path('packaging/appimage/secureops.desktop').read_text()
    assert '[Desktop Entry]' in content
    assert 'Name=SecureOps' in content
    assert 'Type=Application' in content
    assert 'Categories=' in content


def test_icon_svg_exists_and_is_xml():
    content = Path('packaging/appimage/secureops.svg').read_text()
    assert '<svg' in content


def test_pyinstaller_spec_exists_and_is_valid_python():
    content = Path('secureops.spec').read_text()
    ast.parse(content)


def test_gitignore_excludes_dist():
    content = Path('.gitignore').read_text()
    assert 'dist/' in content
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `pytest tests/test_packaging.py -v`
Expected: Most fail — files don't exist yet

- [ ] **Step 3: Create directory structure**

Run:
```bash
mkdir -p packaging/deb/DEBIAN packaging/appimage
```

- [ ] **Step 4: Create packaging/tool_versions.sh**

```bash
SUBFINDER_VERSION="2.6.6"
DNSX_VERSION="1.2.0"
NAABU_VERSION="2.3.1"
HTTPX_VERSION="1.6.10"
KATANA_VERSION="1.1.2"
NUCLEI_VERSION="3.3.9"
```

- [ ] **Step 5: Create packaging/deb/DEBIAN/control**

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

Note: `{VERSION}` is a literal template placeholder substituted by `sed` in `build.sh`.

- [ ] **Step 6: Create packaging/deb/DEBIAN/postinst**

```bash
#!/bin/sh
set -e
chmod +x /opt/secureops/secureops
find /opt/secureops/tools -type f -exec chmod +x {} \;
chmod +x /usr/local/bin/secureops
```

- [ ] **Step 7: Create packaging/deb/DEBIAN/copyright**

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: secureops
Upstream-Contact: Abhishek K <abhi30702@gmail.com>
Source: https://github.com/abhi-30702/secureops

Files: *
Copyright: 2024 Abhishek K
License: MIT

License: MIT
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 .
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 .
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
```

- [ ] **Step 8: Create packaging/appimage/AppRun**

```bash
#!/bin/sh
HERE="$(dirname "$(readlink -f "$0")")"
exec "$HERE/usr/bin/secureops" "$@"
```

Then make it executable:
```bash
chmod +x packaging/appimage/AppRun
```

- [ ] **Step 9: Create packaging/appimage/secureops.desktop**

```ini
[Desktop Entry]
Name=SecureOps
Comment=Penetration testing and security audit platform
Exec=secureops
Icon=secureops
Type=Application
Categories=Network;Security;
StartupNotify=true
```

- [ ] **Step 10: Create packaging/appimage/secureops.svg**

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect width="64" height="64" rx="8" fill="#0a0e1a"/>
  <rect x="18" y="30" width="28" height="22" rx="4" fill="#00d4ff"/>
  <path d="M24 30V22a8 8 0 0 1 16 0v8" stroke="#00d4ff" stroke-width="3.5"
        fill="none" stroke-linecap="round"/>
  <circle cx="32" cy="41" r="3.5" fill="#0a0e1a"/>
  <line x1="32" y1="41" x2="32" y2="47" stroke="#0a0e1a" stroke-width="2.5"
        stroke-linecap="round"/>
</svg>
```

- [ ] **Step 11: Run packaging tests (build.sh and .gitignore tests still fail)**

Run: `pytest tests/test_packaging.py -v`
Expected: `test_build_script_*` and `test_gitignore_excludes_dist` fail; all others pass

- [ ] **Step 12: Commit**

```bash
git add packaging/ tests/test_packaging.py
git commit -m "feat: add packaging metadata files and infrastructure tests"
```

---

### Task 5: Write build.sh

**Files:**
- Create: `build.sh`

- [ ] **Step 1: Create build.sh**

Create `build.sh` in the repo root with the following content:

```bash
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Read version from app.py (single source of truth)
VERSION=$(sed -n 's/.*setApplicationVersion("\([^"]*\)").*/\1/p' app.py)
echo "Building SecureOps v${VERSION}..."

# Load pinned tool versions
source packaging/tool_versions.sh

mkdir -p dist/tools

# ─── Stage 1: Fetch Go tools ─────────────────────────────────────────────────
echo ""
echo "=== Stage 1: Fetching Go tools ==="

for ENTRY in \
    "subfinder:$SUBFINDER_VERSION" \
    "dnsx:$DNSX_VERSION" \
    "naabu:$NAABU_VERSION" \
    "httpx:$HTTPX_VERSION" \
    "katana:$KATANA_VERSION" \
    "nuclei:$NUCLEI_VERSION"; do

    TOOL="${ENTRY%%:*}"
    VER="${ENTRY##*:}"
    DEST="dist/tools/${TOOL}"

    if [ -f "$DEST" ]; then
        echo "  (cached) $TOOL"
        continue
    fi

    URL="https://github.com/projectdiscovery/${TOOL}/releases/download/v${VER}/${TOOL}_${VER}_linux_amd64.zip"
    echo "  Downloading $TOOL v${VER}..."
    curl -fsSL "$URL" -o "dist/${TOOL}.zip"
    unzip -j -o "dist/${TOOL}.zip" "${TOOL}" -d dist/tools/
    chmod +x "$DEST"
    rm -f "dist/${TOOL}.zip"
    echo "  Done: $TOOL"
done

# ─── Stage 2: PyInstaller ────────────────────────────────────────────────────
echo ""
echo "=== Stage 2: Building Python bundle ==="

source venv/bin/activate
pip install -q -r requirements.txt
pip install -q "pyinstaller>=6.0"

pyinstaller secureops.spec --noconfirm

# Copy bundled Go tools into the PyInstaller output directory
cp -r dist/tools dist/secureops/tools
echo "  PyInstaller bundle ready at dist/secureops/"

# ─── Stage 3: Build .deb ─────────────────────────────────────────────────────
echo ""
echo "=== Stage 3: Building .deb ==="

rm -rf dist/deb-staging
mkdir -p dist/deb-staging/DEBIAN
mkdir -p dist/deb-staging/opt/secureops
mkdir -p dist/deb-staging/usr/local/bin
mkdir -p dist/deb-staging/usr/share/applications
mkdir -p dist/deb-staging/usr/share/pixmaps

# App files
cp -r dist/secureops/. dist/deb-staging/opt/secureops/

# Control files (substitute {VERSION} placeholder)
sed "s/{VERSION}/${VERSION}/" packaging/deb/DEBIAN/control \
    > dist/deb-staging/DEBIAN/control
cp packaging/deb/DEBIAN/postinst dist/deb-staging/DEBIAN/postinst
cp packaging/deb/DEBIAN/copyright dist/deb-staging/DEBIAN/copyright
chmod 0755 dist/deb-staging/DEBIAN/postinst

# Thin shell launcher at /usr/local/bin/secureops
cat > dist/deb-staging/usr/local/bin/secureops << 'LAUNCHER'
#!/bin/sh
exec /opt/secureops/secureops "$@"
LAUNCHER
chmod 0755 dist/deb-staging/usr/local/bin/secureops

# Desktop integration
cp packaging/appimage/secureops.desktop \
    dist/deb-staging/usr/share/applications/secureops.desktop
cp packaging/appimage/secureops.svg \
    dist/deb-staging/usr/share/pixmaps/secureops.svg

# Executable permissions on binaries
chmod 0755 dist/deb-staging/opt/secureops/secureops
find dist/deb-staging/opt/secureops/tools -type f -exec chmod 0755 {} \;

DEB_PATH="dist/secureops_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group dist/deb-staging "$DEB_PATH"
echo "  Built: $DEB_PATH"

# ─── Stage 4: Build .AppImage ────────────────────────────────────────────────
echo ""
echo "=== Stage 4: Building AppImage ==="

if [ ! -f dist/appimagetool ]; then
    echo "  Downloading appimagetool..."
    curl -fsSL \
        "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
        -o dist/appimagetool
    chmod +x dist/appimagetool
fi

rm -rf dist/AppDir
mkdir -p dist/AppDir/usr/bin

# App files (same PyInstaller output)
cp -r dist/secureops/. dist/AppDir/usr/bin/

# AppImage structure
cp packaging/appimage/AppRun dist/AppDir/AppRun
chmod +x dist/AppDir/AppRun
cp packaging/appimage/secureops.desktop dist/AppDir/secureops.desktop
cp packaging/appimage/secureops.svg dist/AppDir/secureops.svg

APPIMAGE_PATH="dist/SecureOps-${VERSION}-x86_64.AppImage"
ARCH=x86_64 dist/appimagetool dist/AppDir "$APPIMAGE_PATH"
echo "  Built: $APPIMAGE_PATH"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "=== Build complete ==="
echo "  $DEB_PATH"
echo "  $APPIMAGE_PATH"
```

- [ ] **Step 2: Make build.sh executable**

Run: `chmod +x build.sh`

- [ ] **Step 3: Verify syntax**

Run: `bash -n build.sh && echo "Syntax OK"`
Expected: `Syntax OK`

- [ ] **Step 4: Run packaging tests — all should pass now**

Run: `pytest tests/test_packaging.py -v`
Expected: `test_build_script_exists_and_is_executable` and `test_build_script_syntax` now pass. `test_gitignore_excludes_dist` still fails.

- [ ] **Step 5: Run full test suite**

Run: `pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add build.sh
git commit -m "feat: add build.sh — packages .deb and .AppImage via PyInstaller"
```

- [ ] **Step 7 (optional, takes ~5–10 min, requires internet): Smoke-test the build**

Run: `./build.sh`
Expected: Stages 1–4 complete; `dist/secureops_0.1.0_amd64.deb` and `dist/SecureOps-0.1.0-x86_64.AppImage` exist.

Verify the .deb installs and launches:
```bash
sudo dpkg -i dist/secureops_0.1.0_amd64.deb
secureops
sudo dpkg -r secureops
```

Verify the AppImage runs:
```bash
chmod +x dist/SecureOps-0.1.0-x86_64.AppImage
./dist/SecureOps-0.1.0-x86_64.AppImage
```

---

### Task 6: Add .gitignore

**Files:**
- Create: `.gitignore`

- [ ] **Step 1: Create .gitignore**

No `.gitignore` exists. Create it in the repo root:

```
# Build output
dist/
*.deb
*.AppImage

# Python
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.egg-info/

# Virtual environment
venv/
```

- [ ] **Step 2: Run the gitignore test**

Run: `pytest tests/test_packaging.py::test_gitignore_excludes_dist -v`
Expected: PASS

- [ ] **Step 3: Run full test suite one final time**

Run: `pytest --tb=short -q`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add .gitignore
git commit -m "chore: add .gitignore — exclude dist/, __pycache__, venv"
```
