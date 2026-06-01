# Phase 1 — App Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable PyQt6 desktop application with a collapsible sidebar, dark cyberpunk theme, five screen placeholder shells, and a persistent tool-health status bar — no scan engine, no database.

**Architecture:** Flat module structure at the project root. `main_window.py` owns a `QStackedWidget` (screens) and a `Sidebar` (navigation). `tool_checker.py` runs `shutil.which()` for all 9 tools at startup and passes the results dict to the main window, status bar, and settings screen as constructor arguments. No signals or shared state needed in Phase 1.

**Tech Stack:** PyQt6, pytest, pytest-qt (headless via `QT_QPA_PLATFORM=offscreen`)

---

## File Map

| File | Responsibility |
|------|---------------|
| `requirements.txt` | Python dependencies |
| `pytest.ini` | Test config (offscreen platform) |
| `tests/conftest.py` | pytest shared fixtures |
| `tool_checker.py` | `check_tools() -> dict[str, bool]` — shutil.which for 9 tools |
| `app.py` | `create_app()` — QApplication + global QSS dark theme |
| `sidebar.py` | `Sidebar(QWidget)` — collapsible hover sidebar, `screen_changed` signal |
| `status_bar.py` | `ToolStatusBar(QWidget)` — tool health pill, `navigate_to_settings` signal |
| `screens/__init__.py` | Empty |
| `screens/dashboard.py` | `DashboardScreen(QWidget)` — metric cards + placeholder panels |
| `screens/client_onboarding.py` | `ClientOnboardingScreen(QWidget)` — form shell |
| `screens/scan_view.py` | `ScanViewScreen(QWidget)` — 5-panel grid skeleton |
| `screens/report.py` | `ReportScreen(QWidget)` — placeholder + disabled PDF button |
| `screens/settings.py` | `SettingsScreen(QWidget)` — tool status rows + path overrides |
| `main_window.py` | `MainWindow(QMainWindow)` — wires all components |
| `main.py` | Entry point |

---

## Task 1: Project scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `pytest.ini`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `screens/__init__.py`

- [ ] **Step 1: Create `requirements.txt`**

```
PyQt6>=6.6.0
pytest>=8.0.0
pytest-qt>=4.4.0
```

- [ ] **Step 2: Install dependencies into the existing venv**

```bash
source venv/bin/activate && pip install -r requirements.txt
```

Expected: all packages install without error.

- [ ] **Step 3: Create `pytest.ini`**

```ini
[pytest]
testpaths = tests
qt_api = pyqt6
```

- [ ] **Step 4: Create `tests/__init__.py` and `tests/conftest.py`**

`tests/__init__.py` — empty file.

`tests/conftest.py`:
```python
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
```

- [ ] **Step 5: Create `screens/__init__.py`**

Empty file.

- [ ] **Step 6: Verify pytest runs with no errors (no tests yet)**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: `no tests ran` — no errors.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt pytest.ini tests/__init__.py tests/conftest.py screens/__init__.py
git commit -m "feat: project scaffolding — deps, pytest config, directory structure"
```

---

## Task 2: Tool checker

**Files:**
- Create: `tool_checker.py`
- Create: `tests/test_tool_checker.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_tool_checker.py`:
```python
from unittest.mock import patch
from tool_checker import check_tools, is_critical_missing, ready_count, TOOLS, CRITICAL_TOOLS


def test_check_tools_returns_dict_with_all_tools():
    with patch("tool_checker.shutil.which", return_value="/usr/bin/tool"):
        result = check_tools()
    assert set(result.keys()) == set(TOOLS)


def test_check_tools_true_when_tool_found():
    with patch("tool_checker.shutil.which", return_value="/usr/bin/subfinder"):
        result = check_tools()
    assert result["subfinder"] is True


def test_check_tools_false_when_tool_missing():
    with patch("tool_checker.shutil.which", return_value=None):
        result = check_tools()
    assert result["subfinder"] is False


def test_is_critical_missing_false_when_all_present():
    results = {t: True for t in TOOLS}
    assert is_critical_missing(results) is False


def test_is_critical_missing_true_when_nmap_absent():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    assert is_critical_missing(results) is True


def test_ready_count_all_present():
    results = {t: True for t in TOOLS}
    assert ready_count(results) == len(TOOLS)


def test_ready_count_partial():
    results = {t: True for t in TOOLS}
    results["dnsx"] = False
    results["katana"] = False
    assert ready_count(results) == len(TOOLS) - 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_tool_checker.py -v
```

Expected: `ModuleNotFoundError: No module named 'tool_checker'`

- [ ] **Step 3: Write `tool_checker.py`**

```python
import shutil

TOOLS = [
    "subfinder", "dnsx", "naabu", "httpx", "katana",
    "nuclei", "nmap", "nikto", "testssl.sh",
]

CRITICAL_TOOLS = {"subfinder", "nuclei", "nmap"}


def check_tools() -> dict:
    return {tool: shutil.which(tool) is not None for tool in TOOLS}


def is_critical_missing(results: dict) -> bool:
    return any(not results.get(t, False) for t in CRITICAL_TOOLS)


def ready_count(results: dict) -> int:
    return sum(1 for v in results.values() if v)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_tool_checker.py -v
```

Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add tool_checker.py tests/test_tool_checker.py
git commit -m "feat: tool checker — shutil.which for 9 tools with critical flag logic"
```

---

## Task 3: App and dark theme

**Files:**
- Create: `app.py`
- Create: `tests/test_app.py`

- [ ] **Step 1: Write the failing test**

`tests/test_app.py`:
```python
from app import create_app, DARK_QSS


def test_create_app_returns_qapplication(qapp):
    from PyQt6.QtWidgets import QApplication
    app = create_app()
    assert isinstance(app, QApplication)


def test_create_app_idempotent(qapp):
    app1 = create_app()
    app2 = create_app()
    assert app1 is app2


def test_dark_qss_contains_background_color():
    assert "#0a0e1a" in DARK_QSS


def test_dark_qss_contains_accent_cyan():
    assert "#00d4ff" in DARK_QSS
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_app.py -v
```

Expected: `ModuleNotFoundError: No module named 'app'`

- [ ] **Step 3: Write `app.py`**

```python
import sys
from PyQt6.QtWidgets import QApplication

DARK_QSS = """
QMainWindow, QDialog {
    background-color: #0a0e1a;
}

QWidget {
    background-color: #0a0e1a;
    color: #e2e8f0;
    font-family: "Inter", "Segoe UI", sans-serif;
    font-size: 13px;
}

QWidget#sidebar {
    background-color: #111827;
    border-right: 1px solid #1e2d40;
}

QPushButton#nav-btn {
    background-color: transparent;
    border: none;
    color: #64748b;
    font-size: 18px;
    padding: 8px 0px;
    text-align: center;
}

QPushButton#nav-btn:hover {
    background-color: #1e2d40;
    color: #e2e8f0;
}

QPushButton#nav-btn[active="true"] {
    background-color: #0f1f35;
    color: #00d4ff;
    border-left: 3px solid #00d4ff;
}

QFrame#panel {
    border: 1px solid #1e2d40;
    border-radius: 4px;
    background-color: #111827;
}

QWidget#status-bar-widget {
    background-color: #111827;
    border-top: 1px solid #1e2d40;
}

QLineEdit {
    background-color: #111827;
    border: 1px solid #1e2d40;
    border-radius: 4px;
    color: #e2e8f0;
    padding: 6px 10px;
}

QLineEdit:focus {
    border: 1px solid #00d4ff;
}

QComboBox {
    background-color: #111827;
    border: 1px solid #1e2d40;
    border-radius: 4px;
    color: #e2e8f0;
    padding: 6px 10px;
}

QComboBox::drop-down {
    border: none;
}

QTextEdit {
    background-color: #111827;
    border: 1px solid #1e2d40;
    border-radius: 4px;
    color: #e2e8f0;
    padding: 6px;
}

QPushButton {
    background-color: #1e2d40;
    border: 1px solid #2d4a6b;
    border-radius: 4px;
    color: #e2e8f0;
    padding: 8px 16px;
}

QPushButton:hover {
    background-color: #2d4a6b;
    border-color: #00d4ff;
}

QPushButton:disabled {
    background-color: #111827;
    border-color: #1e2d40;
    color: #64748b;
}

QScrollBar:vertical {
    background: #111827;
    width: 8px;
}

QScrollBar::handle:vertical {
    background: #2d4a6b;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QSplitter::handle {
    background: #1e2d40;
}
"""


def create_app(argv=None) -> QApplication:
    existing = QApplication.instance()
    if existing:
        return existing
    app = QApplication(argv or sys.argv)
    app.setApplicationName("SecureOps")
    app.setApplicationVersion("0.1.0")
    app.setStyleSheet(DARK_QSS)
    return app
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_app.py -v
```

Expected: all 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add app.py tests/test_app.py
git commit -m "feat: QApplication setup with dark cyberpunk QSS theme"
```

---

## Task 4: Sidebar

**Files:**
- Create: `sidebar.py`
- Create: `tests/test_sidebar.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_sidebar.py`:
```python
import pytest
from PyQt6.QtCore import Qt
from sidebar import Sidebar, COLLAPSED_WIDTH, EXPANDED_WIDTH


def test_sidebar_has_five_nav_buttons(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert len(sidebar._buttons) == 5


def test_sidebar_starts_collapsed(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert sidebar.maximumWidth() == COLLAPSED_WIDTH


def test_sidebar_emits_screen_changed_on_click(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    sidebar.show()

    with qtbot.waitSignal(sidebar.screen_changed, timeout=1000) as blocker:
        qtbot.mouseClick(sidebar._buttons[2], Qt.MouseButton.LeftButton)

    assert blocker.args == [2]


def test_sidebar_tracks_active_index(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    sidebar.show()

    qtbot.mouseClick(sidebar._buttons[3], Qt.MouseButton.LeftButton)
    assert sidebar.active_index == 3


def test_sidebar_default_active_index_is_zero(qtbot):
    sidebar = Sidebar()
    qtbot.addWidget(sidebar)
    assert sidebar.active_index == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_sidebar.py -v
```

Expected: `ModuleNotFoundError: No module named 'sidebar'`

- [ ] **Step 3: Write `sidebar.py`**

```python
from PyQt6.QtCore import Qt, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QPushButton, QLabel

COLLAPSED_WIDTH = 52
EXPANDED_WIDTH = 180

_NAV_ITEMS = [
    ("⊞", "Dashboard", 0),
    ("+", "New Client", 1),
    ("⚡", "Scan", 2),
    ("📄", "Report", 3),
    ("⚙", "Settings", 4),
]


class Sidebar(QWidget):
    screen_changed = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("sidebar")
        self._active_index = 0
        self._buttons: list[QPushButton] = []
        self._setup_ui()
        self._setup_animation()

    def _setup_ui(self):
        self.setMinimumWidth(COLLAPSED_WIDTH)
        self.setMaximumWidth(COLLAPSED_WIDTH)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        logo = QLabel("🔒")
        logo.setFixedHeight(52)
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size: 20px;")
        layout.addWidget(logo)

        for icon, label, index in _NAV_ITEMS:
            btn = QPushButton(icon)
            btn.setObjectName("nav-btn")
            btn.setFixedHeight(48)
            btn.setToolTip(label)
            btn.setProperty("active", False)
            btn.clicked.connect(lambda checked, i=index: self._on_nav_click(i))
            self._buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        version = QLabel("v0.1.0")
        version.setFixedHeight(32)
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version.setStyleSheet("color: #64748b; font-size: 10px;")
        layout.addWidget(version)

        self._refresh_active_styles()

    def _setup_animation(self):
        self._animation = QPropertyAnimation(self, b"maximumWidth")
        self._animation.setDuration(150)
        self._animation.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def _on_nav_click(self, index: int):
        self._active_index = index
        self._refresh_active_styles()
        self.screen_changed.emit(index)

    def _refresh_active_styles(self):
        for i, btn in enumerate(self._buttons):
            btn.setProperty("active", str(i == self._active_index).lower())
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def enterEvent(self, event):
        self._animate_to(EXPANDED_WIDTH)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._animate_to(COLLAPSED_WIDTH)
        super().leaveEvent(event)

    def _animate_to(self, width: int):
        self._animation.stop()
        self._animation.setStartValue(self.maximumWidth())
        self._animation.setEndValue(width)
        self._animation.start()

    @property
    def active_index(self) -> int:
        return self._active_index
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_sidebar.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add sidebar.py tests/test_sidebar.py
git commit -m "feat: collapsible hover sidebar with screen_changed signal"
```

---

## Task 5: Status bar

**Files:**
- Create: `status_bar.py`
- Create: `tests/test_status_bar.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_status_bar.py`:
```python
import pytest
from PyQt6.QtCore import Qt
from tool_checker import TOOLS
from status_bar import ToolStatusBar


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def _non_critical_missing():
    results = {t: True for t in TOOLS}
    results["dnsx"] = False
    return results


def test_status_bar_shows_ready_count_all_present(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    assert f"{len(TOOLS)}/{len(TOOLS)}" in bar._label.text()


def test_status_bar_shows_partial_count(qtbot):
    results = _all_present()
    results["dnsx"] = False
    bar = ToolStatusBar(results)
    qtbot.addWidget(bar)
    assert f"{len(TOOLS) - 1}/{len(TOOLS)}" in bar._label.text()


def test_status_bar_dot_green_when_all_present(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    assert "#00ff88" in bar._dot.styleSheet()


def test_status_bar_dot_red_when_critical_missing(qtbot):
    bar = ToolStatusBar(_critical_missing())
    qtbot.addWidget(bar)
    assert "#ff4444" in bar._dot.styleSheet()


def test_status_bar_dot_amber_when_non_critical_missing(qtbot):
    bar = ToolStatusBar(_non_critical_missing())
    qtbot.addWidget(bar)
    assert "#ffaa00" in bar._dot.styleSheet()


def test_status_bar_emits_navigate_on_click(qtbot):
    bar = ToolStatusBar(_all_present())
    qtbot.addWidget(bar)
    bar.show()

    with qtbot.waitSignal(bar.navigate_to_settings, timeout=1000):
        qtbot.mouseClick(bar, Qt.MouseButton.LeftButton)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_status_bar.py -v
```

Expected: `ModuleNotFoundError: No module named 'status_bar'`

- [ ] **Step 3: Write `status_bar.py`**

```python
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel
from tool_checker import is_critical_missing, ready_count, CRITICAL_TOOLS, TOOLS


class ToolStatusBar(QWidget):
    navigate_to_settings = pyqtSignal()

    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self.setObjectName("status-bar-widget")
        self.setFixedHeight(28)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._tool_results = tool_results
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(6)

        n_ready = ready_count(self._tool_results)
        total = len(TOOLS)

        self._label = QLabel(f"Tools: {n_ready}/{total} ready")
        self._label.setStyleSheet("color: #64748b; font-size: 11px;")

        self._dot = QLabel("●")
        self._dot.setStyleSheet(f"color: {self._dot_color()}; font-size: 11px;")

        layout.addStretch()
        layout.addWidget(self._label)
        layout.addWidget(self._dot)

    def _dot_color(self) -> str:
        if is_critical_missing(self._tool_results):
            return "#ff4444"
        if ready_count(self._tool_results) < len(TOOLS):
            return "#ffaa00"
        return "#00ff88"

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.navigate_to_settings.emit()
        super().mousePressEvent(event)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_status_bar.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add status_bar.py tests/test_status_bar.py
git commit -m "feat: tool health status bar with green/amber/red states"
```

---

## Task 6: Dashboard screen

**Files:**
- Create: `screens/dashboard.py`
- Create: `tests/test_screen_dashboard.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_screen_dashboard.py`:
```python
from tool_checker import TOOLS
from screens.dashboard import DashboardScreen


def _all_present():
    return {t: True for t in TOOLS}


def _critical_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    return results


def test_dashboard_has_three_metric_cards(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._metric_cards) == 3


def test_dashboard_metric_card_labels(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    titles = [c.title for c in screen._metric_cards]
    assert "Clients" in titles
    assert "Scans" in titles
    assert "Findings" in titles


def test_dashboard_warning_banner_hidden_when_tools_ok(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert not screen._warning_banner.isVisible()


def test_dashboard_warning_banner_shown_when_critical_missing(qtbot):
    screen = DashboardScreen(_critical_missing())
    qtbot.addWidget(screen)
    assert screen._warning_banner.isVisible()


def test_dashboard_has_severity_strip(qtbot):
    screen = DashboardScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._severity_strip is not None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_dashboard.py -v
```

Expected: `ModuleNotFoundError: No module named 'screens.dashboard'`

- [ ] **Step 3: Write `screens/dashboard.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
)
from tool_checker import is_critical_missing


class MetricCard(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.title = title
        self.setObjectName("panel")
        self.setMinimumHeight(80)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #64748b; font-size: 11px; text-transform: uppercase;")

        value_label = QLabel("0")
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #e2e8f0;")

        layout.addWidget(title_label)
        layout.addWidget(value_label)


def _placeholder_panel(label_text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(label_text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class SeverityStrip(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(24)

        for color, label in [
            ("#ff4444", "Critical"), ("#ff8800", "High"),
            ("#ffcc00", "Medium"), ("#4488ff", "Low"),
        ]:
            dot = QLabel(f"<span style='color:{color}'>●</span>  {label}  <b>0</b>")
            dot.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(dot)


class DashboardScreen(QWidget):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._metric_cards: list[MetricCard] = []
        self._warning_banner: QLabel | None = None
        self._severity_strip: SeverityStrip | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Warning banner (hidden by default)
        self._warning_banner = QLabel(
            "⚠  Critical tools missing — check Settings"
        )
        self._warning_banner.setStyleSheet(
            "background-color: #3d2800; color: #ffaa00; "
            "padding: 6px 12px; border: 1px solid #ffaa00; border-radius: 4px;"
        )
        self._warning_banner.setVisible(is_critical_missing(self._tool_results))
        layout.addWidget(self._warning_banner)

        # Metric cards
        cards_row = QHBoxLayout()
        for title in ("Clients", "Scans", "Findings"):
            card = MetricCard(title)
            self._metric_cards.append(card)
            cards_row.addWidget(card)
        layout.addLayout(cards_row)

        # Middle panels
        middle_row = QHBoxLayout()
        middle_row.addWidget(
            _placeholder_panel("Attack Surface Graph\nLive in Phase 3"), stretch=1
        )
        middle_row.addWidget(
            _placeholder_panel("Threat Feed\nLive in Phase 3"), stretch=1
        )
        layout.addLayout(middle_row)

        # Severity strip
        self._severity_strip = SeverityStrip()
        layout.addWidget(self._severity_strip)

        layout.addStretch()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_dashboard.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add screens/dashboard.py tests/test_screen_dashboard.py
git commit -m "feat: dashboard screen — metric cards, placeholder panels, severity strip"
```

---

## Task 7: Client onboarding screen

**Files:**
- Create: `screens/client_onboarding.py`
- Create: `tests/test_screen_client_onboarding.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_screen_client_onboarding.py`:
```python
from PyQt6.QtCore import Qt
from screens.client_onboarding import ClientOnboardingScreen


def test_client_screen_has_company_name_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._company_name_input is not None


def test_client_screen_has_domain_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._domain_input is not None


def test_client_screen_has_firewall_combo(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._firewall_combo.count() > 0


def test_client_screen_has_notes_field(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._notes_input is not None


def test_client_screen_has_save_button(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    assert screen._save_btn is not None


def test_client_screen_save_shows_confirmation(qtbot):
    screen = ClientOnboardingScreen()
    qtbot.addWidget(screen)
    screen.show()

    assert not screen._confirmation_label.isVisible()
    qtbot.mouseClick(screen._save_btn, Qt.MouseButton.LeftButton)
    assert screen._confirmation_label.isVisible()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_client_onboarding.py -v
```

Expected: `ModuleNotFoundError: No module named 'screens.client_onboarding'`

- [ ] **Step 3: Write `screens/client_onboarding.py`**

```python
from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QComboBox, QTextEdit, QPushButton, QFormLayout, QFrame,
)


class ClientOnboardingScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._company_name_input: QLineEdit | None = None
        self._domain_input: QLineEdit | None = None
        self._firewall_combo: QComboBox | None = None
        self._notes_input: QTextEdit | None = None
        self._save_btn: QPushButton | None = None
        self._confirmation_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.setSpacing(16)

        title = QLabel("New Client")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        outer.addWidget(title)

        card = QFrame()
        card.setObjectName("panel")
        form_layout = QFormLayout(card)
        form_layout.setContentsMargins(20, 20, 20, 20)
        form_layout.setSpacing(12)

        self._company_name_input = QLineEdit()
        self._company_name_input.setPlaceholderText("Acme Corp")
        form_layout.addRow("Company Name", self._company_name_input)

        self._domain_input = QLineEdit()
        self._domain_input.setPlaceholderText("example.com")
        form_layout.addRow("Domain", self._domain_input)

        self._firewall_combo = QComboBox()
        self._firewall_combo.addItems(["None", "pfSense", "Cisco ASA", "Fortinet", "Other"])
        form_layout.addRow("Firewall Type", self._firewall_combo)

        self._notes_input = QTextEdit()
        self._notes_input.setPlaceholderText("Additional notes...")
        self._notes_input.setFixedHeight(80)
        form_layout.addRow("Notes", self._notes_input)

        outer.addWidget(card)

        self._save_btn = QPushButton("Save Client")
        self._save_btn.clicked.connect(self._on_save)
        outer.addWidget(self._save_btn)

        self._confirmation_label = QLabel("✓  Client saved (not persisted yet)")
        self._confirmation_label.setStyleSheet("color: #00ff88;")
        self._confirmation_label.setVisible(False)
        outer.addWidget(self._confirmation_label)

        outer.addStretch()

    def _on_save(self):
        self._confirmation_label.setVisible(True)
        QTimer.singleShot(2000, lambda: self._confirmation_label.setVisible(False))
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_client_onboarding.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add screens/client_onboarding.py tests/test_screen_client_onboarding.py
git commit -m "feat: client onboarding screen — form shell with save confirmation"
```

---

## Task 8: Scan view screen

**Files:**
- Create: `screens/scan_view.py`
- Create: `tests/test_screen_scan_view.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_screen_scan_view.py`:
```python
from screens.scan_view import ScanViewScreen


def test_scan_view_has_target_input(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._target_input is not None


def test_scan_view_start_button_disabled(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert not screen._start_btn.isEnabled()


def test_scan_view_has_pipeline_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._pipeline_panel is not None


def test_scan_view_has_attack_graph_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._attack_graph_panel is not None


def test_scan_view_has_severity_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._severity_panel is not None


def test_scan_view_has_finding_cards_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._finding_cards_panel is not None


def test_scan_view_has_terminal_panel(qtbot):
    screen = ScanViewScreen()
    qtbot.addWidget(screen)
    assert screen._terminal_panel is not None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py -v
```

Expected: `ModuleNotFoundError: No module named 'screens.scan_view'`

- [ ] **Step 3: Write `screens/scan_view.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QSplitter,
)


def _placeholder_panel(text: str) -> QFrame:
    frame = QFrame()
    frame.setObjectName("panel")
    layout = QVBoxLayout(frame)
    layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label = QLabel(text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("color: #64748b; font-size: 12px;")
    label.setWordWrap(True)
    layout.addWidget(label)
    return frame


class ScanViewScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._target_input: QLineEdit | None = None
        self._start_btn: QPushButton | None = None
        self._pipeline_panel: QFrame | None = None
        self._attack_graph_panel: QFrame | None = None
        self._severity_panel: QFrame | None = None
        self._finding_cards_panel: QFrame | None = None
        self._terminal_panel: QFrame | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Top bar: target input + start button
        top_bar = QHBoxLayout()
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target domain or IP (e.g. example.com)")
        self._start_btn = QPushButton("▶  Start Scan")
        self._start_btn.setEnabled(False)
        self._start_btn.setToolTip("Scan engine available in Phase 2")
        top_bar.addWidget(self._target_input, stretch=1)
        top_bar.addWidget(self._start_btn)
        layout.addLayout(top_bar)

        # 5-panel grid via nested QSplitters
        self._pipeline_panel = _placeholder_panel("Pipeline Tracker\nPhase 3")
        self._attack_graph_panel = _placeholder_panel("Attack Surface Graph\nPhase 3")
        self._severity_panel = _placeholder_panel("Severity\nRings\nPhase 3")
        self._finding_cards_panel = _placeholder_panel("Finding Cards Stream\nPhase 3")
        self._terminal_panel = _placeholder_panel("Terminal Feed\nPhase 3")

        # Top row: pipeline (25%) | attack graph (75%)
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self._pipeline_panel)
        top_splitter.addWidget(self._attack_graph_panel)
        top_splitter.setSizes([250, 750])

        # Middle row: severity (25%) | finding cards (75%)
        mid_splitter = QSplitter(Qt.Orientation.Horizontal)
        mid_splitter.addWidget(self._severity_panel)
        mid_splitter.addWidget(self._finding_cards_panel)
        mid_splitter.setSizes([250, 750])

        # Combine top + middle into a container
        top_mid = QWidget()
        top_mid_layout = QVBoxLayout(top_mid)
        top_mid_layout.setContentsMargins(0, 0, 0, 0)
        top_mid_layout.setSpacing(8)
        top_mid_layout.addWidget(top_splitter, stretch=1)
        top_mid_layout.addWidget(mid_splitter, stretch=1)

        # Main vertical splitter: top_mid (80%) | terminal (20%)
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.addWidget(top_mid)
        main_splitter.addWidget(self._terminal_panel)
        main_splitter.setSizes([800, 200])

        layout.addWidget(main_splitter, stretch=1)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_scan_view.py -v
```

Expected: all 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add screens/scan_view.py tests/test_screen_scan_view.py
git commit -m "feat: scan view screen — 5-panel grid skeleton with QSplitter layout"
```

---

## Task 9: Report screen

**Files:**
- Create: `screens/report.py`
- Create: `tests/test_screen_report.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_screen_report.py`:
```python
from screens.report import ReportScreen


def test_report_has_export_button(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._export_btn is not None


def test_report_export_button_disabled(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert not screen._export_btn.isEnabled()


def test_report_has_placeholder_label(qtbot):
    screen = ReportScreen()
    qtbot.addWidget(screen)
    assert screen._placeholder_label is not None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_report.py -v
```

Expected: `ModuleNotFoundError: No module named 'screens.report'`

- [ ] **Step 3: Write `screens/report.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QFrame,
)


class ReportScreen(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._export_btn: QPushButton | None = None
        self._placeholder_label: QLabel | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Report")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(title)

        panel = QFrame()
        panel.setObjectName("panel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._placeholder_label = QLabel(
            "Report assembles here during scan\nPhase 4"
        )
        self._placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder_label.setStyleSheet("color: #64748b; font-size: 14px;")

        subtitle = QLabel("Run a scan to generate a report")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #64748b; font-size: 11px;")

        panel_layout.addWidget(self._placeholder_label)
        panel_layout.addWidget(subtitle)
        layout.addWidget(panel, stretch=1)

        self._export_btn = QPushButton("Export PDF")
        self._export_btn.setEnabled(False)
        self._export_btn.setToolTip("PDF export available in Phase 4")
        layout.addWidget(self._export_btn)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_report.py -v
```

Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add screens/report.py tests/test_screen_report.py
git commit -m "feat: report screen — placeholder panel with disabled PDF export button"
```

---

## Task 10: Settings screen

**Files:**
- Create: `screens/settings.py`
- Create: `tests/test_screen_settings.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_screen_settings.py`:
```python
from tool_checker import TOOLS, CRITICAL_TOOLS
from screens.settings import SettingsScreen


def _all_present():
    return {t: True for t in TOOLS}


def _some_missing():
    results = {t: True for t in TOOLS}
    results["nmap"] = False
    results["dnsx"] = False
    return results


def test_settings_has_row_for_every_tool(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert len(screen._tool_rows) == len(TOOLS)


def test_settings_tool_rows_keyed_by_tool_name(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in TOOLS:
        assert tool in screen._tool_rows


def test_settings_critical_tools_marked(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in CRITICAL_TOOLS:
        row = screen._tool_rows[tool]
        assert row["is_critical"] is True


def test_settings_non_critical_not_marked(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    for tool in TOOLS:
        if tool not in CRITICAL_TOOLS:
            assert screen._tool_rows[tool]["is_critical"] is False


def test_settings_missing_tool_shows_false_status(qtbot):
    results = _some_missing()
    screen = SettingsScreen(results)
    qtbot.addWidget(screen)
    assert screen._tool_rows["nmap"]["present"] is False
    assert screen._tool_rows["dnsx"]["present"] is False


def test_settings_present_tool_shows_true_status(qtbot):
    screen = SettingsScreen(_all_present())
    qtbot.addWidget(screen)
    assert screen._tool_rows["subfinder"]["present"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_screen_settings.py -v
```

Expected: `ModuleNotFoundError: No module named 'screens.settings'`

- [ ] **Step 3: Write `screens/settings.py`**

```python
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFrame, QScrollArea,
)
from tool_checker import TOOLS, CRITICAL_TOOLS


class SettingsScreen(QWidget):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._tool_rows: dict[str, dict] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        title = QLabel("Settings")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e2e8f0;")
        layout.addWidget(title)

        section_label = QLabel("TOOL STATUS")
        section_label.setStyleSheet("color: #64748b; font-size: 10px; letter-spacing: 1px;")
        layout.addWidget(section_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(4)

        for tool in TOOLS:
            present = self._tool_results.get(tool, False)
            is_critical = tool in CRITICAL_TOOLS
            row_widget = self._build_tool_row(tool, present, is_critical)
            container_layout.addWidget(row_widget)
            self._tool_rows[tool] = {
                "present": present,
                "is_critical": is_critical,
                "widget": row_widget,
            }

        container_layout.addStretch()
        scroll.setWidget(container)
        layout.addWidget(scroll, stretch=1)

        save_btn = QPushButton("Save Paths")
        save_btn.setEnabled(False)
        save_btn.setToolTip("Path overrides wired in Phase 2")
        layout.addWidget(save_btn)

    def _build_tool_row(self, tool: str, present: bool, is_critical: bool) -> QFrame:
        row = QFrame()
        row.setObjectName("panel")
        row.setFixedHeight(44)

        h = QHBoxLayout(row)
        h.setContentsMargins(12, 0, 12, 0)
        h.setSpacing(12)

        status_dot = QLabel("✓" if present else "✗")
        status_dot.setStyleSheet(
            f"color: {'#00ff88' if present else '#ff4444'}; font-size: 14px;"
        )
        status_dot.setFixedWidth(20)

        name_label = QLabel(tool)
        name_label.setStyleSheet("color: #e2e8f0; font-family: monospace;")

        if is_critical:
            critical_tag = QLabel("CRITICAL")
            critical_tag.setStyleSheet(
                "color: #ff8800; font-size: 9px; "
                "border: 1px solid #ff8800; border-radius: 3px; padding: 1px 4px;"
            )
        else:
            critical_tag = QLabel("")
            critical_tag.setFixedWidth(0)

        path_input = QLineEdit()
        path_input.setPlaceholderText(f"/usr/bin/{tool}")
        path_input.setFixedWidth(220)
        path_input.setEnabled(False)

        h.addWidget(status_dot)
        h.addWidget(name_label)
        h.addWidget(critical_tag)
        h.addStretch()
        h.addWidget(path_input)

        return row
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_screen_settings.py -v
```

Expected: all 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add screens/settings.py tests/test_screen_settings.py
git commit -m "feat: settings screen — tool status rows with critical flags and path inputs"
```

---

## Task 11: Main window

**Files:**
- Create: `main_window.py`
- Create: `tests/test_main_window.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_main_window.py`:
```python
from tool_checker import TOOLS
from main_window import MainWindow


def _all_present():
    return {t: True for t in TOOLS}


def test_main_window_stack_has_five_screens(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._stack.count() == 5


def test_main_window_default_screen_is_dashboard(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._stack.currentIndex() == 0


def test_main_window_sidebar_signal_changes_screen(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    win._sidebar.screen_changed.emit(3)
    assert win._stack.currentIndex() == 3


def test_main_window_status_bar_signal_navigates_to_settings(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    win._status_bar_widget.navigate_to_settings.emit()
    assert win._stack.currentIndex() == 4


def test_main_window_has_status_bar_widget(qtbot):
    win = MainWindow(_all_present())
    qtbot.addWidget(win)
    assert win._status_bar_widget is not None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source venv/bin/activate && pytest tests/test_main_window.py -v
```

Expected: `ModuleNotFoundError: No module named 'main_window'`

- [ ] **Step 3: Write `main_window.py`**

```python
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
)
from sidebar import Sidebar
from status_bar import ToolStatusBar
from screens.dashboard import DashboardScreen
from screens.client_onboarding import ClientOnboardingScreen
from screens.scan_view import ScanViewScreen
from screens.report import ReportScreen
from screens.settings import SettingsScreen


class MainWindow(QMainWindow):
    def __init__(self, tool_results: dict, parent=None):
        super().__init__(parent)
        self._tool_results = tool_results
        self._sidebar: Sidebar | None = None
        self._stack: QStackedWidget | None = None
        self._status_bar_widget: ToolStatusBar | None = None
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("SecureOps")
        self.setMinimumSize(1200, 700)

        outer = QWidget()
        self.setCentralWidget(outer)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Content row: sidebar + stack
        content_row = QWidget()
        row_layout = QHBoxLayout(content_row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)

        self._sidebar = Sidebar()
        self._stack = QStackedWidget()

        self._stack.addWidget(DashboardScreen(self._tool_results))        # 0
        self._stack.addWidget(ClientOnboardingScreen())                    # 1
        self._stack.addWidget(ScanViewScreen())                            # 2
        self._stack.addWidget(ReportScreen())                              # 3
        self._stack.addWidget(SettingsScreen(self._tool_results))          # 4

        row_layout.addWidget(self._sidebar)
        row_layout.addWidget(self._stack, stretch=1)
        outer_layout.addWidget(content_row, stretch=1)

        # Status bar pinned to bottom
        self._status_bar_widget = ToolStatusBar(self._tool_results)
        outer_layout.addWidget(self._status_bar_widget)

        # Wire signals
        self._sidebar.screen_changed.connect(self._stack.setCurrentIndex)
        self._status_bar_widget.navigate_to_settings.connect(
            lambda: self._stack.setCurrentIndex(4)
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
source venv/bin/activate && pytest tests/test_main_window.py -v
```

Expected: all 5 tests PASS.

- [ ] **Step 5: Run full test suite**

```bash
source venv/bin/activate && pytest --tb=short
```

Expected: all tests PASS, no failures.

- [ ] **Step 6: Commit**

```bash
git add main_window.py tests/test_main_window.py
git commit -m "feat: main window — QStackedWidget wired to sidebar and status bar signals"
```

---

## Task 12: Entry point and smoke test

**Files:**
- Create: `main.py`
- Create: `tests/test_main.py`

- [ ] **Step 1: Write the failing test**

`tests/test_main.py`:
```python
from unittest.mock import patch
from main import build_window


def test_build_window_returns_main_window(qapp):
    with patch("main.check_tools", return_value={}):
        from main_window import MainWindow
        win = build_window()
        assert isinstance(win, MainWindow)
        win.close()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source venv/bin/activate && pytest tests/test_main.py -v
```

Expected: `ModuleNotFoundError: No module named 'main'` or `ImportError`

- [ ] **Step 3: Write `main.py`**

```python
import sys
from app import create_app
from tool_checker import check_tools
from main_window import MainWindow


def build_window() -> MainWindow:
    tool_results = check_tools()
    return MainWindow(tool_results)


def main():
    app = create_app(sys.argv)
    window = build_window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
source venv/bin/activate && pytest tests/test_main.py -v
```

Expected: 1 test PASS.

- [ ] **Step 5: Run full test suite one final time**

```bash
source venv/bin/activate && pytest --tb=short -v
```

Expected: all tests PASS across all files.

- [ ] **Step 6: Commit**

```bash
git add main.py tests/test_main.py
git commit -m "feat: entry point — check_tools on startup, build window, launch app"
```

- [ ] **Step 7: Push to GitHub**

```bash
git remote set-url origin https://YOUR_TOKEN@github.com/abhi-30702/secureops.git
git push origin master
git remote set-url origin https://github.com/abhi-30702/secureops.git
```

---

## Self-review notes

- **Spec coverage:** All sections covered — project structure (Task 1), theme (Task 3), sidebar (Task 4), status bar (Task 5), all 5 screens (Tasks 6–10), main window (Task 11), tool checker (Task 2), entry point (Task 12). ✓
- **Type consistency:** `tool_results: dict` used uniformly across all constructors. `screen_changed = pyqtSignal(int)` and `navigate_to_settings = pyqtSignal()` match their `.connect()` call sites in `main_window.py`. ✓
- **No placeholders:** All steps contain complete runnable code. ✓
- **QSS applied:** `create_app()` applies `DARK_QSS` at `QApplication` level — all widgets inherit it without per-widget stylesheet duplication. ✓
