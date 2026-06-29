# app.py
import sys
from PyQt6.QtWidgets import QApplication

from screens.widgets import theme as T


# QSS template — tokens written as @NAME@ and substituted from theme below.
# (Avoids brace-collision with QSS blocks that an f-string would cause.)
_QSS_TEMPLATE = """
QMainWindow, QDialog {
    background-color: @BG@;
}

QWidget {
    background-color: @BG@;
    color: @TXT@;
    font-family: @FONT_SANS@;
    font-size: @FS_BODY@px;
}

QToolTip {
    background-color: @TXT@;
    color: @CARD@;
    border: none;
    border-radius: @RADIUS_SM@px;
    padding: 4px 8px;
    font-size: @FS_SMALL@px;
}

/* ── Sidebar ─────────────────────────────────────────────────────────── */
QWidget#sidebar {
    background-color: @CARD@;
    border-right: 1px solid @BORDER@;
}

QPushButton#nav-btn {
    background-color: transparent;
    border: none;
    border-left: 3px solid transparent;
    color: @TXT3@;
    font-size: 13px;
    text-align: left;
    padding: 10px 14px;
}

QPushButton#nav-btn:hover {
    background-color: @HOVER@;
    color: @TXT@;
}

QPushButton#nav-btn[active="true"] {
    background-color: @ACCENT_SOFT@;
    color: @ACCENT@;
    border-left: 3px solid @ACCENT@;
    font-weight: bold;
}

/* ── Panels / cards ──────────────────────────────────────────────────── */
QFrame#panel, QFrame#card {
    border: 1px solid @BORDER@;
    border-radius: @RADIUS_MD@px;
    background-color: @CARD@;
}

QWidget#status-bar-widget {
    background-color: @CARD@;
    border-top: 1px solid @BORDER@;
}

/* ── Inputs ──────────────────────────────────────────────────────────── */
QLineEdit, QComboBox, QPlainTextEdit, QTextEdit, QSpinBox {
    background-color: @CARD@;
    border: 1px solid @BORDER@;
    border-radius: @RADIUS_SM@px;
    color: @TXT@;
    padding: 7px 10px;
    selection-background-color: @ACCENT@;
    selection-color: @CARD@;
}

QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus,
QTextEdit:focus, QSpinBox:focus {
    border: 2px solid @FOCUS@;
    padding: 6px 9px;
}

QLineEdit:disabled, QComboBox:disabled {
    background-color: @BG_ALT@;
    color: @TXT3@;
}

QComboBox::drop-down {
    border: none;
    width: 22px;
}

QComboBox QAbstractItemView {
    background-color: @CARD@;
    border: 1px solid @BORDER@;
    selection-background-color: @ACCENT_SOFT@;
    selection-color: @ACCENT@;
    outline: none;
}

/* ── Buttons ─────────────────────────────────────────────────────────── */
QPushButton {
    background-color: @CARD@;
    border: 1px solid @BORDER_STRONG@;
    border-radius: @RADIUS_SM@px;
    color: @ACCENT@;
    padding: 8px 16px;
    font-weight: 600;
}

QPushButton:hover {
    background-color: @HOVER@;
    border-color: @ACCENT@;
}

QPushButton:pressed {
    background-color: @ACCENT_SOFT@;
}

QPushButton:focus {
    border: 2px solid @FOCUS@;
    padding: 7px 15px;
}

QPushButton:disabled {
    background-color: @BG_ALT@;
    border-color: @BORDER@;
    color: @TXT3@;
}

/* Primary call-to-action */
QPushButton#primary {
    background-color: @ACCENT@;
    border: 1px solid @ACCENT@;
    color: @CARD@;
}

QPushButton#primary:hover {
    background-color: @ACCENT_H@;
    border-color: @ACCENT_H@;
}

QPushButton#primary:pressed {
    background-color: @ACCENT_D@;
}

QPushButton#primary:disabled {
    background-color: @BORDER@;
    border-color: @BORDER@;
    color: @CARD@;
}

/* Danger action */
QPushButton#danger {
    background-color: @CARD@;
    border: 1px solid @CRITICAL@;
    color: @CRITICAL@;
}

QPushButton#danger:hover {
    background-color: @CRITICAL@;
    color: @CARD@;
}

QCheckBox {
    color: @TXT@;
    spacing: 8px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid @BORDER_STRONG@;
    border-radius: @RADIUS_SM@px;
    background: @CARD@;
}

QCheckBox::indicator:checked {
    background: @ACCENT@;
    border-color: @ACCENT@;
}

/* ── Tables ──────────────────────────────────────────────────────────── */
QTableWidget {
    background-color: @CARD@;
    color: @TXT@;
    gridline-color: @BORDER@;
    border: 1px solid @BORDER@;
    border-radius: @RADIUS_MD@px;
    alternate-background-color: @BG_ALT@;
}

QTableWidget::item {
    padding: 4px 6px;
}

QTableWidget::item:selected {
    background-color: @ACCENT_SOFT@;
    color: @TXT@;
}

QHeaderView::section {
    background-color: @ACCENT@;
    color: @CARD@;
    border: none;
    border-right: 1px solid @ACCENT_H@;
    padding: 6px 8px;
    font-weight: bold;
}

QListWidget {
    background-color: @CARD@;
    border: 1px solid @BORDER@;
    border-radius: @RADIUS_MD@px;
    color: @TXT@;
    outline: none;
    padding: 4px;
}

QListWidget::item {
    padding: 8px 10px;
    border-radius: @RADIUS_SM@px;
}

QListWidget::item:hover {
    background-color: @HOVER@;
}

QListWidget::item:selected {
    background-color: @ACCENT_SOFT@;
    color: @ACCENT@;
}

/* ── Scrollbars ──────────────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: @BORDER_STRONG@;
    border-radius: 5px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background: @ACCENT_H@;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 2px;
}

QScrollBar::handle:horizontal {
    background: @BORDER_STRONG@;
    border-radius: 5px;
    min-width: 24px;
}

QScrollBar::handle:horizontal:hover {
    background: @ACCENT_H@;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QSplitter::handle {
    background: @BORDER@;
}

QSplitter::handle:hover {
    background: @ACCENT_H@;
}

/* ── Tabs ────────────────────────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid @BORDER@;
    border-radius: @RADIUS_MD@px;
    top: -1px;
}

QTabBar::tab {
    background: transparent;
    color: @TXT3@;
    padding: 8px 16px;
    border-bottom: 2px solid transparent;
}

QTabBar::tab:selected {
    color: @ACCENT@;
    border-bottom: 2px solid @ACCENT@;
    font-weight: bold;
}

QTabBar::tab:hover:!selected {
    color: @TXT@;
}
"""


def _build_qss() -> str:
    tokens = {
        "BG": T.BG, "BG_ALT": T.BG_ALT, "CARD": T.CARD, "INPUT": T.INPUT,
        "HOVER": T.HOVER, "ACCENT": T.ACCENT, "ACCENT_H": T.ACCENT_H,
        "ACCENT_D": T.ACCENT_D, "ACCENT_SOFT": T.ACCENT_SOFT,
        "TXT": T.TXT, "TXT2": T.TXT2, "TXT3": T.TXT3, "BORDER": T.BORDER,
        "BORDER_STRONG": T.BORDER_STRONG, "FOCUS": T.FOCUS,
        "CRITICAL": T.CRITICAL, "SUCCESS": T.SUCCESS,
        "FONT_SANS": T.FONT_SANS, "FONT_MONO": T.FONT_MONO,
        "FS_BODY": str(T.FS_BODY), "FS_SMALL": str(T.FS_SMALL),
        "RADIUS_SM": str(T.RADIUS_SM), "RADIUS_MD": str(T.RADIUS_MD),
    }
    qss = _QSS_TEMPLATE
    for key, val in tokens.items():
        qss = qss.replace(f"@{key}@", val)
    return qss


# Public constant retained for backwards compatibility / tests.
COOL_QSS = _build_qss()


def create_app(argv=None) -> QApplication:
    existing = QApplication.instance()
    if existing:
        return existing
    app = QApplication(argv or sys.argv)
    app.setApplicationName("SecureOps")
    app.setApplicationVersion("1.2.0")
    app.setStyleSheet(COOL_QSS)
    return app
