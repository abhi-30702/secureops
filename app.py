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
