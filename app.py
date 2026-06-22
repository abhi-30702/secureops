# app.py
import sys
from PyQt6.QtWidgets import QApplication

COOL_QSS = """
QMainWindow, QDialog {
    background-color: #F4F6F9;
}

QWidget {
    background-color: #F4F6F9;
    color: #1A202C;
    font-family: "Inter", "Segoe UI", sans-serif;
    font-size: 13px;
}

QWidget#sidebar {
    background-color: #FFFFFF;
    border-right: 1px solid #D1D9E6;
}

QPushButton#nav-btn {
    background-color: transparent;
    border: none;
    color: #A0AEC0;
    font-size: 18px;
    padding: 8px 0px;
    text-align: center;
}

QPushButton#nav-btn:hover {
    background-color: #EEF1F6;
    color: #1A202C;
}

QPushButton#nav-btn[active="true"] {
    background-color: #FFFFFF;
    color: #3D5A80;
    border-left: 3px solid #3D5A80;
}

QFrame#panel {
    border: 1px solid #D1D9E6;
    border-radius: 4px;
    background-color: #FFFFFF;
}

QWidget#status-bar-widget {
    background-color: #FFFFFF;
    border-top: 1px solid #D1D9E6;
}

QLineEdit {
    background-color: #EEF1F6;
    border: 1px solid #D1D9E6;
    border-radius: 4px;
    color: #1A202C;
    padding: 6px 10px;
}

QLineEdit:focus {
    border: 1px solid #3D5A80;
}

QComboBox {
    background-color: #EEF1F6;
    border: 1px solid #D1D9E6;
    border-radius: 4px;
    color: #1A202C;
    padding: 6px 10px;
}

QComboBox::drop-down {
    border: none;
}

QTextEdit {
    background-color: #EEF1F6;
    border: 1px solid #D1D9E6;
    border-radius: 4px;
    color: #1A202C;
    padding: 6px;
}

QPushButton {
    background-color: #FFFFFF;
    border: 1px solid #D1D9E6;
    border-radius: 4px;
    color: #3D5A80;
    padding: 8px 16px;
}

QPushButton:hover {
    background-color: #5C7FA8;
    border-color: #3D5A80;
    color: #FFFFFF;
}

QPushButton:disabled {
    background-color: #EEF1F6;
    border-color: #D1D9E6;
    color: #A0AEC0;
}

QCheckBox {
    color: #1A202C;
}

QTableWidget {
    background-color: #FFFFFF;
    color: #1A202C;
    gridline-color: #D1D9E6;
    border: 1px solid #D1D9E6;
}

QTableWidget::item:selected {
    background-color: #5C7FA8;
    color: #FFFFFF;
}

QHeaderView::section {
    background-color: #EEF1F6;
    color: #3D5A80;
    border: 1px solid #D1D9E6;
    padding: 4px;
}

QListWidget {
    background-color: #FFFFFF;
    border: 1px solid #D1D9E6;
    color: #1A202C;
}

QListWidget::item:selected {
    background-color: #3D5A80;
    color: #FFFFFF;
}

QScrollBar:vertical {
    background: #EEF1F6;
    width: 8px;
}

QScrollBar::handle:vertical {
    background: #D1D9E6;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #EEF1F6;
    height: 8px;
}

QScrollBar::handle:horizontal {
    background: #D1D9E6;
    border-radius: 4px;
    min-width: 20px;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QSplitter::handle {
    background: #D1D9E6;
}
"""


def create_app(argv=None) -> QApplication:
    existing = QApplication.instance()
    if existing:
        return existing
    app = QApplication(argv or sys.argv)
    app.setApplicationName("SecureOps")
    app.setApplicationVersion("1.2.0")
    app.setStyleSheet(COOL_QSS)
    return app
