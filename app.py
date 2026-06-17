# app.py
import sys
from PyQt6.QtWidgets import QApplication

CHIFFON_QSS = """
QMainWindow, QDialog {
    background-color: #FEFACD;
}

QWidget {
    background-color: #FEFACD;
    color: #2A1F45;
    font-family: "Inter", "Segoe UI", sans-serif;
    font-size: 13px;
}

QWidget#sidebar {
    background-color: #FFFEF2;
    border-right: 1px solid #C8B8E8;
}

QPushButton#nav-btn {
    background-color: transparent;
    border: none;
    color: #9B8FC2;
    font-size: 18px;
    padding: 8px 0px;
    text-align: center;
}

QPushButton#nav-btn:hover {
    background-color: #C8B8E8;
    color: #2A1F45;
}

QPushButton#nav-btn[active="true"] {
    background-color: #FFFEF2;
    color: #5F4A8B;
    border-left: 3px solid #5F4A8B;
}

QFrame#panel {
    border: 1px solid #C8B8E8;
    border-radius: 4px;
    background-color: #FFFEF2;
}

QWidget#status-bar-widget {
    background-color: #FFFEF2;
    border-top: 1px solid #C8B8E8;
}

QLineEdit {
    background-color: #F5F0DC;
    border: 1px solid #C8B8E8;
    border-radius: 4px;
    color: #2A1F45;
    padding: 6px 10px;
}

QLineEdit:focus {
    border: 1px solid #5F4A8B;
}

QComboBox {
    background-color: #F5F0DC;
    border: 1px solid #C8B8E8;
    border-radius: 4px;
    color: #2A1F45;
    padding: 6px 10px;
}

QComboBox::drop-down {
    border: none;
}

QTextEdit {
    background-color: #F5F0DC;
    border: 1px solid #C8B8E8;
    border-radius: 4px;
    color: #2A1F45;
    padding: 6px;
}

QPushButton {
    background-color: #FFFEF2;
    border: 1px solid #C8B8E8;
    border-radius: 4px;
    color: #5F4A8B;
    padding: 8px 16px;
}

QPushButton:hover {
    background-color: #8B75C2;
    border-color: #5F4A8B;
    color: #FEFACD;
}

QPushButton:disabled {
    background-color: #F5F0DC;
    border-color: #C8B8E8;
    color: #9B8FC2;
}

QCheckBox {
    color: #2A1F45;
}

QTableWidget {
    background-color: #FFFEF2;
    color: #2A1F45;
    gridline-color: #C8B8E8;
    border: 1px solid #C8B8E8;
}

QTableWidget::item:selected {
    background-color: #8B75C2;
    color: #FEFACD;
}

QHeaderView::section {
    background-color: #F5F0DC;
    color: #5F4A8B;
    border: 1px solid #C8B8E8;
    padding: 4px;
}

QListWidget {
    background-color: #FFFEF2;
    border: 1px solid #C8B8E8;
    color: #2A1F45;
}

QListWidget::item:selected {
    background-color: #5F4A8B;
    color: #FEFACD;
}

QScrollBar:vertical {
    background: #F5F0DC;
    width: 8px;
}

QScrollBar::handle:vertical {
    background: #C8B8E8;
    border-radius: 4px;
    min-height: 20px;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #F5F0DC;
    height: 8px;
}

QScrollBar::handle:horizontal {
    background: #C8B8E8;
    border-radius: 4px;
    min-width: 20px;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

QSplitter::handle {
    background: #C8B8E8;
}
"""


def create_app(argv=None) -> QApplication:
    existing = QApplication.instance()
    if existing:
        return existing
    app = QApplication(argv or sys.argv)
    app.setApplicationName("SecureOps")
    app.setApplicationVersion("1.1.0")
    app.setStyleSheet(CHIFFON_QSS)
    return app
