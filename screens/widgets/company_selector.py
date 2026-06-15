from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel, QComboBox
from PyQt6.QtCore import pyqtSignal
from db import DB


class CompanySelector(QWidget):
    company_selected = pyqtSignal(dict)

    def __init__(self, db: DB, parent=None):
        super().__init__(parent)
        self._db = db
        self._companies: list[dict] = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Company:"))
        self._combo = QComboBox()
        self._combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self._combo.currentIndexChanged.connect(self._on_changed)
        layout.addWidget(self._combo, 1)
        self.refresh()

    def refresh(self) -> None:
        self._combo.blockSignals(True)
        self._combo.clear()
        self._companies = self._db.get_companies() if self._db else []
        for c in self._companies:
            self._combo.addItem(c["name"])
        self._combo.blockSignals(False)
        if self._companies:
            self._on_changed(0)

    def current_company(self) -> dict | None:
        idx = self._combo.currentIndex()
        if 0 <= idx < len(self._companies):
            return self._companies[idx]
        return None

    def _on_changed(self, index: int) -> None:
        if 0 <= index < len(self._companies):
            self.company_selected.emit(self._companies[index])
