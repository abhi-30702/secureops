"""Severity column — claymorphism callouts (Critical/High/Medium/Low).

Kept the class name `SeverityRings` and its public API (`_rings`, `add_finding`,
`on_scan_complete`, `reset`) for back-compat; internally each row is a
`ClaySeverityCard` from the morphism library.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel

from screens.widgets import theme as T
from screens.widgets.morphism import ClaySeverityCard

_SEVERITIES = ["critical", "high", "medium", "low"]


class SeverityRings(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rings: dict[str, ClaySeverityCard] = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(10)

        header = QLabel("SEVERITY")
        header.setStyleSheet(T.overline(T.ACCENT, T.FS_TINY) + " background: transparent;")
        layout.addWidget(header)

        for sev in _SEVERITIES:
            card = ClaySeverityCard(sev)
            self._rings[sev] = card
            layout.addWidget(card)

        layout.addStretch(1)

    def add_finding(self, finding):
        if finding.severity in self._rings:
            self._rings[finding.severity].increment()
            self._refresh_bars()

    def _refresh_bars(self):
        mx = max((r.count for r in self._rings.values()), default=0)
        for r in self._rings.values():
            r.set_proportion(r.count / mx if mx else 0.0)

    def on_scan_complete(self, hosts: int, findings: int):
        pass  # cards freeze on scan complete

    def reset(self):
        for card in self._rings.values():
            card.reset()
        self._refresh_bars()
