from PyQt6.QtCore import Qt, QPropertyAnimation
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGraphicsOpacityEffect,
)

from screens.widgets.theme import TXT, TXT3, BORDER, ACCENT, SUCCESS, CRITICAL

_MAIN_CHAIN = ["subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei"]
_PARALLEL = ["nmap", "nikto", "testssl"]

_DOT_COLORS = {
    "idle":    BORDER,
    "running": ACCENT,
    "done":    SUCCESS,
    "failed":  CRITICAL,
}


class _ToolNode(QFrame):
    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.name = name
        self._state = "idle"
        self._animation: QPropertyAnimation | None = None
        self.setObjectName("panel")
        self.setFixedSize(88, 58)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._dot = QLabel("●")
        self._dot.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['idle']}; font-size: 10px;")

        self._name_label = QLabel(name)
        self._name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._name_label.setStyleSheet(f"color: {TXT}; font-size: 9px; font-family: monospace;")

        self._count_label = QLabel("")
        self._count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._count_label.setStyleSheet(f"color: {TXT3}; font-size: 9px;")
        self._count_label.setVisible(False)

        layout.addWidget(self._dot)
        layout.addWidget(self._name_label)
        layout.addWidget(self._count_label)

    def set_running(self):
        self._state = "running"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['running']}; font-size: 10px;")
        effect = QGraphicsOpacityEffect(self._dot)
        self._dot.setGraphicsEffect(effect)
        self._animation = QPropertyAnimation(effect, b"opacity")
        self._animation.setDuration(600)
        self._animation.setKeyValueAt(0.0, 1.0)
        self._animation.setKeyValueAt(0.5, 0.3)
        self._animation.setKeyValueAt(1.0, 1.0)
        self._animation.setLoopCount(-1)
        self._animation.start()

    def set_done(self, count: int):
        self._state = "done"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['done']}; font-size: 10px;")
        self._count_label.setText(str(count))
        self._count_label.setVisible(True)

    def set_failed(self):
        self._state = "failed"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['failed']}; font-size: 10px;")
        self._count_label.setText("failed")
        self._count_label.setVisible(True)

    def reset(self):
        self._state = "idle"
        self._stop_anim()
        self._dot.setStyleSheet(f"color: {_DOT_COLORS['idle']}; font-size: 10px;")
        self._count_label.setText("")
        self._count_label.setVisible(False)

    def _stop_anim(self):
        if self._animation:
            self._animation.stop()
            self._animation = None
        self._dot.setGraphicsEffect(None)

    @property
    def state(self) -> str:
        return self._state


class PipelineTracker(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._nodes: dict[str, _ToolNode] = {}
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(8)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        main_row = QHBoxLayout()
        main_row.setSpacing(2)
        main_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for name in _MAIN_CHAIN:
            node = _ToolNode(name)
            self._nodes[name] = node
            main_row.addWidget(node)
            if name != _MAIN_CHAIN[-1]:
                arr = QLabel("→")
                arr.setStyleSheet(f"color: {BORDER}; font-size: 12px;")
                main_row.addWidget(arr)

        parallel_row = QHBoxLayout()
        parallel_row.setSpacing(8)
        parallel_row.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for name in _PARALLEL:
            node = _ToolNode(name)
            self._nodes[name] = node
            parallel_row.addWidget(node)

        outer.addLayout(main_row)
        outer.addLayout(parallel_row)

    def on_tool_started(self, name: str):
        if name in self._nodes:
            self._nodes[name].set_running()

    def on_tool_finished(self, name: str, count: int):
        if name in self._nodes:
            self._nodes[name].set_done(count)

    def on_tool_failed(self, name: str, msg: str):
        if name in self._nodes:
            self._nodes[name].set_failed()

    def on_scan_complete(self, hosts: int, findings: int):
        pass  # intentionally empty — totals summary deferred to Phase 4

    def reset(self):
        for node in self._nodes.values():
            node.reset()
