import pytest
from screens.widgets.pipeline_tracker import PipelineTracker


def test_pipeline_tracker_all_nodes_start_idle(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    for name, node in tracker._nodes.items():
        assert node.state == "idle"


def test_pipeline_tracker_on_tool_started_sets_running(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("subfinder")
    assert tracker._nodes["subfinder"].state == "running"


def test_pipeline_tracker_on_tool_finished_sets_done(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("subfinder")
    tracker.on_tool_finished("subfinder", 14)
    assert tracker._nodes["subfinder"].state == "done"
    assert tracker._nodes["subfinder"]._count_label.text() == "14"


def test_pipeline_tracker_on_tool_failed_sets_failed(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("nmap")
    tracker.on_tool_failed("nmap", "not found")
    assert tracker._nodes["nmap"].state == "failed"


def test_pipeline_tracker_reset_returns_all_to_idle(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("nuclei")
    tracker.on_tool_finished("nuclei", 3)
    tracker.reset()
    assert tracker._nodes["nuclei"].state == "idle"


def test_pipeline_tracker_has_all_nine_nodes(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    expected = {"subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei", "nmap", "nikto", "testssl"}
    assert set(tracker._nodes.keys()) == expected


def test_pipeline_tracker_reset_on_running_node_clears_animation(qtbot):
    tracker = PipelineTracker()
    qtbot.addWidget(tracker)
    tracker.on_tool_started("httpx")
    tracker.reset()
    assert tracker._nodes["httpx"].state == "idle"
    assert tracker._nodes["httpx"]._animation is None
