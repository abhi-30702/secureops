from models import Host, Finding
from screens.widgets.attack_graph import AttackGraph


def _host(subdomain: str = None, ip: str = None, port: int = None,
          url: str = None) -> Host:
    return Host(id=None, scan_id=1, subdomain=subdomain, ip=ip, port=port,
                protocol="tcp", service=None, url=url,
                source_tool="subfinder", created_at="2024-01-01T00:00:00")


def _finding(severity: str = "critical") -> Finding:
    return Finding(id=None, scan_id=1, host_id=None, tool="nuclei",
                   severity=severity, title="Test Vuln", description="",
                   raw_json="{}", created_at="2024-01-01T00:00:00")


def test_attack_graph_starts_with_one_node_after_reset(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    assert graph.node_count == 1


def test_attack_graph_add_host_increases_node_count(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    assert graph.node_count == 2


def test_attack_graph_add_finding_increases_node_count(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_finding(_finding())
    assert graph.node_count == 2


def test_attack_graph_duplicate_host_not_added_twice(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.add_host(_host(subdomain="api.example.com"))
    assert graph.node_count == 2


def test_attack_graph_timer_stops_on_scan_complete(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.on_scan_complete(5, 3)
    assert not graph._timer.isActive()


def test_attack_graph_reset_clears_nodes(qtbot):
    graph = AttackGraph()
    qtbot.addWidget(graph)
    graph.reset()
    graph.add_host(_host(subdomain="api.example.com"))
    graph.add_finding(_finding())
    graph.reset()
    assert graph.node_count == 1
