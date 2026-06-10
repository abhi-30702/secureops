import pytest
from workers.internal_worker import _classify_device


def test_port_53_is_router():
    assert _classify_device([53]) == "router"


def test_port_23_is_router():
    assert _classify_device([23]) == "router"


def test_port_179_is_router():
    assert _classify_device([179]) == "router"


def test_port_3389_is_workstation():
    assert _classify_device([3389]) == "workstation"


def test_port_445_is_workstation():
    assert _classify_device([445]) == "workstation"


def test_port_631_is_printer():
    assert _classify_device([631]) == "printer"


def test_port_9100_is_printer():
    assert _classify_device([9100]) == "printer"


def test_port_1883_is_iot():
    assert _classify_device([1883]) == "iot"


def test_port_80_443_is_server():
    assert _classify_device([80, 443]) == "server"


def test_port_22_only_is_server():
    assert _classify_device([22]) == "server"


def test_port_80_is_server():
    assert _classify_device([80]) == "server"


def test_empty_ports_is_unknown():
    assert _classify_device([]) == "unknown"


def test_priority_router_over_server():
    # port 53 + 80: router wins (checked first)
    assert _classify_device([53, 80]) == "router"


def test_priority_workstation_over_server():
    # port 3389 + 443: workstation wins
    assert _classify_device([3389, 443]) == "workstation"
