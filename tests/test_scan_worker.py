from unittest.mock import patch
from workers.scan_worker import ScanWorker
from models import Scan
from db import DB


def _make_worker(db, target="example.com"):
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target=target, status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    return ScanWorker(target=target, scan_id=scan_id, db=db), scan_id


def test_scan_worker_emits_tool_started_signals(qtbot, db):
    worker, _ = _make_worker(db)
    started_tools = []
    worker.tool_started.connect(started_tools.append)

    with patch("workers.scan_worker.subfinder.run", return_value=[]):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    assert "subfinder" in started_tools
    assert "nuclei" in started_tools


def test_scan_worker_emits_tool_failed_on_tool_error(qtbot, db):
    from workers.base_tool import ToolError
    worker, _ = _make_worker(db)
    failed_tools = []
    worker.tool_failed.connect(lambda name, _msg: failed_tools.append(name))

    with patch("workers.scan_worker.subfinder.run", side_effect=ToolError("subfinder: not found")):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    assert "subfinder" in failed_tools


def test_scan_worker_sets_status_complete_in_db(qtbot, db):
    worker, scan_id = _make_worker(db)

    with patch("workers.scan_worker.subfinder.run", return_value=[]):
        with patch("workers.scan_worker.dnsx.run", return_value=[]):
            with patch("workers.scan_worker.naabu.run", return_value=[]):
                with patch("workers.scan_worker.httpx.run", return_value=[]):
                    with patch("workers.scan_worker.katana.run", return_value=[]):
                        with patch("workers.scan_worker.nuclei.run", return_value=[]):
                            with patch("workers.scan_worker.nmap.run", return_value=[]):
                                with patch("workers.scan_worker.nikto.run", return_value=[]):
                                    with patch("workers.scan_worker.testssl.run", return_value=[]):
                                        with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                            worker.start()

    scans = db.query_scans_by_client(None)
    assert scans[0].status == "complete"


def test_scan_worker_cancel_emits_scan_failed(qtbot, db):
    from workers.base_tool import CancelledError
    worker, _ = _make_worker(db)
    failed_msgs = []
    worker.scan_failed.connect(failed_msgs.append)

    with patch("workers.scan_worker.subfinder.run", side_effect=CancelledError()):
        with qtbot.waitSignal(worker.scan_failed, timeout=5000):
            worker.start()

    assert any("cancel" in m.lower() for m in failed_msgs)


from workers.scan_worker import _is_ip


def test_is_ip_true_for_ipv4():
    assert _is_ip("192.168.1.1") is True


def test_is_ip_true_for_ipv6():
    assert _is_ip("::1") is True
    assert _is_ip("2001:db8::1") is True


def test_is_ip_false_for_domain():
    assert _is_ip("example.com") is False
    assert _is_ip("scanme.nmap.org") is False
    assert _is_ip("") is False


def test_ip_mode_skips_subfinder_and_dnsx(qtbot, db):
    worker, _ = _make_worker(db, target="10.0.0.1")
    started_tools = []
    worker.tool_started.connect(started_tools.append)

    with patch("workers.scan_worker.naabu.run", return_value=[]):
        with patch("workers.scan_worker.httpx.run", return_value=[]):
            with patch("workers.scan_worker.katana.run", return_value=[]):
                with patch("workers.scan_worker.nuclei.run", return_value=[]):
                    with patch("workers.scan_worker.nmap.run", return_value=[]):
                        with patch("workers.scan_worker.nikto.run", return_value=[]):
                            with patch("workers.scan_worker.testssl.run", return_value=[]):
                                with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                    worker.start()

    assert "subfinder" not in started_tools
    assert "dnsx" not in started_tools
    assert "naabu" in started_tools


def test_ip_mode_feeds_ip_directly_to_naabu(qtbot, db):
    worker, _ = _make_worker(db, target="10.0.0.1")
    captured = {}

    def fake_naabu(ips, runner, db, scan_id):
        captured["ips"] = ips
        return []

    with patch("workers.scan_worker.naabu.run", side_effect=fake_naabu):
        with patch("workers.scan_worker.httpx.run", return_value=[]):
            with patch("workers.scan_worker.katana.run", return_value=[]):
                with patch("workers.scan_worker.nuclei.run", return_value=[]):
                    with patch("workers.scan_worker.nmap.run", return_value=[]):
                        with patch("workers.scan_worker.nikto.run", return_value=[]):
                            with patch("workers.scan_worker.testssl.run", return_value=[]):
                                with qtbot.waitSignal(worker.scan_complete, timeout=5000):
                                    worker.start()

    assert captured["ips"] == ["10.0.0.1"]
