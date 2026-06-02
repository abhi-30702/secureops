from models import Scan
from db import DB


class MockRunner:
    def __init__(self, lines: list[str] = None, buffered: str = ""):
        self._lines = lines or []
        self._buffered = buffered

    def run(self, cmd: list[str], timeout: int = 300):
        yield from self._lines

    def run_buffered(self, cmd: list[str], timeout: int = 300) -> str:
        return self._buffered


# ── subfinder ────────────────────────────────────────────────────────────────

def test_subfinder_returns_host(db):
    from workers.tools import subfinder
    line = '{"host": "api.example.com", "input": "example.com", "source": ["certspotter"]}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = subfinder.run("example.com", MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].subdomain == "api.example.com"
    assert hosts[0].source_tool == "subfinder"
    assert hosts[0].scan_id == scan_id
    assert len(db.query_hosts_by_scan(scan_id)) == 1


# ── dnsx ─────────────────────────────────────────────────────────────────────

def test_dnsx_returns_host_with_ip(db):
    from workers.tools import dnsx
    line = '{"host": "api.example.com", "a": ["93.184.216.34"], "status_code": "NOERROR"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = dnsx.run(["api.example.com"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].ip == "93.184.216.34"
    assert hosts[0].subdomain == "api.example.com"
    assert hosts[0].source_tool == "dnsx"


# ── naabu ─────────────────────────────────────────────────────────────────────

def test_naabu_returns_host_with_port(db):
    from workers.tools import naabu
    line = '{"ip": "93.184.216.34", "port": 443, "protocol": "tcp"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = naabu.run(["93.184.216.34"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].ip == "93.184.216.34"
    assert hosts[0].port == 443
    assert hosts[0].protocol == "tcp"
    assert hosts[0].source_tool == "naabu"


# ── httpx ─────────────────────────────────────────────────────────────────────

def test_httpx_returns_host_with_url(db):
    from workers.tools import httpx as httpx_tool
    line = '{"url": "https://api.example.com", "status_code": 200, "title": "API Gateway", "webserver": "nginx/1.18.0", "input": "api.example.com:443"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = httpx_tool.run(["api.example.com:443"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].url == "https://api.example.com"
    assert hosts[0].service == "nginx/1.18.0"
    assert hosts[0].source_tool == "httpx"


# ── katana ────────────────────────────────────────────────────────────────────

def test_katana_returns_host_with_url(db):
    from workers.tools import katana
    line = '{"timestamp": "2024-01-01T00:00:00Z", "request": {"method": "GET", "endpoint": "https://api.example.com/login"}}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    hosts = katana.run(["https://api.example.com"], MockRunner([line]), db, scan_id)

    assert len(hosts) == 1
    assert hosts[0].url == "https://api.example.com/login"
    assert hosts[0].source_tool == "katana"
