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


# ── nuclei ────────────────────────────────────────────────────────────────────

def test_nuclei_returns_finding(db):
    from workers.tools import nuclei
    line = '{"template-id": "cve-2021-41773", "info": {"name": "Apache Path Traversal", "severity": "critical", "description": "Allows path traversal"}, "host": "https://api.example.com", "matched-at": "https://api.example.com/.%2e/etc/passwd", "timestamp": "2024-01-01T00:00:00Z"}'
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    findings = nuclei.run(["https://api.example.com"], MockRunner([line]), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nuclei"
    assert findings[0].severity == "critical"
    assert findings[0].title == "Apache Path Traversal"
    assert findings[0].scan_id == scan_id
    assert len(db.query_findings_by_scan(scan_id)) == 1


# ── nmap ──────────────────────────────────────────────────────────────────────

def test_nmap_returns_finding_for_open_port(db):
    from workers.tools import nmap
    xml_output = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))

    findings = nmap.run(["93.184.216.34"], MockRunner(buffered=xml_output), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nmap"
    assert findings[0].title == "Open port 443/tcp (https)"
    assert "nginx" in findings[0].description
    assert len(db.query_findings_by_scan(scan_id)) == 1


# ── nikto ─────────────────────────────────────────────────────────────────────

def test_nikto_returns_finding_from_json(db, tmp_path):
    from workers.tools import nikto
    import json as _json

    json_content = _json.dumps({
        "host": "https://api.example.com",
        "ip": "93.184.216.34",
        "port": "443",
        "vulnerabilities": [
            {"id": "999986", "method": "GET", "url": "/", "msg": "X-Frame-Options header not present.", "references": "CWE-693"}
        ]
    })

    class NiktoMockRunner:
        def run_buffered(self, cmd, timeout=300):
            output_flag = "-output"
            if output_flag in cmd:
                idx = cmd.index(output_flag)
                path = cmd[idx + 1]
                with open(path, "w") as f:
                    f.write(json_content)
            return ""

    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    findings = nikto.run(["https://api.example.com"], NiktoMockRunner(), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "nikto"
    assert "X-Frame-Options" in findings[0].title


# ── testssl ───────────────────────────────────────────────────────────────────

def test_testssl_returns_finding_for_critical(db):
    from workers.tools import testssl
    import json as _json

    json_content = _json.dumps([
        {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE, uses SSLv3+"},
        {"id": "cert_trust", "severity": "OK", "finding": "certificate chain valid"},
    ])

    class TestsslMockRunner:
        def run_buffered(self, cmd, timeout=300):
            jsonfile_flag = "--jsonfile"
            if jsonfile_flag in cmd:
                idx = cmd.index(jsonfile_flag)
                path = cmd[idx + 1]
                with open(path, "w") as f:
                    f.write(json_content)
            return ""

    scan_id = db.insert_scan(Scan(id=None, client_id=None, target="example.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    findings = testssl.run(["https://api.example.com"], TestsslMockRunner(), db, scan_id)

    assert len(findings) == 1
    assert findings[0].tool == "testssl"
    assert findings[0].severity == "critical"
    assert "heartbleed" in findings[0].title
