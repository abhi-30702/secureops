from models import Client, Scan, Host, Finding, AdvisoryItem


def test_client_fields():
    c = Client(id=None, name="Acme", domain="acme.com", firewall="pfSense", notes="", created_at="2024-01-01T00:00:00")
    assert c.name == "Acme"
    assert c.id is None


def test_scan_nullable_client_id():
    s = Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None)
    assert s.client_id is None
    assert s.finished_at is None


def test_host_all_nullable():
    h = Host(id=None, scan_id=1, subdomain=None, ip=None, port=None, protocol=None, service=None, url=None, source_tool="subfinder", created_at="2024-01-01T00:00:00")
    assert h.subdomain is None
    assert h.source_tool == "subfinder"


def test_finding_fields():
    f = Finding(id=None, scan_id=1, host_id=None, tool="nuclei", severity="critical", title="CVE-2021-41773", description="Path traversal", raw_json="{}", created_at="2024-01-01T00:00:00")
    assert f.severity == "critical"
    assert f.host_id is None


def test_advisory_item_fields():
    item = AdvisoryItem(
        id=None, scan_id=1, tier="immediate",
        text="Patch the vulnerable service", accepted=False,
        created_at="2026-06-03T00:00:00",
    )
    assert item.id is None
    assert item.scan_id == 1
    assert item.tier == "immediate"
    assert item.text == "Patch the vulnerable service"
    assert item.accepted is False


def test_advisory_item_accepted_flag():
    item = AdvisoryItem(
        id=5, scan_id=2, tier="preventive",
        text="Enable MFA", accepted=True,
        created_at="2026-06-03T00:00:00",
    )
    assert item.id == 5
    assert item.accepted is True
