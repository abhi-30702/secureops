from models import Client, Scan, Host, Finding, Schedule, AdvisoryItem
from db import DB


def test_insert_and_query_client(db):
    client = Client(id=None, name="Acme", domain="acme.com", firewall="pfSense", notes="", created_at="2024-01-01T00:00:00")
    cid = db.insert_client(client)
    assert isinstance(cid, int)
    clients = db.query_clients()
    assert len(clients) == 1
    assert clients[0].name == "Acme"
    assert clients[0].id == cid


def test_insert_scan_nullable_client(db):
    scan = Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None)
    sid = db.insert_scan(scan)
    assert isinstance(sid, int)


def test_update_scan_status(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    db.update_scan_status(sid, "complete", "2024-01-01T01:00:00")
    scans = db.query_scans_by_client(None)
    assert scans[0].status == "complete"
    assert scans[0].finished_at == "2024-01-01T01:00:00"


def test_insert_and_query_host(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    host = Host(id=None, scan_id=sid, subdomain="api.acme.com", ip="1.2.3.4", port=443, protocol="tcp", service="https", url="https://api.acme.com", source_tool="httpx", created_at="2024-01-01T00:00:00")
    hid = db.insert_host(host)
    hosts = db.query_hosts_by_scan(sid)
    assert len(hosts) == 1
    assert hosts[0].subdomain == "api.acme.com"
    assert hosts[0].id == hid


def test_insert_and_query_finding(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    finding = Finding(id=None, scan_id=sid, host_id=None, tool="nuclei", severity="critical", title="CVE-2021-41773", description="Path traversal", raw_json="{}", created_at="2024-01-01T00:00:00")
    fid = db.insert_finding(finding)
    findings = db.query_findings_by_scan(sid)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].id == fid


def test_host_nullable_fields(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    host = Host(id=None, scan_id=sid, subdomain="api.acme.com", ip=None, port=None, protocol=None, service=None, url=None, source_tool="subfinder", created_at="2024-01-01T00:00:00")
    db.insert_host(host)
    hosts = db.query_hosts_by_scan(sid)
    assert hosts[0].ip is None


def test_finding_nullable_host_id(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="acme.com", status="running", started_at="2024-01-01T00:00:00", finished_at=None))
    finding = Finding(id=None, scan_id=sid, host_id=None, tool="nuclei", severity="high", title="Open Redirect", description="", raw_json="{}", created_at="2024-01-01T00:00:00")
    db.insert_finding(finding)
    findings = db.query_findings_by_scan(sid)
    assert findings[0].host_id is None


def test_query_scans_by_client(db):
    cid = db.insert_client(Client(id=None, name="Acme", domain="acme.com", firewall="", notes="", created_at="2024-01-01T00:00:00"))
    db.insert_scan(Scan(id=None, client_id=cid, target="acme.com", status="complete", started_at="2024-01-01T00:00:00", finished_at="2024-01-01T01:00:00"))
    scans = db.query_scans_by_client(cid)
    assert len(scans) == 1
    assert scans[0].client_id == cid


def test_insert_and_query_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    schedules = db.query_schedules()
    assert len(schedules) == 1
    assert schedules[0].target == "example.com"
    assert schedules[0].id == sid


def test_update_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    db.update_schedule(sid, enabled=False, last_run="2026-06-03T10:00:00")
    schedules = db.query_schedules()
    assert schedules[0].enabled is False
    assert schedules[0].last_run == "2026-06-03T10:00:00"


def test_delete_schedule(db):
    s = Schedule(id=None, target="example.com", interval_h=24, enabled=True,
                 last_run=None, created_at="2026-06-03T00:00:00")
    sid = db.insert_schedule(s)
    db.delete_schedule(sid)
    assert db.query_schedules() == []


def test_query_recent_findings_limit(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T10:00:00",
                              finished_at=None))
    for i in range(5):
        db.insert_finding(Finding(id=None, scan_id=sid, host_id=None, tool="nuclei",
                                  severity="high", title=f"Finding {i}", description="",
                                  raw_json="{}", created_at=f"2026-06-03T10:0{i}:00"))
    findings = db.query_recent_findings(limit=3)
    assert len(findings) == 3


def test_insert_and_query_advisory_item(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    item = AdvisoryItem(id=None, scan_id=sid, tier="immediate",
                        text="Patch now", accepted=False,
                        created_at="2026-06-03T00:00:00")
    iid = db.insert_advisory_item(item)
    items = db.query_advisory_items_by_scan(sid)
    assert len(items) == 1
    assert items[0].tier == "immediate"
    assert items[0].id == iid
    assert items[0].accepted is False


def test_update_advisory_item_accepted(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    iid = db.insert_advisory_item(AdvisoryItem(id=None, scan_id=sid, tier="preventive",
                                               text="Enable monitoring", accepted=False,
                                               created_at="2026-06-03T00:00:00"))
    db.update_advisory_item_accepted(iid, True)
    items = db.query_advisory_items_by_scan(sid)
    assert items[0].accepted is True


def test_delete_advisory_items_by_scan(db):
    sid = db.insert_scan(Scan(id=None, client_id=None, target="t.com",
                              status="complete", started_at="2026-06-03T00:00:00",
                              finished_at=None))
    for tier in ("immediate", "short_term", "preventive"):
        db.insert_advisory_item(AdvisoryItem(id=None, scan_id=sid, tier=tier,
                                             text="action", accepted=False,
                                             created_at="2026-06-03T00:00:00"))
    db.delete_advisory_items_by_scan(sid)
    assert db.query_advisory_items_by_scan(sid) == []


def test_get_setting_returns_none_when_absent(db):
    assert db.get_setting("ai_advisor_enabled") is None


def test_set_and_get_setting(db):
    db.set_setting("ai_advisor_enabled", "1")
    assert db.get_setting("ai_advisor_enabled") == "1"


def test_set_setting_overwrites(db):
    db.set_setting("gemini_api_key", "old-key")
    db.set_setting("gemini_api_key", "new-key")
    assert db.get_setting("gemini_api_key") == "new-key"
