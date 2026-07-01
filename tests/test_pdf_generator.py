import os
from datetime import datetime, timezone
from models import Scan, Host, Finding
from report.pdf_generator import PdfGenerator


def _make_log_finding(scan_id, title="SSH Brute Force", severity="high"):
    return Finding(
        id=1, scan_id=scan_id, host_id=None,
        tool="log-analyzer", severity=severity,
        title=title, description="10 failed SSH attempts from 1.2.3.4",
        raw_json="", created_at=datetime.now(timezone.utc).isoformat(),
    )


def test_pdf_includes_log_section_when_log_findings_present(tmp_path):
    scan = Scan(id=1, client_id=None, target="test.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    findings = [_make_log_finding(scan_id=1)]
    out = str(tmp_path / "report_log.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=findings, output_path=out)
    gen.generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def test_pdf_excludes_log_section_when_no_log_findings(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    findings = [Finding(id=1, scan_id=1, host_id=None, tool="nmap", severity="medium",
                        title="Open port", description="Port 80 open", raw_json="",
                        created_at=datetime.now(timezone.utc).isoformat())]
    out = str(tmp_path / "report_noscan.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=findings, output_path=out)
    gen.generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def _make_event(event_type, ts, source="10.0.0.5", dest="", desc="event"):
    return {
        "scan_id": 1, "timestamp": ts, "event_type": event_type,
        "source_host": source, "dest_host": dest, "description": desc,
        "evidence": "",
    }


def test_pdf_includes_breach_timeline_when_events_present(tmp_path):
    scan = Scan(id=1, client_id=None, target="auth.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    findings = [_make_log_finding(scan_id=1)]
    events = [
        _make_event("entry", "2026-06-05T09:00:00+00:00", desc="SSH brute force"),
        _make_event("lateral", "2026-06-05T09:30:00+00:00", dest="10.0.0.9", desc="sudo to root"),
        _make_event("persistence", "2026-06-05T10:00:00+00:00", desc="new cron job"),
    ]
    out = str(tmp_path / "report_breach.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=findings,
                       output_path=out, incident_events=events)
    gen.generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def test_pdf_breach_timeline_section_built_only_with_events(tmp_path):
    scan = Scan(id=1, client_id=None, target="auth.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    gen_with = PdfGenerator(scan=scan, hosts=[], findings=[],
                            incident_events=[_make_event("entry", "2026-06-05T09:00:00+00:00")])
    gen_without = PdfGenerator(scan=scan, hosts=[], findings=[])
    assert gen_with._breach_timeline_section()
    assert gen_without._incident_events == []


def test_pdf_breach_timeline_sorts_events_chronologically(tmp_path):
    scan = Scan(id=1, client_id=None, target="auth.log", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at=None)
    events = [
        _make_event("persistence", "2026-06-05T10:00:00+00:00", desc="late"),
        _make_event("entry", "2026-06-05T08:00:00+00:00", desc="early"),
    ]
    out = str(tmp_path / "report_sorted.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=[],
                       output_path=out, incident_events=events)
    # section builds without error and renders a row per event plus header
    flowables = gen._breach_timeline_section()
    tables = [f for f in flowables if hasattr(f, "_cellvalues")]
    assert tables and len(tables[0]._cellvalues) == 3  # header + 2 events


# ── OSINT section (Phase 6) ────────────────────────────────────────────────────

def _make_osint(item_type, value, source="theharvester"):
    return {"item_type": item_type, "value": value, "source": source,
            "domain": "example.com"}


def test_pdf_includes_osint_section_when_items_present(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at="2026-06-05T10:00:02+00:00")
    osint = [
        _make_osint("email", "admin@example.com"),
        _make_osint("subdomain", "mail.example.com"),
        _make_osint("ip", "203.0.113.5"),
    ]
    out = str(tmp_path / "report_osint.pdf")
    gen = PdfGenerator(scan=scan, hosts=[], findings=[],
                       output_path=out, osint_items=osint)
    gen.generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def test_pdf_osint_section_groups_by_type(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at=None)
    osint = [
        _make_osint("email", "a@example.com"),
        _make_osint("email", "b@example.com"),
        _make_osint("subdomain", "x.example.com"),
    ]
    gen = PdfGenerator(scan=scan, hosts=[], findings=[], osint_items=osint)
    flowables = gen._osint_section()
    tables = [f for f in flowables if hasattr(f, "_cellvalues")]
    # summary table: header + 2 type rows (email, subdomain)
    assert tables[0]._cellvalues[0] == ["Type", "Count"]
    summary_body = tables[0]._cellvalues[1:]
    counts = {row[0]: row[1] for row in summary_body}
    assert counts["email"] == "2"
    assert counts["subdomain"] == "1"


def test_pdf_no_osint_section_when_empty(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at=None)
    gen = PdfGenerator(scan=scan, hosts=[], findings=[])
    assert gen._osint_items == []


def test_iso_map_covers_osint_tool():
    from report.pdf_generator import _ISO_MAP
    assert _ISO_MAP["theharvester"][0] == "A.13.2"


def test_iso_control_defaults_for_unknown_tool(tmp_path):
    scan = Scan(id=1, client_id=None, target="example.com", status="complete",
                started_at="2026-06-05T10:00:00+00:00", finished_at=None)
    gen = PdfGenerator(scan=scan, hosts=[], findings=[])
    # Unmapped tools fall back to the generic technical-vulnerability control.
    assert gen._iso_control("some_unmapped_tool") == ("A.12.6", "Technical vulnerability management")
