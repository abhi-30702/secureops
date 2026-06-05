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
