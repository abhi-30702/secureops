import os
from models import Scan, Host, Finding
from report.pdf_generator import PdfGenerator


def _scan() -> Scan:
    return Scan(id=1, client_id=None, target="example.com",
                status="complete", started_at="2026-06-03T10:00:00",
                finished_at="2026-06-03T10:04:00")


def _host() -> Host:
    return Host(id=1, scan_id=1, subdomain="api.example.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")


def _finding(severity: str = "high", tool: str = "nuclei",
             title: str = "Test Finding") -> Finding:
    return Finding(id=1, scan_id=1, host_id=1, tool=tool, severity=severity,
                   title=title, description="A test finding description.",
                   raw_json="{}", created_at="2026-06-03T10:02:00")


def test_pdf_generates_file(tmp_path):
    path = str(tmp_path / "report.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[_host()], findings=[_finding()],
                       output_path=path)
    result = gen.generate()
    assert result == path
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_pdf_with_no_findings(tmp_path):
    path = str(tmp_path / "empty.pdf")
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[], output_path=path)
    gen.generate()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 500


def test_pdf_with_all_severities(tmp_path):
    path = str(tmp_path / "all_sev.pdf")
    findings = [
        _finding("critical", "nuclei", "Critical issue"),
        _finding("high", "nmap", "High issue"),
        _finding("medium", "nikto", "Medium issue"),
        _finding("low", "testssl", "Low issue"),
        _finding("info", "httpx", "Info item"),
    ]
    gen = PdfGenerator(scan=_scan(), hosts=[_host()], findings=findings,
                       output_path=path)
    gen.generate()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_pdf_risk_rating_critical(tmp_path):
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[_finding("critical")],
                       output_path=str(tmp_path / "c.pdf"))
    assert gen._risk_rating() == "CRITICAL"


def test_pdf_risk_rating_passed(tmp_path):
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[],
                       output_path=str(tmp_path / "p.pdf"))
    assert gen._risk_rating() == "PASSED"


def test_pdf_risk_rating_high():
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[_finding("high")],
                       output_path="/dev/null")
    assert gen._risk_rating() == "HIGH"


def test_pdf_iso_mapping_testssl():
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[],
                       output_path="/dev/null")
    ctrl, _ = gen._iso_control("testssl")
    assert ctrl == "A.10.1"


def test_pdf_iso_mapping_default():
    gen = PdfGenerator(scan=_scan(), hosts=[], findings=[],
                       output_path="/dev/null")
    ctrl, _ = gen._iso_control("unknown_tool")
    assert ctrl == "A.12.6"
