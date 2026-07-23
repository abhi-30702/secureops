import json
import os

from models import Scan, Host, Finding, AdvisoryItem
from report.pdf_report import (
    ProfessionalReport, extract_finding_detail, _as_list, _clip,
)


def _scan() -> Scan:
    return Scan(id=15, client_id=None, target="45.33.32.156",
                status="complete", started_at="2026-06-03T10:00:00",
                finished_at="2026-06-03T10:04:00")


def _host() -> Host:
    return Host(id=1, scan_id=15, subdomain="api.example.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")


def _finding(severity="high", tool="nuclei", title="Test Finding", raw="{}") -> Finding:
    return Finding(id=1, scan_id=15, host_id=1, tool=tool, severity=severity,
                   title=title, description="A test finding description.",
                   raw_json=raw, created_at="2026-06-03T10:02:00")


# ── render smoke tests ────────────────────────────────────────────────────────

def test_report_generates_file(tmp_path):
    path = str(tmp_path / "report.pdf")
    r = ProfessionalReport(scan=_scan(), hosts=[_host()], findings=[_finding()],
                           output_path=path, collect_versions=False)
    assert r.generate() == path
    assert os.path.exists(path)
    assert os.path.getsize(path) > 2000


def test_report_no_findings(tmp_path):
    path = str(tmp_path / "empty.pdf")
    ProfessionalReport(scan=_scan(), hosts=[], findings=[], output_path=path,
                       collect_versions=False).generate()
    assert os.path.exists(path)
    assert os.path.getsize(path) > 1000


def test_report_all_severities(tmp_path):
    path = str(tmp_path / "all.pdf")
    findings = [_finding(s, t, f"{s} issue")
                for s, t in [("critical", "nuclei"), ("high", "nmap"),
                             ("medium", "nikto"), ("low", "testssl"), ("info", "httpx")]]
    ProfessionalReport(scan=_scan(), hosts=[_host()], findings=findings,
                       output_path=path, collect_versions=False).generate()
    assert os.path.getsize(path) > 2000


def test_report_with_advisory(tmp_path):
    items = [AdvisoryItem(id=1, scan_id=15, tier="immediate", text="Patch OpenSSL",
                          accepted=True, created_at="2026-06-03T10:00:00")]
    path = str(tmp_path / "adv.pdf")
    ProfessionalReport(scan=_scan(), hosts=[], findings=[], output_path=path,
                       advisory_items=items, collect_versions=False).generate()
    assert os.path.exists(path)


# ── rating / metadata ─────────────────────────────────────────────────────────

def test_report_with_network_summary(tmp_path):
    net = {
        "stats": {"total": 8000, "blocked": 82, "allowed": 7918,
                  "unique_employees": 8,
                  "top_blocked": [("malware-c2.example", 26), ("casino-online.example", 13)]},
        "top_employees": [("j.rivera (Sales)", 40), ("s.okafor (Engineering)", 22)],
        "alerts": [{"severity": "critical", "domain": "malware-c2.example",
                    "employee_name": "j.rivera (Sales)", "created_at": "2026-07-23T10:00:00",
                    "acknowledged": False, "notes": "Known C2"}],
    }
    path = str(tmp_path / "net.pdf")
    ProfessionalReport(scan=_scan(), hosts=[], findings=[_finding()], output_path=path,
                       network_summary=net, collect_versions=False).generate()
    assert os.path.exists(path) and os.path.getsize(path) > 2000


def test_network_section_included_only_with_data():
    with_data = ProfessionalReport(scan=_scan(), hosts=[], findings=[],
                                   network_summary={"stats": {"total": 5, "blocked": 1}},
                                   collect_versions=False)
    assert with_data._has_network_data()
    assert "Network Activity Monitoring" in with_data._network_html()

    empty = ProfessionalReport(scan=_scan(), hosts=[], findings=[], collect_versions=False)
    assert not empty._has_network_data()

    zero = ProfessionalReport(scan=_scan(), hosts=[], findings=[],
                              network_summary={"stats": {"total": 0}}, collect_versions=False)
    assert not zero._has_network_data()


def test_network_html_renders_alert_and_domains():
    r = ProfessionalReport(
        scan=_scan(), hosts=[], findings=[], collect_versions=False,
        network_summary={
            "stats": {"total": 100, "blocked": 10, "allowed": 90, "unique_employees": 3,
                      "top_blocked": [("bad.example", 7)]},
            "top_employees": [("emp1", 6)],
            "alerts": [{"severity": "high", "domain": "bad.example", "employee_name": "emp1",
                        "created_at": "2026-07-23T09:00:00", "acknowledged": True, "notes": "P2P"}],
        })
    out = r._network_html()
    assert "bad.example" in out and "emp1" in out and "HIGH" in out
    assert "10.0%" in out  # block rate


def test_report_id_format():
    r = ProfessionalReport(scan=_scan(), hosts=[], findings=[], collect_versions=False)
    assert r._report_id == "SO-0015-20260603"


def test_rating_critical():
    r = ProfessionalReport(scan=_scan(), hosts=[], findings=[_finding("critical")],
                           collect_versions=False)
    assert r._rating() == "CRITICAL"


def test_rating_passed_when_empty():
    r = ProfessionalReport(scan=_scan(), hosts=[], findings=[], collect_versions=False)
    assert r._rating() == "PASSED"


# ── field-mapping extractor (real tool raw_json shapes) ───────────────────────

def test_extract_nuclei_pulls_cvss_cve_cwe_refs():
    raw = json.dumps({
        "template-id": "CVE-2023-48795",
        "matched-at": "http://45.33.32.156:22",
        "extracted-results": ["Vulnerable to Terrapin"],
        "info": {
            "reference": ["https://terrapin-attack.com/"],
            "remediation": "Disable the affected algorithms.",
            "classification": {
                "cve-id": "CVE-2023-48795",
                "cwe-id": ["cwe-354"],
                "cvss-metrics": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                "cvss-score": 5.9,
            },
        },
    })
    d = extract_finding_detail(_finding("medium", "nuclei", raw=raw))
    assert d["asset"] == "http://45.33.32.156:22"
    assert d["cvss_score"] == 5.9
    assert d["cvss_vector"].startswith("CVSS:3.1")
    assert d["cve"] == ["CVE-2023-48795"]
    assert d["cwe"] == ["CWE-354"]
    assert d["references"] == ["https://terrapin-attack.com/"]
    assert d["remediation"] == "Disable the affected algorithms."
    assert "Terrapin" in d["evidence"]


def test_extract_nuclei_handles_null_cve():
    raw = json.dumps({"info": {"classification": {"cve-id": None, "cwe-id": ["cwe-538"],
                                                  "cvss-score": 5.3}}})
    d = extract_finding_detail(_finding("low", "nuclei", raw=raw))
    assert d["cve"] == []
    assert d["cwe"] == ["CWE-538"]
    assert d["cvss_score"] == 5.3


def test_extract_nikto():
    raw = json.dumps({"id": "013587", "method": "GET",
                      "msg": "Suggested security header missing: permissions-policy.",
                      "references": "https://developer.mozilla.org/", "url": "/"})
    d = extract_finding_detail(_finding("medium", "nikto", raw=raw))
    assert d["asset"] == "/"
    assert "GET" in d["evidence"]
    assert "013587" in d["evidence"]
    assert d["references"] == ["https://developer.mozilla.org/"]


def test_extract_testssl():
    raw = json.dumps({"id": "BREACH", "finding": "potentially VULNERABLE",
                      "ip": "1.2.3.4", "port": "443", "cve": "CVE-2013-3587"})
    d = extract_finding_detail(_finding("medium", "testssl", raw=raw))
    assert d["asset"] == "1.2.3.4:443"
    assert d["cve"] == ["CVE-2013-3587"]
    assert "VULNERABLE" in d["evidence"]


def test_extract_bad_json_falls_back_to_description():
    d = extract_finding_detail(_finding("info", "nmap", raw="<xml>not json</xml>"))
    assert d["evidence"] == "A test finding description."
    assert d["cve"] == [] and d["cwe"] == []


def test_as_list_normalises():
    assert _as_list(None) == []
    assert _as_list("x") == ["x"]
    assert _as_list(["a", None, "", "b"]) == ["a", "b"]


def test_clip_truncates():
    assert _clip("abc", 10) == "abc"
    assert _clip("a" * 50, 10).endswith("…")
