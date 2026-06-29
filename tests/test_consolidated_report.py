import os
from datetime import datetime, timezone

from models import Scan, Finding
from db import DB
from report.consolidated import (
    correlate_cross_company, ConsolidatedPdfGenerator,
    build_consolidated_data, _normalize_title,
)


def _f(title, severity="high", tool="nuclei"):
    return Finding(id=None, scan_id=1, host_id=None, tool=tool, severity=severity,
                   title=title, description="d", raw_json="",
                   created_at=datetime.now(timezone.utc).isoformat())


# ── correlation logic ──────────────────────────────────────────────────────────

def test_normalize_title_strips_host_suffix():
    assert _normalize_title("Open port 22 — 10.0.0.5") == "open port 22"
    assert _normalize_title("CVE-2023-1234") == "cve-2023-1234"


def test_correlate_finds_shared_weakness():
    per_company = [
        ("Co A", [_f("Exposed .git directory"), _f("Weak TLS")]),
        ("Co B", [_f("Exposed .git directory")]),
        ("Co C", [_f("Unique to C")]),
    ]
    shared = correlate_cross_company(per_company)
    titles = {s["title"] for s in shared}
    assert "Exposed .git directory" in titles
    assert "Weak TLS" not in titles  # only in one company
    assert "Unique to C" not in titles


def test_correlate_counts_distinct_companies():
    per_company = [
        ("Co A", [_f("Shared issue — host1")]),
        ("Co B", [_f("Shared issue — host2")]),
    ]
    shared = correlate_cross_company(per_company)
    assert len(shared) == 1
    assert shared[0]["companies"] == ["Co A", "Co B"]


def test_correlate_same_company_twice_not_shared():
    # Same finding on two hosts of ONE company is not cross-company.
    per_company = [("Co A", [_f("Dup — h1"), _f("Dup — h2")])]
    assert correlate_cross_company(per_company) == []


def test_correlate_keeps_worst_severity():
    per_company = [
        ("Co A", [_f("Issue", severity="low")]),
        ("Co B", [_f("Issue", severity="critical")]),
    ]
    shared = correlate_cross_company(per_company)
    assert shared[0]["severity"] == "critical"


def test_correlate_sorted_by_company_count_desc():
    per_company = [
        ("Co A", [_f("Wide"), _f("Narrow")]),
        ("Co B", [_f("Wide")]),
        ("Co C", [_f("Wide"), _f("Narrow")]),
    ]
    shared = correlate_cross_company(per_company)
    # "Wide" affects 3 companies, "Narrow" affects 2 → Wide first
    assert shared[0]["title"] == "Wide"


# ── consolidated PDF ────────────────────────────────────────────────────────────

def _entry(name, findings, target="x.com"):
    scan = Scan(id=1, client_id=None, target=target, status="complete",
                started_at="2026-06-28T10:00:00+00:00", finished_at=None)
    return {"company": {"name": name}, "scan": scan, "hosts": [], "findings": findings}


def test_consolidated_pdf_generates(tmp_path):
    data = [
        _entry("Fidelitus HQ", [_f("Public S3 bucket", "critical", "aws_auditor")]),
        _entry("Fidelitus Tech", [_f("Public S3 bucket", "critical", "aws_auditor"),
                                  _f("Weak TLS", "medium", "testssl")]),
    ]
    out = str(tmp_path / "consolidated.pdf")
    ConsolidatedPdfGenerator(data, output_path=out).generate()
    assert os.path.exists(out)
    assert os.path.getsize(out) > 1000


def test_consolidated_group_rating_is_worst(tmp_path):
    data = [
        _entry("A", [_f("x", "low")]),
        _entry("B", [_f("y", "critical")]),
    ]
    gen = ConsolidatedPdfGenerator(data, output_path=str(tmp_path / "c.pdf"))
    assert gen._group_rating() == "CRITICAL"


def test_consolidated_group_rating_passed_when_no_findings(tmp_path):
    data = [_entry("A", []), _entry("B", [])]
    gen = ConsolidatedPdfGenerator(data, output_path=str(tmp_path / "c.pdf"))
    assert gen._group_rating() == "PASSED"


def test_consolidated_summary_table_has_group_total_row(tmp_path):
    data = [_entry("A", [_f("x", "high")]), _entry("B", [_f("y", "medium")])]
    gen = ConsolidatedPdfGenerator(data, output_path=str(tmp_path / "c.pdf"))
    flowables = gen._group_summary()
    tables = [f for f in flowables if hasattr(f, "_cellvalues")]
    last_row = tables[0]._cellvalues[-1]
    assert last_row[0] == "GROUP TOTAL"
    assert last_row[-1] == "2"  # two findings total


# ── data assembly from DB ────────────────────────────────────────────────────────

def test_build_consolidated_data_matches_company_and_findings():
    db = DB(":memory:")
    companies = db.get_companies()
    company = companies[0]
    scan = Scan(id=None, client_id=company["id"], target="hq.com", status="complete",
                started_at=datetime.now(timezone.utc).isoformat(), finished_at=None)
    scan_id = db.insert_scan(scan)
    db.insert_finding(_f("Finding A"))

    data = build_consolidated_data(db, [scan_id])
    assert len(data) == 1
    assert data[0]["company"]["id"] == company["id"]
    assert data[0]["scan"].id == scan_id


def test_build_consolidated_data_skips_missing_scan():
    db = DB(":memory:")
    assert build_consolidated_data(db, [9999]) == []
