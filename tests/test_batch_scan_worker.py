import gc
import pytest
from unittest.mock import patch, MagicMock
from db import DB
from models import Host, Finding
from workers.batch_scan_worker import BatchScanWorker


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


COMPANIES = [
    {"id": 1, "name": "Co A", "domains": '["a.com"]', "ip_ranges": "[]",
     "aws_profile": "", "gcp_project": "", "firewall_type": ""},
    {"id": 2, "name": "Co B", "domains": '["b.com"]', "ip_ranges": "[]",
     "aws_profile": "", "gcp_project": "", "firewall_type": ""},
]


def _make_db():
    return DB(":memory:")


def _fake_host(subdomain="a.com", url=None):
    from datetime import datetime, timezone
    return Host(id=1, scan_id=1, subdomain=subdomain, ip=None, port=None,
                protocol=None, service=None, url=url,
                source_tool="test", created_at=datetime.now(timezone.utc).isoformat())


def _fake_finding():
    from datetime import datetime, timezone
    return Finding(id=1, scan_id=1, host_id=None, tool="nuclei",
                   severity="high", title="XSS", description="found xss",
                   raw_json="{}", created_at=datetime.now(timezone.utc).isoformat())


def test_company_started_emitted():
    db = _make_db()
    started = []

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[]):
        worker = BatchScanWorker(companies=COMPANIES, db=db)
        worker.company_started.connect(lambda name, idx: started.append(name))
        worker.run()

    assert "Co A" in started
    assert "Co B" in started


def test_finding_discovered_signal_emitted():
    db = _make_db()
    fake_host = _fake_host(subdomain="a.com")
    fake_live = _fake_host(url="http://a.com")
    fake_f = _fake_finding()
    discovered = []

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[fake_host]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[fake_live]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[fake_f]):
        worker = BatchScanWorker(companies=[COMPANIES[0]], db=db)
        worker.finding_discovered.connect(discovered.append)
        worker.run()

    assert len(discovered) == 1
    assert discovered[0].title == "XSS"


def test_companies_with_no_domain_skipped():
    db = _make_db()
    empty_company = {"id": 3, "name": "Empty", "domains": "[]", "ip_ranges": "[]",
                     "aws_profile": "", "gcp_project": "", "firewall_type": ""}

    with patch("workers.batch_scan_worker.subfinder.run") as mock_sub:
        worker = BatchScanWorker(companies=[empty_company], db=db)
        worker.run()

    mock_sub.assert_not_called()


def test_batch_complete_fires():
    db = _make_db()
    completed = []

    with patch("workers.batch_scan_worker.subfinder.run", return_value=[]), \
         patch("workers.batch_scan_worker.httpx.run", return_value=[]), \
         patch("workers.batch_scan_worker.nuclei.run", return_value=[]):
        worker = BatchScanWorker(companies=COMPANIES, db=db)
        worker.batch_complete.connect(lambda scanned, total: completed.append((scanned, total)))
        worker.run()

    assert len(completed) == 1
    assert completed[0][0] == 2


def test_one_company_failure_does_not_abort_batch():
    """A failure scanning one company must not stop the rest of the batch."""
    db = _make_db()
    completed = []
    errors = []
    scanned_companies = []

    def flaky_run_company(self, domain, scan_id):
        if domain == "a.com":
            raise RuntimeError("db locked")
        return 0

    with patch.object(BatchScanWorker, "_run_company", flaky_run_company):
        worker = BatchScanWorker(companies=COMPANIES, db=db)
        worker.batch_complete.connect(lambda scanned, total: completed.append((scanned, total)))
        worker.error_occurred.connect(lambda name, msg: errors.append(name))
        worker.company_complete.connect(lambda name, count: scanned_companies.append(name))
        worker.run()

    # Batch still finished, second company still scanned, first reported as error
    assert len(completed) == 1
    assert "Co B" in scanned_companies
    assert errors  # the failing company surfaced an error
