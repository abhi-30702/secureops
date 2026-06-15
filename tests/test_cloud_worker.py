import gc
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from db import DB
from models import Scan
from workers.cloud_worker import CloudWorker

FAKE_AWS_FINDINGS = [
    {"tool": "aws_auditor", "severity": "critical", "title": "Public S3 bucket",
     "description": "Bucket 'bad'", "host": "bad", "port": None, "raw": "{}"},
]
FAKE_GCP_FINDINGS = [
    {"tool": "gcp_auditor", "severity": "high", "title": "Service account with owner/editor role",
     "description": "deploy@ has roles/owner", "host": "deploy@", "port": None, "raw": "{}"},
]


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def _make_db_with_scan():
    db = DB(":memory:")
    db.insert_scan(Scan(
        id=None, client_id=None, target="cloud",
        status="running",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=None,
    ))
    return db


def test_findings_emitted_for_aws():
    db = _make_db_with_scan()
    emitted = []

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="", gcp_creds_file="",
        )
        worker.finding_discovered.connect(emitted.append)
        worker.run()

    assert len(emitted) == 1
    assert emitted[0]["title"] == "Public S3 bucket"


def test_findings_written_to_db():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=FAKE_GCP_FINDINGS):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.run()

    rows = db._conn.execute("SELECT * FROM findings WHERE scan_id=1").fetchall()
    assert len(rows) == 2


def test_gcp_skipped_when_no_project():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=[]) as mock_aws, \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]) as mock_gcp:
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="", gcp_creds_file="",
        )
        worker.run()

    mock_gcp.assert_not_called()


def test_aws_skipped_when_no_credentials():
    db = _make_db_with_scan()

    with patch("workers.cloud_worker.aws_auditor.run", return_value=[]) as mock_aws, \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=[]) as mock_gcp:
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="", aws_region="",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.run()

    mock_aws.assert_not_called()


def test_scan_complete_fires():
    db = _make_db_with_scan()
    completed = []

    with patch("workers.cloud_worker.aws_auditor.run", return_value=FAKE_AWS_FINDINGS), \
         patch("workers.cloud_worker.gcp_auditor.run", return_value=FAKE_GCP_FINDINGS):
        worker = CloudWorker(
            scan_id=1, db=db,
            aws_profile="test", aws_region="us-east-1",
            gcp_project="my-project", gcp_creds_file="",
        )
        worker.scan_complete.connect(completed.append)
        worker.run()

    assert len(completed) == 1
    assert completed[0]["total"] == 2
