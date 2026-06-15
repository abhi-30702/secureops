import json
import pytest
from unittest.mock import patch, MagicMock
from workers.tools import gcp_auditor


def test_returns_empty_on_no_credentials():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_client:
        from google.auth.exceptions import DefaultCredentialsError
        mock_client.side_effect = DefaultCredentialsError()
        result = gcp_auditor.run("my-project", "")
    assert result == []


def test_finds_public_gcs_bucket():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_storage_cls, \
         patch("workers.tools.gcp_auditor.resourcemanager_v3.ProjectsClient") as mock_rm_cls:

        mock_bucket = MagicMock()
        mock_bucket.name = "public-bucket"
        policy = MagicMock()
        policy.bindings = [
            MagicMock(role="roles/storage.objectViewer", members=["allUsers"])
        ]
        mock_bucket.get_iam_policy.return_value = policy

        mock_storage = MagicMock()
        mock_storage.list_buckets.return_value = [mock_bucket]
        mock_storage_cls.return_value = mock_storage

        mock_rm = MagicMock()
        mock_rm.get_iam_policy.return_value = MagicMock(bindings=[])
        mock_rm_cls.return_value = mock_rm

        result = gcp_auditor.run("my-project", "")

    assert len(result) == 1
    assert result[0]["severity"] == "critical"
    assert result[0]["title"] == "Public GCS bucket"
    assert "public-bucket" in result[0]["description"]


def test_finds_privileged_service_account():
    with patch("workers.tools.gcp_auditor.storage.Client") as mock_storage_cls, \
         patch("workers.tools.gcp_auditor.resourcemanager_v3.ProjectsClient") as mock_rm_cls:

        mock_storage = MagicMock()
        mock_storage.list_buckets.return_value = []
        mock_storage_cls.return_value = mock_storage

        mock_rm = MagicMock()
        binding = MagicMock()
        binding.role = "roles/owner"
        binding.members = ["serviceAccount:deploy@my-project.iam.gserviceaccount.com"]
        mock_rm.get_iam_policy.return_value = MagicMock(bindings=[binding])
        mock_rm_cls.return_value = mock_rm

        result = gcp_auditor.run("my-project", "")

    assert len(result) == 1
    assert result[0]["severity"] == "high"
    assert result[0]["title"] == "Service account with owner/editor role"
    assert "deploy@my-project" in result[0]["description"]
