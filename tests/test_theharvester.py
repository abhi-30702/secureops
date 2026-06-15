import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from workers.tools import theharvester


def test_returns_empty_when_tool_missing():
    """Test that FileNotFoundError returns empty list."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError()
        result = theharvester.run("example.com", "crtsh", "/tmp/test_harvest")
        assert result == []


def test_parses_json_output_correctly():
    """Test JSON parsing with emails, hosts, ips, and urls."""
    # Create temp file with test data
    tmpfile = "/tmp/test_harvest_parse.json"
    test_data = {
        "emails": ["admin@example.com", "info@example.com"],
        "hosts": ["mail.example.com:10.0.0.1", "api.example.com"],
        "ips": ["10.0.0.1"],
        "interesting_urls": ["http://example.com/admin"]
    }

    with open(tmpfile, "w") as f:
        json.dump(test_data, f)

    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = theharvester.run("example.com", "crtsh", "/tmp/test_harvest_parse")

            # Should have 6 items: 2 emails + 2 hosts + 1 ip + 1 url
            assert len(result) == 6

            # Check for specific items
            assert {"item_type": "email", "value": "admin@example.com", "source": "theharvester"} in result
            assert {"item_type": "email", "value": "info@example.com", "source": "theharvester"} in result
            assert {"item_type": "subdomain", "value": "mail.example.com", "source": "theharvester"} in result
            assert {"item_type": "subdomain", "value": "api.example.com", "source": "theharvester"} in result
            assert {"item_type": "ip", "value": "10.0.0.1", "source": "theharvester"} in result
            assert {"item_type": "url", "value": "http://example.com/admin", "source": "theharvester"} in result
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)


def test_malformed_json_returns_empty():
    """Test that malformed JSON returns empty list."""
    tmpfile = "/tmp/test_harvest_bad.json"

    with open(tmpfile, "w") as f:
        f.write("not valid json")

    try:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = theharvester.run("example.com", "crtsh", "/tmp/test_harvest_bad")
            assert result == []
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)
