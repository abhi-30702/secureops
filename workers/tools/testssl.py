import json
import os
import tempfile
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "OK": None,
    "NOT OK": "medium",
    "WARN": "low",
    "DEBUG": "info",
}

# testssl.sh probes a long battery of TLS checks and regularly runs 2-3 min per
# host — well past the 300s default once a host is slow. Per-host ceiling.
_TIMEOUT = 600  # 10 min per host


def run(https_hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    for host in https_hosts:
        findings.extend(_scan_host(host, runner, db, scan_id))
    return findings


def _scan_host(host: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="secureops_testssl_")
    os.close(fd)
    try:
        runner.run_buffered(["testssl.sh", "--jsonfile", tmpfile, "--quiet", "--color", "0", host], timeout=_TIMEOUT)
        if not os.path.exists(tmpfile) or os.path.getsize(tmpfile) == 0:
            return []
        return _parse_json_file(tmpfile, db, scan_id)
    except Exception:
        return []
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)


def _parse_json_file(path: str, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    try:
        with open(path) as f:
            items = json.load(f)
        for item in items:
            raw_sev = (item.get("severity") or "").upper()
            severity = _SEVERITY_MAP.get(raw_sev)
            if severity is None:
                continue
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="testssl",
                severity=severity,
                title=f"testssl: {item.get('id', 'unknown')}",
                description=item.get("finding") or "",
                raw_json=json.dumps(item),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = db.insert_finding(finding)
            findings.append(finding)
    except (json.JSONDecodeError, TypeError):
        pass
    return findings
