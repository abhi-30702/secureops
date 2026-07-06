import json
import os
import tempfile
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner

# nikto is thorough and slow; this is a per-host ceiling (the wrapper scans each
# host in its own run_buffered call).
_TIMEOUT = 600  # 10 min per host


def run(http_hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    for host in http_hosts:
        findings.extend(_scan_host(host, runner, db, scan_id))
    return findings


def _scan_host(host: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    fd, tmpfile = tempfile.mkstemp(suffix=".json", prefix="secureops_nikto_")
    os.close(fd)
    try:
        runner.run_buffered(["nikto", "-h", host, "-Format", "json", "-output", tmpfile, "-nointeractive"], timeout=_TIMEOUT)
        if os.path.getsize(tmpfile) > 0:
            return _parse_json_file(tmpfile, db, scan_id)
        return []
    except Exception:
        return []
    finally:
        if os.path.exists(tmpfile):
            os.unlink(tmpfile)


def _parse_json_file(path: str, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
        for vuln in data.get("vulnerabilities") or []:
            msg = vuln.get("msg") or vuln.get("message") or "Unknown issue"
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="nikto",
                severity="medium",
                title=msg[:120],
                description=f"URL: {vuln.get('url', '')}  Ref: {vuln.get('references', '')}",
                raw_json=json.dumps(vuln),
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = db.insert_finding(finding)
            findings.append(finding)
    except (json.JSONDecodeError, KeyError):
        pass
    return findings
