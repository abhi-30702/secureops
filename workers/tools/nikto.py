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

# nikto writes its report only at the END of its ~7000-check run, so a mid-run
# SIGKILL from the ToolRunner watchdog loses everything → silent 0 findings. Pass
# -maxtime just under _TIMEOUT so nikto stops itself and writes partial results
# before the watchdog fires.
_MAXTIME = "570s"


def run(http_hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    for host in http_hosts:
        findings.extend(_scan_host(host, runner, db, scan_id))
    return findings


def _scan_host(host: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    fd, tmpfile = tempfile.mkstemp(prefix="secureops_nikto_")
    os.close(fd)
    # nikto 2.6.0 APPENDS the -Format extension to -output, so `-output X -Format
    # json` actually writes to `X.json`, not `X`. Check the appended path first,
    # then the bare path, so we read whichever this nikto build produced.
    candidates = [tmpfile + ".json", tmpfile]
    try:
        runner.run_buffered(
            ["nikto", "-h", host, "-Format", "json", "-output", tmpfile, "-nointeractive", "-maxtime", _MAXTIME],
            timeout=_TIMEOUT,
        )
        for path in candidates:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                return _parse_json_file(path, db, scan_id)
        return []
    except Exception:
        return []
    finally:
        for path in candidates:
            if os.path.exists(path):
                os.unlink(path)


def _parse_json_file(path: str, db: DB, scan_id: int) -> list[Finding]:
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return findings
    # nikto 2.6.0 emits a LIST of per-host result objects, each carrying its own
    # "vulnerabilities" array. Older builds emitted a single dict — handle both.
    if isinstance(data, dict):
        host_objs = [data]
    elif isinstance(data, list):
        host_objs = data
    else:
        return findings
    for host_obj in host_objs:
        if not isinstance(host_obj, dict):
            continue
        for vuln in host_obj.get("vulnerabilities") or []:
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
    return findings
