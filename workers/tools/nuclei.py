import json
import os
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(targets: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    if not targets:
        return []
    tmpfile = _write_tmpfile(targets)
    findings = []
    try:
        for line in runner.run(["nuclei", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = data.get("info") or {}
            finding = Finding(
                id=None,
                scan_id=scan_id,
                host_id=None,
                tool="nuclei",
                severity=(info.get("severity") or "info").lower(),
                title=info.get("name") or data.get("template-id") or "Unknown",
                description=info.get("description") or "",
                raw_json=line,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = db.insert_finding(finding)
            findings.append(finding)
    finally:
        os.unlink(tmpfile)
    return findings
