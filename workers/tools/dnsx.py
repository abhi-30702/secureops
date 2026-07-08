import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, ToolError, _write_tmpfile

# Resolving thousands of subdomains can run past the 300s default on big orgs.
_TIMEOUT = 600  # 10 min


def run(subdomains: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not subdomains:
        return []
    tmpfile = _write_tmpfile(subdomains)
    hosts = []
    try:
        for line in runner.run(["dnsx", "-l", tmpfile, "-json", "-silent"], timeout=_TIMEOUT):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            ips = data.get("a") or []
            ip = ips[0] if ips else None
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=data.get("host"),
                ip=ip,
                port=None,
                protocol=None,
                service=None,
                url=None,
                source_tool="dnsx",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host.id = db.insert_host(host)
            hosts.append(host)
    except ToolError:
        # Keep partial results on a timeout; re-raise a true zero-result failure
        # so it still surfaces instead of silently reporting success.
        if not hosts:
            raise
    finally:
        os.unlink(tmpfile)
    return hosts
