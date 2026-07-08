import json
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, ToolError

# Passive enumeration across many sources can exceed 300s for large orgs.
_TIMEOUT = 600  # 10 min


def run(target: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    cmd = ["subfinder", "-d", target, "-json", "-silent"]
    hosts = []
    try:
        for line in runner.run(cmd, timeout=_TIMEOUT):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=data.get("host"),
                ip=None,
                port=None,
                protocol=None,
                service=None,
                url=None,
                source_tool="subfinder",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host.id = db.insert_host(host)
            hosts.append(host)
    except ToolError:
        # A timeout after partial output shouldn't discard what we already
        # streamed to the DB — return it. But a genuine zero-result failure must
        # still surface (don't reintroduce the silent-green class of bug).
        if not hosts:
            raise
    return hosts
