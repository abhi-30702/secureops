import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(targets: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not targets:
        return []
    tmpfile = _write_tmpfile(targets)
    hosts = []
    try:
        for line in runner.run(["httpx", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=None,
                port=None,
                protocol=None,
                service=data.get("webserver"),
                url=data.get("url"),
                source_tool="httpx",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host.id = db.insert_host(host)
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
