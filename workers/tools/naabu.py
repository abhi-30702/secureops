import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(ips: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not ips:
        return []
    tmpfile = _write_tmpfile(ips)
    hosts = []
    try:
        for line in runner.run(["naabu", "-l", tmpfile, "-json", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=data.get("ip"),
                port=data.get("port"),
                protocol=data.get("protocol"),
                service=None,
                url=None,
                source_tool="naabu",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host.id = db.insert_host(host)
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
