import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, _write_tmpfile


def run(urls: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not urls:
        return []
    tmpfile = _write_tmpfile(urls)
    hosts = []
    try:
        for line in runner.run(["katana", "-list", tmpfile, "-jsonl", "-silent"]):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = (data.get("request") or {}).get("endpoint")
            if not endpoint:
                continue
            host = Host(
                id=None,
                scan_id=scan_id,
                subdomain=None,
                ip=None,
                port=None,
                protocol=None,
                service=None,
                url=endpoint,
                source_tool="katana",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            host.id = db.insert_host(host)
            hosts.append(host)
    finally:
        os.unlink(tmpfile)
    return hosts
