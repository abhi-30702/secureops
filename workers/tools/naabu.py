import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, ToolError, _write_tmpfile

# Port-scanning many hosts can outrun the 300s default on larger address sets.
_TIMEOUT = 600  # 10 min


def run(ips: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not ips:
        return []
    tmpfile = _write_tmpfile(ips)
    hosts = []
    try:
        for line in runner.run(["naabu", "-l", tmpfile, "-json", "-silent"], timeout=_TIMEOUT):
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
    except ToolError:
        # Keep partial results on a timeout; re-raise a true zero-result failure
        # so it still surfaces instead of silently reporting success.
        if not hosts:
            raise
    finally:
        os.unlink(tmpfile)
    return hosts
