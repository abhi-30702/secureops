import json
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner


def run(target: str, runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    cmd = ["subfinder", "-d", target, "-json", "-silent"]
    hosts = []
    for line in runner.run(cmd):
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
    return hosts
