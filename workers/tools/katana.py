import json
import os
from datetime import datetime, timezone
from models import Host
from db import DB
from workers.base_tool import ToolRunner, ToolError, _write_tmpfile

# Crawling many URLs can outrun the 300s default; give the crawler more room.
_TIMEOUT = 600  # 10 min


def run(urls: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Host]:
    if not urls:
        return []
    tmpfile = _write_tmpfile(urls)
    hosts = []
    try:
        for line in runner.run(["katana", "-list", tmpfile, "-jsonl", "-silent"], timeout=_TIMEOUT):
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
    except ToolError:
        # Crawling routinely outlives the timeout — keep the endpoints already
        # streamed to the DB instead of reporting the whole crawl as failed.
        # Re-raise only if nothing was crawled, so a real failure still surfaces.
        if not hosts:
            raise
    finally:
        os.unlink(tmpfile)
    return hosts
