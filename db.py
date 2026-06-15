import sqlite3
import threading
from models import Client, Scan, Host, Finding, Schedule

_SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL,
    firewall    TEXT,
    notes       TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id   INTEGER REFERENCES clients(id),
    target      TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    subdomain   TEXT,
    ip          TEXT,
    port        INTEGER,
    protocol    TEXT,
    service     TEXT,
    url         TEXT,
    source_tool TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    host_id     INTEGER REFERENCES hosts(id),
    tool        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    raw_json    TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL UNIQUE,
    interval_h  INTEGER NOT NULL DEFAULT 24,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run    TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS advisory_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES scans(id),
    tier       TEXT NOT NULL,
    text       TEXT NOT NULL,
    accepted   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incident_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    timestamp   TEXT,
    event_type  TEXT,
    source_host TEXT,
    dest_host   TEXT,
    description TEXT,
    evidence    TEXT
);
CREATE TABLE IF NOT EXISTS osint_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    domain      TEXT,
    item_type   TEXT,
    value       TEXT,
    source      TEXT,
    created_at  TEXT
);
CREATE TABLE IF NOT EXISTS companies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    domains       TEXT DEFAULT '[]',
    ip_ranges     TEXT DEFAULT '[]',
    aws_profile   TEXT DEFAULT '',
    gcp_project   TEXT DEFAULT '',
    firewall_type TEXT DEFAULT '',
    created_at    TEXT DEFAULT ''
);
"""

_SEED_COMPANIES = [
    {"name": "Fidelitus Corp HQ",      "domains": '["fidelitus.com"]',          "ip_ranges": '["10.0.0.0/24"]'},
    {"name": "Fidelitus Education",    "domains": '["fidelitusedu.com"]',       "ip_ranges": '["10.0.8.0/24"]'},
    {"name": "Fidelitus Finance",      "domains": '["fidelitusfinance.com"]',   "ip_ranges": '["10.0.3.0/24"]'},
    {"name": "Fidelitus Healthcare",   "domains": '["fidelitushealth.com"]',    "ip_ranges": '["10.0.7.0/24"]'},
    {"name": "Fidelitus HR Solutions", "domains": '["fidelitushr.com"]',        "ip_ranges": '["10.0.2.0/24"]'},
    {"name": "Fidelitus Legal",        "domains": '["fidelituslegal.com"]',     "ip_ranges": '["10.0.6.0/24"]'},
    {"name": "Fidelitus Logistics",    "domains": '["fidelituslogistics.com"]', "ip_ranges": '["10.0.4.0/24"]'},
    {"name": "Fidelitus Properties",   "domains": '["fidelitusproperties.com"]',"ip_ranges": '["10.0.1.0/24"]'},
    {"name": "Fidelitus Tech",         "domains": '["fidelitustech.com"]',      "ip_ranges": '["10.0.5.0/24"]'},
]


class DB:
    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        for stmt in _SCHEMA.strip().split(";"):
            if stmt.strip():
                self._conn.execute(stmt)
        self._conn.commit()
        self._ensure_seed_companies()

    def _ensure_seed_companies(self) -> None:
        with self._lock:
            count = self._conn.execute("SELECT COUNT(*) FROM companies").fetchone()[0]
            if count == 0:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc).isoformat()
                for c in _SEED_COMPANIES:
                    self._conn.execute(
                        "INSERT INTO companies (name, domains, ip_ranges, aws_profile, gcp_project, firewall_type, created_at) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (c["name"], c.get("domains", "[]"), c.get("ip_ranges", "[]"),
                         c.get("aws_profile", ""), c.get("gcp_project", ""),
                         c.get("firewall_type", ""), now),
                    )
                self._conn.commit()

    def insert_company(self, company: dict) -> int:
        from datetime import datetime, timezone
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO companies (name, domains, ip_ranges, aws_profile, gcp_project, firewall_type, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (company.get("name", ""), company.get("domains", "[]"),
                 company.get("ip_ranges", "[]"), company.get("aws_profile", ""),
                 company.get("gcp_project", ""), company.get("firewall_type", ""),
                 company.get("created_at", datetime.now(timezone.utc).isoformat())),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_companies(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, domains, ip_ranges, aws_profile, gcp_project, firewall_type, created_at "
                "FROM companies ORDER BY name"
            ).fetchall()
        return [dict(r) for r in rows]

    def update_company(self, company_id: int, company: dict) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE companies SET name=?, domains=?, ip_ranges=?, aws_profile=?, gcp_project=?, firewall_type=? "
                "WHERE id=?",
                (company.get("name", ""), company.get("domains", "[]"),
                 company.get("ip_ranges", "[]"), company.get("aws_profile", ""),
                 company.get("gcp_project", ""), company.get("firewall_type", ""),
                 company_id),
            )
            self._conn.commit()

    def delete_company(self, company_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM companies WHERE id=?", (company_id,))
            self._conn.commit()

    def insert_client(self, client: Client) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO clients (name, domain, firewall, notes, created_at) VALUES (?,?,?,?,?)",
                (client.name, client.domain, client.firewall, client.notes, client.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_clients(self) -> list[Client]:
        rows = self._conn.execute("SELECT * FROM clients ORDER BY id").fetchall()
        return [Client(id=r["id"], name=r["name"], domain=r["domain"], firewall=r["firewall"] or "", notes=r["notes"] or "", created_at=r["created_at"]) for r in rows]

    def insert_scan(self, scan: Scan) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (client_id, target, status, started_at, finished_at) VALUES (?,?,?,?,?)",
                (scan.client_id, scan.target, scan.status, scan.started_at, scan.finished_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def update_scan_status(self, scan_id: int, status: str, finished_at: str | None = None):
        with self._lock:
            self._conn.execute(
                "UPDATE scans SET status=?, finished_at=? WHERE id=?",
                (status, finished_at, scan_id),
            )
            self._conn.commit()

    def query_scans_by_client(self, client_id: int | None) -> list[Scan]:
        if client_id is None:
            rows = self._conn.execute("SELECT * FROM scans WHERE client_id IS NULL ORDER BY id").fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM scans WHERE client_id=? ORDER BY id", (client_id,)).fetchall()
        return [Scan(id=r["id"], client_id=r["client_id"], target=r["target"], status=r["status"], started_at=r["started_at"], finished_at=r["finished_at"]) for r in rows]

    def insert_host(self, host: Host) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO hosts (scan_id, subdomain, ip, port, protocol, service, url, source_tool, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (host.scan_id, host.subdomain, host.ip, host.port, host.protocol, host.service, host.url, host.source_tool, host.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_hosts_by_scan(self, scan_id: int) -> list[Host]:
        rows = self._conn.execute("SELECT * FROM hosts WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [Host(id=r["id"], scan_id=r["scan_id"], subdomain=r["subdomain"], ip=r["ip"], port=r["port"], protocol=r["protocol"], service=r["service"], url=r["url"], source_tool=r["source_tool"], created_at=r["created_at"]) for r in rows]

    def insert_finding(self, finding: Finding) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings (scan_id, host_id, tool, severity, title, description, raw_json, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (finding.scan_id, finding.host_id, finding.tool, finding.severity, finding.title, finding.description, finding.raw_json, finding.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def insert_incident_event(self, event: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO incident_events "
                "(scan_id, timestamp, event_type, source_host, dest_host, description, evidence) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    event.get("scan_id"),
                    event.get("timestamp", ""),
                    event.get("event_type", "anomaly"),
                    event.get("source_host", ""),
                    event.get("dest_host", ""),
                    event.get("description", ""),
                    event.get("evidence", ""),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_incident_events(self, scan_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, scan_id, timestamp, event_type, source_host, dest_host, description, evidence "
                "FROM incident_events WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [
            {
                "id": r["id"], "scan_id": r["scan_id"], "timestamp": r["timestamp"],
                "event_type": r["event_type"], "source_host": r["source_host"],
                "dest_host": r["dest_host"], "description": r["description"],
                "evidence": r["evidence"],
            }
            for r in rows
        ]

    def insert_osint_item(self, item: dict) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO osint_items "
                "(scan_id, domain, item_type, value, source, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    item.get("scan_id"),
                    item.get("domain", ""),
                    item.get("item_type", ""),
                    item.get("value", ""),
                    item.get("source", ""),
                    item.get("created_at", ""),
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_osint_items(self, scan_id: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, scan_id, domain, item_type, value, source, created_at "
                "FROM osint_items WHERE scan_id=? ORDER BY id",
                (scan_id,),
            ).fetchall()
        return [
            {
                "id": r["id"], "scan_id": r["scan_id"], "domain": r["domain"],
                "item_type": r["item_type"], "value": r["value"],
                "source": r["source"], "created_at": r["created_at"],
            }
            for r in rows
        ]

    def query_findings_by_scan(self, scan_id: int) -> list[Finding]:
        rows = self._conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
        return [Finding(id=r["id"], scan_id=r["scan_id"], host_id=r["host_id"], tool=r["tool"], severity=r["severity"], title=r["title"], description=r["description"] or "", raw_json=r["raw_json"] or "", created_at=r["created_at"]) for r in rows]

    def insert_schedule(self, schedule: Schedule) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO schedules (target, interval_h, enabled, last_run, created_at) VALUES (?,?,?,?,?)",
                (schedule.target, schedule.interval_h, 1 if schedule.enabled else 0,
                 schedule.last_run, schedule.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_schedules(self) -> list[Schedule]:
        rows = self._conn.execute("SELECT * FROM schedules ORDER BY id").fetchall()
        return [Schedule(id=r["id"], target=r["target"], interval_h=r["interval_h"],
                         enabled=bool(r["enabled"]), last_run=r["last_run"],
                         created_at=r["created_at"]) for r in rows]

    def update_schedule(self, schedule_id: int, enabled: bool,
                        last_run: str | None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE schedules SET enabled=?, last_run=? WHERE id=?",
                (1 if enabled else 0, last_run, schedule_id),
            )
            self._conn.commit()

    def delete_schedule(self, schedule_id: int) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM schedules WHERE id=?", (schedule_id,))
            self._conn.commit()

    def query_recent_findings(self, limit: int = 20) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [Finding(id=r["id"], scan_id=r["scan_id"], host_id=r["host_id"],
                        tool=r["tool"], severity=r["severity"], title=r["title"],
                        description=r["description"] or "", raw_json=r["raw_json"] or "",
                        created_at=r["created_at"]) for r in rows]

    def insert_advisory_item(self, item) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO advisory_items (scan_id, tier, text, accepted, created_at)"
                " VALUES (?,?,?,?,?)",
                (item.scan_id, item.tier, item.text,
                 1 if item.accepted else 0, item.created_at),
            )
            self._conn.commit()
            return cur.lastrowid

    def query_advisory_items_by_scan(self, scan_id: int) -> list:
        rows = self._conn.execute(
            "SELECT * FROM advisory_items WHERE scan_id=? ORDER BY id", (scan_id,)
        ).fetchall()
        from models import AdvisoryItem
        return [AdvisoryItem(id=r["id"], scan_id=r["scan_id"], tier=r["tier"],
                             text=r["text"], accepted=bool(r["accepted"]),
                             created_at=r["created_at"]) for r in rows]

    def update_advisory_item_accepted(self, item_id: int, accepted: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE advisory_items SET accepted=? WHERE id=?",
                (1 if accepted else 0, item_id),
            )
            self._conn.commit()

    def delete_advisory_items_by_scan(self, scan_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "DELETE FROM advisory_items WHERE scan_id=?", (scan_id,)
            )
            self._conn.commit()

    def get_setting(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM app_settings WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO app_settings (key, value) VALUES (?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()
