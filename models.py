from dataclasses import dataclass


@dataclass
class Client:
    id: int | None
    name: str
    domain: str
    firewall: str
    notes: str
    created_at: str


@dataclass
class Scan:
    id: int | None
    client_id: int | None
    target: str
    status: str
    started_at: str
    finished_at: str | None


@dataclass
class Host:
    id: int | None
    scan_id: int
    subdomain: str | None
    ip: str | None
    port: int | None
    protocol: str | None
    service: str | None
    url: str | None
    source_tool: str
    created_at: str


@dataclass
class Finding:
    id: int | None
    scan_id: int
    host_id: int | None
    tool: str
    severity: str
    title: str
    description: str
    raw_json: str
    created_at: str
