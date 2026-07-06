import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from models import Finding
from db import DB
from workers.base_tool import ToolRunner, ToolError, _write_tmpfile

# -sV service/version detection across many hosts is slow; the 300s default cuts
# scans short on larger subnets. Give nmap a wider ceiling.
_TIMEOUT = 1200  # 20 min


def run(hosts: list[str], runner: ToolRunner, db: DB, scan_id: int) -> list[Finding]:
    if not hosts:
        return []
    tmpfile = _write_tmpfile(hosts)
    findings = []
    try:
        xml_output = runner.run_buffered(["nmap", "-iL", tmpfile, "-oX", "-", "-sV"], timeout=_TIMEOUT)
        if not xml_output.strip():
            return findings
        root = ET.fromstring(xml_output)
        for host_el in root.findall("host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            ip = addr_el.get("addr") if addr_el is not None else "unknown"
            ports_el = host_el.find("ports")
            if ports_el is None:
                continue
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                proto = port_el.get("protocol", "tcp")
                portid = port_el.get("portid", "?")
                service_el = port_el.find("service")
                svc_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                desc = " ".join(filter(None, [product, version])) or svc_name
                finding = Finding(
                    id=None,
                    scan_id=scan_id,
                    host_id=None,
                    tool="nmap",
                    severity="info",
                    title=f"Open port {portid}/{proto} ({svc_name})",
                    description=desc,
                    raw_json=xml_output[:2000],
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
                finding.id = db.insert_finding(finding)
                findings.append(finding)
    except ET.ParseError:
        raise ToolError("nmap: failed to parse XML output")
    finally:
        os.unlink(tmpfile)
    return findings
