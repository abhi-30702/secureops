"""Live network-activity capture worker for the Network Activity Monitor page.

Runs on a QThread (Rule #1 — the UI never blocks). Passively sniffs the wire
with scapy (Wireshark-style live capture), extracting the destination host from
DNS queries (primary signal), HTTP ``Host:`` headers and TLS SNI (best-effort).
Requires ``CAP_NET_RAW`` — run the app with ``sudo``.

Every observed host is matched against the :class:`BlocklistEngine`, written to
SQLite immediately (crash-safe audit trail), and streamed to the UI via signals.
This is strictly passive detection/reporting: the worker never injects, blocks,
or modifies traffic.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from blocklist_engine import BlocklistEngine

# BPF filter for the traffic we can parse a hostname out of.
_CAPTURE_FILTER = "udp port 53 or tcp port 80 or tcp port 443"


def list_interfaces() -> list[str]:
    """Available capture interfaces, for the UI picker (Wireshark-style).

    Prefers scapy's interface list; falls back to ``/sys/class/net``. Never
    raises — returns an empty list if nothing can be enumerated."""
    try:
        from scapy.all import get_if_list  # lazy: scapy import is heavy
        ifaces = [i for i in get_if_list() if i]
    except Exception:
        try:
            import os
            ifaces = os.listdir("/sys/class/net")
        except OSError:
            ifaces = []
    # keep it stable + put loopback last
    ifaces = sorted(set(ifaces))
    return sorted(ifaces, key=lambda n: (n in ("lo", "any"), n))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_sni(payload: bytes) -> str | None:
    """Best-effort TLS ClientHello SNI extraction from raw TCP bytes.

    Returns the server_name or None. Deliberately defensive — malformed or
    non-ClientHello payloads simply yield None rather than raising.
    """
    try:
        # TLS record: type(1)=0x16 handshake, version(2), length(2)
        if len(payload) < 43 or payload[0] != 0x16:
            return None
        # Handshake: type(1)=0x01 ClientHello, length(3)
        if payload[5] != 0x01:
            return None
        idx = 43  # skip record+handshake headers, version, random(32)
        session_id_len = payload[idx]
        idx += 1 + session_id_len
        cipher_len = int.from_bytes(payload[idx:idx + 2], "big")
        idx += 2 + cipher_len
        comp_len = payload[idx]
        idx += 1 + comp_len
        if idx + 2 > len(payload):
            return None
        idx += 2  # extensions total length
        while idx + 4 <= len(payload):
            ext_type = int.from_bytes(payload[idx:idx + 2], "big")
            ext_len = int.from_bytes(payload[idx + 2:idx + 4], "big")
            idx += 4
            if ext_type == 0x0000:  # server_name
                # server_name_list(2) + type(1) + name_len(2) + name
                name_len = int.from_bytes(payload[idx + 3:idx + 5], "big")
                name = payload[idx + 5:idx + 5 + name_len]
                return name.decode("ascii", "ignore") or None
            idx += ext_len
    except Exception:
        return None
    return None


def _extract_http_host(payload: bytes) -> str | None:
    try:
        text = payload.decode("latin-1", "ignore")
        if not text.startswith(("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ")):
            return None
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip() or None
    except Exception:
        return None
    return None


class NetworkMonitorWorker(QThread):
    """Streams live-captured network events + blocklist alerts."""

    event_captured = pyqtSignal(dict)   # one network event (already persisted)
    alert_raised   = pyqtSignal(dict)   # a blocked event → red flag
    state_changed  = pyqtSignal(str, str)  # state, human message
    error_occurred = pyqtSignal(str, str)  # source, message

    def __init__(
        self,
        db: DB,
        blocklist: BlocklistEngine,
        iface: str | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._db = db
        self._blocklist = blocklist
        self._iface = iface or None
        self._cancel = threading.Event()

    def stop(self) -> None:
        self._cancel.set()

    # -- QThread entry ------------------------------------------------- #
    def run(self) -> None:
        try:
            self._run_live()
        except Exception as exc:  # last-resort guard — never crash the app
            self.error_occurred.emit("network-monitor", str(exc))
            self.state_changed.emit("error", f"Capture error: {exc}")

    # -- shared event handling ---------------------------------------- #
    def _handle(self, src_ip: str, dst_ip: str, domain: str,
                port: int, protocol: str) -> None:
        """Classify, persist and emit a single observed host access."""
        if not domain:
            return
        domain = domain.lower().rstrip(".")
        match = self._blocklist.match(domain)
        blocked = match is not None
        employee = self._blocklist.employee_for(src_ip)
        event = {
            "timestamp": _now(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "domain": domain,
            "port": port,
            "protocol": protocol,
            "status": "blocked" if blocked else "allowed",
            "blocked_reason": match["reason"] if blocked else "",
            "employee_name": employee,
        }
        try:
            event["id"] = self._db.insert_network_event(event)
        except Exception as exc:
            self.error_occurred.emit("db", f"event persist failed: {exc}")
            event["id"] = None

        self.event_captured.emit(event)

        if blocked:
            alert = {
                "event_id": event.get("id"),
                "severity": match["severity"],
                "domain": domain,
                "src_ip": src_ip,
                "employee_name": employee,
                "created_at": event["timestamp"],
                "acknowledged": False,
                "notes": match["reason"],
            }
            try:
                alert["id"] = self._db.insert_network_alert(alert)
            except Exception as exc:
                self.error_occurred.emit("db", f"alert persist failed: {exc}")
            self.alert_raised.emit(alert)

    # -- live capture -------------------------------------------------- #
    def _run_live(self) -> None:
        try:
            from scapy.all import AsyncSniffer  # lazy: heavy import, root-only
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.packet import Raw
        except Exception as exc:
            self.state_changed.emit(
                "error", f"scapy unavailable ({exc}). Install scapy to capture."
            )
            return

        def _on_packet(pkt) -> None:
            # Per-packet isolation (Rule #2): one bad packet never stops capture.
            try:
                if IP not in pkt:
                    return
                src = pkt[IP].src
                dst = pkt[IP].dst
                # DNS query — the primary "website visited" signal.
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                    qname = pkt[DNSQR].qname
                    domain = qname.decode("utf-8", "ignore") if isinstance(qname, bytes) else str(qname)
                    self._handle(src, dst, domain, 53, "DNS")
                    return
                if TCP in pkt and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    dport = int(pkt[TCP].dport)
                    if dport == 443:
                        host = _extract_sni(payload)
                        if host:
                            self._handle(src, dst, host, 443, "TLS")
                    elif dport == 80:
                        host = _extract_http_host(payload)
                        if host:
                            self._handle(src, dst, host, 80, "HTTP")
            except Exception as exc:
                self.error_occurred.emit("parse", str(exc))

        try:
            sniffer = AsyncSniffer(
                filter=_CAPTURE_FILTER,
                prn=_on_packet,
                store=False,
                iface=self._iface,
            )
            sniffer.start()
        except (PermissionError, OSError) as exc:
            self.state_changed.emit(
                "error",
                "Live capture needs root (CAP_NET_RAW) — launch SecureOps with sudo. "
                f"({exc})",
            )
            return
        except Exception as exc:
            self.state_changed.emit("error", f"Could not start capture: {exc}")
            return

        self.state_changed.emit(
            "running", f"Live capture on {self._iface or 'default interface'}"
        )
        # Poll the cancel flag; scapy sniffs on its own thread.
        while not self._cancel.is_set():
            time.sleep(0.2)
        try:
            sniffer.stop()
        except Exception:
            pass
        self.state_changed.emit("stopped", "Live capture stopped")
