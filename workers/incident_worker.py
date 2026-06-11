import re
import threading
from collections import defaultdict
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding
from workers.log_rules import detect_format, RULES
from workers.base_tool import CancelledError

try:
    from advisor.gemini_client import GeminiClient as _GeminiClient
except Exception:
    _GeminiClient = None

_RULE_EVENT_TYPE: dict[str, str] = {
    "ssh_brute_force":     "entry",
    "root_sudo":           "lateral",
    "user_account_change": "persistence",
    "pubkey_login":        "entry",
    "sqli_attempt":        "entry",
    "scanner_ua":          "entry",
    "http_scan_rate":      "entry",
    "port_scan":           "entry",
    "repeated_block":      "entry",
    "oom_killer":          "anomaly",
    "kernel_panic":        "anomaly",
}


class IncidentWorker(QThread):
    finding_found  = pyqtSignal(object)
    tool_progress  = pyqtSignal(str, int, str)
    log_line       = pyqtSignal(str)
    scan_complete  = pyqtSignal(int, int)
    scan_failed    = pyqtSignal(str)
    error_occurred = pyqtSignal(str, str)

    def __init__(
        self,
        log_path: str,
        scan_id: int,
        db: DB,
        yara_extra_path: str = "",
        parent=None,
    ):
        super().__init__(parent)
        self._log_path = log_path
        self._scan_id = scan_id
        self._db = db
        self._yara_extra_path = yara_extra_path
        self._cancel_event = threading.Event()

    def stop(self) -> None:
        self._cancel_event.set()

    def run(self) -> None:
        total = 0
        try:
            # Stage 1
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            result1 = self._stage1_log_analysis(None)
            if result1 is None:
                self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
                return
            total += result1

            # Stage 2
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            total += self._stage2_yara_scan()

            # Stage 3
            if self._cancel_event.is_set():
                self._db.update_scan_status(self._scan_id, "cancelled", datetime.now(timezone.utc).isoformat())
                return
            total += self._stage3_persistence()

        except Exception as exc:
            self._db.update_scan_status(self._scan_id, "failed", datetime.now(timezone.utc).isoformat())
            self.scan_failed.emit(f"Incident scan error: {exc}")
            return

        self._db.update_scan_status(self._scan_id, "complete", datetime.now(timezone.utc).isoformat())
        self.scan_complete.emit(0, total)

    # ── Stage 1: Log Analysis ────────────────────────────────────────────────

    def _stage1_log_analysis(self, _runner) -> int | None:
        self.log_line.emit("[incident] Stage 1 — log analysis")
        try:
            lines = self._read_file()
        except FileNotFoundError:
            self.scan_failed.emit(f"Log file not found: {self._log_path}")
            return None
        except PermissionError:
            self.scan_failed.emit("Cannot read log file: permission denied")
            return None

        fmt = detect_format(lines)
        self.log_line.emit(f"[incident] detected format: {fmt}")

        findings = self._run_rules(lines, fmt)
        self.log_line.emit(f"[incident] rules complete — {len(findings)} findings")

        findings = self._enrich_with_ai(findings)

        for f in findings:
            f.id = self._db.insert_finding(f)
            self._maybe_write_event(f)
            self.finding_found.emit(f)

        self.log_line.emit(f"[incident] Stage 1 complete — {len(findings)} findings")
        return len(findings)

    def _read_file(self) -> list[str]:
        with open(self._log_path, "r", errors="replace") as fh:
            return fh.readlines()

    def _run_rules(self, lines: list[str], fmt: str) -> list[Finding]:
        applicable = [
            r for r in RULES
            if "*" in r.formats or fmt in r.formats or fmt == "unknown"
        ]

        count_rules = {"ssh_brute_force", "http_scan_rate", "repeated_block", "port_scan"}
        count_hits: dict[str, dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
        match_hits: dict[str, set[str]] = defaultdict(set)

        for lineno, line in enumerate(lines, start=1):
            for rule in applicable:
                m = rule.pattern.search(line)
                if not m:
                    continue
                if rule.name in count_rules:
                    key = m.group(1) if m.lastindex and m.lastindex >= 1 else "unknown"
                    count_hits[rule.name][key].append(lineno)
                else:
                    match_hits[rule.name].add(m.group(0)[:120])

        findings: list[Finding] = []
        thresholds = {
            "ssh_brute_force": 5,
            "http_scan_rate":  20,
            "repeated_block":  10,
            "port_scan":       1,
        }
        rule_by_name = {r.name: r for r in applicable}

        for rule_name, key_hits in count_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            threshold = thresholds.get(rule_name, 1)
            for key, line_numbers in key_hits.items():
                if len(line_numbers) < threshold:
                    continue
                desc = (
                    f"{rule.description}: {len(line_numbers)} occurrences from {key} "
                    f"(lines {line_numbers[0]}–{line_numbers[-1]})"
                )
                findings.append(Finding(
                    id=None, scan_id=self._scan_id, host_id=None,
                    tool="log-analyzer", severity=rule.severity.lower(),
                    title=f"{rule_name.replace('_', ' ').title()} — {key}",
                    description=desc, raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        for rule_name, matched_strings in match_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            for matched in matched_strings:
                findings.append(Finding(
                    id=None, scan_id=self._scan_id, host_id=None,
                    tool="log-analyzer", severity=rule.severity.lower(),
                    title=rule_name.replace("_", " ").title(),
                    description=f"{rule.description}: {matched}", raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        return findings

    def _enrich_with_ai(self, findings: list[Finding]) -> list[Finding]:
        if not self._db:
            return findings
        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""
        if not enabled or not api_key or _GeminiClient is None:
            return findings
        self.log_line.emit("[incident] enriching with AI Advisor...")
        try:
            summary_lines = [
                f"- [{f.severity.upper()}] {f.title}: {f.description[:200]}"
                for f in findings
            ]
            prompt = (
                "You are a security analyst. Analyse these log anomalies and identify "
                "any additional security concerns. For each concern respond with:\n"
                "SEVERITY: HIGH|MEDIUM|LOW\nTITLE: short title\nDESCRIPTION: one sentence\n\n"
                + "\n".join(summary_lines[:20])
            )
            response = _GeminiClient(api_key).generate(prompt)
            ai_findings = self._parse_ai_response(response)
            findings.extend(ai_findings)
            self.log_line.emit(f"[incident] AI Advisor added {len(ai_findings)} findings")
        except Exception as exc:
            self.log_line.emit(f"[incident] AI Advisor error (skipped): {exc}")
        return findings

    def _parse_ai_response(self, text: str) -> list[Finding]:
        findings = []
        blocks = re.split(r"\n(?=SEVERITY:)", text.strip())
        for block in blocks:
            sev_m = re.search(r"SEVERITY:\s*(HIGH|MEDIUM|LOW|CRITICAL|INFO)", block, re.IGNORECASE)
            title_m = re.search(r"TITLE:\s*(.+)", block)
            desc_m = re.search(r"DESCRIPTION:\s*(.+)", block)
            if not (sev_m and title_m):
                continue
            findings.append(Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="log-analyzer", severity=sev_m.group(1).lower(),
                title=title_m.group(1).strip(),
                description=desc_m.group(1).strip() if desc_m else "",
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
        return findings

    def _maybe_write_event(self, finding: Finding) -> None:
        rule_name = finding.title.split(" — ")[0].lower().replace(" ", "_")
        event_type = _RULE_EVENT_TYPE.get(rule_name)
        if event_type is None:
            return
        source = finding.title.split(" — ")[1] if " — " in finding.title else ""
        self._db.insert_incident_event({
            "scan_id":    self._scan_id,
            "timestamp":  finding.created_at,
            "event_type": event_type,
            "source_host": source,
            "dest_host":  "",
            "description": finding.title,
            "evidence":   finding.description[:200],
        })

    # ── Stage 2: YARA Scan ───────────────────────────────────────────────────

    def _stage2_yara_scan(self) -> int:
        self.log_line.emit("[incident] Stage 2 — YARA scan")
        try:
            from workers.tools import yara_scanner
            matches = yara_scanner.run(extra_path=self._yara_extra_path)
        except Exception as exc:
            self.log_line.emit(f"[incident] YARA stage skipped: {exc}")
            return 0

        count = 0
        for m in matches:
            finding = Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="yara", severity=m.get("severity", "high"),
                title=f"YARA: {m['rule']}",
                description=m.get("description", ""),
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = self._db.insert_finding(finding)
            self._db.insert_incident_event({
                "scan_id":    self._scan_id,
                "timestamp":  finding.created_at,
                "event_type": "entry",
                "source_host": m.get("file", ""),
                "dest_host":  "",
                "description": finding.title,
                "evidence":   finding.description[:200],
            })
            self.finding_found.emit(finding)
            self.log_line.emit(f"[incident] YARA match: {m['rule']} in {m.get('file', '')}")
            count += 1

        self.log_line.emit(f"[incident] Stage 2 complete — {count} matches")
        return count

    # ── Stage 3: Persistence Check ───────────────────────────────────────────

    def _stage3_persistence(self) -> int:
        self.log_line.emit("[incident] Stage 3 — persistence check")
        try:
            from workers.tools import persistence_checker
            results = persistence_checker.run()
        except Exception as exc:
            self.log_line.emit(f"[incident] persistence check skipped: {exc}")
            return 0

        count = 0
        for r in results:
            finding = Finding(
                id=None, scan_id=self._scan_id, host_id=None,
                tool="persistence", severity=r.get("severity", "medium"),
                title=f"Persistence: {r['check'].replace('_', ' ').title()} — {r['path']}",
                description=r.get("detail", ""),
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            finding.id = self._db.insert_finding(finding)
            self._db.insert_incident_event({
                "scan_id":    self._scan_id,
                "timestamp":  finding.created_at,
                "event_type": "persistence",
                "source_host": r.get("path", ""),
                "dest_host":  "",
                "description": finding.title,
                "evidence":   r.get("detail", "")[:200],
            })
            self.finding_found.emit(finding)
            self.log_line.emit(f"[incident] persistence: {r['check']} — {r['path']}")
            count += 1

        self.log_line.emit(f"[incident] Stage 3 complete — {count} findings")
        return count
