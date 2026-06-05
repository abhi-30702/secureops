import re
from collections import defaultdict
from datetime import datetime, timezone

from PyQt6.QtCore import QThread, pyqtSignal

from db import DB
from models import Finding
from workers.log_rules import detect_format, RULES, LogRule
from advisor.gemini_client import GeminiClient


class LogAnalyzerWorker(QThread):
    finding_found = pyqtSignal(object)
    log_line      = pyqtSignal(str)
    scan_complete = pyqtSignal(int, int)
    scan_failed   = pyqtSignal(str)

    def __init__(self, path: str, scan_id: int, db: DB, parent=None):
        super().__init__(parent)
        self._path = path
        self._scan_id = scan_id
        self._db = db

    def run(self):
        try:
            lines = self._read_file()
        except FileNotFoundError:
            self.scan_failed.emit(f"Log file not found: {self._path}")
            return
        except PermissionError:
            self.scan_failed.emit(f"Cannot read log file: permission denied")
            return

        fmt = detect_format(lines)
        self.log_line.emit(f"[log-analyzer] detected format: {fmt}")

        findings = self._run_rules(lines, fmt)
        self.log_line.emit(f"[log-analyzer] rules complete — {len(findings)} findings")

        findings = self._enrich_with_ai(findings)

        for f in findings:
            f.id = self._db.insert_finding(f)
            self.finding_found.emit(f)

        self._db.update_scan_status(
            self._scan_id, "complete", datetime.now(timezone.utc).isoformat()
        )
        self.scan_complete.emit(0, len(findings))

    def _read_file(self) -> list[str]:
        with open(self._path, "r", errors="replace") as fh:
            return fh.readlines()

    def _run_rules(self, lines: list[str], fmt: str) -> list[Finding]:
        applicable = [
            r for r in RULES
            if "*" in r.formats or fmt in r.formats or "unknown" in r.formats
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
                    id=None,
                    scan_id=self._scan_id,
                    host_id=None,
                    tool="log-analyzer",
                    severity=rule.severity.lower(),
                    title=f"{rule_name.replace('_', ' ').title()} — {key}",
                    description=desc,
                    raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        for rule_name, matched_strings in match_hits.items():
            rule = rule_by_name.get(rule_name)
            if not rule:
                continue
            for matched in matched_strings:
                findings.append(Finding(
                    id=None,
                    scan_id=self._scan_id,
                    host_id=None,
                    tool="log-analyzer",
                    severity=rule.severity.lower(),
                    title=rule_name.replace("_", " ").title(),
                    description=f"{rule.description}: {matched}",
                    raw_json="",
                    created_at=datetime.now(timezone.utc).isoformat(),
                ))

        return findings

    def _enrich_with_ai(self, findings: list[Finding]) -> list[Finding]:
        if not self._db:
            return findings
        enabled = self._db.get_setting("ai_advisor_enabled") == "1"
        api_key = self._db.get_setting("gemini_api_key") or ""
        if not enabled or not api_key:
            return findings

        self.log_line.emit("[log-analyzer] enriching with AI Advisor...")
        try:
            summary_lines = [f"- [{f.severity.upper()}] {f.title}: {f.description[:200]}" for f in findings]
            prompt = (
                "You are a security analyst. Analyse these log anomalies and identify "
                "any additional security concerns. For each concern respond with:\n"
                "SEVERITY: HIGH|MEDIUM|LOW\nTITLE: short title\nDESCRIPTION: one sentence\n\n"
                + "\n".join(summary_lines[:20])
            )
            response = GeminiClient(api_key).generate(prompt)
            ai_findings = self._parse_ai_response(response)
            findings.extend(ai_findings)
            self.log_line.emit(f"[log-analyzer] AI Advisor added {len(ai_findings)} findings")
        except Exception as exc:
            self.log_line.emit(f"[log-analyzer] AI Advisor error (skipped): {exc}")
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
                id=None,
                scan_id=self._scan_id,
                host_id=None,
                tool="log-analyzer",
                severity=sev_m.group(1).lower(),
                title=title_m.group(1).strip(),
                description=desc_m.group(1).strip() if desc_m else "",
                raw_json="",
                created_at=datetime.now(timezone.utc).isoformat(),
            ))
        return findings
