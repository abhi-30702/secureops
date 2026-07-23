"""Professional client-facing PDF report (WeasyPrint HTML/CSS engine).

Produces a print-optimized security-assessment deliverable:

  * a STRICT cover-only page 1 (brand, title, scope, subtitle, report id) —
    no findings, tables, or summary bleed onto it,
  * body pages (page 2+) with a running header + footer carrying the report
    title, confidentiality marking, report id, and "Page X of Y",
  * detailed findings with Finding ID, CVSS/CVE/CWE, affected asset, evidence,
    impact, likelihood, remediation, and references extracted from each tool's
    ``raw_json``.

This is deliberately separate from ``report/pdf_generator.py`` (the ReportLab
engine still used by the consolidated multi-company report), so neither engine
regresses when the other changes.
"""

from __future__ import annotations

import html
import json
import math
import re
import subprocess
from datetime import datetime, timezone

from weasyprint import HTML

from models import Scan, Host, Finding, Client

# ── palette (print-optimised, flat, high-contrast — NOT the glass UI) ──────────
_INK      = "#16181D"   # near-black body text
_INK_SOFT = "#33363F"
_MUTED    = "#5B616E"   # secondary text
_HAIR     = "#E3E5EA"   # hairline rules / borders
_PANEL    = "#F6F7F9"   # subtle panel fill
_ACCENT   = "#18181B"   # graphite accent (matches app)

# Severity colours — match the app, darkened just enough for AA on white paper.
_SEV_COLOR = {
    "critical": "#DC2626",
    "high":     "#EA580C",
    "medium":   "#CA8A04",
    "low":      "#2563EB",
    "info":     "#64748B",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_REMEDIATION = {
    "critical": "Remediate immediately. This finding represents a critical risk to the "
                "assessed environment and should be treated as an emergency change.",
    "high":     "Remediate within 30 days. Apply the vendor fix or documented hardening "
                "guidance and re-test to confirm closure.",
    "medium":   "Remediate within 90 days as part of the standard patch/hardening cycle.",
    "low":      "Address as part of routine maintenance; low urgency, defense-in-depth value.",
    "info":     "Informational — no remediation required; retain for situational awareness.",
}
_IMPACT = {
    "critical": "Full compromise of the affected asset or disclosure of sensitive data is "
                "plausible; exploitation would carry severe business consequences.",
    "high":     "Significant exposure that could lead to unauthorised access, data "
                "disclosure, or service disruption if exploited.",
    "medium":   "Moderate exposure that weakens the security posture and can aid an "
                "attacker when chained with other weaknesses.",
    "low":      "Limited direct impact; primarily relevant to hardening and defence in depth.",
    "info":     "No direct security impact; provided for situational awareness.",
}
_LIKELIHOOD = {
    "critical": "High — widely known and readily exploitable with commodity tooling.",
    "high":     "High — practical, documented exploitation paths exist.",
    "medium":   "Moderate — exploitation is feasible but may require specific conditions.",
    "low":      "Low — exploitation is difficult or of limited value in isolation.",
    "info":     "Not applicable.",
}

# Best-effort version probes (tool -> argv). Only tools that produced findings
# are queried, each with a short timeout; any failure is swallowed.
_VERSION_CMDS = {
    "subfinder": ["subfinder", "-version"],
    "dnsx":      ["dnsx", "-version"],
    "naabu":     ["naabu", "-version"],
    "httpx":     ["httpx-toolkit", "-version"],
    "katana":    ["katana", "-version"],
    "nuclei":    ["nuclei", "-version"],
    "nmap":      ["nmap", "--version"],
    "nikto":     ["nikto", "-Version"],
    "testssl":   ["testssl.sh", "--version"],
    "theharvester": ["theHarvester", "--version"],
}
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _as_list(v) -> list[str]:
    """Normalise a raw_json value (None | str | list) to a clean list of strings."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if x not in (None, "")]
    return [str(v)] if str(v).strip() else []


def extract_finding_detail(f: Finding) -> dict:
    """Map a Finding's per-tool ``raw_json`` into the report's finding fields.

    Pure function (no I/O) so it can be unit-tested against real tool output.
    Returns keys: asset, cvss_score, cvss_vector, cve, cwe, evidence, references,
    remediation.
    """
    tool = (f.tool or "").lower()
    try:
        raw = json.loads(f.raw_json) if f.raw_json else {}
    except (ValueError, TypeError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}

    d = {"asset": "", "cvss_score": None, "cvss_vector": "", "cve": [], "cwe": [],
         "evidence": "", "references": [], "remediation": ""}

    if tool == "nuclei":
        info = raw.get("info") or {}
        cls = info.get("classification") or {}
        d["asset"] = raw.get("matched-at") or raw.get("url") or raw.get("host") or ""
        d["cvss_score"] = cls.get("cvss-score")
        d["cvss_vector"] = cls.get("cvss-metrics") or ""
        d["cve"] = _as_list(cls.get("cve-id"))
        d["cwe"] = [c.upper() for c in _as_list(cls.get("cwe-id"))]
        d["references"] = _as_list(info.get("reference"))
        ev = []
        if raw.get("matcher-name"):
            ev.append(f"Matcher: {raw['matcher-name']}")
        if raw.get("extracted-results"):
            ev.append("Extracted: " + ", ".join(_as_list(raw["extracted-results"])))
        if raw.get("template-id"):
            ev.append(f"Template: {raw['template-id']}")
        d["evidence"] = "\n".join(ev)
        d["remediation"] = info.get("remediation") or ""
    elif tool == "nikto":
        d["asset"] = raw.get("url") or ""
        d["references"] = _as_list(raw.get("references"))
        ev = []
        if raw.get("method"):
            ev.append(f"Method: {raw['method']}")
        if raw.get("id"):
            ev.append(f"Nikto test ID: {raw['id']}")
        if raw.get("msg"):
            ev.append(str(raw["msg"]))
        d["evidence"] = "\n".join(ev)
    elif tool == "testssl":
        asset = ":".join(str(raw.get(k)) for k in ("ip", "port") if raw.get(k))
        d["asset"] = asset
        d["cve"] = _as_list(raw.get("cve"))
        d["evidence"] = raw.get("finding") or (f.description or "")
    else:
        d["evidence"] = f.description or ""

    return d


def collect_tool_versions(tools, timeout: float = 5.0) -> dict[str, str]:
    """Best-effort version string for each tool. Any error → empty string."""
    out: dict[str, str] = {}
    for t in sorted({(x or "").lower() for x in tools}):
        cmd = _VERSION_CMDS.get(t)
        if not cmd:
            continue
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            blob = _ANSI.sub("", (r.stdout or "") + "\n" + (r.stderr or ""))
            line = next((ln.strip() for ln in blob.splitlines()
                         if any(ch.isdigit() for ch in ln)), "")
            out[t] = line[:120]
        except Exception:
            out[t] = ""
    return out


class ProfessionalReport:
    def __init__(self, scan: Scan, hosts: list[Host], findings: list[Finding],
                 client: Client | None = None, output_path: str = "report.pdf",
                 advisory_items: list | None = None,
                 incident_events: list | None = None,
                 osint_items: list | None = None,
                 network_summary: dict | None = None,
                 collect_versions: bool = True):
        self._scan = scan
        self._hosts = hosts or []
        self._findings = findings or []
        self._client = client
        self._output_path = output_path
        self._advisory_items = advisory_items or []
        self._incident_events = incident_events or []
        self._osint_items = osint_items or []
        self._network_summary = network_summary or {}
        self._collect_versions = collect_versions
        self._report_id = self._make_report_id()

    # ── public ────────────────────────────────────────────────────────────────
    def generate(self) -> str:
        HTML(string=self._build_html()).write_pdf(self._output_path)
        return self._output_path

    # ── identity / metadata ─────────────────────────────────────────────────
    def _make_report_id(self) -> str:
        sid = self._scan.id or 0
        day = (self._scan.started_at or datetime.now(timezone.utc).isoformat())[:10].replace("-", "")
        return f"SO-{sid:04d}-{day}"

    def _target_label(self) -> str:
        return (self._client.name if self._client else None) or self._scan.target

    def _scan_types(self) -> list[str]:
        tgt = self._scan.target or ""
        types = []
        if "log-analyzer" in {f.tool for f in self._findings} or _looks_like_path(tgt):
            types.append("Log / Incident Analysis")
        if _is_ipish(tgt):
            types.append("Single-host network scan")
        elif not _looks_like_path(tgt):
            types.append("External attack-surface assessment")
        if self._incident_events:
            types.append("Breach reconstruction")
        if self._osint_items:
            types.append("OSINT footprint")
        return types or ["Security assessment"]

    def _tools_used(self) -> list[str]:
        seen = []
        for f in self._findings:
            if f.tool and f.tool not in seen:
                seen.append(f.tool)
        return seen

    # ── counts / rating ─────────────────────────────────────────────────────
    def _counts(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for f in self._findings:
            sev = f.severity if f.severity in _SEV_COLOR else "info"
            c[sev] = c.get(sev, 0) + 1
        return c

    def _rating(self) -> str:
        sevs = {(f.severity or "info").lower() for f in self._findings}
        for sev in ("critical", "high", "medium", "low"):
            if sev in sevs:
                return sev.upper()
        return "PASSED" if not self._findings else "INFO"

    def _duration(self) -> str:
        if not self._scan.finished_at or not self._scan.started_at:
            return "—"
        try:
            start = datetime.fromisoformat(self._scan.started_at[:19])
            end = datetime.fromisoformat(self._scan.finished_at[:19])
            m, s = divmod(max(0, int((end - start).total_seconds())), 60)
            return f"{m}m {s}s"
        except (ValueError, TypeError, OverflowError):
            return "—"

    # ── HTML assembly ────────────────────────────────────────────────────────
    def _build_html(self) -> str:
        net = [f for f in self._findings if f.tool != "log-analyzer"]
        logs = [f for f in self._findings if f.tool == "log-analyzer"]
        versions = collect_tool_versions(self._tools_used()) if self._collect_versions else {}

        css = _CSS.replace("SO-REPORT", html.escape(self._report_id))
        parts = [
            "<style>", css, "</style>",
            self._cover_html(),
            self._exec_summary_html(),
            self._scope_html(versions),
            self._overview_html(),
            self._detailed_findings_html(net, "Detailed Findings"),
        ]
        if logs:
            parts.append(self._detailed_findings_html(logs, "Log Analysis Findings"))
        if self._incident_events:
            parts.append(self._breach_html())
        if self._osint_items:
            parts.append(self._osint_html())
        if self._has_network_data():
            parts.append(self._network_html())
        if self._advisory_items:
            parts.append(self._advisory_html())
        parts.append(self._appendix_html(versions))
        return "\n".join(parts)

    def _cover_html(self) -> str:
        gen = datetime.now(timezone.utc).astimezone().strftime("%d %B %Y, %H:%M %Z")
        scope_rows = "".join(
            f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
            for k, v in [
                ("Prepared for", self._target_label()),
                ("Scope", self._scan.target),
                ("Assessment type", " · ".join(self._scan_types())),
                ("Report generated", gen),
            ]
        )
        return f"""
<section class="cover">
  <div class="cover-top">
    <div class="brand">
      <span class="lock">{_LOCK_SVG}</span>
      <span class="brand-name">SecureOps</span>
    </div>
  </div>
  <div class="cover-mid">
    <div class="kicker">SECURITY ASSESSMENT</div>
    <h1 class="cover-title">Security Assessment Report</h1>
    <p class="cover-sub">Findings, risk posture, and remediation guidance for the
       systems in scope, prepared for internal security review.</p>
    <table class="cover-scope">{scope_rows}</table>
  </div>
  <div class="cover-bottom">
    <div class="confidential">CONFIDENTIAL — for the intended recipient only</div>
    <div class="report-id">Report ID: {html.escape(self._report_id)}</div>
  </div>
</section>
"""

    def _exec_summary_html(self) -> str:
        counts = self._counts()
        total = sum(counts.values())
        rating = self._rating()
        sev_line = ", ".join(
            f"{counts.get(s, 0)} {s}" for s in _SEVERITY_ORDER if counts.get(s, 0)
        ) or "no findings"
        top = self._top_risks(3)
        top_html = "".join(
            f"<li><span class='dot' style='background:{_SEV_COLOR.get(f.severity,'#64748B')}'></span>"
            f"<b>{f.severity.upper()}</b> — {html.escape(f.title)}</li>"
            for f in top
        ) or "<li>No elevated risks were identified during this assessment.</li>"

        if rating in ("PASSED", "INFO"):
            posture = ("The assessment did not surface any exploitable weaknesses that rise "
                       "to actionable risk. The in-scope surface appears well maintained; "
                       "continue routine monitoring and periodic re-assessment.")
        else:
            posture = (f"The overall risk rating for the assessed scope is "
                       f"<b>{rating}</b>. A total of <b>{total}</b> finding(s) were recorded "
                       f"({sev_line}). The items below should be prioritised by severity, "
                       f"starting with the highest-rated issues, which offer the greatest "
                       f"risk-reduction per unit of effort.")

        return f"""
<section class="page">
  {self._section_head('1', 'Executive Summary')}
  <div class="rating-banner sev-{rating.lower()}">
     <span class="rating-label">Overall risk rating</span>
     <span class="rating-value">{rating}</span>
  </div>
  <p>{posture}</p>
  <div class="sev-chips">
     {''.join(self._sev_chip(s, counts.get(s, 0)) for s in _SEVERITY_ORDER)}
  </div>
  <h3>Top risks</h3>
  <ul class="top-risks">{top_html}</ul>
</section>
"""

    def _scope_html(self, versions: dict) -> str:
        tool_rows = "".join(
            f"<tr><td>{html.escape(t)}</td><td>{html.escape(versions.get(t.lower(), '') or '—')}</td></tr>"
            for t in self._tools_used()
        ) or "<tr><td colspan='2'>No automated tools recorded findings for this scan.</td></tr>"
        return f"""
<section class="page">
  {self._section_head('2', 'Scope &amp; Methodology')}
  <table class="kv">
    <tr><th>Target(s) assessed</th><td>{html.escape(self._scan.target)}</td></tr>
    <tr><th>Assessment type</th><td>{html.escape(' · '.join(self._scan_types()))}</td></tr>
    <tr><th>Assessment window</th><td>{html.escape((self._scan.started_at or '—')[:19].replace('T',' '))}
        &nbsp;→&nbsp; {html.escape((self._scan.finished_at or '—')[:19].replace('T',' '))} ({self._duration()})</td></tr>
    <tr><th>Hosts discovered</th><td>{len(self._hosts)}</td></tr>
    <tr><th>Total findings</th><td>{len(self._findings)}</td></tr>
  </table>
  <p>The assessment was performed using automated discovery and vulnerability
     tooling in a detection-and-reporting capacity. No exploitation was attempted.
     The tools listed below were used to enumerate the attack surface and identify
     misconfigurations and known vulnerabilities.</p>
  <table class="grid">
    <thead><tr><th>Tool</th><th>Version</th></tr></thead>
    <tbody>{tool_rows}</tbody>
  </table>
</section>
"""

    def _overview_html(self) -> str:
        counts = self._counts()
        total = sum(counts.values()) or 1
        rows = "".join(
            f"<tr><td><span class='dot' style='background:{_SEV_COLOR[s]}'></span>{s.upper()}</td>"
            f"<td>{counts.get(s, 0)}</td>"
            f"<td>{round(100 * counts.get(s, 0) / total)}%</td></tr>"
            for s in _SEVERITY_ORDER
        )
        return f"""
<section class="page">
  {self._section_head('3', 'Findings Overview')}
  <div class="overview">
    <div class="donut">{self._donut_svg(counts)}</div>
    <table class="grid overview-table">
      <thead><tr><th>Severity</th><th>Count</th><th>Share</th></tr></thead>
      <tbody>{rows}</tbody>
      <tfoot><tr><td>Total</td><td>{sum(counts.values())}</td><td>100%</td></tr></tfoot>
    </table>
  </div>
  <div class="bars">{self._bars_html(counts)}</div>
</section>
"""

    def _detailed_findings_html(self, findings: list, title: str) -> str:
        if not findings:
            return ""
        buckets: dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
        for f in findings:
            buckets[f.severity if f.severity in buckets else "info"].append(f)

        # Full detailed blocks for critical→low; info findings (no direct security
        # impact, often the bulk of a scan) are consolidated into a compact table
        # so the deliverable stays readable.
        blocks, info_rows = [], []
        n = 0
        for sev in _SEVERITY_ORDER:
            for f in buckets[sev]:
                n += 1
                if sev == "info":
                    info_rows.append(self._info_row(f, n))
                else:
                    blocks.append(self._finding_block(f, n))

        info_html = ""
        if info_rows:
            info_html = f"""
  <h3>Informational Findings</h3>
  <p class="note">{len(info_rows)} informational item(s) are consolidated below.
     These carry no direct security impact and are listed for situational awareness
     and completeness of the assessment record.</p>
  <table class="grid info-table">
    <thead><tr><th>ID</th><th>Finding</th><th>Affected asset</th><th>Tool</th></tr></thead>
    <tbody>{''.join(info_rows)}</tbody>
  </table>
"""
        if not blocks and not info_html:
            return ""
        num = "4" if title == "Detailed Findings" else "•"
        return f"""
<section class="page findings">
  {self._section_head(num, html.escape(title))}
  {''.join(blocks)}
  {info_html}
</section>
"""

    def _info_row(self, f: Finding, idx: int) -> str:
        d = extract_finding_detail(f)
        fid = f"{self._report_id.split('-')[0]}-{self._scan.id or 0:04d}-F{idx:03d}"
        asset = d["asset"] or self._scan.target
        return (f"<tr><td class='mono'>{html.escape(fid)}</td>"
                f"<td>{html.escape(f.title)}</td>"
                f"<td class='mono'>{html.escape(asset)}</td>"
                f"<td>{html.escape(f.tool)}</td></tr>")

    def _finding_block(self, f: Finding, idx: int) -> str:
        sev = (f.severity or "info").lower()
        d = extract_finding_detail(f)
        fid = f"{self._report_id.split('-')[0]}-{self._scan.id or 0:04d}-F{idx:03d}"
        asset = d["asset"] or self._scan.target

        meta = [("Finding ID", fid),
                ("Affected asset", asset),
                ("Source tool", f.tool)]
        if d["cvss_score"] is not None:
            vec = f" &nbsp;<span class='vec'>{html.escape(d['cvss_vector'])}</span>" if d["cvss_vector"] else ""
            meta.append(("CVSS", f"{d['cvss_score']}{vec}"))
        if d["cve"]:
            meta.append(("CVE", ", ".join(html.escape(c) for c in d["cve"])))
        if d["cwe"]:
            meta.append(("CWE", ", ".join(html.escape(c) for c in d["cwe"])))
        meta_html = "".join(f"<tr><th>{html.escape(k)}</th><td>{v}</td></tr>" for k, v in meta)

        def field(label, body_html):
            return f"<div class='field'><h5>{label}</h5>{body_html}</div>" if body_html else ""

        desc = html.escape(_clip(f.description, 1400)) if f.description else ""
        evidence = html.escape(_clip(d["evidence"], 1400)) if d["evidence"] else ""
        remediation = html.escape(d["remediation"]) if d["remediation"] else _REMEDIATION.get(sev, "")
        refs = ""
        if d["references"]:
            refs = "<ul class='refs'>" + "".join(
                f"<li>{html.escape(r)}</li>" for r in d["references"][:8]
            ) + "</ul>"

        return f"""
<div class="finding">
  <div class="finding-head">
     <span class="fid">{html.escape(fid)}</span>
     <span class="ftitle">{html.escape(f.title)}</span>
     <span class="sev-pill" style="background:{_SEV_COLOR[sev]}">{sev.upper()}</span>
  </div>
  <table class="meta">{meta_html}</table>
  {field('Description', f'<p>{desc}</p>') if desc else ''}
  {field('Evidence', f'<pre>{evidence}</pre>') if evidence else ''}
  <div class="two-col">
     {field('Impact', f'<p>{_IMPACT.get(sev, "")}</p>')}
     {field('Likelihood', f'<p>{_LIKELIHOOD.get(sev, "")}</p>')}
  </div>
  {field('Remediation', f'<p>{html.escape(remediation)}</p>')}
  {field('References', refs)}
</div>
"""

    def _breach_html(self) -> str:
        events = sorted(self._incident_events, key=lambda e: e.get("timestamp", "") or "")
        rows = ""
        for e in events:
            ts = (e.get("timestamp", "") or "")[:19].replace("T", " ")
            stage = (e.get("event_type", "") or "").upper()
            src = e.get("source_host", "") or ""
            dst = e.get("dest_host", "") or ""
            hostcol = f"{src} → {dst}" if dst else (src or "—")
            rows += (f"<tr><td>{html.escape(ts)}</td><td><b>{html.escape(stage)}</b></td>"
                     f"<td>{html.escape(hostcol)}</td><td>{html.escape(e.get('description', '') or '')}</td></tr>")
        return f"""
<section class="page">
  {self._section_head('•', 'Breach Timeline')}
  <p>Reconstructed attacker activity in chronological order, derived from log
     analysis, IOC matches, and persistence checks.</p>
  <table class="grid"><thead><tr><th>Time</th><th>Stage</th><th>Host</th><th>Description</th></tr></thead>
  <tbody>{rows}</tbody></table>
</section>
"""

    def _osint_html(self) -> str:
        grouped: dict[str, list] = {}
        for item in self._osint_items:
            grouped.setdefault(item.get("item_type", "other"), []).append(item)
        order = ["email", "subdomain", "ip", "url", "name"]
        summary = "".join(
            f"<tr><td>{html.escape(t)}</td><td>{len(grouped[t])}</td></tr>"
            for t in order + [t for t in grouped if t not in order] if t in grouped
        )
        details = ""
        for t in order + [t for t in grouped if t not in order]:
            items = grouped.get(t)
            if not items:
                continue
            rows = "".join(
                f"<tr><td>{html.escape(i.get('value', ''))}</td><td>{html.escape(i.get('source', ''))}</td></tr>"
                for i in items
            )
            details += (f"<h4>{html.escape(t.capitalize())}</h4>"
                        f"<table class='grid'><thead><tr><th>Value</th><th>Source</th></tr></thead>"
                        f"<tbody>{rows}</tbody></table>")
        return f"""
<section class="page">
  {self._section_head('•', 'OSINT — Public Footprint')}
  <p>Information about the target gathered from public sources. Exposure of these
     items expands the external attack surface.</p>
  <table class="grid"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>{summary}</tbody></table>
  {details}
</section>
"""

    def _has_network_data(self) -> bool:
        stats = self._network_summary.get("stats") or {}
        return bool(stats.get("total"))

    def _network_html(self) -> str:
        s = self._network_summary
        stats = s.get("stats") or {}
        total = int(stats.get("total", 0) or 0)
        blocked = int(stats.get("blocked", 0) or 0)
        allowed = int(stats.get("allowed", total - blocked) or 0)
        employees = int(stats.get("unique_employees", 0) or 0)
        rate = (100.0 * blocked / total) if total else 0.0

        summary = "".join(
            f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>"
            for k, v in [
                ("Total requests observed", f"{total:,}"),
                ("Allowed", f"{allowed:,}"),
                ("Blocked (policy / threat-intel)", f"{blocked:,}"),
                ("Block rate", f"{rate:.1f}%"),
                ("Distinct workstations", f"{employees:,}"),
            ]
        )

        top_domains = stats.get("top_blocked") or []
        dom_rows = "".join(
            f"<tr><td>{html.escape(str(d))}</td><td>{n}</td></tr>" for d, n in top_domains
        ) or "<tr><td colspan='2'>No blocked domains recorded.</td></tr>"

        top_emp = s.get("top_employees") or []
        emp_rows = "".join(
            f"<tr><td>{html.escape(str(e))}</td><td>{n}</td></tr>" for e, n in top_emp
        ) or "<tr><td colspan='2'>No flagged workstations.</td></tr>"

        alerts = s.get("alerts") or []
        alert_rows = ""
        for a in alerts:
            ts = (a.get("created_at", "") or "")[:19].replace("T", " ")
            sev = (a.get("severity", "") or "info").lower()
            sev_color = _SEV_COLOR.get(sev, _SEV_COLOR["info"])
            ack = "Yes" if a.get("acknowledged") else "No"
            alert_rows += (
                f"<tr><td>{html.escape(ts)}</td>"
                f"<td><b style='color:{sev_color}'>{html.escape(sev.upper())}</b></td>"
                f"<td>{html.escape(a.get('employee_name', '') or '')}</td>"
                f"<td>{html.escape(a.get('domain', '') or '')}</td>"
                f"<td>{html.escape(a.get('notes', '') or '')}</td>"
                f"<td>{ack}</td></tr>"
            )
        alerts_table = (
            f"<h4>Red-Flag Alerts</h4>"
            f"<table class='grid'><thead><tr><th>Time</th><th>Severity</th>"
            f"<th>Workstation</th><th>Domain</th><th>Reason</th><th>Ack</th></tr></thead>"
            f"<tbody>{alert_rows}</tbody></table>"
        ) if alert_rows else ""

        return f"""
<section class="page">
  {self._section_head('•', 'Network Activity Monitoring')}
  <p>Passive monitoring of employee web activity, cross-referenced against the
     organisation blocklist and threat-intelligence feeds. Figures reflect the
     current monitoring audit trail (detection and reporting only — no traffic
     was blocked or altered).</p>
  <table class="kv">{summary}</table>
  <h4>Top Blocked Domains</h4>
  <table class='grid'><thead><tr><th>Domain</th><th>Hits</th></tr></thead><tbody>{dom_rows}</tbody></table>
  <h4>Most Flagged Workstations</h4>
  <table class='grid'><thead><tr><th>Workstation / Employee</th><th>Blocked requests</th></tr></thead><tbody>{emp_rows}</tbody></table>
  {alerts_table}
</section>
"""

    def _advisory_html(self) -> str:
        tiers = [("immediate", "Immediate Actions"),
                 ("short_term", "Short-Term Actions"),
                 ("preventive", "Preventive Measures")]
        body = ""
        for tier, heading in tiers:
            items = [i for i in self._advisory_items if getattr(i, "tier", None) == tier]
            if not items:
                continue
            lis = "".join(f"<li>{html.escape(i.text)}</li>" for i in items)
            body += f"<h4>{heading}</h4><ul>{lis}</ul>"
        return f"""
<section class="page">
  {self._section_head('•', 'AI Advisory')}
  <p class="note"><i>AI-generated content — reviewed and accepted by the analyst.</i></p>
  {body}
</section>
"""

    def _appendix_html(self, versions: dict) -> str:
        if self._hosts:
            rows = "".join(
                f"<tr><td>{html.escape(h.subdomain or '—')}</td><td>{html.escape(h.ip or '—')}</td>"
                f"<td>{h.port or '—'}</td><td>{html.escape(h.service or '—')}</td>"
                f"<td>{html.escape(h.source_tool or '—')}</td></tr>"
                for h in self._hosts
            )
            host_table = (f"<table class='grid'><thead><tr><th>Subdomain</th><th>IP</th>"
                          f"<th>Port</th><th>Service</th><th>Tool</th></tr></thead><tbody>{rows}</tbody></table>")
        else:
            host_table = "<p>No hosts were discovered during this assessment.</p>"

        meta_rows = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(str(v))}</td></tr>" for k, v in [
            ("Report ID", self._report_id),
            ("Scan ID", self._scan.id or "—"),
            ("Status", (self._scan.status or "").capitalize()),
            ("Started", (self._scan.started_at or "—")[:19].replace("T", " ")),
            ("Finished", (self._scan.finished_at or "—")[:19].replace("T", " ")),
            ("Duration", self._duration()),
            ("Generated", datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")),
        ])
        return f"""
<section class="page">
  {self._section_head('A', 'Appendix')}
  <h4>A.1 &nbsp;Host Inventory</h4>
  {host_table}
  <h4>A.2 &nbsp;Scan Metadata</h4>
  <table class="kv">{meta_rows}</table>
</section>
"""

    # ── small render helpers ─────────────────────────────────────────────────
    def _section_head(self, num: str, title: str) -> str:
        return f"<h2 class='sec'><span class='sec-num'>{num}</span>{title}</h2>"

    def _sev_chip(self, sev: str, n: int) -> str:
        return (f"<div class='chip'><span class='chip-n' style='color:{_SEV_COLOR[sev]}'>{n}</span>"
                f"<span class='chip-l'>{sev.upper()}</span></div>")

    def _top_risks(self, k: int) -> list[Finding]:
        rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
        ranked = sorted(self._findings, key=lambda f: rank.get(f.severity, 99))
        return [f for f in ranked if f.severity in ("critical", "high", "medium")][:k]

    def _donut_svg(self, counts: dict) -> str:
        total = sum(counts.values())
        r, cx, cy, w = 54, 70, 70, 20
        if total == 0:
            return (f"<svg viewBox='0 0 140 140' width='150'><circle cx='{cx}' cy='{cy}' r='{r}' "
                    f"fill='none' stroke='{_HAIR}' stroke-width='{w}'/>"
                    f"<text x='{cx}' y='{cy+5}' text-anchor='middle' class='donut-num'>0</text></svg>")
        C = 2 * math.pi * r
        segs, offset = [], 0.0
        for s in _SEVERITY_ORDER:
            n = counts.get(s, 0)
            if not n:
                continue
            dash = C * n / total
            segs.append(
                f"<circle cx='{cx}' cy='{cy}' r='{r}' fill='none' stroke='{_SEV_COLOR[s]}' "
                f"stroke-width='{w}' stroke-dasharray='{dash:.2f} {C - dash:.2f}' "
                f"stroke-dashoffset='{-offset:.2f}'/>")
            offset += dash
        return (f"<svg viewBox='0 0 140 140' width='150'>"
                f"<g transform='rotate(-90 {cx} {cy})'>{''.join(segs)}</g>"
                f"<text x='{cx}' y='{cy-2}' text-anchor='middle' class='donut-num'>{total}</text>"
                f"<text x='{cx}' y='{cy+14}' text-anchor='middle' class='donut-cap'>findings</text></svg>")

    def _bars_html(self, counts: dict) -> str:
        mx = max(counts.values()) if counts else 0
        rows = []
        for s in _SEVERITY_ORDER:
            n = counts.get(s, 0)
            pct = round(100 * n / mx) if mx else 0
            rows.append(
                f"<div class='bar-row'><span class='bar-label'>{s.upper()}</span>"
                f"<span class='bar-track'><span class='bar-fill' style='width:{pct}%;"
                f"background:{_SEV_COLOR[s]}'></span></span><span class='bar-n'>{n}</span></div>")
        return "".join(rows)


# ── module-level helpers ──────────────────────────────────────────────────────
def _clip(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n].rstrip() + " …"


def _is_ipish(t: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t or "")) or ":" in (t or "") and "/" not in (t or "")


def _looks_like_path(t: str) -> bool:
    return (t or "").startswith("/") or (t or "").lower().endswith((".log", ".txt"))


_LOCK_SVG = (
    "<svg viewBox='0 0 24 24' width='30' height='30' fill='none' "
    "stroke='#18181B' stroke-width='1.8'>"
    "<rect x='4' y='10' width='16' height='11' rx='2'/>"
    "<path d='M8 10V7a4 4 0 0 1 8 0v3'/></svg>"
)

_CSS = """
@page {
  size: A4;
  margin: 22mm 17mm 18mm 17mm;
  @top-left  { content: "Security Assessment Report"; font-family: Helvetica, Arial, sans-serif;
               font-size: 7.5pt; color: #8A8F99; }
  @top-right { content: "SecureOps"; font-family: Helvetica, Arial, sans-serif;
               font-size: 7.5pt; color: #8A8F99; letter-spacing: .04em; }
  @bottom-left   { content: "CONFIDENTIAL"; font-family: Helvetica, Arial, sans-serif;
                   font-size: 7pt; color: #A2A7B0; letter-spacing: .06em; }
  @bottom-center { content: "SO-REPORT"; font-family: Helvetica, Arial, sans-serif;
                   font-size: 7pt; color: #A2A7B0; }
  @bottom-right  { content: "Page " counter(page) " of " counter(pages);
                   font-family: Helvetica, Arial, sans-serif; font-size: 7pt; color: #A2A7B0; }
}
@page cover {
  margin: 0;
  @top-left { content: none; } @top-right { content: none; }
  @bottom-left { content: none; } @bottom-center { content: none; } @bottom-right { content: none; }
}

* { box-sizing: border-box; }
html { font-family: Helvetica, Arial, sans-serif; color: #16181D; font-size: 10pt; line-height: 1.5; }
p { margin: 0 0 8pt; }
b { color: #16181D; }

/* ── cover (page 1) ────────────────────────────────────────────────────── */
.cover {
  page: cover;
  height: 297mm; padding: 30mm 26mm;
  display: flex; flex-direction: column; justify-content: space-between;
  border-top: 6mm solid #18181B;
}
.brand { display: flex; align-items: center; gap: 10px; }
.brand .lock { line-height: 0; }
.brand-name { font-size: 20pt; font-weight: 700; letter-spacing: .01em; color: #16181D; }
.cover-mid { margin-top: -30mm; }
.kicker { font-size: 9pt; letter-spacing: .28em; color: #8A8F99; font-weight: 700; margin-bottom: 10px; }
.cover-title { font-size: 34pt; line-height: 1.1; font-weight: 700; margin: 0 0 14px; color: #16181D; }
.cover-sub { font-size: 12pt; color: #5B616E; max-width: 120mm; margin: 0 0 26px; line-height: 1.55; }
.cover-scope { border-collapse: collapse; width: 100%; max-width: 150mm; }
.cover-scope th, .cover-scope td { text-align: left; padding: 9px 0; border-bottom: 1px solid #E3E5EA;
  font-size: 10.5pt; vertical-align: top; }
.cover-scope th { width: 42mm; color: #8A8F99; font-weight: 600; }
.cover-scope td { color: #16181D; }
.cover-bottom { border-top: 1px solid #E3E5EA; padding-top: 12px;
  display: flex; justify-content: space-between; font-size: 8.5pt; color: #8A8F99; letter-spacing: .04em; }

/* ── body sections ─────────────────────────────────────────────────────── */
.page { break-before: page; }
h2.sec { font-size: 16pt; font-weight: 700; color: #16181D; margin: 0 0 4px;
  padding-bottom: 8px; border-bottom: 2px solid #18181B; display: flex; align-items: baseline; gap: 12px; }
.sec-num { display: inline-block; min-width: 26px; font-size: 12pt; color: #FFFFFF; background: #18181B;
  border-radius: 5px; text-align: center; padding: 2px 6px; }
h3 { font-size: 12pt; margin: 16px 0 6px; color: #16181D; }
h4 { font-size: 11pt; margin: 14px 0 6px; color: #33363F; }
h5 { font-size: 8pt; letter-spacing: .1em; text-transform: uppercase; color: #8A8F99;
  margin: 8px 0 3px; font-weight: 700; }

/* tables */
table.kv, table.grid { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 9.5pt; }
table.kv th { text-align: left; width: 46mm; color: #5B616E; font-weight: 600; vertical-align: top;
  padding: 6px 10px; border-bottom: 1px solid #E3E5EA; }
table.kv td { padding: 6px 10px; border-bottom: 1px solid #E3E5EA; color: #16181D; }
table.grid th { background: #18181B; color: #fff; text-align: left; padding: 7px 9px; font-size: 9pt; }
table.grid td { padding: 6px 9px; border-bottom: 1px solid #E3E5EA; vertical-align: top; }
table.grid tbody tr:nth-child(even) { background: #F6F7F9; }
table.grid tfoot td { font-weight: 700; border-top: 1.5px solid #C9CDD4; }

.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 7px; vertical-align: middle; }

/* rating banner */
.rating-banner { display: flex; align-items: center; justify-content: space-between;
  border: 1px solid #E3E5EA; border-left: 6px solid #64748B; border-radius: 6px;
  padding: 12px 16px; margin: 12px 0 14px; background: #F6F7F9; }
.rating-label { font-size: 9pt; letter-spacing: .1em; text-transform: uppercase; color: #5B616E; font-weight: 700; }
.rating-value { font-size: 18pt; font-weight: 800; letter-spacing: .02em; }
.rating-banner.sev-critical { border-left-color: #DC2626; } .rating-banner.sev-critical .rating-value { color: #DC2626; }
.rating-banner.sev-high { border-left-color: #EA580C; } .rating-banner.sev-high .rating-value { color: #EA580C; }
.rating-banner.sev-medium { border-left-color: #CA8A04; } .rating-banner.sev-medium .rating-value { color: #CA8A04; }
.rating-banner.sev-low { border-left-color: #2563EB; } .rating-banner.sev-low .rating-value { color: #2563EB; }
.rating-banner.sev-passed .rating-value, .rating-banner.sev-info .rating-value { color: #16A34A; }
.rating-banner.sev-passed { border-left-color: #16A34A; } .rating-banner.sev-info { border-left-color: #16A34A; }

/* severity chips */
.sev-chips { display: flex; gap: 10px; margin: 6px 0 4px; }
.chip { flex: 1; border: 1px solid #E3E5EA; border-radius: 6px; padding: 10px 6px; text-align: center; }
.chip-n { display: block; font-size: 18pt; font-weight: 800; line-height: 1; }
.chip-l { display: block; font-size: 7.5pt; letter-spacing: .08em; color: #5B616E; margin-top: 4px; font-weight: 700; }
ul.top-risks { list-style: none; padding: 0; margin: 4px 0; }
ul.top-risks li { padding: 5px 0; border-bottom: 1px solid #EEF0F3; }

/* overview */
.overview { display: flex; gap: 22px; align-items: center; margin: 6px 0 10px; }
.overview-table { flex: 1; }
.donut-num { font-size: 20pt; font-weight: 800; fill: #16181D; }
.donut-cap { font-size: 7pt; fill: #8A8F99; letter-spacing: .05em; }
.bars { margin-top: 6px; }
.bar-row { display: flex; align-items: center; gap: 10px; margin: 5px 0; }
.bar-label { width: 20mm; font-size: 8.5pt; color: #5B616E; font-weight: 700; }
.bar-track { flex: 1; height: 12px; background: #EEF0F3; border-radius: 6px; overflow: hidden; }
.bar-fill { display: block; height: 100%; border-radius: 6px; }
.bar-n { width: 12mm; text-align: right; font-size: 9pt; font-weight: 700; }

/* findings */
.findings .finding { border: 1px solid #E3E5EA; border-radius: 7px; padding: 12px 14px;
  margin: 0 0 12px; break-inside: avoid; }
.finding-head { display: flex; align-items: baseline; gap: 10px; break-after: avoid;
  padding-bottom: 8px; border-bottom: 1px solid #EEF0F3; margin-bottom: 8px; }
.fid { font-size: 7.5pt; font-weight: 700; color: #8A8F99; letter-spacing: .04em; white-space: nowrap; }
.ftitle { flex: 1; font-size: 11pt; font-weight: 700; color: #16181D; }
.sev-pill { color: #fff; font-size: 7.5pt; font-weight: 800; letter-spacing: .06em;
  padding: 3px 9px; border-radius: 20px; white-space: nowrap; }
table.meta { border-collapse: collapse; width: 100%; margin: 2px 0 6px; font-size: 9pt; }
table.meta th { text-align: left; width: 34mm; color: #8A8F99; font-weight: 600; padding: 3px 8px 3px 0; vertical-align: top; }
table.meta td { padding: 3px 0; color: #16181D; vertical-align: top; }
.vec { font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; color: #5B616E; }
.field { margin: 6px 0; }
.field p { margin: 0; font-size: 9.5pt; }
.field pre { background: #F6F7F9; border: 1px solid #EEF0F3; border-radius: 5px; padding: 8px 10px;
  font-family: "DejaVu Sans Mono", monospace; font-size: 8pt; color: #33363F; white-space: pre-wrap;
  word-break: break-word; margin: 0; }
.two-col { display: flex; gap: 18px; }
.two-col .field { flex: 1; }
ul.refs { margin: 2px 0; padding-left: 16px; }
ul.refs li { font-size: 8.5pt; color: #2563EB; word-break: break-all; margin: 2px 0; }
.note { color: #8A8F99; }
.info-table { font-size: 9pt; }
.info-table td.mono { font-family: "DejaVu Sans Mono", monospace; font-size: 8pt;
  color: #5B616E; white-space: nowrap; }
"""
