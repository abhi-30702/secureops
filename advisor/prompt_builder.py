import re

# Matches IPv4 dotted-quad addresses.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(text: str, hosts, client, target: str) -> str:
    """Strip identifying details from text before it leaves the machine (FR-53).

    Replaces, in order of specificity: hostnames/subdomains and the target
    domain, the company name, then any remaining IPv4 addresses. Order
    matters — hostnames are redacted before bare IPs so a hostname that
    embeds digits is not partly mangled by the IP pass.
    """
    if not text:
        return text

    # Collect concrete identifiers, longest first so "api.example.com" is
    # redacted before "example.com" leaves a dangling "api.".
    identifiers: list[str] = []
    for h in hosts or []:
        if getattr(h, "subdomain", None):
            identifiers.append(h.subdomain)
    if target:
        identifiers.append(target)
    for ident in sorted(set(identifiers), key=len, reverse=True):
        if ident:
            text = text.replace(ident, "[HOST]")

    if client and getattr(client, "name", None):
        text = re.sub(re.escape(client.name), "[COMPANY]", text, flags=re.IGNORECASE)

    text = _IP_RE.sub("[IP]", text)
    return text


class PromptBuilder:
    def __init__(self, redact: bool = False):
        self._redact = redact

    def build(self, scan, client, hosts, findings) -> str:
        firewall = (client.firewall if client else None) or "unknown"

        findings_text = "\n".join(
            f"[{f.severity.upper()}] {f.title}: {f.description[:200]}"
            for f in findings
        ) or "No findings."

        hosts_text = "\n".join(
            f"{h.subdomain or h.ip or 'unknown'}"
            f"  port={h.port or 'N/A'}  service={h.service or 'N/A'}"
            for h in hosts
        ) or "No hosts."

        target = scan.target or ""

        if self._redact:
            findings_text = redact(findings_text, hosts, client, target)
            hosts_text = redact(hosts_text, hosts, client, target)
            target = "[HOST]"

        return (
            "You are a security advisor reviewing a penetration test scan result.\n"
            "Produce ONLY defensive precautions and remediation guidance.\n"
            "Do NOT include any exploitation steps, attack methods, or offensive techniques.\n\n"
            "Respond in EXACTLY this format — no other text, no preamble:\n"
            "IMMEDIATE:\n"
            "1. [action]\n"
            "SHORT_TERM:\n"
            "1. [action]\n"
            "PREVENTIVE:\n"
            "1. [action]\n\n"
            f"Target: {target}\n"
            f"Client firewall: {firewall}\n\n"
            f"FINDINGS:\n{findings_text}\n\n"
            f"HOSTS:\n{hosts_text}"
        )
