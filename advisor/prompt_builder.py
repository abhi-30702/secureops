class PromptBuilder:
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
            f"Target: {scan.target}\n"
            f"Client firewall: {firewall}\n\n"
            f"FINDINGS:\n{findings_text}\n\n"
            f"HOSTS:\n{hosts_text}"
        )
