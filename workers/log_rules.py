import re
from dataclasses import dataclass


@dataclass
class LogRule:
    name: str
    pattern: re.Pattern
    severity: str        # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    description: str
    formats: list[str]   # log format tags this rule applies to; ["*"] = all formats


def detect_format(lines: list[str]) -> str:
    sample = "\n".join(lines[:20])
    scores = {
        "auth":     0,
        "nginx":    0,
        "apache":   0,
        "firewall": 0,
        "syslog":   0,
    }

    if re.search(r"\bsshd\b|\bsudo\b|\bPAM\b|\buseradd\b|\bpam_unix\b", sample):
        scores["auth"] += 3
    if re.search(r'"(GET|POST|PUT|DELETE|HEAD)\s+\S+\s+HTTP/\d', sample):
        scores["nginx"] += 2
        scores["apache"] += 2
    if re.search(r"nginx", sample, re.IGNORECASE):
        scores["nginx"] += 2
    if re.search(r"apache|httpd", sample, re.IGNORECASE):
        scores["apache"] += 2
    if re.search(r"UFW BLOCK|iptables|IN=\w+.*OUT=|DPT=\d+", sample):
        scores["firewall"] += 3
    if re.search(r"^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+", sample, re.MULTILINE):
        scores["syslog"] += 1

    best = max(scores, key=lambda k: scores[k])
    return best if scores[best] > 0 else "unknown"


RULES: list[LogRule] = [
    LogRule(
        name="ssh_brute_force",
        pattern=re.compile(r"Failed password for .+ from (\d{1,3}(?:\.\d{1,3}){3})"),
        severity="HIGH",
        description="Repeated SSH authentication failures from same IP (potential brute force)",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="root_sudo",
        pattern=re.compile(r"sudo.*USER=root.*COMMAND=", re.IGNORECASE),
        severity="MEDIUM",
        description="sudo command executed as root",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="user_account_change",
        pattern=re.compile(r"\b(useradd|usermod|userdel)\b"),
        severity="HIGH",
        description="User account created, modified, or deleted",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="pubkey_login",
        pattern=re.compile(r"Accepted publickey for .+ from (\d{1,3}(?:\.\d{1,3}){3})"),
        severity="INFO",
        description="SSH public key authentication succeeded",
        formats=["auth", "syslog", "unknown"],
    ),
    LogRule(
        name="sqli_attempt",
        pattern=re.compile(
            r"(UNION\s+SELECT|'\s*--\s|1\s*=\s*1|OR\s+1\s*=\s*1|DROP\s+TABLE)",
            re.IGNORECASE,
        ),
        severity="HIGH",
        description="Possible SQL injection pattern in request",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="scanner_ua",
        pattern=re.compile(r"\b(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei)\b", re.IGNORECASE),
        severity="MEDIUM",
        description="Known security scanner User-Agent detected",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="http_scan_rate",
        pattern=re.compile(r'" [45]\d{2} '),
        severity="MEDIUM",
        description="High rate of HTTP 4xx/5xx responses from same IP (possible scan)",
        formats=["nginx", "apache", "unknown"],
    ),
    LogRule(
        name="port_scan",
        pattern=re.compile(r"(?:UFW BLOCK|iptables.*DROP).*SRC=(\d{1,3}(?:\.\d{1,3}){3}).*DPT=(\d+)"),
        severity="HIGH",
        description="Port scan pattern — multiple blocked ports from same source IP",
        formats=["firewall", "unknown"],
    ),
    LogRule(
        name="repeated_block",
        pattern=re.compile(r"(?:UFW BLOCK|iptables.*DROP).*SRC=(\d{1,3}(?:\.\d{1,3}){3})"),
        severity="MEDIUM",
        description="Repeated firewall blocks from same source IP",
        formats=["firewall", "unknown"],
    ),
    LogRule(
        name="oom_killer",
        pattern=re.compile(r"Out of memory: Kill process", re.IGNORECASE),
        severity="MEDIUM",
        description="Linux OOM killer invoked — system under memory pressure",
        formats=["syslog", "unknown"],
    ),
    LogRule(
        name="kernel_panic",
        pattern=re.compile(r"\b(segfault|kernel panic|BUG: unable to handle)\b", re.IGNORECASE),
        severity="MEDIUM",
        description="Kernel error or panic detected",
        formats=["syslog", "unknown"],
    ),
]
