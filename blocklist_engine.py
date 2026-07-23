"""Blocklist / firewall-rule matching for the Network Activity Monitor.

Loads a JSON policy file describing blocked domains and a workstation→employee
map, then matches captured domains against it. Pure detection/reporting: this
engine only classifies traffic that has already been observed — it never blocks,
injects, or otherwise touches the network.

Rule format (config/blocklist.json)::

    {
      "blocklist": [
        {"pattern": "*.torrent-tracker.net", "reason": "P2P / piracy", "severity": "high"},
        {"pattern": "malware-c2.example",     "reason": "Known C2",     "severity": "critical"}
      ],
      "employees": {
        "192.168.10.21": "j.rivera",
        "192.168.10.22": "s.okafor"
      }
    }

Pattern semantics:
  * ``example.com``    matches the domain itself and any subdomain of it.
  * ``*.example.com``  matches any subdomain (but not the bare apex).
  * matching is case-insensitive and ignores a trailing dot.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_DEFAULT_SEVERITY = "medium"
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Resolved relative to this file so it works regardless of the launch cwd.
_DEFAULT_RULES_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config", "blocklist.json"
)


@dataclass
class BlockRule:
    """A single normalised blocklist entry."""

    pattern: str
    reason: str = ""
    severity: str = _DEFAULT_SEVERITY
    # Internal: the bare suffix to compare against (no leading '*.').
    _suffix: str = field(default="", repr=False)
    _wildcard: bool = field(default=False, repr=False)

    def matches(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        if not d or not self._suffix:
            return False
        if self._wildcard:
            # '*.example.com' → only subdomains, not the apex.
            return d.endswith("." + self._suffix)
        # bare pattern → the domain itself or any subdomain of it.
        return d == self._suffix or d.endswith("." + self._suffix)


class BlocklistEngine:
    """Loads block rules + employee map and classifies observed domains."""

    def __init__(self, rules_path: str | None = None) -> None:
        self._rules_path = rules_path or _DEFAULT_RULES_PATH
        self._rules: list[BlockRule] = []
        self._employees: dict[str, str] = {}
        self.load()

    # -- loading ------------------------------------------------------- #
    def load(self) -> None:
        """(Re)load rules from disk. Never raises — a bad/missing file yields
        an empty (allow-all) policy so the monitor keeps running."""
        self._rules = []
        self._employees = {}
        try:
            with open(self._rules_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        for raw in data.get("blocklist", []):
            try:
                pattern = str(raw.get("pattern", "")).strip().lower().rstrip(".")
                if not pattern:
                    continue
                wildcard = pattern.startswith("*.")
                suffix = pattern[2:] if wildcard else pattern
                severity = str(raw.get("severity", _DEFAULT_SEVERITY)).lower()
                if severity not in _VALID_SEVERITIES:
                    severity = _DEFAULT_SEVERITY
                self._rules.append(
                    BlockRule(
                        pattern=pattern,
                        reason=str(raw.get("reason", "")),
                        severity=severity,
                        _suffix=suffix,
                        _wildcard=wildcard,
                    )
                )
            except Exception:
                # One malformed rule must never break the whole policy.
                continue

        employees = data.get("employees", {})
        if isinstance(employees, dict):
            self._employees = {str(k): str(v) for k, v in employees.items()}

    reload = load  # alias

    # -- matching ------------------------------------------------------ #
    def match(self, domain: str) -> dict | None:
        """Return ``{'reason', 'severity', 'pattern'}`` if *domain* is blocked,
        else ``None``. First matching rule wins."""
        if not domain:
            return None
        for rule in self._rules:
            if rule.matches(domain):
                return {
                    "reason": rule.reason,
                    "severity": rule.severity,
                    "pattern": rule.pattern,
                }
        return None

    def is_blocked(self, domain: str) -> bool:
        return self.match(domain) is not None

    def employee_for(self, ip: str) -> str:
        """Friendly workstation label for a source IP, or the IP itself."""
        return self._employees.get(ip, ip)

    # -- introspection ------------------------------------------------- #
    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def employees(self) -> dict[str, str]:
        return dict(self._employees)

    @property
    def blocked_domains(self) -> list[str]:
        """Concrete (non-wildcard) blocked domains — used by the demo feed."""
        return [r._suffix for r in self._rules]
