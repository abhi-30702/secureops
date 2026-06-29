from models import Scan, Client, Host, Finding
from advisor.prompt_builder import PromptBuilder


def _scan():
    return Scan(id=1, client_id=1, target="example.com",
                status="complete", started_at="2026-06-03T10:00:00", finished_at=None)


def _client():
    return Client(id=1, name="Acme", domain="example.com",
                  firewall="pfSense", notes="", created_at="2026-06-03T00:00:00")


def _finding():
    return Finding(id=1, scan_id=1, host_id=None, tool="nuclei",
                   severity="high", title="SQL Injection",
                   description="Found unsanitised input", raw_json="{}",
                   created_at="2026-06-03T10:01:00")


def _host():
    return Host(id=1, scan_id=1, subdomain="api.example.com", ip="1.2.3.4",
                port=443, protocol="tcp", service="https", url=None,
                source_tool="naabu", created_at="2026-06-03T10:01:00")


def test_prompt_contains_target():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "example.com" in prompt


def test_prompt_contains_firewall():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "pfSense" in prompt


def test_prompt_contains_finding_title():
    prompt = PromptBuilder().build(_scan(), _client(), [], [_finding()])
    assert "SQL Injection" in prompt


def test_prompt_contains_finding_severity():
    prompt = PromptBuilder().build(_scan(), _client(), [], [_finding()])
    assert "HIGH" in prompt


def test_prompt_contains_host():
    prompt = PromptBuilder().build(_scan(), _client(), [_host()], [])
    assert "api.example.com" in prompt


def test_prompt_has_all_three_section_markers():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "IMMEDIATE:" in prompt
    assert "SHORT_TERM:" in prompt
    assert "PREVENTIVE:" in prompt


def test_prompt_no_client_uses_unknown_firewall():
    prompt = PromptBuilder().build(_scan(), None, [], [])
    assert "unknown" in prompt


def test_prompt_no_exploitation_instruction():
    prompt = PromptBuilder().build(_scan(), _client(), [], [])
    assert "exploitation" in prompt.lower() or "offensive" in prompt.lower()


# ── redaction (FR-53) ───────────────────────────────────────────────────────────

def test_redact_strips_target_domain():
    prompt = PromptBuilder(redact=True).build(_scan(), _client(), [_host()], [])
    assert "example.com" not in prompt
    assert "[HOST]" in prompt


def test_redact_strips_subdomain():
    prompt = PromptBuilder(redact=True).build(_scan(), _client(), [_host()], [])
    assert "api.example.com" not in prompt


def test_redact_strips_ip():
    f = Finding(id=1, scan_id=1, host_id=None, tool="nuclei", severity="high",
                title="Exposed admin", description="Admin panel at 1.2.3.4 reachable",
                raw_json="{}", created_at="2026-06-03T10:01:00")
    prompt = PromptBuilder(redact=True).build(_scan(), _client(), [], [f])
    assert "1.2.3.4" not in prompt
    assert "[IP]" in prompt


def test_redact_strips_company_name():
    f = Finding(id=1, scan_id=1, host_id=None, tool="nuclei", severity="high",
                title="Acme login exposed", description="Acme portal leak",
                raw_json="{}", created_at="2026-06-03T10:01:00")
    prompt = PromptBuilder(redact=True).build(_scan(), _client(), [], [f])
    assert "Acme" not in prompt
    assert "[COMPANY]" in prompt


def test_redact_off_by_default_keeps_details():
    f = Finding(id=1, scan_id=1, host_id=None, tool="nuclei", severity="high",
                title="Exposed admin", description="Admin panel at 1.2.3.4 reachable",
                raw_json="{}", created_at="2026-06-03T10:01:00")
    prompt = PromptBuilder().build(_scan(), _client(), [_host()], [f])
    assert "example.com" in prompt
    assert "1.2.3.4" in prompt


def test_redact_preserves_finding_severity():
    prompt = PromptBuilder(redact=True).build(_scan(), _client(), [], [_finding()])
    # Redaction must not destroy the security content itself.
    assert "HIGH" in prompt
    assert "SQL Injection" in prompt
