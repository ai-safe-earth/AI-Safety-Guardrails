"""tests/unit/test_audit_rules_trust_boundary.py
-----------------------------------------------
AUD-301 (lethal trifecta), AUD-302 (untrusted content into a prompt) and AUD-303
(system prompt built from request data), on real discovery output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aisg.devtools.audit.discover import DiscoverOptions
from aisg.devtools.audit.model import (
    TRIFECTA_RULE_ID,
    AuditContext,
    Inventory,
    MatchKind,
    Severity,
)
from aisg.devtools.audit.pydeep import PyFacts
from aisg.devtools.audit.rules import trust_boundary
from aisg.devtools.audit.rules.trust_boundary import (
    RULES,
    LethalTrifecta,
    SystemPromptFromRequest,
    UntrustedIntoPrompt,
    trifecta_scopes,
)

ALLOWED_LINT_RULES = {
    "EU-AIA-005a",
    "EU-AIA-005b",
    "EU-AIA-005c",
    "EU-AIA-009a",
    "EU-AIA-010a",
    "EU-AIA-010b",
    "EU-AIA-011a",
    "EU-AIA-012a",
    "EU-AIA-012b",
    "EU-AIA-013a",
    "EU-AIA-013b",
    "EU-AIA-014a",
    "EU-AIA-014b",
    "EU-AIA-015a",
    "EU-AIA-015b",
    "EU-AIA-015c",
    "EU-AIA-050a",
    "EU-AIA-050b",
    "EU-GDPR-001",
} | {f"ALIGN-00{n}" for n in range(1, 9)}

AGENT_PY = (
    "import anthropic\n"
    "\n"
    "client = anthropic.Anthropic()\n"
    "\n"
    "\n"
    "def ask(prompt):\n"
    "    response = client.messages.create(\n"
    '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
    '        messages=[{"role": "user", "content": prompt}],\n'
    "    )\n"
    "    return response.content[0].text\n"
)


def _run(rule_cls, ctx):
    rule = rule_cls()
    return rule.evaluate(ctx), rule


def _ids(findings):
    return [f.id for f in findings]


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_cls", RULES)
def test_rule_metadata(rule_cls):
    assert rule_cls.id.startswith("AUD-")
    assert rule_cls.priority == int(rule_cls.id[4])
    assert rule_cls.controls
    assert len(rule_cls.recommendation.alternatives) >= 3
    assert any("aisg" not in alt.lower() for alt in rule_cls.recommendation.alternatives)
    assert rule_cls.measured_precision is None
    assert set(rule_cls.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule_cls.known_failure_modes
    assert rule_cls.requires_ai_surface is True


def test_module_exports():
    assert [r.id for r in RULES] == ["AUD-301", "AUD-302", "AUD-303"]
    assert LethalTrifecta.id == TRIFECTA_RULE_ID
    assert trust_boundary.RULES is RULES


# ---------------------------------------------------------------------------
# AUD-301 lethal trifecta
# ---------------------------------------------------------------------------


def test_trifecta_deep_py_agent(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings, rule = _run(LethalTrifecta, ctx)
    assert _ids(findings) == ["AUD-301"]
    f = findings[0]
    assert f.id == TRIFECTA_RULE_ID
    assert f.scope.kind == "function"
    assert f.scope.name == "app.py::chat"
    assert f.scope.unit == "u0"
    assert f.confidence.match_kind == MatchKind.AST
    assert f.severity == Severity.CRITICAL
    assert [e.role for e in f.evidence] == ["private", "untrusted", "external_action"]
    assert all(e.file == "app.py" for e in f.evidence)
    assert all("\\" not in e.file for e in f.evidence)
    assert f.location == ("app.py", 25)
    assert rule.unknown == []
    assert trifecta_scopes(ctx) == [f.scope]


def test_trifecta_unit_tier_without_deep(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    assert ctx.pyfacts is None
    findings, _ = _run(LethalTrifecta, ctx)
    assert _ids(findings) == ["AUD-301"]
    f = findings[0]
    assert f.scope.kind == "unit"
    assert f.scope.unit == "u0"
    assert f.confidence.match_kind == MatchKind.STRUCTURED
    assert [e.role for e in f.evidence] == ["private", "untrusted", "external_action"]
    assert "data flow not verified" in (f.notes or "")
    assert trifecta_scopes(ctx) == [f.scope]


def test_trifecta_deep_wins_over_unit_tier(tmp_path, audit_context):
    """Legs spread over unrelated files: the unit tier fires, the AST tier does not."""
    _write(tmp_path, "agent.py", AGENT_PY)
    _write(tmp_path, "store.py", 'import os\n\nDB_URL = os.environ.get("DB_URL", "")\n')
    _write(
        tmp_path,
        "runner.py",
        "import subprocess\n\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
    )
    _write(
        tmp_path,
        "web.py",
        "import requests\n\n\ndef fetch(url):\n    return requests.get(url).text\n",
    )
    shallow, _ = _run(LethalTrifecta, audit_context(tmp_path, deep=False))
    assert _ids(shallow) == ["AUD-301"]
    assert shallow[0].scope.kind == "unit"
    assert {e.file for e in shallow[0].evidence} == {"store.py", "runner.py", "web.py"}

    deep, rule = _run(LethalTrifecta, audit_context(tmp_path, deep=True))
    assert deep == []
    assert rule.unknown == []


def test_trifecta_mcp_server_supplies_missing_leg(tmp_path, audit_context):
    _write(tmp_path, "agent.py", AGENT_PY)
    _write(tmp_path, "store.py", 'import os\n\nDB_URL = os.environ.get("DB_URL", "")\n')
    _write(tmp_path, "mail.py", "import smtplib\n\n\ndef send(msg):\n    smtplib.SMTP()\n")
    _write(
        tmp_path,
        ".mcp.json",
        json.dumps({"mcpServers": {"web": {"type": "sse", "url": "http://mcp.example.com/sse"}}}),
    )
    for deep in (True, False):
        findings, _ = _run(LethalTrifecta, audit_context(tmp_path, deep=deep))
        assert _ids(findings) == ["AUD-301"], deep
        f = findings[0]
        assert f.scope.kind == "unit"
        assert f.confidence.match_kind == MatchKind.STRUCTURED
        roles = {e.role: e for e in f.evidence}
        assert set(roles) == {"private", "untrusted", "external_action"}
        assert roles["untrusted"].file == ".mcp.json"
        assert "mcp server web" in roles["untrusted"].snippet
        assert "implied by MCP server 'web'" in (f.notes or "")
        assert "data flow not verified" in (f.notes or "")


def test_trifecta_trusted_remote_host_is_not_untrusted_ingress(tmp_path, audit_context):
    _write(tmp_path, "agent.py", AGENT_PY)
    _write(tmp_path, "store.py", 'import os\n\nDB_URL = os.environ.get("DB_URL", "")\n')
    _write(tmp_path, "mail.py", "import smtplib\n\n\ndef send(msg):\n    smtplib.SMTP()\n")
    _write(
        tmp_path,
        ".mcp.json",
        json.dumps({"mcpServers": {"web": {"type": "sse", "url": "http://mcp.example.com/sse"}}}),
    )
    options = DiscoverOptions(trusted_mcp_hosts=("mcp.example.com",))
    ctx = audit_context(tmp_path, deep=False, options=options)
    servers = ctx.inventory.mcp["servers"]
    assert [s["trusted"] for s in servers] == [True]
    assert "untrusted" in servers[0]["implied_legs"]
    findings, _ = _run(LethalTrifecta, ctx)
    assert findings == []


def test_trifecta_needs_all_three_legs(tmp_path, audit_context):
    _write(tmp_path, "agent.py", AGENT_PY)
    _write(tmp_path, "store.py", 'import os\n\nDB_URL = os.environ.get("DB_URL", "")\n')
    _write(tmp_path, "mail.py", "import smtplib\n\n\ndef send(msg):\n    smtplib.SMTP()\n")
    for deep in (True, False):
        findings, _ = _run(LethalTrifecta, audit_context(tmp_path, deep=deep))
        assert findings == [], deep


@pytest.mark.parametrize("name", ["clean_py", "noise", "info_only"])
@pytest.mark.parametrize("deep", [True, False])
def test_trifecta_silent_on_negative_fixtures(audit_fixture, audit_context, name, deep):
    findings, rule = _run(LethalTrifecta, audit_context(audit_fixture(name), deep=deep))
    assert findings == []
    assert rule.unknown == []


def test_trifecta_skips_units_without_ai_surface(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("clean_py"), deep=False)
    assert not any(u.ai_surface for u in ctx.inventory.units)
    findings, _ = _run(LethalTrifecta, ctx)
    assert findings == []


# ---------------------------------------------------------------------------
# AUD-302 / AUD-303 prompt assembly
# ---------------------------------------------------------------------------


def test_untrusted_into_prompt_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings, rule = _run(UntrustedIntoPrompt, ctx)
    assert _ids(findings) == ["AUD-302"]
    f = findings[0]
    assert f.location == ("app.py", 38)
    assert f.confidence.match_kind == MatchKind.AST
    assert f.severity == Severity.HIGH
    assert [e.role for e in f.evidence][:2] == ["assembly", "source"]
    assert f.evidence[1].line == 35
    assert "body" in (f.notes or "")
    assert rule.unknown == []


def test_system_prompt_from_request_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings, _ = _run(SystemPromptFromRequest, ctx)
    assert _ids(findings) == ["AUD-303"]
    f = findings[0]
    assert f.location == ("app.py", 37)
    assert f.confidence.match_kind == MatchKind.AST
    assert f.severity == Severity.HIGH
    assert f.evidence[0].role == "assembly"
    assert "system prompt" in (f.notes or "")


def test_prompt_rules_grep_tier(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    user, _ = _run(UntrustedIntoPrompt, ctx)
    system, _ = _run(SystemPromptFromRequest, ctx)
    assert [(f.id, f.location) for f in user] == [("AUD-302", ("app.py", 38))]
    assert [(f.id, f.location) for f in system] == [("AUD-303", ("app.py", 37))]
    for f in user + system:
        assert f.confidence.match_kind == MatchKind.GREP
        assert "unverified" in (f.notes or "")
        assert "data flow not verified" in (f.notes or "")
        assert any(e.role == "source" and e.line == 35 for e in f.evidence)
    assert any(e.role == "system_role" and e.line == 45 for e in system[0].evidence)


def test_prompt_rules_deep_wins_no_grep_duplicates(py_agent, audit_context):
    ctx = audit_context(py_agent)
    for rule_cls in (UntrustedIntoPrompt, SystemPromptFromRequest):
        findings, _ = _run(rule_cls, ctx)
        assert all(f.confidence.match_kind == MatchKind.AST for f in findings)
        locations = [f.location for f in findings]
        assert len(locations) == len(set(locations))


@pytest.mark.parametrize("deep", [True, False])
def test_sanitiser_in_file_downgrades_never_drops(tmp_path, audit_context, deep):
    _write(
        tmp_path,
        "app.py",
        "import anthropic\n"
        "from fastapi import FastAPI, Request\n"
        "\n"
        "app = FastAPI()\n"
        "client = anthropic.Anthropic()\n"
        "\n"
        "\n"
        "def sanitize(text):\n"
        '    return text.replace("<", "")\n'
        "\n"
        "\n"
        '@app.post("/ask")\n'
        "async def ask(request: Request):\n"
        "    body = await request.json()\n"
        "    prompt = f\"Question: {body['q']}\"\n"
        "    response = client.messages.create(\n"
        '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
        '        messages=[{"role": "user", "content": prompt}],\n'
        "    )\n"
        "    return response.content[0].text\n",
    )
    ctx = audit_context(tmp_path, deep=deep)
    findings, _ = _run(UntrustedIntoPrompt, ctx)
    assert [(f.id, f.location) for f in findings] == [("AUD-302", ("app.py", 15))]
    f = findings[0]
    assert f.severity == Severity.LOW
    assert "sanitize" in (f.notes or "")
    assert "verify" in (f.notes or "")
    expected = MatchKind.AST if deep else MatchKind.GREP
    assert f.confidence.match_kind == expected


@pytest.mark.parametrize("name", ["clean_py", "noise", "info_only"])
@pytest.mark.parametrize("deep", [True, False])
@pytest.mark.parametrize("rule_cls", [UntrustedIntoPrompt, SystemPromptFromRequest])
def test_prompt_rules_silent_on_negative_fixtures(
    audit_fixture, audit_context, name, deep, rule_cls
):
    findings, rule = _run(rule_cls, audit_context(audit_fixture(name), deep=deep))
    assert findings == []
    assert rule.unknown == []


def test_prompt_grep_tier_needs_shared_identifier(tmp_path, audit_context):
    _write(
        tmp_path,
        "app.py",
        "import anthropic\n"
        "from fastapi import FastAPI, Request\n"
        "\n"
        "app = FastAPI()\n"
        "client = anthropic.Anthropic()\n"
        "\n"
        "\n"
        '@app.post("/ask")\n'
        "async def ask(request: Request):\n"
        "    payload = await request.json()\n"
        '    prompt = f"Question: {GREETING}"\n'
        "    response = client.messages.create(\n"
        '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
        '        messages=[{"role": "user", "content": prompt}],\n'
        "    )\n"
        "    return response.content[0].text\n",
    )
    ctx = audit_context(tmp_path, deep=False)
    for rule_cls in (UntrustedIntoPrompt, SystemPromptFromRequest):
        findings, _ = _run(rule_cls, ctx)
        assert findings == []


# ---------------------------------------------------------------------------
# Empty context: never raises
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_cls", RULES)
def test_empty_context(tmp_path, rule_cls):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    findings, rule = _run(rule_cls, ctx)
    assert findings == []
    assert rule.unknown == []
    ctx = AuditContext(root=tmp_path, inventory=Inventory(), pyfacts=PyFacts())
    findings, rule = _run(rule_cls, ctx)
    assert findings == []
    assert rule.unknown == []
    assert trifecta_scopes(ctx) == []
