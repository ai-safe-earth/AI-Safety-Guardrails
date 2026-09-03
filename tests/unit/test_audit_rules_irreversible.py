"""
tests/unit/test_audit_rules_irreversible.py
-------------------------------------------
AUD-201 (irreversible tool with no gate), AUD-202 (inert or bypassed gate) and
AUD-203 (no dry-run / idempotency affordance) against the shipped audit
fixtures, scratch trees under tmp_path, and hand-built contexts.

`py_agent` ships `send_email` (irreversible, ungated, no dry-run) next to
`fetch_url` and `run_shell`, which are not irreversible: the positive and the
negative case live in the same file. Gate variants are built by editing a
scratch copy so every case still runs through real discovery output.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    EvidenceKind,
    Inventory,
    MatchKind,
    Severity,
)
from aisg.devtools.audit.rules import run_rules
from aisg.devtools.audit.rules.irreversible import (
    DRY_RUN_SYMBOLS,
    RULES,
    InertGate,
    IrreversibleUngated,
    NoDryRun,
)

ALLOWED_LINT_RULES = {
    *(f"EU-AIA-{n}" for n in "005a 005b 005c 009a 010a 010b 011a 012a 012b 013a 013b".split()),
    *(f"EU-AIA-{n}" for n in "014a 014b 015a 015b 015c 050a 050b".split()),
    "EU-GDPR-001",
    *(f"ALIGN-00{n}" for n in range(1, 9)),
}
CONTROL_TOKEN = re.compile(
    r"^(?:ASI(?:0[1-9]|10)|LLM(?:0[1-9]|10)|EU:Art\.\d+|NIST:[A-Z]+-\d+\.\d+)$"
)

SEND_EMAIL_HEAD = (
    "def send_email(to: str, subject: str, body: str) -> str:\n    msg = EmailMessage()"
)
REGISTRY_LINE = 68  # `TOOLS = {` in py_agent/tools.py: where the AST tier anchors registry tools
SCHEMA_LINE = 36  # `"name": "send_email"` in the same file: where the grep tier anchors it
DEF_LINE = 15  # `def send_email(`


def _by_id(findings, rule_id: str):
    return [f for f in findings if f.id == rule_id]


def _only(findings, rule_id: str):
    matches = _by_id(findings, rule_id)
    assert len(matches) == 1, [f.display_id for f in matches]
    return matches[0]


def _eval(rule, ctx):
    instance = rule()
    findings = instance.evaluate(ctx)
    assert instance.unknown == []
    return findings


def _write_tree(root: Path, files: dict[str, str]) -> Path:
    for relpath, text in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _patch_send_email(py_agent: Path, replacement: str) -> Path:
    """Rewrite the head of `send_email` in the scratch copy; the replacement must apply."""
    tools = py_agent / "tools.py"
    source = tools.read_text(encoding="utf-8")
    assert SEND_EMAIL_HEAD in source
    tools.write_text(source.replace(SEND_EMAIL_HEAD, replacement), encoding="utf-8")
    return py_agent


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_rules_list_is_ordered_and_complete():
    assert [r.id for r in RULES] == ["AUD-201", "AUD-202", "AUD-203"]
    assert RULES == [IrreversibleUngated, InertGate, NoDryRun]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    number = rule.id.split("-", 1)[1]
    assert rule.priority == int(number[0]) == 2
    assert rule.controls
    for token in rule.controls:
        assert CONTROL_TOKEN.match(token), token
    assert len(rule.recommendation.alternatives) >= 3
    assert any("aisg" not in alt for alt in rule.recommendation.alternatives)
    assert rule.measured_precision is None
    assert rule.related_lint_rules
    assert set(rule.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule.known_failure_modes
    assert any("MCP" in mode for mode in rule.known_failure_modes)
    assert rule.basis is Basis.PRESENCE
    assert rule.evidence_kind is EvidenceKind.CODE
    assert rule.match_kind is MatchKind.AST
    assert rule.requires_ai_surface is False


def test_dry_run_vocabulary_is_stable():
    assert "dry_run" in DRY_RUN_SYMBOLS
    assert "idempotency_key" in DRY_RUN_SYMBOLS
    assert "Idempotency-Key" in DRY_RUN_SYMBOLS


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_empty_context_yields_nothing(rule, tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert _eval(rule, ctx) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
@pytest.mark.parametrize("fixture", ["clean_py", "info_only", "noise", "ts_agent"])
def test_fixtures_without_an_irreversible_tool_yield_nothing(
    rule, fixture, audit_fixture, audit_context
):
    ctx = audit_context(audit_fixture(fixture))
    assert _eval(rule, ctx) == []


def test_run_rules_on_py_agent(py_agent, audit_context):
    findings, unknown = run_rules(RULES, audit_context(py_agent))
    assert unknown == []
    assert [f.display_id for f in findings] == ["AUD-201", "AUD-203"]
    for finding in findings:
        assert finding.confidence.precision is None
        assert finding.controls
        assert "send_email" in finding.evidence[0].snippet


# ---------------------------------------------------------------------------
# AUD-201 irreversible tool with no gate
# ---------------------------------------------------------------------------


def test_aud201_send_email_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(IrreversibleUngated, ctx), "AUD-201")
    assert finding.severity is Severity.CRITICAL
    assert finding.basis is Basis.PRESENCE
    assert finding.confidence.evidence_kind is EvidenceKind.CODE
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.location == ("tools.py", REGISTRY_LINE)
    assert [(e.role, e.file, e.line) for e in finding.evidence] == [
        ("match", "tools.py", REGISTRY_LINE),
        ("definition", "tools.py", DEF_LINE),
    ]
    assert finding.evidence[1].snippet.startswith("def send_email(")
    assert finding.scope.kind == "unit"
    assert finding.scope.unit == "u0"
    assert finding.notes and "send_email" in finding.notes and "APPROVAL_SYMBOLS" in finding.notes


def test_aud201_send_email_grep(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(IrreversibleUngated, ctx), "AUD-201")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("tools.py", SCHEMA_LINE)
    assert len(finding.evidence) == 1
    assert '"send_email"' in finding.evidence[0].snippet


def test_aud201_only_irreversible_tools(py_agent, audit_context):
    for deep in (True, False):
        findings = _eval(IrreversibleUngated, audit_context(py_agent, deep=deep))
        assert len(findings) == 1
        assert "fetch_url" not in findings[0].evidence[0].snippet
        assert "run_shell" not in findings[0].evidence[0].snippet


def test_aud201_live_gate_on_the_call_path_silences_it(py_agent, audit_context):
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    if not ask_user(f'send to {to}?'):\n        return 'cancelled'\n"
        "    msg = EmailMessage()",
    )
    deep = audit_context(py_agent)
    assert deep.pyfacts is not None and deep.pyfacts.tool_gate_join["send_email"] is not None
    assert _eval(IrreversibleUngated, deep) == []
    assert _eval(IrreversibleUngated, audit_context(py_agent, deep=False)) == []


def test_aud201_inert_gate_is_aud202_not_aud201(py_agent, audit_context):
    """An inert gate on the call path is AUD-202's finding; AUD-201 does not double it."""
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    guard = ToolPolicyGuard(require_approval=True)\n"
        "    msg = EmailMessage()",
    )
    ctx = audit_context(py_agent)
    assert ctx.pyfacts is not None
    assert ctx.pyfacts.tool_gate_join["send_email"] is not None
    assert any(
        g.file == "tools.py" and g.line == DEF_LINE + 1 and g.inert_reason
        for g in ctx.pyfacts.gates
    )
    assert _eval(IrreversibleUngated, ctx) == []
    inert = _only(_eval(InertGate, ctx), "AUD-202")
    assert inert.location == ("tools.py", DEF_LINE + 1)
    assert inert.scope.name == "tools.py::send_email"


# ---------------------------------------------------------------------------
# AUD-202 inert or bypassed gate
# ---------------------------------------------------------------------------


def _gate_tree(tmp_path: Path) -> Path:
    return _write_tree(
        tmp_path / "gate",
        {
            "pyproject.toml": "[project]\nname = 'gate'\n",
            "agent.py": (
                "from anthropic import Anthropic\nfrom aisg import ToolPolicyGuard\n\n"
                "client = Anthropic()\nguard = ToolPolicyGuard(require_approval=True)\n\n\n"
                "def run(prompt):\n    auto_approve = True\n"
                "    return client.messages.create(model='m', max_tokens=10, messages=[])\n"
            ),
        },
    )


def test_aud202_deep_reports_inert_and_bypassed_gates(tmp_path: Path, audit_context):
    ctx = audit_context(_gate_tree(tmp_path))
    findings = _by_id(_eval(InertGate, ctx), "AUD-202")
    assert [f.location for f in findings] == [("agent.py", 5), ("agent.py", 9)]
    inert, bypass = findings
    assert inert.severity is Severity.CRITICAL
    assert inert.confidence.match_kind is MatchKind.AST
    assert inert.confidence.evidence_kind is EvidenceKind.CODE
    assert inert.evidence[0].snippet == "guard = ToolPolicyGuard(require_approval=True)"
    assert inert.notes == "ToolPolicyGuard: require_approval=True without approval_callback"
    assert inert.scope.kind == "file"
    assert bypass.evidence[0].snippet == "auto_approve = True"
    assert bypass.notes == "auto_approve: bypass: auto_approve = True"
    assert bypass.scope.kind == "function"
    assert bypass.scope.name == "agent.py::run"
    assert len({f.fingerprint for f in findings}) == 2


def test_aud202_grep_tier_only_sees_the_bypass_literal(tmp_path: Path, audit_context):
    ctx = audit_context(_gate_tree(tmp_path), deep=False)
    finding = _only(_eval(InertGate, ctx), "AUD-202")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("agent.py", 9)
    assert finding.scope.kind == "file"
    assert finding.notes and "GATE_BYPASS" in finding.notes


def test_aud202_grep_tier_covers_non_python_even_when_deep(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "ts",
        {
            "package.json": '{"name": "x", "dependencies": {"openai": "^4.0.0"}}\n',
            "agent.ts": (
                "import OpenAI from 'openai';\nconst client = new OpenAI();\n"
                "export const agent = { autoApprove: true };\n"
            ),
        },
    )
    finding = _only(_eval(InertGate, audit_context(root)), "AUD-202")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("agent.ts", 3)
    assert "autoApprove: true" in finding.evidence[0].snippet


def test_aud202_fail_open_approval_is_reported(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "swallow",
        {
            "pyproject.toml": "[project]\nname = 'swallow'\n",
            "agent.py": (
                "from openai import OpenAI\nfrom aisg import ToolPolicyGuard\n\n"
                "client = OpenAI()\nguard = ToolPolicyGuard(approval_callback=input)\n\n\n"
                "def guarded(action):\n"
                "    try:\n        guard.check(action)\n    except Exception:\n        pass\n"
                "    return client.chat.completions.create(model='m', messages=[])\n"
            ),
        },
    )
    ctx = audit_context(root)
    assert ctx.pyfacts is not None and ctx.pyfacts.fail_open
    finding = _only(_eval(InertGate, ctx), "AUD-202")
    assert finding.location == ("agent.py", 9)
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.notes == "fail_open: fails open: exception swallowed"
    assert finding.scope.name == "agent.py::guarded"


def test_aud202_a_live_gate_is_not_reported(py_agent, audit_context):
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    if not ask_user(f'send to {to}?'):\n        return 'cancelled'\n"
        "    msg = EmailMessage()",
    )
    assert _eval(InertGate, audit_context(py_agent)) == []
    assert _eval(InertGate, audit_context(py_agent, deep=False)) == []


def test_aud202_nothing_on_py_agent(py_agent, audit_context):
    assert _eval(InertGate, audit_context(py_agent)) == []
    assert _eval(InertGate, audit_context(py_agent, deep=False)) == []


# ---------------------------------------------------------------------------
# AUD-203 no dry-run / idempotency affordance
# ---------------------------------------------------------------------------


def test_aud203_send_email_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(NoDryRun, ctx), "AUD-203")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.location == ("tools.py", REGISTRY_LINE)
    assert [(e.role, e.line) for e in finding.evidence] == [
        ("match", REGISTRY_LINE),
        ("definition", DEF_LINE),
    ]
    assert finding.scope.kind == "unit"
    assert finding.notes and "dry_run" in finding.notes


def test_aud203_send_email_grep(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(NoDryRun, ctx), "AUD-203")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("tools.py", SCHEMA_LINE)


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_aud203_dry_run_parameter_silences_it(py_agent, audit_context, deep):
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str, dry_run: bool = False) -> str:\n"
        "    msg = EmailMessage()\n    if dry_run:\n        return 'would send'",
    )
    ctx = audit_context(py_agent, deep=deep)
    assert _eval(NoDryRun, ctx) == []
    # The gate finding is independent of the affordance: still ungated.
    assert len(_eval(IrreversibleUngated, ctx)) == 1


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_aud203_idempotency_key_silences_it(py_agent, audit_context, deep):
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str, idempotency_key: str = '') -> str:\n"
        "    msg = EmailMessage()\n    msg['Idempotency-Key'] = idempotency_key",
    )
    assert _eval(NoDryRun, audit_context(py_agent, deep=deep)) == []


def test_aud203_prefix_match_does_not_cross_identifiers(py_agent, audit_context):
    _patch_send_email(
        py_agent,
        "def send_email(to: str, subject: str, body: str) -> str:\n"
        "    laundry_run = True\n    msg = EmailMessage()",
    )
    assert len(_eval(NoDryRun, audit_context(py_agent))) == 1
