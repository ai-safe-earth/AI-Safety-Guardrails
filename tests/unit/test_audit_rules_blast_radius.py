"""
tests/unit/test_audit_rules_blast_radius.py
-------------------------------------------
AUD-101..AUD-108 against the shipped audit fixtures, scratch trees under
tmp_path, and hand-built contexts.

Each rule gets a positive case on real discovery output, a negative case on
`clean_py` (no AI surface) and `info_only` (an AI surface that already carries a
cap, a budget, an allowlist and a kill-switch read), a grep-tier case where the
rule has one, and an empty-context case that must return [] without raising.
"""

from __future__ import annotations

import re
import shutil
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
from aisg.devtools.audit.rules.blast_radius import (
    RULES,
    BroadCredentials,
    ExecNoSandbox,
    FetchNoAllowlist,
    HostOverGrant,
    NoKillSwitch,
    NoToolBudget,
    UncappedLoop,
    UnsafeHooksCi,
    iter_tools,
    tool_spans,
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
SETTINGS = ".claude/settings.json"


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


OPENAI_AGENT = (
    "from openai import OpenAI\n\nclient = OpenAI()\n\n\ndef ask(q):\n"
    "    return client.chat.completions.create(model='gpt-4o', messages=[])\n"
)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_rules_list_is_ordered_and_complete():
    assert [r.id for r in RULES] == [f"AUD-10{n}" for n in range(1, 9)]
    assert RULES == [
        HostOverGrant,
        UncappedLoop,
        FetchNoAllowlist,
        ExecNoSandbox,
        NoToolBudget,
        BroadCredentials,
        NoKillSwitch,
        UnsafeHooksCi,
    ]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    number = rule.id.split("-", 1)[1]
    assert rule.priority == int(number[0]) == 1
    assert rule.controls
    for token in rule.controls:
        assert CONTROL_TOKEN.match(token), token
    assert len(rule.recommendation.alternatives) >= 3
    assert any("aisg" not in alt for alt in rule.recommendation.alternatives)
    assert rule.measured_precision is None
    assert rule.related_lint_rules
    assert set(rule.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule.known_failure_modes
    assert rule.title


def test_ai_surface_gating_is_declared_where_absence_would_be_noise():
    assert NoToolBudget.requires_ai_surface is True
    assert BroadCredentials.requires_ai_surface is True
    assert NoKillSwitch.requires_ai_surface is True
    assert NoKillSwitch.basis is Basis.ABSENCE
    assert HostOverGrant.requires_ai_surface is False
    assert UnsafeHooksCi.requires_ai_surface is False


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_empty_context_yields_nothing(rule, tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert _eval(rule, ctx) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_no_ai_surface_yields_nothing(rule, audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("clean_py"))
    assert _eval(rule, ctx) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_info_only_agent_yields_nothing(rule, audit_fixture, audit_context):
    """A capped loop, a budget, an allowlist and a kill-switch read: nothing to report."""
    ctx = audit_context(audit_fixture("info_only"))
    assert _eval(rule, ctx) == []


def test_run_rules_on_py_agent_reports_every_rule_it_should(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings, unknown = run_rules(RULES, ctx)
    assert unknown == []
    ids = sorted({f.display_id for f in findings})
    assert ids == ["AUD-101", "AUD-102", "AUD-103", "AUD-104", "AUD-105", "AUD-107"]
    for finding in findings:
        assert finding.controls
        assert finding.confidence.precision is None
        assert len(finding.evidence[0].snippet) <= 160


# ---------------------------------------------------------------------------
# AUD-101 host over-grant
# ---------------------------------------------------------------------------


def test_aud101_claude_bash_star(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("hosts/claude_bash_star"))
    finding = _only(_eval(HostOverGrant, ctx), "AUD-101")
    assert finding.sub is None
    assert finding.severity is Severity.CRITICAL
    assert finding.basis is Basis.PRESENCE
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert finding.confidence.match_kind is MatchKind.STRUCTURED
    assert finding.location == (SETTINGS, 3)
    assert "Bash(*)" in finding.evidence[0].snippet


@pytest.mark.parametrize(
    ("fixture", "needle"),
    [
        ("hosts/claude_bypass", "bypassPermissions"),
        ("hosts/cursor_yolo", "autoRun"),
        ("hosts/gemini_auto", "autoAccept"),
    ],
)
def test_aud101_other_hosts(audit_fixture, audit_context, fixture, needle):
    ctx = audit_context(audit_fixture(fixture))
    finding = _only(_eval(HostOverGrant, ctx), "AUD-101")
    assert finding.sub is None
    assert finding.severity is Severity.CRITICAL
    assert finding.location[1] == 3
    assert needle in finding.evidence[0].snippet


def test_aud101_codex_never_reports_both_grants(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("hosts/codex_never"))
    findings = _by_id(_eval(HostOverGrant, ctx), "AUD-101")
    assert [f.location[1] for f in findings] == [2, 3]
    snippets = " ".join(f.evidence[0].snippet for f in findings)
    assert "never" in snippets
    assert "danger-full-access" in snippets


def test_aud101_interpreter_grant_is_a_medium_sub_finding(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("hosts/claude_interpreter"))
    finding = _only(_eval(HostOverGrant, ctx), "AUD-101")
    assert finding.display_id == "AUD-101/interpreter"
    assert finding.severity is Severity.MEDIUM
    assert finding.location == (SETTINGS, 3)
    assert "Bash(python" in finding.evidence[0].snippet


def test_aud101_docs_mention_is_low_and_never_doubled(audit_fixture, audit_context):
    """The literal is both a structured over-grant literal and a grep hit; one finding."""
    ctx = audit_context(audit_fixture("hosts/docs_mention"))
    finding = _only(_eval(HostOverGrant, ctx), "AUD-101")
    assert finding.display_id == "AUD-101/docs"
    assert finding.severity is Severity.LOW
    assert finding.location == ("README.md", 5)
    assert "--dangerously-skip-permissions" in finding.evidence[0].snippet
    assert finding.notes and "mention" in finding.notes


def test_aud101_py_agent_reports_each_grant_once(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings = _by_id(_eval(HostOverGrant, ctx), "AUD-101")
    assert [(f.location, f.sub) for f in findings] == [((SETTINGS, 3), None), ((SETTINGS, 3), None)]
    assert sorted(f.evidence[0].snippet.split(": ")[-1] for f in findings) == [
        "Bash(*)",
        "WebFetch",
    ]
    assert len({f.fingerprint for f in findings}) == 2


def test_aud101_grep_only_literal_in_docs(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "docs",
        {
            "pyproject.toml": "[project]\nname = 'docs'\n",
            "agent.py": OPENAI_AGENT,
            "RUNBOOK.md": "# Ops\n\nRun the agent with --dangerously-skip-permissions in CI.\n",
        },
    )
    ctx = audit_context(root)
    findings = _by_id(_eval(HostOverGrant, ctx), "AUD-101")
    assert len(findings) == 1
    assert findings[0].location == ("RUNBOOK.md", 3)
    assert findings[0].display_id == "AUD-101/docs"
    assert findings[0].severity is Severity.LOW


# ---------------------------------------------------------------------------
# AUD-102 uncapped loop
# ---------------------------------------------------------------------------


def test_aud102_deep_resolves_the_enclosing_function(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(UncappedLoop, ctx), "AUD-102")
    assert finding.severity is Severity.HIGH
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.confidence.evidence_kind is EvidenceKind.CODE
    assert finding.location == ("app.py", 41)
    assert finding.evidence[0].snippet == "while True:"
    assert finding.scope.kind == "function"
    assert finding.scope.name == "app.py::chat"
    assert [(e.role, e.file, e.line) for e in finding.evidence] == [
        ("match", "app.py", 41),
        ("llm_call", "app.py", 42),
    ]


def test_aud102_grep_tier_is_co_located_not_resolved(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(UncappedLoop, ctx), "AUD-102")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("app.py", 41)
    assert finding.scope.kind == "file"
    assert finding.notes and "co-located" in finding.notes
    assert len(finding.evidence) == 1


def test_aud102_grep_tier_needs_an_llm_call_in_the_same_file(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "loop",
        {
            "pyproject.toml": "[project]\nname = 'loop'\n",
            "agent.py": OPENAI_AGENT,
            "worker.py": "import time\n\n\ndef spin():\n    while True:\n        time.sleep(1)\n",
        },
    )
    ctx = audit_context(root, deep=False)
    assert _eval(UncappedLoop, ctx) == []


def test_aud102_deep_and_grep_never_double_report(py_agent, audit_context):
    ctx = audit_context(py_agent)
    findings = _eval(UncappedLoop, ctx)
    assert len(findings) == 1
    assert len({f.fingerprint for f in findings}) == 1


# ---------------------------------------------------------------------------
# AUD-103 / AUD-104 fetch without allowlist, exec without sandbox
# ---------------------------------------------------------------------------


def test_aud103_fetch_tool_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(FetchNoAllowlist, ctx), "AUD-103")
    assert finding.severity is Severity.HIGH
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.location == ("tools.py", 68)
    assert "fetch_url" in finding.evidence[0].snippet
    assert ("definition", "tools.py", 25) in [(e.role, e.file, e.line) for e in finding.evidence]
    assert finding.scope.kind == "unit"
    assert finding.notes and "fetch_url" in finding.notes


def test_aud103_fetch_tool_grep(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(FetchNoAllowlist, ctx), "AUD-103")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("tools.py", 49)
    assert len(finding.evidence) == 1


def test_aud103_allowlist_in_unit_silences_it(py_agent, audit_context):
    (py_agent / "policy.py").write_text(
        "allowed_domains = ('example.com',)\n\n\ndef is_allowed_url(url):\n"
        "    return any(url.startswith(f'https://{d}') for d in allowed_domains)\n",
        encoding="utf-8",
    )
    ctx = audit_context(py_agent)
    assert _by_id(_eval(FetchNoAllowlist, ctx), "AUD-103") == []


def test_aud104_exec_tool_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(ExecNoSandbox, ctx), "AUD-104")
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.location == ("tools.py", 68)
    assert "run_shell" in finding.evidence[0].snippet
    assert ("definition", "tools.py", 29) in [(e.role, e.file, e.line) for e in finding.evidence]


def test_aud104_exec_tool_grep(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(ExecNoSandbox, ctx), "AUD-104")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("tools.py", 58)


def test_aud104_sandbox_in_unit_silences_it(py_agent, audit_context):
    (py_agent / "isolation.py").write_text(
        "import subprocess\n\n\ndef run_in_sandbox(cmd):\n"
        "    return subprocess.run(['firejail', '--quiet', *cmd], capture_output=True)\n",
        encoding="utf-8",
    )
    ctx = audit_context(py_agent)
    assert _by_id(_eval(ExecNoSandbox, ctx), "AUD-104") == []


def test_tools_are_never_listed_twice_across_tiers(py_agent, audit_context):
    ctx = audit_context(py_agent)
    tools = iter_tools(ctx)
    assert sorted(t.name for t in tools) == ["fetch_url", "run_shell", "send_email"]
    assert all(t.deep for t in tools)
    assert tool_spans(ctx, "send_email") == (("tools.py", 15, 22),)
    grep_only = iter_tools(audit_context(py_agent, deep=False))
    assert sorted(t.name for t in grep_only) == ["fetch_url", "run_shell", "send_email"]
    assert not any(t.deep for t in grep_only)
    assert tool_spans(audit_context(py_agent, deep=False), "send_email") == ()


# ---------------------------------------------------------------------------
# AUD-105 no tool budget
# ---------------------------------------------------------------------------


def test_aud105_three_tools_no_budget_deep(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(NoToolBudget, ctx), "AUD-105")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.match_kind is MatchKind.AST
    assert finding.location == ("tools.py", 68)
    assert finding.evidence[0].snippet == "3 tools registered: fetch_url, run_shell, send_email"
    assert [e.snippet for e in finding.evidence[1:]] == ["fetch_url", "run_shell", "send_email"]
    assert all(e.role == "tool" for e in finding.evidence[1:])
    assert finding.scope.kind == "unit"


def test_aud105_grep_tier_points_at_each_schema(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    finding = _only(_eval(NoToolBudget, ctx), "AUD-105")
    assert finding.confidence.match_kind is MatchKind.GREP
    assert finding.location == ("tools.py", 36)
    assert [(e.role, e.line) for e in finding.evidence] == [
        ("match", 36),
        ("tool", 36),
        ("tool", 49),
        ("tool", 58),
    ]


def test_aud105_budget_symbol_in_unit_silences_it(py_agent, audit_context):
    (py_agent / "limits.py").write_text(
        "max_tool_calls = 20\n\n\ndef within_budget(n):\n    return n < max_tool_calls\n",
        encoding="utf-8",
    )
    ctx = audit_context(py_agent)
    assert _eval(NoToolBudget, ctx) == []


def test_aud105_fewer_than_three_tools_is_not_a_finding(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "two",
        {
            "pyproject.toml": "[project]\nname = 'two'\n",
            "agent.py": OPENAI_AGENT + "\nTOOL_SCHEMAS = [\n"
            "    {'name': 'lookup', 'description': 'Look up an order.',"
            " 'input_schema': {'type': 'object', 'properties': {}}},\n"
            "    {'name': 'status', 'description': 'Order status.',"
            " 'input_schema': {'type': 'object', 'properties': {}}},\n]\n",
        },
    )
    ctx = audit_context(root)
    assert _eval(NoToolBudget, ctx) == []


# ---------------------------------------------------------------------------
# AUD-106 broad credentials in agent scope
# ---------------------------------------------------------------------------


def _cred_tree(tmp_path: Path, *, gitignore: bool) -> Path:
    files = {
        "pyproject.toml": "[project]\nname = 'cred'\n",
        "agent.py": OPENAI_AGENT,
        ".env": "AWS_SECRET_ACCESS_KEY=redacted-in-test\nAPP_NAME=demo\n",
    }
    if gitignore:
        files[".gitignore"] = ".env\n"
    return _write_tree(tmp_path / "cred", files)


def test_aud106_env_binding_names_the_key_never_the_value(tmp_path: Path, audit_context):
    ctx = audit_context(_cred_tree(tmp_path, gitignore=True))
    finding = _only(_eval(BroadCredentials, ctx), "AUD-106")
    assert finding.severity is Severity.HIGH
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert finding.confidence.match_kind is MatchKind.STRUCTURED
    assert finding.location == (".env", 1)
    assert finding.evidence[0].snippet == "AWS_SECRET_ACCESS_KEY"
    assert "redacted-in-test" not in finding.evidence[0].snippet
    assert "redacted-in-test" not in (finding.notes or "")
    assert finding.gitignored is True
    assert finding.scope.kind == "unit"


def test_aud106_not_gitignored_is_recorded_as_such(tmp_path: Path, audit_context):
    ctx = audit_context(_cred_tree(tmp_path, gitignore=False))
    finding = _only(_eval(BroadCredentials, ctx), "AUD-106")
    assert finding.gitignored is False


def test_aud106_grep_tier_gives_the_same_answer(tmp_path: Path, audit_context):
    ctx = audit_context(_cred_tree(tmp_path, gitignore=True), deep=False)
    finding = _only(_eval(BroadCredentials, ctx), "AUD-106")
    assert finding.evidence[0].snippet == "AWS_SECRET_ACCESS_KEY"
    assert finding.gitignored is True


def test_aud106_narrow_names_are_not_broad(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "narrow",
        {
            "pyproject.toml": "[project]\nname = 'narrow'\n",
            "agent.py": OPENAI_AGENT,
            ".env": "OPENAI_API_KEY=placeholder\nAPP_NAME=demo\n",
        },
    )
    ctx = audit_context(root)
    assert _eval(BroadCredentials, ctx) == []


def test_aud106_skipped_by_run_rules_without_an_ai_surface(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "plain",
        {
            "pyproject.toml": "[project]\nname = 'plain'\n",
            "app.py": "print('hello')\n",
            ".env": "AWS_SECRET_ACCESS_KEY=placeholder\n",
        },
    )
    ctx = audit_context(root)
    findings, unknown = run_rules([BroadCredentials], ctx)
    assert findings == [] and unknown == []


# ---------------------------------------------------------------------------
# AUD-107 no kill switch
# ---------------------------------------------------------------------------


def test_aud107_absence_on_py_agent(py_agent, audit_context):
    ctx = audit_context(py_agent)
    finding = _only(_eval(NoKillSwitch, ctx), "AUD-107")
    assert finding.sub is None
    assert finding.severity is Severity.MEDIUM
    assert finding.basis is Basis.ABSENCE
    assert finding.confidence.evidence_kind is EvidenceKind.ABSENCE
    assert finding.scope.kind == "unit"
    assert [e.role for e in finding.evidence] == ["absence"]
    assert "KILL_SWITCH" in finding.evidence[0].snippet


def test_aud107_declared_only_reports_absence_and_inert(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("killswitch_declared_only"))
    findings = _eval(NoKillSwitch, ctx)
    assert [f.display_id for f in findings] == ["AUD-107", "AUD-107/inert"]
    absence, inert = findings
    assert absence.notes and "declared but never read" in absence.notes
    assert [(e.role, e.file, e.line) for e in absence.evidence] == [
        ("absence", ".", 0),
        ("declared", "settings.py", 10),
    ]
    assert inert.location == (".env.example", 2)
    assert inert.evidence[0].snippet == "GUARDRAILS_DISABLE_ALL=false"
    assert inert.confidence.evidence_kind is EvidenceKind.CONFIG
    assert inert.notes and "does not honour" in inert.notes
    assert absence.fingerprint != inert.fingerprint


def test_aud107_kill_switch_read_silences_it(py_agent, audit_context):
    (py_agent / "switch.py").write_text(
        "import os\n\n\ndef halted():\n    return os.environ.get('AGENT_DISABLED') == '1'\n",
        encoding="utf-8",
    )
    ctx = audit_context(py_agent)
    assert _eval(NoKillSwitch, ctx) == []


def test_aud107_grep_tier_matches_deep(py_agent, audit_context):
    deep = _eval(NoKillSwitch, audit_context(py_agent))
    grep = _eval(NoKillSwitch, audit_context(py_agent, deep=False))
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in grep]


# ---------------------------------------------------------------------------
# AUD-108 unsafe hooks / CI steps
# ---------------------------------------------------------------------------


def test_aud108_hook_piping_the_network_into_a_shell(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("hosts/hooks_curl"))
    finding = _only(_eval(UnsafeHooksCi, ctx), "AUD-108")
    assert finding.severity is Severity.HIGH
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert finding.confidence.match_kind is MatchKind.STRUCTURED
    assert finding.location == (SETTINGS, 12)
    assert finding.evidence[0].snippet == "curl -s https://x | sh"
    assert finding.notes and "PostToolUse" in finding.notes and "curl_pipe_sh" in finding.notes


def test_aud108_ci_step(tmp_path: Path, audit_context):
    root = _write_tree(
        tmp_path / "ci",
        {
            "pyproject.toml": "[project]\nname = 'ci'\n",
            ".github/workflows/ci.yml": (
                "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
                "      - uses: actions/checkout@v4\n      - run: curl https://x | sh\n"
            ),
        },
    )
    ctx = audit_context(root)
    finding = _only(_eval(UnsafeHooksCi, ctx), "AUD-108")
    assert finding.location == (".github/workflows/ci.yml", 8)
    assert finding.evidence[0].snippet == "curl https://x | sh"
    assert finding.notes and "CI step" in finding.notes


def test_aud108_pinned_ci_is_not_a_finding(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("info_only"))
    assert ctx.config_facts is not None and ctx.config_facts.ci
    assert _eval(UnsafeHooksCi, ctx) == []


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_findings_are_deterministic_across_runs(rule, py_agent, tmp_path: Path, audit_context):
    first = _eval(rule, audit_context(py_agent))
    copy = tmp_path / "again"
    shutil.copytree(py_agent, copy)
    second = _eval(rule, audit_context(copy))
    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]
