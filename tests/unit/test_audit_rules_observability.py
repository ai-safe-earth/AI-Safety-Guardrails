"""
tests/unit/test_audit_rules_observability.py
--------------------------------------------
AUD-701 (no LLM observability), AUD-702 (no tool-call audit log) and AUD-703
(no incident path) against the shipped audit fixtures and hand-built contexts.

All three are absence rules: each test pins that the finding names what was
looked for, that generic APM never satisfies AUD-701, and that none of them
fires on a tree with no AI surface.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    EvidenceKind,
    Inventory,
    MatchKind,
    Severity,
    Unit,
)
from aisg.devtools.audit.report import BANNED_PHRASES
from aisg.devtools.audit.rules import run_rules
from aisg.devtools.audit.rules.observability import (
    RULES,
    NoIncidentPath,
    NoLLMObservability,
    NoToolCallAuditLog,
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
BASELINE_FIXTURE = "clean_py"  # the fixture with no AI surface at all


def _run(rule, ctx):
    findings, unknown = run_rules([rule], ctx)
    return findings, unknown


def _ai_unit(root: str = ".") -> Unit:
    return Unit(id="u0", root=root, manifest="pyproject.toml", language="python", ai_surface=True)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_rules_list_is_ordered_and_complete():
    assert [r.id for r in RULES] == ["AUD-701", "AUD-702", "AUD-703"]
    assert RULES == [NoLLMObservability, NoToolCallAuditLog, NoIncidentPath]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    number = rule.id.split("-", 1)[1]
    assert rule.priority == int(number[:-2]) == 7
    assert rule.controls
    for token in rule.controls:
        assert CONTROL_TOKEN.match(token), token
    assert len(rule.recommendation.alternatives) >= 3
    assert any("aisg" not in alt for alt in rule.recommendation.alternatives)
    assert rule.measured_precision is None
    assert set(rule.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule.basis is Basis.ABSENCE
    assert rule.evidence_kind is EvidenceKind.ABSENCE
    assert rule.match_kind is MatchKind.STRUCTURED
    assert rule.requires_ai_surface is True
    assert rule.known_failure_modes


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_empty_context_yields_nothing(rule, tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    instance = rule()
    assert instance.evaluate(ctx) == []
    assert instance.unknown == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_ai_surface_unit_with_none_sections_does_not_raise(rule, tmp_path: Path):
    inventory = Inventory(units=[_ai_unit()])
    ctx = AuditContext(
        root=tmp_path, inventory=inventory, pyfacts=None, options=None, config_facts=None
    )
    findings = rule().evaluate(ctx)
    for finding in findings:
        assert finding.evidence
        assert "\\" not in finding.evidence[0].file


# ---------------------------------------------------------------------------
# AUD-701 No observability on LLM calls
# ---------------------------------------------------------------------------


def test_701_fires_on_py_agent_with_no_tracing(py_agent, audit_context):
    findings, unknown = _run(NoLLMObservability, audit_context(py_agent))
    assert [f.display_id for f in findings] == ["AUD-701"]
    finding = findings[0]
    assert finding.severity is Severity.MEDIUM
    assert finding.bucket is Bucket.ASSERTED
    assert finding.scope.kind == "unit" and finding.scope.unit == "u0"
    assert finding.evidence[0].role == "absence"
    assert finding.evidence[0].file == "." and finding.evidence[0].line == 0
    assert "langfuse" in finding.evidence[0].snippet
    assert not finding.evidence[0].snippet.endswith("...")
    assert "LANGCHAIN_TRACING" in finding.notes and "braintrust" in finding.notes
    assert not [u for u in unknown if "AUD-701" in u.rule_ids]


def test_701_apm_only_is_low_sub_finding_not_silence(audit_fixture, audit_context):
    findings, _ = _run(NoLLMObservability, audit_context(audit_fixture("apm_only")))
    assert [f.display_id for f in findings] == ["AUD-701/apm-only"]
    finding = findings[0]
    assert finding.sub == "apm-only"
    assert finding.severity is Severity.LOW
    assert finding.title == "APM present, LLM call tracing not evident"
    roles = {e.role: e for e in finding.evidence}
    assert roles["match"].file == "agent.py" and roles["match"].line == 10
    assert "sentry" in roles["match"].snippet
    assert roles["absence"].line == 0
    assert (
        finding.fingerprint != NoLLMObservability().absence_finding(unit=None, why="x").fingerprint
    )


def test_701_silent_when_llm_tracing_present(audit_fixture, audit_context):
    findings, _ = _run(NoLLMObservability, audit_context(audit_fixture("info_only")))
    assert findings == []


def test_701_silent_on_baseline_and_skipped_without_ai_surface(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture(BASELINE_FIXTURE))
    assert not any(u.ai_surface for u in ctx.inventory.units)
    assert NoLLMObservability().evaluate(ctx) == []
    findings, _ = run_rules(RULES, ctx)
    assert findings == []


def test_701_generic_apm_alongside_llm_tracing_is_satisfied(tmp_path: Path):
    inventory = Inventory(
        units=[_ai_unit()],
        observability=[
            {"lib": "apm:datadog", "file": "app.py", "line": 3},
            {"lib": "langsmith", "file": "app.py", "line": 4},
        ],
    )
    ctx = AuditContext(root=tmp_path, inventory=inventory)
    assert NoLLMObservability().evaluate(ctx) == []


def test_701_is_per_unit(tmp_path: Path):
    traced = Unit(id="u1", root="svc/traced", manifest=None, language="python", ai_surface=True)
    blind = Unit(id="u2", root="svc/blind", manifest=None, language="python", ai_surface=True)
    plain = Unit(id="u3", root="svc/plain", manifest=None, language="python", ai_surface=False)
    inventory = Inventory(
        units=[blind, traced, plain],
        observability=[{"lib": "langfuse", "file": "svc/traced/app.py", "line": 1}],
    )
    ctx = AuditContext(root=tmp_path, inventory=inventory)
    findings = NoLLMObservability().evaluate(ctx)
    assert [(f.scope.unit, f.evidence[0].file) for f in findings] == [("u2", "svc/blind")]


def test_701_deep_false_gives_same_verdict(py_agent, audit_context):
    deep, _ = _run(NoLLMObservability, audit_context(py_agent, deep=True))
    shallow, _ = _run(NoLLMObservability, audit_context(py_agent, deep=False))
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in shallow]


# ---------------------------------------------------------------------------
# AUD-702 No tool-call audit log
# ---------------------------------------------------------------------------


def test_702_fires_on_py_agent_tools_without_audit_symbol(py_agent, audit_context):
    findings, _ = _run(NoToolCallAuditLog, audit_context(py_agent))
    assert [f.display_id for f in findings] == ["AUD-702"]
    finding = findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.scope.kind == "unit" and finding.scope.unit == "u0"
    snippet = finding.evidence[0].snippet
    assert "3 tool(s)" in snippet
    for name in ("send_email", "fetch_url", "run_shell"):
        assert name in snippet
        assert name in finding.notes
    assert "AuditLogger" in snippet and "record_tool_call" in snippet
    assert "audit.log" in finding.notes and "structlog" in finding.notes
    assert not snippet.endswith("...")


def test_702_silent_when_tool_calls_are_recorded(audit_fixture, audit_context):
    findings, _ = _run(NoToolCallAuditLog, audit_context(audit_fixture("info_only")))
    assert findings == []


def test_702_silent_without_tools(audit_fixture, audit_context):
    for name in (BASELINE_FIXTURE, "apm_only", "noise"):
        findings, _ = _run(NoToolCallAuditLog, audit_context(audit_fixture(name)))
        assert findings == [], name


def test_702_deep_false_still_fires(py_agent, audit_context):
    findings, _ = _run(NoToolCallAuditLog, audit_context(py_agent, deep=False))
    assert [f.display_id for f in findings] == ["AUD-702"]


def test_702_resolves_unit_from_file_when_tool_has_no_unit_key(tmp_path: Path):
    inventory = Inventory(
        units=[_ai_unit()],
        tools=[{"id": "t1", "name": "run_shell", "file": "tools.py", "line": 4}],
    )
    ctx = AuditContext(root=tmp_path, inventory=inventory)
    findings = NoToolCallAuditLog().evaluate(ctx)
    assert len(findings) == 1 and "run_shell" in findings[0].evidence[0].snippet


# ---------------------------------------------------------------------------
# AUD-703 No incident path
# ---------------------------------------------------------------------------


def test_703_fires_on_py_agent_card_without_contact(py_agent, audit_context):
    ctx = audit_context(py_agent)
    assert ctx.inventory.incident_path == []
    assert ctx.inventory.system_card["incident_contact"] is None
    findings, _ = _run(NoIncidentPath, ctx)
    assert [f.display_id for f in findings] == ["AUD-703"]
    finding = findings[0]
    assert finding.severity is Severity.LOW
    assert finding.scope.kind == "repo"
    assert finding.evidence[0].role == "absence"
    assert "SECURITY.md" in finding.evidence[0].snippet
    assert "ai-system-card.yaml has no incident_contact" in finding.evidence[0].snippet
    assert ".github/ISSUE_TEMPLATE/*security*" in finding.notes
    assert len(finding.evidence[0].snippet) <= 160


def test_703_silent_when_security_md_exists(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("info_only"))
    assert ctx.inventory.incident_path == ["SECURITY.md"]
    findings, _ = _run(NoIncidentPath, ctx)
    assert findings == []


def test_703_silent_when_card_names_a_contact(tmp_path: Path):
    inventory = Inventory(
        units=[_ai_unit()],
        system_card={"file": "ai-system-card.yaml", "incident_contact": "oncall@example.test"},
    )
    assert NoIncidentPath().evaluate(AuditContext(root=tmp_path, inventory=inventory)) == []


def test_703_silent_on_baseline(audit_fixture, audit_context):
    assert NoIncidentPath().evaluate(audit_context(audit_fixture(BASELINE_FIXTURE))) == []


def test_703_fires_once_per_repo_not_per_unit(tmp_path: Path):
    units = [
        Unit(id="u1", root="a", manifest=None, language="python", ai_surface=True),
        Unit(id="u2", root="b", manifest=None, language="python", ai_surface=True),
    ]
    ctx = AuditContext(root=tmp_path, inventory=Inventory(units=units))
    findings = NoIncidentPath().evaluate(ctx)
    assert len(findings) == 1
    assert findings[0].evidence[0].file == "."


# ---------------------------------------------------------------------------
# Determinism and honesty
# ---------------------------------------------------------------------------


def test_findings_are_deterministic_across_runs(py_agent, audit_context):
    ctx = audit_context(py_agent)
    first, _ = run_rules(RULES, ctx)
    second, _ = run_rules(RULES, audit_context(py_agent))
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    assert len({f.fingerprint for f in first}) == len(first)


def test_texts_describe_evidence_not_verdicts(py_agent, audit_context):
    banned = BANNED_PHRASES  # assembled from fragments in report.py, never a literal here
    assert len(banned) >= 7
    findings, _ = run_rules(RULES, audit_context(py_agent))
    for rule in RULES:
        blob = " ".join(
            [rule.title, rule.recommendation.summary, *rule.recommendation.alternatives]
        ).lower()
        for phrase in banned:
            assert phrase not in blob, (rule.id, phrase)
    for finding in findings:
        for evidence in finding.evidence:
            assert evidence.snippet.isascii()
            assert not any(p in evidence.snippet.lower() for p in banned)
