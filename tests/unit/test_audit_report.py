"""tests/unit/test_audit_report.py
-------------------------------
Pins for the audit renderers: schema-first JSON, the disclaimer in every format, no
compliance language and never the word the design bans, `[UNMEASURED]` on every
finding, `[REPORTED <age>d, <source>]` on report-derived findings, ASCII terminal
output, the mandatory `below --fail-on` summary line, the exit-code rule and the
section 3.2 summary shape.

Findings are built by hand: the rule registry is empty in this wave, so a local
`AuditRule` subclass stands in for the catalogue.
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest

from aisg.devtools.audit.baseline import BaselineDiff
from aisg.devtools.audit.model import (
    DISCLAIMER,
    AuditContext,
    Basis,
    Bucket,
    Confidence,
    Evidence,
    EvidenceKind,
    ExternalToolResult,
    Finding,
    Inventory,
    MatchKind,
    Recommendation,
    Report,
    ReportRecord,
    Scope,
    Severity,
    Status,
    Tier,
    UnknownItem,
)
from aisg.devtools.audit.report import (
    _TEMPLATES,
    BANNED_PHRASES,
    SARIF_LEVEL,
    build_report,
    catalogue,
    check_templates,
    compute_exit_code,
    render,
    summarise,
    to_terminal,
    tool_version,
)
from aisg.devtools.audit.rules import AuditRule

FORMATS = ("json", "sarif", "markdown", "terminal")

# The negative-phrase list of section 10 item 1. This tuple is the one place a test may
# spell the phrases out.
EXPECTED_BANNED = (
    "is compliant",
    "compliance verified",
    "certified",
    "meets the requirements",
    "fully compliant",
    "passes the eu",
    "nist compliant",
)
CLEAN_WORD = re.compile(r"\bclean\b", re.IGNORECASE)

REPORT_BLOCK = {
    "file": "measure-report.json",
    "schema": "aisg/1",
    "generated_at": None,
    "age_source": "mtime",
    "age_days": 41,
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-101",
    *,
    severity: Severity | str = Severity.CRITICAL,
    priority: int = 1,
    bucket: Bucket | str = Bucket.ASSERTED,
    basis: Basis | str = Basis.PRESENCE,
    file: str = "services/agent/app.py",
    line: int = 12,
    snippet: str = 'permissions: {"allow": ["Bash(*)"]}',
    role: str = "match",
    sub: str | None = None,
    precision: float | None = None,
    evidence_kind: EvidenceKind | str = EvidenceKind.CODE,
    match_kind: MatchKind | str = MatchKind.GREP,
    report: dict[str, Any] | None = None,
    notes: str | None = None,
    gitignored: bool = False,
    title: str | None = None,
    scope: Scope | None = None,
) -> Finding:
    return Finding(
        id=rule_id,
        sub=sub,
        title=title or f"title for {rule_id}",
        severity=severity,
        priority=priority,
        bucket=bucket,
        basis=basis,
        confidence=Confidence(evidence_kind, match_kind, precision),
        scope=scope or Scope(kind="file", unit="u1", name=file),
        evidence=[Evidence(role=role, file=file, line=line, snippet=snippet)],
        controls=("ASI01", "EU:Art.9"),
        recommendation=Recommendation(
            tier=Tier.T1,
            summary=f"fix for {rule_id}",
            alternatives=("aisg ToolPolicyGuard", "NeMo Guardrails", "LLM Guard"),
        ),
        related_lint_rules=("EU-AIA-012a",),
        known_failure_modes=("scope over-approximates in monorepos", "grep tier"),
        report=report,
        notes=notes,
        gitignored=gitignored,
    )


def every_kind() -> list[Finding]:
    """One finding of every kind the renderers must handle; AUD-301 deliberately last."""
    return [
        make_finding("AUD-101", snippet="allow: Bash(*) caf\u00e9"),
        make_finding(
            "AUD-107",
            sub="inert",
            severity=Severity.HIGH,
            priority=1,
            snippet="GUARDRAILS_DISABLE_ALL: bool = False",
        ),
        make_finding(
            "AUD-803",
            severity=Severity.HIGH,
            priority=8,
            evidence_kind=EvidenceKind.REPORT,
            match_kind=MatchKind.STRUCTURED,
            file="measure-report.json",
            line=0,
            snippet="prompt_injection false_positive_rate 0.14",
            report=dict(REPORT_BLOCK),
        ),
        make_finding(
            "AUD-501",
            severity=Severity.CRITICAL,
            priority=5,
            bucket=Bucket.MEASURED,
            precision=0.95,
            evidence_kind=EvidenceKind.TOOL_OUTPUT,
            match_kind=MatchKind.EXTERNAL,
            file="secrets.py",
            line=1,
            snippet="ANTHROPIC_API_KEY = <redacted:...xxxx>",
        ),
        make_finding(
            "AUD-1002",
            severity=Severity.INFO,
            priority=10,
            file="ai-system-card.yaml",
            line=4,
            snippet="risk_tier: unknown",
            notes="Risk tier is a legal determination made by the operator.",
        ),
        make_finding(
            "AUD-501",
            severity=Severity.HIGH,
            priority=5,
            file=".env",
            line=2,
            snippet="OPENAI_API_KEY=<redacted:...abcd>",
            gitignored=True,
        ),
        make_finding(
            "AUD-301",
            severity=Severity.CRITICAL,
            priority=3,
            match_kind=MatchKind.AST,
            file="services/agent/app.py",
            line=52,
            snippet='rows = db.execute("select * from customers")',
            role="private",
            scope=Scope(kind="function", unit="u1", name="services/agent/app.py::handle"),
        ),
    ]


class DummyRule(AuditRule):
    id = "AUD-101"
    title = "Host over-grant"
    priority = 1
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    controls = ("ASI01",)
    recommendation = Recommendation(tier=Tier.T1, summary="narrow", alternatives=("a", "b", "c"))
    tier = Tier.T1


class OtherRule(DummyRule):
    id = "AUD-701"
    title = "No observability"


def make_ctx() -> AuditContext:
    inventory = Inventory(
        target={"path": "C:\\work\\target", "git_sha": "abc123", "dirty": False},
        languages={"python": 3},
        llm_calls=[{"file": "app.py"}],
        tools=[{"name": "send_email"}],
        mcp={"configs": [".mcp.json"], "servers": [{"name": "fs"}]},
        hosts=[{"host": "claude"}],
    )
    return AuditContext(root=Path("C:/work/target"), inventory=inventory)


def unknown_items() -> list[UnknownItem]:
    return [
        UnknownItem(
            category="tools",
            what="secret scanning corroboration",
            why="gitleaks not on PATH",
            how_to_resolve="install gitleaks and re-run",
            rule_ids=("AUD-501",),
        ),
        UnknownItem(
            category="deep", what="deep analysis of 1 file", why="SyntaxError", file="x.py"
        ),
    ]


def external_results() -> list[ExternalToolResult]:
    return [
        ExternalToolResult(
            name="gitleaks",
            status=Status.RAN,
            network=False,
            version="8.18.4",
            duration_ms=640,
            findings=1,
            argv=("gitleaks", "detect", "--no-git"),
        ),
        ExternalToolResult(name="pip-audit", status=Status.NOT_ON_PATH, network=True),
        ExternalToolResult(
            name="promptfoo", status=Status.SKIPPED_NEEDS_FLAG, network=True, flag="--run-evals"
        ),
    ]


def report_records() -> list[ReportRecord]:
    return [
        ReportRecord(
            kind="measure",
            file="measure-report.json",
            schema="aisg/1",
            age_source="mtime",
            age_days=41,
            body={
                "guards": {
                    "prompt_injection": {
                        "catch_rate": 0.4375,
                        "false_positive_rate": 0.14,
                        "threshold_failures": ["false_positive_rate"],
                        "p99_ms": 12.0,
                    }
                }
            },
        ),
        ReportRecord(
            kind="probe",
            file="probe-report.json",
            schema="aisg/1",
            age_source="git",
            age_days=12,
            body={"summary": {"sent": 48, "passed": 40, "failed": 3, "errors": 2}},
        ),
    ]


def build(
    findings: list[Finding] | None = None,
    *,
    fail_on: str = "low",
    unknown: list[UnknownItem] | None = None,
    baseline: BaselineDiff | None = None,
    rules: list[type[AuditRule]] | None = None,
) -> Report:
    findings = every_kind() if findings is None else findings
    unknown = unknown_items() if unknown is None else unknown
    code = compute_exit_code(findings, unknown, fail_on=fail_on)
    return build_report(
        make_ctx(),
        findings,
        unknown,
        external_results(),
        report_records(),
        baseline,
        rules=[DummyRule] if rules is None else rules,
        fail_on=fail_on,
        exit_code=code,
    )


def outputs(report: Report) -> dict[str, str]:
    return {fmt: render(report, fmt) for fmt in FORMATS}


# ---------------------------------------------------------------------------
# constants and self-check
# ---------------------------------------------------------------------------


def test_banned_phrases_match_the_design_list():
    assert BANNED_PHRASES == EXPECTED_BANNED
    assert all(p == p.lower() for p in BANNED_PHRASES)


def test_templates_carry_no_banned_phrase_and_no_clean():
    assert check_templates() == []
    assert DISCLAIMER in _TEMPLATES
    for template in _TEMPLATES:
        assert not CLEAN_WORD.search(template), template


def test_tool_version_comes_from_package_metadata():
    try:
        expected = metadata.version("ai-safety-guardrails")
    except metadata.PackageNotFoundError:
        expected = "unknown"
    assert tool_version() == expected


def test_sarif_level_map():
    assert SARIF_LEVEL[Severity.CRITICAL] == "error"
    assert SARIF_LEVEL[Severity.HIGH] == "error"
    assert SARIF_LEVEL[Severity.MEDIUM] == "warning"
    assert SARIF_LEVEL[Severity.LOW] == "note"
    assert SARIF_LEVEL[Severity.INFO] == "note"


def test_catalogue_uses_attribute_values_and_ran_flags():
    rows = catalogue([DummyRule, OtherRule], ran_ids={"AUD-101"})
    assert rows == [
        {
            "id": "AUD-101",
            "title": "Host over-grant",
            "measured_precision": None,
            "ran": True,
            "experimental": False,
        },
        {
            "id": "AUD-701",
            "title": "No observability",
            "measured_precision": None,
            "ran": False,
            "experimental": False,
        },
    ]


# ---------------------------------------------------------------------------
# exit code and summary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "fail_on", "expected"),
    [
        (Severity.MEDIUM, "high", 0),
        (Severity.HIGH, "high", 1),
        (Severity.CRITICAL, "never", 0),
        (Severity.INFO, "low", 0),
        (Severity.LOW, "low", 1),
    ],
)
def test_compute_exit_code_threshold(severity, fail_on, expected):
    finding = make_finding(severity=severity)
    assert compute_exit_code([finding], [], fail_on=fail_on) == expected


def test_compute_exit_code_fail_on_unknown_by_category():
    deep_only = [UnknownItem(category="deep", what="ts taint", why="python only")]
    tools = deep_only + [UnknownItem(category="tools", what="pip-audit", why="not on PATH")]
    assert compute_exit_code([], deep_only, fail_on="low", fail_on_unknown={"tools"}) == 0
    assert compute_exit_code([], tools, fail_on="low", fail_on_unknown={"tools"}) == 1
    assert compute_exit_code([], tools, fail_on="low", fail_on_unknown=None) == 0
    assert compute_exit_code([], tools, fail_on="low", fail_on_unknown=set()) == 0


def test_compute_exit_code_ignores_unchanged_baseline_findings():
    finding = make_finding(severity=Severity.CRITICAL)
    finding.baseline_status = "unchanged"
    assert compute_exit_code([finding], [], fail_on="low") == 0
    finding.baseline_status = "new"
    assert compute_exit_code([finding], [], fail_on="low") == 1


def test_compute_exit_code_rejects_unknown_level():
    with pytest.raises(ValueError):
        compute_exit_code([], [], fail_on="loud")


def test_summarise_shape_and_order():
    findings = every_kind()
    summary = summarise(
        findings, unknown_items(), external_results(), report_records(), None, "high", 1
    )
    assert list(summary) == [
        "findings",
        "by_severity",
        "by_bucket",
        "reported",
        "below_threshold",
        "fail_on",
        "unknown_items",
        "unknown_by_category",
        "exit_code",
        "top",
        "suppressed",
        "baseline_new",
    ]
    assert list(summary["by_severity"]) == ["critical", "high", "medium", "low", "info"]
    assert list(summary["by_bucket"]) == ["measured", "asserted", "unknown"]
    assert list(summary["unknown_by_category"]) == ["tools", "deep", "reports", "runtime"]
    assert summary["findings"] == 7
    assert summary["by_severity"] == {"critical": 3, "high": 3, "medium": 0, "low": 0, "info": 1}
    assert summary["by_bucket"] == {"measured": 1, "asserted": 6, "unknown": 0}
    assert summary["reported"] == 1
    assert summary["below_threshold"] == 1  # the info finding, under fail_on high
    assert summary["fail_on"] == "high"
    assert summary["unknown_items"] == 2
    assert summary["unknown_by_category"] == {"tools": 1, "deep": 1, "reports": 0, "runtime": 0}
    assert summary["exit_code"] == 1
    assert summary["top"] == findings[0].display_id
    assert summary["suppressed"] == 0
    assert summary["baseline_new"] is None


def test_summarise_by_bucket_measured_counts_adapter_findings_only():
    report = build()
    assert report.summary["by_bucket"]["measured"] == 1
    measured = [f for f in report.findings if f.bucket is Bucket.MEASURED]
    assert [f.id for f in measured] == ["AUD-501"]
    assert measured[0].confidence.precision == 0.95


def test_summarise_with_baseline_reports_new_count():
    findings = every_kind()
    diff = BaselineDiff(new=findings[:2], fixed=["deadbeef"], unchanged=findings[2:], file="b.json")
    summary = summarise(findings, [], [], [], diff, "low", 1)
    assert summary["baseline_new"] == 2


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------


def test_build_report_pins_trifecta_first_and_fills_blocks():
    report = build()
    assert report.findings[0].id == "AUD-301"
    assert report.tool == {"name": "aisg-audit", "version": tool_version()}
    assert report.target == {"path": "C:/work/target", "git_sha": "abc123", "dirty": False}
    assert report.measured == [
        {
            "source": "gitleaks",
            "status": "ran",
            "version": "8.18.4",
            "duration_ms": 640,
            "findings": 1,
            "network": False,
        }
    ]
    assert report.baseline is None
    assert report.rules == catalogue([DummyRule], {"AUD-101"})
    assert report.disclaimer == DISCLAIMER


def test_build_report_extracts_reports_per_kind():
    report = build()
    measure, probe = report.reports
    assert measure["source"] == "measure-report.json"
    assert measure["age_source"] == "mtime" and measure["age_days"] == 41
    assert measure["guards"] == {
        "prompt_injection": {
            "catch_rate": 0.4375,
            "false_positive_rate": 0.14,
            "threshold_failures": ["false_positive_rate"],
        }
    }
    assert probe["source"] == "probe-report.json"
    assert probe["summary"] == {"sent": 48, "passed": 40, "failed": 3, "errors": 2}


def test_build_report_tolerates_malformed_report_bodies():
    records = [
        ReportRecord(kind="measure", file="m.json", schema="aisg/1", body={"guards": "nope"}),
        ReportRecord(kind="probe", file="p.json", schema="aisg/1", body={"summary": [1, 2]}),
        ReportRecord(kind="measure", file="n.json", schema="aisg/1", body={}),
    ]
    report = build_report(
        make_ctx(), [], [], [], records, None, rules=[], fail_on="low", exit_code=0
    )
    assert [r["guards"] for r in report.reports if "guards" in r] == [{}, {}]
    assert [r["summary"] for r in report.reports if "summary" in r] == [{}]


def test_build_report_can_omit_inventory():
    report = build_report(
        make_ctx(),
        [],
        [],
        [],
        [],
        None,
        rules=[],
        fail_on="low",
        exit_code=0,
        inventory_included=False,
    )
    assert report.inventory is None
    assert json.loads(render(report, "json"))["inventory"] == {}
    assert "(not included)" in render(report, "terminal")


# ---------------------------------------------------------------------------
# renderer invariants across formats
# ---------------------------------------------------------------------------


def test_json_schema_is_first_key():
    doc = json.loads(render(build(), "json"))
    assert list(doc)[0] == "schema"
    assert doc["schema"] == "aisg/1"
    assert doc["kind"] == "audit"
    assert doc["findings"][0]["id"] == "AUD-301"
    assert doc["rules"][0]["measured_precision"] is None


def test_disclaimer_present_in_every_format():
    out = outputs(build())
    sentence = "Not an assessment of compliance with any regulation"
    assert json.loads(out["json"])["disclaimer"] == DISCLAIMER
    sarif = json.loads(out["sarif"])
    assert sarif["runs"][0]["properties"]["disclaimer"] == DISCLAIMER
    assert sentence in out["markdown"]
    assert sentence in out["terminal"]
    assert out["markdown"].splitlines()[0] == "# aisg audit"
    assert out["markdown"].splitlines()[2].startswith("> ")


def test_no_banned_phrase_and_never_clean_in_any_format():
    for fmt, text in outputs(build()).items():
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, (fmt, phrase)
        assert not CLEAN_WORD.search(text), fmt


def test_target_snippet_with_banned_word_does_not_trip_the_self_check():
    snippet = "# " + "certi" + "fied"
    report = build([make_finding(snippet=snippet)])
    for fmt in FORMATS:
        assert snippet in render(report, fmt)
    assert check_templates() == []


def test_sub_finding_renders_with_its_slash_id():
    out = outputs(build())
    assert "AUD-107/inert" in out["markdown"]
    assert "AUD-107/inert" in out["terminal"]
    assert any(f["id"] == "AUD-107/inert" for f in json.loads(out["json"])["findings"])
    sarif = json.loads(out["sarif"])
    assert "AUD-107/inert" in {r["ruleId"] for r in sarif["runs"][0]["results"]}


def test_render_rejects_unknown_format():
    with pytest.raises(ValueError):
        render(build(), "html")


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_shape_levels_and_properties():
    report = build()
    doc = json.loads(render(report, "sarif"))
    assert list(doc)[0] == "schema" and doc["schema"] == "aisg/1"
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "aisg-audit"
    assert driver["version"] == tool_version()
    by_id = {r["id"]: r for r in driver["rules"]}
    assert by_id["AUD-101"]["properties"]["measured_precision"] is None
    assert by_id["AUD-101"]["properties"]["bucket"] == "asserted"
    assert by_id["AUD-101"]["properties"]["tier"] == "T1"
    assert "AUD-107/inert" in by_id  # a sub-finding gets its own rule entry
    results = {(r["ruleId"], r["properties"]["severity"]): r for r in run["results"]}
    assert results[("AUD-301", "critical")]["level"] == "error"
    assert results[("AUD-107/inert", "high")]["level"] == "error"
    assert results[("AUD-1002", "info")]["level"] == "note"
    first = run["results"][0]
    assert first["ruleId"] == "AUD-301"
    assert first["message"]["text"].startswith("[UNMEASURED] ")
    assert first["partialFingerprints"] == {"aisgFingerprint/v1": report.findings[0].fingerprint}
    location = first["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "services/agent/app.py"
    assert location["region"]["startLine"] == 52
    assert first["properties"]["bucket"] == "asserted"
    assert first["properties"]["confidence"]["label"] == "UNMEASURED"
    assert set(first["properties"]) >= {
        "severity",
        "priority",
        "bucket",
        "basis",
        "confidence",
        "scope",
        "sub",
        "report",
        "gitignored",
        "baseline_status",
    }
    assert run["properties"]["summary"]["findings"] == 7
    assert [u["category"] for u in run["properties"]["unknown"]] == ["tools", "deep"]
    assert [t["name"] for t in run["properties"]["external_tools"]] == [
        "gitleaks",
        "pip-audit",
        "promptfoo",
    ]


def test_sarif_measured_finding_and_zero_line_absence():
    doc = json.loads(render(build(), "sarif"))
    results = {(r["ruleId"], r["properties"]["bucket"]): r for r in doc["runs"][0]["results"]}
    measured = results[("AUD-501", "measured")]
    assert measured["message"]["text"].startswith("[MEASURED] ")
    assert measured["properties"]["confidence"]["precision"] == 0.95
    reported = results[("AUD-803", "asserted")]
    assert reported["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert reported["properties"]["report"]["age_days"] == 41
    gitignored = [r for r in doc["runs"][0]["results"] if r["properties"]["gitignored"]]
    assert len(gitignored) == 1 and gitignored[0]["ruleId"] == "AUD-501"


# ---------------------------------------------------------------------------
# Markdown and terminal
# ---------------------------------------------------------------------------


def test_unmeasured_tag_appears_once_per_unmeasured_finding():
    report = build()
    unmeasured = sum(1 for f in report.findings if f.confidence.precision is None)
    assert unmeasured == 6
    for fmt in ("markdown", "terminal"):
        text = render(report, fmt)
        assert text.count("[UNMEASURED]") == unmeasured, fmt
        assert text.count("[MEASURED p=0.95]") == 1, fmt


def test_reported_tag_and_asserted_bucket_on_report_derived_finding():
    report = build()
    for fmt in ("markdown", "terminal"):
        text = render(report, fmt)
        line = next(ln for ln in text.splitlines() if "[REPORTED 41d, mtime]" in ln)
        assert "AUD-803" in line and "asserted" in line
    doc = json.loads(render(report, "json"))
    (entry,) = [f for f in doc["findings"] if f["id"] == "AUD-803"]
    assert entry["bucket"] == "asserted"
    assert entry["confidence"]["evidence_kind"] == "report"
    assert entry["report"] == REPORT_BLOCK


def test_reported_tag_without_age():
    block = dict(REPORT_BLOCK, age_days=None, age_source="unknown")
    report = build([make_finding("AUD-903", severity=Severity.MEDIUM, priority=9, report=block)])
    for fmt in ("markdown", "terminal"):
        assert "[REPORTED age unknown]" in render(report, fmt), fmt


def test_markdown_order_and_finding_detail_lines():
    text = render(build(), "markdown")
    order = [
        "# aisg audit",
        "> ",
        "7 findings (",
        "| MEASURED | 1 |",
        "| ASSERTED | 6 (of which REPORTED 1) |",
        "| UNKNOWN |",
        "## Findings",
        "### Pinned",
        "### P1",
        "### P5",
        "### P8",
        "### P10",
        "## UNKNOWN",
        "## External tools",
        "| gitleaks | ran | no | 8.18.4 | gitleaks detect --no-git |",
        "| pip-audit | not_on_path | yes | - | - |",
        "## Inventory",
        "units: 0",
        "languages: 1 (python 3)",
        "llm_calls: 1",
        "tools: 1",
        "mcp servers: 1",
        "hosts: 1",
    ]
    position = -1
    for needle in order:
        found = text.find(needle, position + 1)
        assert found > position, needle
        position = found
    assert "services/agent/app.py:52: rows = db.execute" in text
    assert "fix (T1): fix for AUD-301" in text
    assert "alternatives: aisg ToolPolicyGuard; NeMo Guardrails; LLM Guard" in text
    assert "controls: ASI01, EU:Art.9" in text
    assert "known failure modes: scope over-approximates in monorepos; grep tier" in text
    assert "[tools] secret scanning corroboration: gitleaks not on PATH" in text
    assert "resolve: install gitleaks and re-run" in text
    assert "rules: AUD-501" in text
    assert "file: x.py" in text
    assert "(gitignored)" in text


def test_legal_determination_note_is_rendered():
    for fmt in ("markdown", "terminal"):
        text = render(build(), fmt)
        assert "legal determination" in text, fmt


def test_terminal_is_ascii_with_every_kind_present():
    text = render(build(), "terminal")
    assert text.isascii()
    assert "\\xe9" in text  # the non-ASCII snippet char was escaped, not dropped
    assert max(len(line) for line in text.splitlines()) <= 100
    assert "[#####]" in text and "[#....]" in text  # critical and info bars
    findings_block = text.split("\nUNKNOWN\n")[0]
    assert "AUD-301" in findings_block
    assert findings_block.index("AUD-301") < findings_block.index("AUD-101")


def test_terminal_summary_line_is_verbatim():
    report = build(fail_on="high")
    text = render(report, "terminal")
    assert "7 findings (1 below --fail-on high, not counted in exit code); 2 unknown items" in text
    assert "exit code: 1" in text


def test_terminal_quiet_prints_disclaimer_summary_unknown_and_tools_only():
    text = to_terminal(build(), quiet=True)
    assert "Not an assessment of compliance with any regulation" in text
    assert "7 findings (" in text
    assert "UNKNOWN" in text and "gitleaks not on PATH" in text
    assert "External tools" in text and "pip-audit" in text
    assert "Findings" not in text
    assert "Inventory" not in text
    assert "AUD-301" not in text
    assert text.isascii()


def test_zero_findings_still_prints_unknown_and_disclaimer():
    report = build([])
    assert report.summary["findings"] == 0 and report.summary["top"] is None
    out = outputs(report)
    assert (
        "0 findings (0 below --fail-on low, not counted in exit code); 2 unknown items"
        in out["terminal"]
    )
    assert (
        "0 findings (0 below --fail-on low, not counted in exit code); 2 unknown items"
        in out["markdown"]
    )
    for fmt, text in out.items():
        assert "gitleaks not on PATH" in text, fmt
        assert not CLEAN_WORD.search(text), fmt
    assert "Not an assessment of compliance with any regulation" in out["terminal"]
    assert "## UNKNOWN" in out["markdown"]
    assert "(none)" in out["markdown"]  # the empty findings list is explicit, never silent


def test_empty_unknown_list_is_explicit():
    report = build([], unknown=[])
    md = render(report, "markdown")
    assert md.split("## UNKNOWN")[1].split("## External tools")[0].strip() == "(none)"
    term = render(report, "terminal")
    assert "UNKNOWN\n-------\n(none)" in term


def test_info_only_exits_zero_but_stays_a_finding():
    finding = make_finding(
        "AUD-1002",
        severity=Severity.INFO,
        priority=10,
        file="ai-system-card.yaml",
        line=4,
        snippet="risk_tier: unknown",
        notes="Risk tier is a legal determination made by the operator.",
    )
    assert compute_exit_code([finding], unknown_items(), fail_on="low") == 0
    report = build([finding], fail_on="low")
    assert report.summary["exit_code"] == 0
    assert report.summary["below_threshold"] == 1
    assert report.summary["findings"] == 1
    out = outputs(report)
    assert "1 finding (1 below --fail-on low, not counted in exit code)" in out["terminal"]
    assert "1 below --fail-on low" in out["markdown"]
    assert json.loads(out["json"])["summary"]["below_threshold"] == 1
    for fmt, text in out.items():
        assert not CLEAN_WORD.search(text), fmt


def test_baseline_block_and_tags_render():
    findings = every_kind()
    diff = BaselineDiff(file="audit-baseline.json")
    for finding in findings:
        finding.baseline_status = "unchanged" if finding.id == "AUD-1002" else "new"
        (diff.unchanged if finding.baseline_status == "unchanged" else diff.new).append(finding)
    diff.fixed = ["0123456789abcdef"]
    report = build(findings, baseline=diff)
    assert report.baseline == {"file": "audit-baseline.json", "new": 6, "fixed": 1, "unchanged": 1}
    assert report.summary["baseline_new"] == 6
    text = render(report, "terminal")
    assert "baseline audit-baseline.json: 6 new, 1 fixed, 1 unchanged" in text
    assert text.count("[baseline: new]") == 6
    assert text.count("[baseline: unchanged]") == 1
    doc = json.loads(render(report, "json"))
    assert doc["baseline"] == report.baseline
    assert {f["baseline_status"] for f in doc["findings"]} == {"new", "unchanged"}
