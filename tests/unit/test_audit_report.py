"""tests/unit/test_audit_report.py
-------------------------------
Pins for the audit renderers: schema-first JSON, the disclaimer in every format, no
compliance language and never the word the design bans, `[UNMEASURED]` on every
finding, `[REPORTED <age>d, <source>]` on report-derived findings, ASCII terminal
output, the mandatory `below --fail-on` summary line, the exit-code rule, the
section 3.2 summary shape, rule-level blocks printed once per rule id, the quiet
mode's severity and bucket lines, and the baseline line after the count line.

Findings are built by hand. The `rules[]` catalogue always lists the whole registry
(`ran: false` for rules that did not run), so a local `AuditRule` subclass with an id
outside the registry stands in for "the rule that ran" without shadowing a real id.
"""

from __future__ import annotations

import json
import re
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest

from aisg.devtools.audit.baseline import BaselineDiff
from aisg.devtools.audit.html import TEMPLATES as HTML_TEMPLATES
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
    _T_ACCEPTED_REASON,
    _TEMPLATES,
    BANNED_PHRASES,
    DISTRIBUTION,
    SARIF_LEVEL,
    all_templates,
    build_report,
    catalogue,
    check_templates,
    compute_exit_code,
    render,
    summarise,
    to_terminal,
    tool_version,
)
from aisg.devtools.audit.rules import ALL_RULES, AuditRule

FORMATS = ("json", "sarif", "markdown", "terminal", "html")

# The negative-phrase list of section 10 item 1, pinned independently of
# `report.BANNED_PHRASES`. Assembled from fragments so no audit file -- this test
# included -- carries one of the phrases as a contiguous literal.
EXPECTED_BANNED = (
    " ".join(("is", "compliant")),
    " ".join(("compliance", "verified")),
    "certi" + "fied",
    " ".join(("meets", "the", "requirements")),
    " ".join(("fully", "compliant")),
    " ".join(("passes", "the", "eu")),
    " ".join(("nist", "compliant")),
)
# The one word the design bans outright, assembled for the same reason.
CLEAN_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# An id no registry rule uses: the catalogue lists every registry rule, so a test double
# that reused a real id would produce two rows for it.
DUMMY_RULE_ID = "AUD-199"

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
    id = DUMMY_RULE_ID
    title = "Host over-grant (test double)"
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
    # `all_templates()` is what `check_templates` and `--debug` scan: the terminal's
    # strings plus the html renderer's, so a phrase in either is caught.
    assert set(all_templates()) == set(_TEMPLATES) | set(HTML_TEMPLATES)
    for template in all_templates():
        assert not CLEAN_WORD.search(template), template
        assert template.isascii(), template


def test_tool_version_comes_from_package_metadata():
    # DISTRIBUTION, not a literal: the wheel publishes as `aisguard` while the
    # importable name stays `aisg`, and the two must not drift apart again.
    try:
        expected = metadata.version(DISTRIBUTION)
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
    rows = catalogue([DummyRule, OtherRule], ran_ids={DUMMY_RULE_ID})
    assert rows == [
        {
            "id": DUMMY_RULE_ID,
            "title": "Host over-grant (test double)",
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
    diff = BaselineDiff(new=findings[:2], gone=["deadbeef"], unchanged=findings[2:], file="b.json")
    summary = summarise(findings, [], [], [], diff, "low", 1)
    assert summary["baseline_new"] == 2


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------


def test_build_report_pins_trifecta_first_and_fills_blocks():
    report = build()
    assert report.findings[0].id == "AUD-301"
    assert report.tool == {"name": "aisg-audit", "version": tool_version()}
    assert report.target == {
        "path": "C:/work/target",
        "git_sha": "abc123",
        "dirty": False,
        "exclude": [],
    }
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
    assert report.disclaimer == DISCLAIMER


def test_build_report_catalogues_the_whole_registry_plus_the_rule_that_ran():
    """`rules[]` is the registry (design 3.2): a rule that did not run is listed `ran: false`."""
    report = build()
    assert report.rules == catalogue([*ALL_RULES, DummyRule], {DUMMY_RULE_ID})
    ids = [row["id"] for row in report.rules]
    assert len(ids) == len(set(ids)), "one catalogue row per rule id"
    assert set(ids) == {rule.id for rule in ALL_RULES} | {DUMMY_RULE_ID}
    ran = {row["id"] for row in report.rules if row["ran"]}
    assert ran == {DUMMY_RULE_ID}
    assert all(row["measured_precision"] is None for row in report.rules)
    assert all(row["experimental"] is False for row in report.rules)


def test_build_report_lists_a_registry_rule_that_ran_once():
    """Passing a real registry rule as `rules` flips its row to `ran: true`, adding nothing."""
    real = ALL_RULES[0]
    report = build(rules=[real])
    assert [row["id"] for row in report.rules] == [rule.id for rule in ALL_RULES]
    assert {row["id"] for row in report.rules if row["ran"]} == {real.id}


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


def test_own_output_skipped_is_one_line_in_every_rendered_format():
    """
    The walk records the audit's own earlier output it skipped; every page says so on one
    line, `none` included, so a tree that holds a stale report is never silently thinner.
    """
    report = build()
    report.inventory.own_output_skipped = ["audit-report.json", "out/audit.html"]
    for fmt in ("terminal", "markdown", "html"):
        text = render(report, fmt)
        assert text.count("own output skipped: audit-report.json, out/audit.html") == 1, fmt
    assert json.loads(render(report, "json"))["inventory"]["own_output_skipped"] == [
        "audit-report.json",
        "out/audit.html",
    ]
    # SARIF has no inventory block, so the list rides in the run's property bag next to
    # the schema marker -- never at the root, which admits no extra keys.
    sarif = json.loads(render(report, "sarif"))
    assert set(sarif) == {"$schema", "version", "runs"}
    assert sarif["runs"][0]["properties"]["own_output_skipped"] == [
        "audit-report.json",
        "out/audit.html",
    ]
    report.inventory.own_output_skipped = []
    for fmt in ("terminal", "markdown", "html"):
        assert render(report, fmt).count("own output skipped: none") == 1, fmt
    assert json.loads(render(report, "sarif"))["runs"][0]["properties"]["own_output_skipped"] == []


def test_sarif_own_output_skipped_is_always_present():
    # A report read back from disk may carry no inventory at all; the key is still there
    # and empty, so a consumer never has to guess whether the walk recorded nothing or
    # the renderer dropped it.
    report = build()
    report.inventory = None
    props = json.loads(render(report, "sarif"))["runs"][0]["properties"]
    assert list(props)[:2] == ["aisg_schema", "own_output_skipped"]
    assert props["own_output_skipped"] == []


def test_sarif_run_property_bag_is_the_first_key_of_the_run():
    """
    The walker decides "own output" from the head of a file. With the bag after
    `results`, a SARIF written into the tree was past the head and got scanned like any
    other file, reproducing its own findings. The root stays exactly the three keys the
    2.1.0 schema allows.
    """
    text = render(build(), "sarif")
    doc = json.loads(text)
    assert list(doc) == ["$schema", "version", "runs"]
    run = doc["runs"][0]
    assert list(run) == ["properties", "tool", "results"]
    assert list(run["properties"])[:2] == ["aisg_schema", "own_output_skipped"]
    # Textual order too: `json.dumps` keeps dict order, and the marker must sit before
    # the first result in the bytes the walker reads.
    assert text.index('"aisg_schema"') < text.index('"results"')


def test_sarif_written_into_the_tree_is_skipped_by_the_walker(tmp_path: Path):
    """Both ends together: the renderer's SARIF, written to disk, is recognised by the
    walker as the audit's own output, under either extension."""
    from aisg.devtools.audit.walk import walk

    text = render(build(), "sarif")
    for name in (".aisg-audit/audit.sarif", "out/audit.json"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    skipped: list[str] = []

    records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

    assert [r.relpath for r in records] == ["app.py"]
    assert sorted(skipped) == [".aisg-audit/audit.sarif", "out/audit.json"]
    assert unknown == []


def test_oversize_count_is_one_inventory_line_in_every_rendered_format():
    """
    The walk hands the caller the paths it never opened; the caller records the count on
    `target.oversize_files` next to `skipped_files`. Every page prints it. A document
    without the key says so instead of claiming zero.
    """
    report = build()
    report.inventory.target["oversize_files"] = 2
    for fmt in ("terminal", "markdown", "html"):
        assert render(report, fmt).count("oversize files skipped: 2") == 1, fmt
    assert json.loads(render(report, "json"))["inventory"]["target"]["oversize_files"] == 2
    # SARIF has no inventory block: the count rides in the run bag after the two marker
    # keys, which keep their pinned order.
    props = json.loads(render(report, "sarif"))["runs"][0]["properties"]
    assert list(props)[:3] == ["aisg_schema", "own_output_skipped", "oversize_files"]
    assert props["oversize_files"] == 2
    report.inventory.target["oversize_files"] = 0
    for fmt in ("terminal", "markdown", "html"):
        assert render(report, fmt).count("oversize files skipped: 0") == 1, fmt
    assert json.loads(render(report, "sarif"))["runs"][0]["properties"]["oversize_files"] == 0
    del report.inventory.target["oversize_files"]
    for fmt in ("terminal", "markdown", "html"):
        assert render(report, fmt).count("oversize files skipped: not recorded") == 1, fmt
    assert json.loads(render(report, "sarif"))["runs"][0]["properties"]["oversize_files"] is None
    report.inventory = None
    assert json.loads(render(report, "sarif"))["runs"][0]["properties"]["oversize_files"] is None


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
    with pytest.raises(ValueError, match="pdf"):
        render(build(), "pdf")


def test_render_dispatches_html():
    page = render(build(), "html")
    assert page.splitlines()[0] == "<!-- # aisg-audit: ignore-file -->"
    assert page.isascii()


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_shape_levels_and_properties():
    report = build()
    doc = json.loads(render(report, "sarif"))
    # The `aisg/1` marker is the first key of every other document; the SARIF
    # root allows no extra keys (Code Scanning rejects the upload), so it
    # rides in the run's property bag instead.
    assert set(doc) == {"$schema", "version", "runs"}
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["properties"]["aisg_schema"] == "aisg/1"
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
        "recommendation",
    }
    # `recommendation.package` rides along so a Code Scanning consumer sees what the
    # package can wire; the shape is `Recommendation.to_dict()`.
    for result in run["results"]:
        package = result["properties"]["recommendation"]["package"]
        assert set(package) >= {"mechanism", "symbols", "same_control", "leaves_open"}
        assert isinstance(package["symbols"], list)
    assert first["properties"]["recommendation"]["package"]["mechanism"] == "none"
    assert "accepted_reason" not in first["properties"]
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


def test_sarif_has_no_nulls_where_the_schema_wants_an_object_or_string():
    """
    What `codeql-action/upload-sarif` validates strictly: no extra root key,
    every `region.snippet` an object, every `helpUri`/`help.text` a string.
    An optional field is omitted, never `null`.
    """
    doc = json.loads(render(build(), "sarif"))
    for run in doc["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            assert isinstance(rule["shortDescription"]["text"], str)
            if "helpUri" in rule:
                assert isinstance(rule["helpUri"], str)
            if "help" in rule:
                assert isinstance(rule["help"]["text"], str)
        for result in run["results"]:
            assert isinstance(result["message"]["text"], str)
            for loc in result.get("locations", []) + result.get("relatedLocations", []):
                region = loc["physicalLocation"]["region"]
                assert region["startLine"] >= 1
                assert isinstance(region["snippet"], dict)
                assert isinstance(region["snippet"]["text"], str)


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
        "own output skipped: none",
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


def test_terminal_quiet_keeps_severity_and_bucket_lines_without_finding_detail():
    """A CI log must say what kind of evidence the count rests on, but never a finding."""
    text = to_terminal(build(), quiet=True)
    lines = text.splitlines()
    count_at = next(i for i, ln in enumerate(lines) if ln.startswith("7 findings ("))
    assert lines[count_at + 1] == "severity: critical 3, high 3, medium 0, low 0, info 1"
    assert (
        lines[count_at + 2] == "buckets: MEASURED 1 | ASSERTED 6 (of which REPORTED 1) | UNKNOWN 2"
    )
    for marker in (
        "scope:",
        "fix (",
        "alternatives",
        "controls:",
        "known failure modes",
        "[match]",
    ):
        assert marker not in text, marker
    assert "[UNMEASURED]" not in text
    assert not any(ln.startswith("[#") for ln in lines)
    # Every line in quiet mode is one the full renderer prints too.
    full_lines = set(to_terminal(build()).splitlines())
    assert set(lines) <= full_lines


# ---------------------------------------------------------------------------
# rule-level blocks once per rule id
# ---------------------------------------------------------------------------

ALTERNATIVES_LINE = "alternatives: aisg ToolPolicyGuard; NeMo Guardrails; LLM Guard"
FAILURE_MODES_LINE = "known failure modes: scope over-approximates in monorepos; grep tier"
CONTROLS_LINE = "controls: ASI01, EU:Art.9"
SEE_FIRST = "alternatives / controls / known failure modes: see the first AUD-101 above"


def two_of_the_same_rule() -> list[Finding]:
    return [
        make_finding("AUD-101", line=3, snippet="permissions.allow: Bash(*)"),
        make_finding("AUD-101", line=4, snippet="permissions.allow: WebFetch"),
    ]


def test_terminal_prints_rule_blocks_once_and_references_them_after():
    text = render(build(two_of_the_same_rule()), "terminal")
    assert text.count(ALTERNATIVES_LINE) == 1
    assert text.count(FAILURE_MODES_LINE) == 1
    assert text.count(CONTROLS_LINE) == 1
    assert text.count(SEE_FIRST) == 1
    # The blocks sit under the first finding, the reference under the second.
    first = text.index("permissions.allow: Bash(*)")
    second = text.index("permissions.allow: WebFetch")
    assert first < text.index(ALTERNATIVES_LINE) < second < text.index(SEE_FIRST)
    # The per-finding lines stay per finding.
    assert text.count("fix (T1): fix for AUD-101") == 2
    assert text.count("scope: file services/agent/app.py") == 2
    assert text.count("[UNMEASURED]") == 2


def test_terminal_reference_appears_once_across_every_kind():
    """every_kind() carries AUD-501 twice and five other rules once: six full blocks, one reference."""
    report = build()
    distinct = len({f.id for f in report.findings})
    assert distinct == 6
    text = render(report, "terminal")
    assert text.count(ALTERNATIVES_LINE) == distinct
    assert text.count(FAILURE_MODES_LINE) == distinct
    assert text.count("see the first ") == 1
    assert "see the first AUD-501 above" in text


def test_markdown_anchors_the_first_occurrence_and_links_the_rest():
    text = render(build(two_of_the_same_rule()), "markdown")
    assert text.count('<a id="aud-101"></a>') == 1
    assert text.count("see the first [AUD-101](#aud-101) above") == 1
    assert text.count(ALTERNATIVES_LINE) == 1
    assert text.count(FAILURE_MODES_LINE) == 1
    assert text.count(CONTROLS_LINE) == 1
    anchored = next(ln for ln in text.splitlines() if 'id="aud-101"' in ln)
    assert anchored.startswith('- <a id="aud-101"></a>**AUD-101** ')
    # A rule with a single finding gets no anchor: nothing links to it.
    single = render(build([make_finding("AUD-101")]), "markdown")
    assert "<a id=" not in single and "see the first" not in single


def test_reference_names_the_display_id_of_the_first_finding_of_the_rule():
    """Sub-findings share their rule's blocks; the reference points at the display id printed."""
    findings = [
        make_finding("AUD-107", sub="inert", severity=Severity.HIGH, line=1),
        make_finding("AUD-107", severity=Severity.MEDIUM, line=2),
    ]
    term = render(build(findings), "terminal")
    assert "see the first AUD-107/inert above" in term
    assert term.count(ALTERNATIVES_LINE) == 1
    md = render(build(findings), "markdown")
    assert '<a id="aud-107-inert"></a>**AUD-107/inert**' in md
    assert "see the first [AUD-107/inert](#aud-107-inert) above" in md


def test_a_block_that_differs_from_the_first_is_printed_in_full():
    """A reference never hides a difference: only identical blocks fold."""
    first, second = two_of_the_same_rule()
    second.recommendation = Recommendation(
        tier=Tier.T2, summary="different fix", alternatives=("x", "y", "z")
    )
    second.known_failure_modes = ("something else",)
    for fmt in ("terminal", "markdown"):
        text = render(build([first, second]), fmt)
        assert text.count(ALTERNATIVES_LINE) == 1, fmt
        assert "alternatives: x; y; z" in text, fmt
        assert "known failure modes: something else" in text, fmt
        assert text.count(CONTROLS_LINE) == 1, fmt
        assert "controls: see the first " in text, fmt
        assert "alternatives / controls" not in text, fmt


def test_first_finding_of_a_rule_never_carries_a_reference():
    text = render(build([make_finding("AUD-101")]), "terminal")
    assert "see the first" not in text
    assert ALTERNATIVES_LINE in text and FAILURE_MODES_LINE in text and CONTROLS_LINE in text


def test_reference_line_is_a_renderer_template():
    assert any("see the first" in t for t in _TEMPLATES)
    assert any('<a id="' in t for t in _TEMPLATES)


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


# ---------------------------------------------------------------------------
# baseline
# ---------------------------------------------------------------------------

BASELINE_LINE = "baseline: 6 new, 1 unchanged, 1 no longer reported (audit-baseline.json)"
GONE = "0123456789abcdef"


def with_baseline() -> Report:
    """every_kind() diffed against a baseline: AUD-1002 unchanged, six new, one gone."""
    findings = every_kind()
    diff = BaselineDiff(
        file="audit-baseline.json", gone=[GONE], no_longer_reported=[{"fingerprint": GONE}]
    )
    for finding in findings:
        finding.baseline_status = "unchanged" if finding.id == "AUD-1002" else "new"
        (diff.unchanged if finding.baseline_status == "unchanged" else diff.new).append(finding)
    return build(findings, baseline=diff)


def test_baseline_block_and_tags_render():
    report = with_baseline()
    # The counts, plus whatever else `BaselineDiff.to_dict()` carries (accepted reasons,
    # the baseline's stamp, the named fingerprints): renderers read it with `.get`. There is
    # no count for the gone fingerprints: `no_longer_reported` is the list and the number.
    assert report.baseline["file"] == "audit-baseline.json"
    assert (report.baseline["new"], report.baseline["unchanged"]) == (6, 1)
    assert "fixed" not in report.baseline
    assert report.baseline.get("accepted") == []
    assert report.baseline.get("no_longer_reported") == [{"fingerprint": GONE}]
    assert report.summary["baseline_new"] == 6
    text = render(report, "terminal")
    assert BASELINE_LINE in text
    assert text.count("[baseline: new]") == 6
    assert text.count("[baseline: unchanged]") == 1
    doc = json.loads(render(report, "json"))
    assert doc["baseline"] == report.baseline
    assert list(doc["baseline"])[:4] == ["file", "kind", "new", "unchanged"]
    assert {f["baseline_status"] for f in doc["findings"]} == {"new", "unchanged"}


def test_baseline_block_without_the_new_keys_still_renders():
    """A report read back from disk may carry a bare block; every renderer copes."""
    report = with_baseline()
    report.baseline = {"file": "audit-baseline.json", "new": 6, "unchanged": 1}
    for fmt in FORMATS:
        text = render(report, fmt)
        assert text
        # Terminal and html are the ASCII-only renderers; markdown and json pass snippets through.
        if fmt in ("terminal", "html"):
            assert text.isascii(), fmt
    bare = "baseline: 6 new, 1 unchanged, 0 no longer reported (audit-baseline.json)"
    assert bare in render(report, "terminal")
    assert bare in render(report, "markdown")
    assert bare in render(report, "html")


def test_no_renderer_calls_an_absent_fingerprint_fixed():
    """A rename or a move produces the same absence, so no format uses the past participle."""
    report = with_baseline()
    for fmt in FORMATS:
        text = render(report, fmt).lower()
        assert ("fix" + "ed") not in text, fmt
        assert BASELINE_LINE in text or fmt in ("json", "sarif"), fmt


@pytest.mark.parametrize("quiet", [False, True])
def test_baseline_line_follows_the_count_line_in_both_terminal_modes(quiet: bool):
    text = to_terminal(with_baseline(), quiet=quiet)
    lines = text.splitlines()
    count_at = next(i for i, ln in enumerate(lines) if ln.startswith("7 findings ("))
    assert lines[count_at + 1] == BASELINE_LINE
    assert lines[count_at + 2].startswith("severity: ")
    assert lines[count_at + 3].startswith("buckets: ")
    assert text.count(BASELINE_LINE) == 1
    # The per-finding marks belong to full mode only; quiet prints no finding line.
    assert text.count("[baseline: new]") == (0 if quiet else 6)
    assert text.count("[baseline: unchanged]") == (0 if quiet else 1)


def test_baseline_line_precedes_findings_in_markdown():
    text = render(with_baseline(), "markdown")
    assert text.count(BASELINE_LINE) == 1
    assert text.index("7 findings (") < text.index(BASELINE_LINE) < text.index("## Findings")
    assert text.count("[baseline: new]") == 6
    assert text.count("[baseline: unchanged]") == 1


def test_no_baseline_line_without_a_baseline():
    for quiet in (False, True):
        assert "baseline:" not in to_terminal(build(), quiet=quiet)
    assert "baseline:" not in render(build(), "markdown")


def test_accepted_reason_is_shown_on_the_finding_in_terminal_and_markdown():
    """
    The reason is why an unchanged finding is not counted; a reader of the rendered page
    should not have to open the baseline file to learn it. Findings without one carry no
    `accepted:` line at all.
    """
    reason = "read-only stub, approval wired in the caller"
    report = with_baseline()
    unchanged = next(f for f in report.findings if f.baseline_status == "unchanged")
    unchanged.accepted_reason = reason
    line = "accepted: " + reason
    assert _T_ACCEPTED_REASON in _TEMPLATES
    for fmt in ("terminal", "markdown"):
        text = render(report, fmt)
        assert text.count(line) == 1, fmt
        assert text.count("accepted: ") == 1, fmt
        # The reason closes the finding's own detail block: the fix line of the same
        # finding (the nearest `scope:` above) precedes it.
        at = text.index(line)
        block = text[text.rindex("scope: ", 0, at) : at]
        assert "fix (" in block and unchanged.display_id in text[: text.rindex("scope: ", 0, at)]
    assert line not in to_terminal(report, quiet=True)
    doc = json.loads(render(report, "json"))
    assert [f["accepted_reason"] for f in doc["findings"] if f.get("accepted_reason")] == [reason]
    sarif = json.loads(render(report, "sarif"))
    accepted = [r for r in sarif["runs"][0]["results"] if "accepted_reason" in r["properties"]]
    assert [r["properties"]["accepted_reason"] for r in accepted] == [reason]
    for fmt in ("terminal", "markdown"):
        assert "accepted: " not in render(build(), fmt), fmt
