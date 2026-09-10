"""tests/unit/test_audit_html.py
-----------------------------
Pins for the html renderer: the ignore marker on line 1, ASCII end to end whatever
the target contained, the disclaimer and the UNKNOWN count before the first figure,
every box drawn with its three numbers and `[UNMEASURED]` at zero findings too, no
severity name and no `--good` token in the figure, UNKNOWN placement, the
"no longer reported" wording, document 2 sections only with a baseline, the package
line variants, the plan's `who` column, the caps, the catalogue's `ran` flag, byte
identity, the rules-did-not-run banner, the dispatch, and the templates self-check.

Findings are built by hand with a fixed `generated_at`, so nothing here depends on the
clock or on the registry beyond `subsystem_of`.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from aisg.devtools.audit import html as html_mod
from aisg.devtools.audit.baseline import BaselineDiff
from aisg.devtools.audit.html import TEMPLATES, render_html
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
    Package,
    Recommendation,
    Report,
    Scope,
    Severity,
    Status,
    Tier,
    Unit,
    UnknownItem,
)
from aisg.devtools.audit.report import (
    BANNED_PHRASES,
    FORMATS,
    all_templates,
    build_report,
    check_templates,
    compute_exit_code,
    render,
)
from aisg.devtools.audit.rules import NOT_ATTRIBUTED, SUBSYSTEMS, AuditRule, subsystem_of

MARKER = "<!-- # aisg-audit: ignore-file -->"
ABSENCE = "Absence of a finding is not evidence of safety."
GENERATED_AT = "2026-09-06T12:00:00Z"
# The word the design bans outright and the past participle the html must never use
# for a fingerprint that is absent, both assembled so this file carries neither.
CLEAN_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)
FIXED_WORD = re.compile(r"\bfix" + r"ed\b", re.IGNORECASE)
DUMMY_RULE_ID = "AUD-199"

GATE = Package("gate", ("ToolPolicyGuard",), True, "the approval prompt itself")
DETECTOR = Package("detector", ("PromptInjectionGuard",), False, "the sandbox boundary")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-101",
    *,
    severity: Severity | str = Severity.CRITICAL,
    file: str = "services/agent/app.py",
    line: int = 12,
    snippet: str = 'permissions: {"allow": ["Bash(*)"]}',
    unit: str | None = "u1",
    package: Package | None = None,
    summary: str | None = None,
    sub: str | None = None,
    title: str | None = None,
    notes: str | None = None,
    baseline_status: str | None = None,
    accepted_reason: str | None = None,
    scope_kind: str = "file",
) -> Finding:
    return Finding(
        id=rule_id,
        sub=sub,
        title=title or f"title for {rule_id}",
        severity=severity,
        priority=int(rule_id.split("-")[1][0]),
        bucket=Bucket.ASSERTED,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP, None),
        scope=Scope(kind=scope_kind, unit=unit, name=file),
        evidence=[Evidence(role="match", file=file, line=line, snippet=snippet)],
        controls=("ASI01",),
        recommendation=Recommendation(
            tier=Tier.T1,
            summary=summary or f"fix for {rule_id}",
            alternatives=("a", "b"),
            package=package or Package("none"),
        ),
        baseline_status=baseline_status,
        accepted_reason=accepted_reason,
        notes=notes,
    )


class DummyRule(AuditRule):
    id = DUMMY_RULE_ID
    title = "test double"
    priority = 1
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    controls = ("ASI01",)
    recommendation = Recommendation(tier=Tier.T1, summary="narrow", alternatives=("a", "b"))
    tier = Tier.T1


def make_inventory(**overrides: Any) -> Inventory:
    fields: dict[str, Any] = dict(
        target={"path": "C:\\work\\target", "git_sha": "abc123", "dirty": False},
        units=[
            Unit(id="u1", root="services/agent", manifest="pyproject.toml", language="python"),
            Unit(id="u2", root="web", manifest="package.json", language="typescript"),
        ],
        languages={"python": 3, "typescript": 1},
        llm_calls=[{"file": "app.py", "line": 3, "provider": "anthropic", "sdk": "anthropic"}],
        models=[{"model": "claude-3-5", "pinned": False, "file": "app.py", "line": 4}],
        tools=[
            {"name": "send_email", "file": "app.py", "line": 20},
            {"name": "db_write", "file": "app.py", "line": 30},
            {"name": "deploy", "file": "app.py", "line": 40},
        ],
        mcp={"configs": [".mcp.json"], "servers": [{"name": "fs", "file": ".mcp.json"}]},
        hosts=[{"host": "claude", "file": ".claude/settings.json"}],
        secrets={"literal_hits": 1, "config_hits": 0, "scanner": "aisg"},
        loops=[{"file": "app.py", "line": 50, "capped": False}],
        own_output_skipped=["audit-report.json"],
    )
    fields.update(overrides)
    return Inventory(**fields)


def build(
    findings: list[Finding] | None = None,
    *,
    unknown: list[UnknownItem] | None = None,
    baseline: BaselineDiff | None = None,
    rules: list[type[AuditRule]] | None = None,
    inventory: Inventory | None = None,
    inventory_included: bool = True,
    fail_on: str = "low",
) -> Report:
    findings = [make_finding()] if findings is None else findings
    unknown = [] if unknown is None else unknown
    ctx = AuditContext(root=Path("C:/work/target"), inventory=inventory or make_inventory())
    code = compute_exit_code(findings, unknown, fail_on=fail_on)
    report = build_report(
        ctx,
        findings,
        unknown,
        [ExternalToolResult(name="gitleaks", status=Status.NOT_ON_PATH, network=False)],
        [],
        baseline,
        rules=[DummyRule] if rules is None else rules,
        fail_on=fail_on,
        exit_code=code,
        inventory_included=inventory_included,
    )
    report.generated_at = GENERATED_AT
    return report


def svg_of(page: str) -> str:
    start, end = page.index("<svg"), page.index("</svg>")
    return page[start:end]


def before_svg(page: str) -> str:
    return page[: page.index("<svg")]


def box_line(page: str, title: str) -> str:
    """The three-number status line under one map box, by the box title."""
    svg = svg_of(page)
    idx = svg.index(f">{title}<")
    tail = svg[idx:]
    m = re.search(r">(reported \d+ \| UNKNOWN \d+)<", tail)
    assert m, title
    rules = re.search(r">(rules ran \d+/\d+)<", tail)
    assert rules, title
    return f"{m.group(1)} | {rules.group(1)}"


def with_baseline(
    *,
    accepted: list[dict[str, Any]] | None = None,
    generated_at: str | None = "2026-09-01T12:00:00Z",
    no_longer_reported: list[dict[str, Any]] | None = None,
    gone: list[str] | None = None,
    new: list[Finding] | None = None,
    kind: str | None = "audit-baseline",
) -> BaselineDiff:
    return BaselineDiff(
        file="audit-baseline.json",
        kind=kind,
        new=list(new or []),
        gone=["0123456789abcdef"] if gone is None else gone,
        accepted=accepted or [],
        generated_at=generated_at,
        no_longer_reported=(
            [
                {
                    "fingerprint": "0123456789abcdef",
                    "rule": "AUD-101",
                    "file": "old.py:1",
                    "title": "old title",
                }
            ]
            if no_longer_reported is None
            else no_longer_reported
        ),
    )


# ---------------------------------------------------------------------------
# document shape
# ---------------------------------------------------------------------------


def test_line_one_is_the_ignore_marker_then_a_standalone_document():
    page = render_html(build())
    lines = page.splitlines()
    assert lines[0] == MARKER
    assert lines[1] == "<!doctype html>"
    assert '<html lang="en">' in page
    assert '<meta charset="utf-8">' in page
    assert '<meta name="aisg-schema" content="aisg/1">' in page
    assert re.search(r'<meta name="aisg-tool" content="aisguard [^"]+">', page)
    assert "<title>" in page and "<style>" in page
    assert "<script" not in page
    assert 'src="' not in page and 'href="http' not in page and "@import" not in page
    assert page.endswith("</html>\n")


def test_ascii_end_to_end_with_a_hostile_reason_and_snippet():
    reason = 'because <script>alert(1)</script> & caf\u00e9 "quoted" \u2192'
    finding = make_finding(snippet="allow: Bash(*) caf\u00e9 <b>", accepted_reason=reason)
    page = render_html(build([finding], baseline=with_baseline()))
    assert page.isascii()
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert "&amp; caf&#xe9;" in page
    assert "&#x2192;" in page
    assert "&quot;quoted&quot;" in page
    assert "Bash(*) caf&#xe9; &lt;b&gt;" in page


def test_read_this_first_precedes_the_figure():
    unknown = [UnknownItem(category="deep", what="deep analysis of 1 file", why="SyntaxError")]
    page = render_html(build(unknown=unknown))
    head = before_svg(page)
    assert DISCLAIMER in head
    assert ABSENCE in head
    assert "UNKNOWN: 1 item the audit could not establish" in head
    # The pointer names the section the items are listed in, and that section exists.
    section = re.search(r"listed in section (\d+)", head).group(1)
    assert f'<h2 id="unknown">{section}. UNKNOWN</h2>' in page
    assert ABSENCE in page[page.index("<footer>") :]


def test_first_survey_header_and_resolved_options():
    page = render_html(build(fail_on="high"))
    assert "Document 1 of 2" in page
    assert "Compared against: none -- this is the first survey" in page
    assert "commit abc123 -- uncommitted changes: no -- generated 2026-09-06T12:00:00Z" in page
    assert "fail-on: high" in page
    assert "Since the baseline" not in page
    assert "Remaining actions" not in page


# ---------------------------------------------------------------------------
# the map
# ---------------------------------------------------------------------------


def test_every_box_is_drawn_with_three_numbers_and_unmeasured():
    page = render_html(build([]))
    svg = svg_of(page)
    assert svg.count("<rect ") == len(SUBSYSTEMS) + 1
    assert svg.count("[UNMEASURED]") == len(SUBSYSTEMS) + 1
    for sub in SUBSYSTEMS:
        assert re.fullmatch(
            r"reported 0 \| UNKNOWN 0 \| rules ran \d+/\d+", box_line(page, sub.title)
        )
    assert "UNKNOWN not attributed to a rule: 0 | reported 0 | rules ran" in svg
    assert 'stroke-dasharray="7 5"' in svg
    assert svg.count("var(--warn)") == 1


def test_zero_findings_says_reported_zero_and_no_surface_is_a_fact_about_the_inventory():
    page = render_html(build([], inventory=Inventory(target={"path": "t"})))
    assert "reported 0" in svg_of(page)
    assert "no surface found" in svg_of(page)
    assert "no surface found" in page[page.index('<h2 id="subsystems">') :]
    assert "(inventory not included)" not in page


def test_inventory_absent_is_said_not_hidden():
    page = render_html(build([], inventory_included=False))
    assert svg_of(page).count("(inventory not included)") == len(SUBSYSTEMS)
    assert "no surface found" not in page


def test_no_severity_name_and_no_good_token_anywhere():
    findings = [
        make_finding("AUD-101", severity=Severity.CRITICAL),
        make_finding("AUD-501", severity=Severity.HIGH, file="secrets.py"),
        make_finding("AUD-1002", severity=Severity.INFO, file="ai-system-card.yaml"),
    ]
    page = render_html(build(findings))
    svg = svg_of(page).lower()
    for name in ("critical", "high", "medium", "low", "info"):
        assert not re.search(rf"\b{name}\b", svg), name
    assert "--good" not in page
    style = page[page.index("<style>") : page.index("</style>")]
    assert "%" not in style


def test_unknown_items_land_on_the_rule_box_or_the_not_attributed_box():
    unknown = [
        UnknownItem(category="tools", what="secret corroboration", why="x", rule_ids=("AUD-501",)),
        UnknownItem(category="deep", what="deep analysis of 1 file", why="SyntaxError"),
        UnknownItem(category="runtime", what="nothing ran", why="y"),
    ]
    page = render_html(build([], unknown=unknown))
    secrets_title = next(s.title for s in SUBSYSTEMS if s.key == subsystem_of("AUD-501"))
    assert box_line(page, secrets_title).startswith("reported 0 | UNKNOWN 1")
    assert "UNKNOWN not attributed to a rule: 2 |" in svg_of(page)
    assert "UNKNOWN: 3 items the audit could not establish" in page
    # Every item is listed in the UNKNOWN section, resolve text included.
    tail = page[page.index('<h2 id="unknown">') :]
    assert "[tools] secret corroboration: x" in tail
    assert "[runtime] nothing ran: y" in tail


def test_findings_are_placed_by_subsystem_and_the_box_counts_them():
    findings = [make_finding("AUD-101"), make_finding("AUD-101", line=13), make_finding("AUD-501")]
    page = render_html(build(findings))
    runtime_title = next(s.title for s in SUBSYSTEMS if s.key == subsystem_of("AUD-101"))
    secrets_title = next(s.title for s in SUBSYSTEMS if s.key == subsystem_of("AUD-501"))
    assert box_line(page, runtime_title).startswith("reported 2 | UNKNOWN 0")
    assert box_line(page, secrets_title).startswith("reported 1 | UNKNOWN 0")


def test_a_finding_of_an_unknown_rule_goes_to_the_not_attributed_section():
    assert subsystem_of(DUMMY_RULE_ID) == NOT_ATTRIBUTED
    page = render_html(build([make_finding(DUMMY_RULE_ID)]))
    assert "UNKNOWN not attributed to a rule: 0 | reported 1 |" in svg_of(page)
    assert 'id="sec-not_attributed"' in page


def test_rules_ran_reflects_the_catalogue():
    class Ran(DummyRule):
        id = "AUD-701"

    report = build([], rules=[Ran])
    page = render_html(report)
    key = subsystem_of("AUD-701")
    title = next(s.title for s in SUBSYSTEMS if s.key == key)
    # The catalogue is the source: the registry's own AUD-701 row is flagged `ran` too
    # (same id), so the expected count is read from `report.rules`, not typed in.
    rows = [row for row in report.rules if subsystem_of(row["id"]) == key]
    expected_k = sum(1 for row in rows if row["ran"])
    assert expected_k >= 1
    assert box_line(page, title).endswith(f"rules ran {expected_k}/{len(rows)}")
    for sub in SUBSYSTEMS:
        if sub.title != title:
            assert re.search(r"rules ran 0/\d+", box_line(page, sub.title)), sub.title
    ran, total_all = re.search(r"(\d+) of (\d+) rules ran", page).groups()
    assert int(ran) == sum(1 for row in report.rules if row["ran"])
    assert int(total_all) == len(report.rules) >= 46


def test_box_facts_come_from_the_inventory():
    page = render_html(build([]))
    svg = svg_of(page)
    # Three tools do not fit the box with two names, so the line keeps one whole name
    # and counts the rest; a single entry drops the count; secrets use the short form.
    assert "3 tools: send_email, +2" in svg
    assert "models: claude-3-5 (unpinned)" in svg
    assert "loops: loop (no cap found)" in svg
    assert "secrets: 1 literal, 0 config" in svg
    assert "hosts: claude" in svg
    for line in re.findall(r'class="svgf">(.*?)<', svg):
        assert len(line) <= html_mod._BOX_FACT_WIDTH, line
    # The section under the map is not clipped: every tool, with its location.
    section = section_of(page, "tools")
    assert "tools: send_email -- app.py:20" in section
    assert "tools: deploy -- app.py:40" in section
    assert "secrets: 1 literal hit in code, 0 in config" in page


def test_byte_identical_on_two_renders():
    report = build()
    assert render_html(report) == render_html(report)
    assert render_html(report) == render_html(build())


# ---------------------------------------------------------------------------
# sections, package lines, plan
# ---------------------------------------------------------------------------


def section_of(page: str, key: str) -> str:
    start = page.index(f'id="sec-{key}"')
    rest = page[start:]
    end = re.search(r'<h3 id="sec-|<h2 id="', rest[10:])
    return rest[: end.start() + 10] if end else rest


def test_section_facts_cap_at_eight_with_a_pointer_to_the_json():
    tools = [{"name": f"tool{i}", "file": "app.py", "line": i + 1} for i in range(12)]
    page = render_html(build([], inventory=make_inventory(tools=tools)))
    section = section_of(page, "tools")
    assert section.count("tools: tool") == html_mod.MAX_FACTS
    # The tools subsystem also owns the mcp servers key: 12 tools + 1 server, 8 shown.
    assert "+5 more in the JSON" in section
    assert "tools: tool0 -- app.py:1" in section
    assert "mcp servers: fs" not in section


def test_findings_cap_at_twelve_per_section():
    findings = [make_finding("AUD-101", line=i) for i in range(15)]
    page = render_html(build(findings))
    section = section_of(page, subsystem_of("AUD-101"))
    assert section.count('<article class="finding"') == html_mod.MAX_FINDINGS_PER_SECTION
    assert "+3 more in the JSON" in section
    # The plan still lists all fifteen.
    plan = page[page.index('<h2 id="plan">') : page.index('<h2 id="unknown">')]
    assert plan.count("<tr><td>") == 15


def test_finding_head_carries_severity_bucket_and_unmeasured():
    page = render_html(build([make_finding("AUD-101", severity=Severity.HIGH)]))
    assert "AUD-101 title for AUD-101 -- high ASSERTED [UNMEASURED]" in page
    assert "[match] services/agent/app.py:12" in page


def test_package_line_same_control():
    page = render_html(build([make_finding("AUD-201", package=GATE)]))
    assert (
        "aisg: ToolPolicyGuard -- implements the control this rule asks for. "
        "Leaves open: the approval prompt itself" in page
    )
    assert "Python-only" not in page
    assert "needs your approval" not in page


def test_package_line_other_control():
    page = render_html(build([make_finding("AUD-201", package=DETECTOR)]))
    assert (
        "aisg: PromptInjectionGuard -- a different control (detector), in addition to, "
        "not instead of: the sandbox boundary" in page
    )


def test_package_line_none_names_the_control_outside_the_package():
    page = render_html(build([make_finding("AUD-201", summary="sandbox the tool")]))
    assert "outside the package: sandbox the tool" in page
    assert "aisg: " not in page[page.index('<h2 id="subsystems">') : page.index('<h2 id="plan">')]


def test_package_line_python_only_note_on_a_typescript_unit():
    finding = make_finding("AUD-201", package=GATE, unit="u2", file="web/agent.ts")
    page = render_html(build([finding]))
    assert "aisg controls are Python-only; the control still applies, this symbol does not." in page


def test_package_line_python_only_note_falls_back_to_the_extension():
    finding = make_finding("AUD-201", package=GATE, unit=None, file="cmd/agent.go")
    page = render_html(build([finding]))
    assert "aisg controls are Python-only" in page
    unknown_ext = make_finding("AUD-201", package=GATE, unit=None, file="config/agent.yaml")
    assert "aisg controls are Python-only" not in render_html(build([unknown_ext]))


def test_package_line_protected_path_needs_approval():
    finding = make_finding("AUD-101", package=GATE, file=".claude/settings.json", line=3)
    page = render_html(build([finding]))
    assert "this edit needs your approval of the specific diff" in page


def test_accepted_reason_is_rendered_verbatim_and_a_move_is_named():
    finding = make_finding("AUD-101", accepted_reason="sandboxed at the OS level")
    entry = {
        "fingerprint": finding.fingerprint,
        "rule": "AUD-101",
        "file": "old/app.py:12",
        "reason": "sandboxed at the OS level",
    }
    page = render_html(build([finding], baseline=with_baseline(accepted=[entry])))
    assert "Operator-recorded reason: sandboxed at the OS level" in page
    assert "recorded at old/app.py:12, now reported at services/agent/app.py:12" in page
    same = dict(entry, file="services/agent/app.py:12")
    page2 = render_html(build([finding], baseline=with_baseline(accepted=[same])))
    assert "now reported at" not in page2


def plan_cells(page: str, end: str = '<h2 id="remaining">') -> list[list[str]]:
    """The plan table's body rows as cell lists; the header row is checked separately."""
    plan = page[page.index('<h2 id="plan">') : page.index(end)]
    rows = re.findall(r"<tr>(.*?)</tr>", plan)
    return [re.findall(r"<td>(.*?)</td>", row) for row in rows[1:]]


def test_plan_who_column():
    findings = [
        make_finding("AUD-201", package=GATE),
        make_finding("AUD-201", package=GATE, unit="u2", file="web/agent.ts"),
        make_finding("AUD-101", package=GATE, file=".claude/settings.json", line=3),
        make_finding("AUD-201", package=DETECTOR),
        make_finding("AUD-201"),
        make_finding("AUD-501", accepted_reason="known"),
    ]
    page = render_html(build(findings, baseline=with_baseline()))
    plan = page[page.index('<h2 id="plan">') : page.index('<h2 id="remaining">')]
    header = re.findall(r"<tr>(.*?)</tr>", plan)[0]
    for col in ("#", "id", "severity", "subsystem", "control", "tier", "aisg", "who", "status"):
        assert f"<th>{col}</th>" in header
    cells = plan_cells(page)
    assert len(cells) == 6
    by_row = [(row[6], row[7], row[8]) for row in cells]
    assert ("PromptInjectionGuard (other control)", "you", "-") in by_row
    assert ("ToolPolicyGuard (same control)", "you, approval needed", "-") in by_row
    assert ("ToolPolicyGuard (same control)", "you", "-") in by_row  # typescript unit
    assert ("ToolPolicyGuard (same control)", "package", "-") in by_row
    assert ("none", "you", "accepted") in by_row
    assert (
        "Rows the package can implement (walk the table top-down; do not skip a row above)" in plan
    )
    package_rows = re.findall(
        r"#(\d+) AUD-201 title for AUD-201 -- ToolPolicyGuard\. Leaves open: the approval prompt itself",
        plan,
    )
    # Exactly one row is the package's to implement: the python unit on an open path.
    assert len(package_rows) == 1
    numbered = [row for row in cells if row[7] == "package"]
    assert [row[0] for row in numbered] == package_rows
    assert (
        "Wiring a control is not evidence the finding is gone: re-run the audit and read document 2."
        in plan
    )


def test_plan_who_is_decided_by_the_file_extension_before_the_unit():
    # The idiom is offered for the file, not the unit: a `.ts` file in a Python-rooted
    # unit cannot import aisg, a `.py` file under a package.json can.
    inventory = make_inventory(
        units=[
            Unit(id="u0", root=".", manifest="pyproject.toml", language="python"),
            Unit(id="u1", root="services/agent", manifest="pyproject.toml", language="python"),
            Unit(id="u2", root="web", manifest="package.json", language="typescript"),
        ]
    )
    ts_in_python = make_finding("AUD-201", package=GATE, unit="u1", file="services/agent/hook.ts")
    py_in_typescript = make_finding("AUD-201", package=GATE, unit="u2", file="web/tool.py")
    repo_scoped = make_finding(
        "AUD-201", package=GATE, unit=None, file="pyproject.toml", scope_kind="repo"
    )
    no_extension = make_finding("AUD-201", package=GATE, unit="u1", file="services/agent/a.yaml")
    # Languages the walker knows and a private copy of its table once did not: a `.rs`
    # or `.java` file inside the Python-rooted unit was called Python and handed to the
    # package. The table is `patterns.LANG_BY_EXT` now, so both are `you`.
    rs_in_python = make_finding("AUD-201", package=GATE, unit="u1", file="services/agent/hook.rs")
    java_in_python = make_finding(
        "AUD-201", package=GATE, unit="u1", file="services/agent/Hook.java"
    )
    findings = [
        ts_in_python,
        py_in_typescript,
        repo_scoped,
        no_extension,
        rs_in_python,
        java_in_python,
    ]
    page = render_html(build(findings, inventory=inventory))
    # The report orders the rows itself, so read `who` back by the row's anchor.
    who = {}
    for row in plan_cells(page, end='<h2 id="unknown">'):
        fingerprint = re.search(r'href="#f-([0-9a-f]+)"', row[1]).group(1)
        who[fingerprint] = row[7]
    assert len(who) == 6
    assert who[ts_in_python.fingerprint] == "you"
    assert who[py_in_typescript.fingerprint] == "package"
    # A repo scope with no useful extension falls back to the root unit's language.
    assert who[repo_scoped.fingerprint] == "package"
    # A config-typed extension falls back to the unit's language.
    assert who[no_extension.fingerprint] == "package"
    assert who[rs_in_python.fingerprint] == "you"
    assert who[java_in_python.fingerprint] == "you"
    blocks = page[page.index('<h2 id="subsystems">') : page.index('<h2 id="plan">')]
    assert blocks.count("aisg controls are Python-only") == 3
    for finding in (rs_in_python, java_in_python):
        block = blocks[blocks.index(f'id="f-{finding.fingerprint}"') :]
        block = block[: block.index("</article>")]
        assert "aisg controls are Python-only" in block
    package_rows = page[page.index("Rows the package can implement") : page.index("Wiring a")]
    for finding in (rs_in_python, java_in_python, ts_in_python):
        assert finding.fingerprint not in package_rows


def test_language_of_uses_the_walkers_table_not_a_copy():
    # Every language the walker names is a language here too, except `config`, which
    # says nothing about what the file can import and falls through to the unit.
    from aisg.devtools.audit.patterns import LANG_BY_EXT

    assert not hasattr(html_mod, "_LANG_BY_EXT")
    languages = {"u1": "python", html_mod.ROOT_UNIT_ID: "python"}
    for ext, lang in LANG_BY_EXT.items():
        finding = make_finding("AUD-201", package=GATE, unit="u1", file=f"services/agent/a{ext}")
        got = html_mod._language_of(finding, languages)
        assert got == ("python" if lang == "config" else lang), ext
    # Case-insensitive on the extension, with the exact spelling tried first.
    upper = make_finding("AUD-201", package=GATE, unit="u1", file="services/agent/A.RS")
    assert html_mod._language_of(upper, languages) == "rust"
    for ext in (".java", ".kt", ".rs", ".rb", ".cs"):
        finding = make_finding("AUD-201", package=GATE, unit="u1", file=f"services/agent/a{ext}")
        assert html_mod._who(finding, html_mod._language_of(finding, languages), False) == "you"


def test_an_accepted_finding_is_not_package_work_and_not_open():
    accepted = make_finding("AUD-201", package=GATE, accepted_reason="approval is manual today")
    # A different snippet: fingerprints ignore line numbers, so the line alone would not
    # tell the two rows apart.
    open_one = make_finding("AUD-201", package=GATE, line=20, snippet="tools=[deploy]")
    assert open_one.fingerprint != accepted.fingerprint
    page = render_html(build([accepted, open_one], baseline=with_baseline()))
    cells = plan_cells(page)
    assert [(row[7], row[8]) for row in cells] == [("package", "accepted"), ("package", "-")]
    plan = page[page.index('<h2 id="plan">') : page.index('<h2 id="remaining">')]
    listed = re.findall(r"<li>#(\d+) AUD-201", plan)
    assert listed == ["2"]
    since = page[page.index('<h2 id="since">') : page.index('<h2 id="map">')]
    assert "1 open row in the plan" in since
    tail = page[page.index('<h2 id="remaining">') : page.index('<h2 id="unknown">')]
    package_group = tail[tail.index("Package control wired") : tail.index("Accepted with")]
    assert package_group.count("<li>") == 1
    assert f'href="#f-{open_one.fingerprint}"' in package_group
    assert f'href="#f-{accepted.fingerprint}"' not in package_group
    accepted_group = tail[tail.index("Accepted with") : tail.index("Still UNKNOWN")]
    assert f'href="#f-{accepted.fingerprint}"' in accepted_group
    assert "the operator wrote: approval is manual today" in accepted_group


def test_box_facts_clip_wide_characters_by_cell_and_stay_ascii():
    cjk = "\u65e5\u672c\u8a9e"  # three wide glyphs, six cells
    wide = cjk * 8  # 24 glyphs, 48 cells: wider than the box
    page = render_html(build([], inventory=make_inventory(tools=[{"name": wide, "file": "a.py"}])))
    assert page.isascii()
    assert "&#x65e5;" in svg_of(page)
    lines = re.findall(r'class="svgf">(.*?)<', svg_of(page))
    line = next(ln for ln in lines if ln.startswith("tools: "))
    text = html_mod._html.unescape(line)
    assert text.endswith("...")
    assert html_mod._width(text) <= html_mod._BOX_FACT_WIDTH
    # Counted per cell, not per character: fewer glyphs than an ASCII line keeps.
    assert len(text) < html_mod._BOX_FACT_WIDTH
    one = cjk[0]
    assert html_mod._clip("ab" + one * 20, 10) == "ab" + one * 2 + "..."
    assert html_mod._width(html_mod._clip("ab" + one * 20, 10)) <= 10
    assert html_mod._clip("plain ascii", 30) == "plain ascii"
    # The section under the map is never clipped: every glyph, as an entity.
    assert section_of(page, "tools").count("&#x65e5;") == 8


def test_notes_are_rendered_and_escaped():
    page = render_html(build([make_finding(notes="see <b>docs</b> & caf\u00e9")]))
    assert "note: see &lt;b&gt;docs&lt;/b&gt; &amp; caf&#xe9;" in page
    assert page.isascii()


def test_plan_lists_none_when_the_package_can_implement_nothing():
    page = render_html(build([make_finding("AUD-201")]))
    plan = page[page.index('<h2 id="plan">') :]
    head = plan[plan.index("Rows the package can implement") :]
    assert "<p>(none)</p>" in head[: head.index("Wiring a control")]


# ---------------------------------------------------------------------------
# document 2
# ---------------------------------------------------------------------------


def test_document_two_sections_only_with_a_baseline():
    without = render_html(build())
    with_ = render_html(build(baseline=with_baseline()))
    for heading in ("Since the baseline", "Remaining actions", "What changed", "What is left"):
        assert heading not in without
        assert heading in with_
    assert "Document 2 of 2: compared against a baseline." in with_
    assert '<h2 id="since">1. Since the baseline</h2>' in with_
    assert '<h2 id="map">1. System map</h2>' in without


def test_no_longer_reported_never_the_past_participle():
    finding = make_finding(baseline_status="new")
    page = render_html(build([finding], baseline=with_baseline(new=[finding])))
    assert "No longer reported: 1" in page
    assert "AUD-101 old title -- old.py:1" in page
    assert "no longer reported at this fingerprint; a rename or a move also produces this" in page
    assert "New since the baseline: 1" in page
    assert "baseline: 1 new, 0 unchanged, 1 no longer reported (audit-baseline.json)" in page
    assert not FIXED_WORD.search(page)
    assert ("fix" + "ed") not in page.lower()


def test_no_longer_reported_without_an_index_still_counts():
    unnamed = with_baseline(no_longer_reported=[{"fingerprint": "0123456789abcdef"}])
    page = render_html(build(baseline=unnamed))
    assert "0123456789abcdef -- not in this run (the baseline did not record rule or file)" in page
    assert "No longer reported: 1" in page
    assert "baseline: 0 new, 0 unchanged, 1 no longer reported (audit-baseline.json)" in page
    # The block carries no count key: a block without the list renders zero, and a stray
    # count under any other name is not read.
    report = build()
    report.baseline = {"file": "b.json", "new": 1, "unchanged": 0, "fix" + "ed": 2}
    page = render_html(report)
    assert "No longer reported: 0" in page
    assert "baseline: 1 new, 0 unchanged, 0 no longer reported (b.json)" in page
    assert page.isascii()


def test_header_baseline_age_and_reasons():
    page = render_html(build(baseline=with_baseline()))
    assert "Compared against: audit-baseline.json, written 5 days ago" in page
    assert "operator-recorded reasons: none" in page
    reasons = [{"fingerprint": "f", "rule": "AUD-101", "file": "a.py:1", "reason": "r"}]
    page = render_html(build(baseline=with_baseline(accepted=reasons)))
    assert "operator-recorded reasons: 1" in page
    page = render_html(build(baseline=with_baseline(generated_at=None)))
    assert "Compared against: audit-baseline.json, age unknown" in page
    page = render_html(build(baseline=with_baseline(generated_at="2026-09-06T09:30:00Z")))
    assert "written 2 hours ago" in page


def test_header_says_when_the_baseline_was_a_report():
    page = render_html(build(baseline=with_baseline(kind="audit")))
    assert "operator-recorded reasons: none: the baseline was a report, not a baseline file" in page
    page = render_html(build(baseline=with_baseline(kind="audit-baseline")))
    assert "the baseline was a report" not in page
    assert "operator-recorded reasons: none" in page


def test_header_lists_the_resolved_exclude():
    report = build(baseline=with_baseline())
    report.target = dict(report.target or {}, exclude=["tests/fixtures", "__pycache__"])
    page = render_html(report)
    assert "fail-on: low; exclude: tests/fixtures, __pycache__" in page
    report.target = dict(report.target, exclude=[])
    assert "exclude:" not in render_html(report)


def test_remaining_actions_groups():
    findings = [
        make_finding("AUD-201", summary="sandbox it"),
        make_finding("AUD-201", package=GATE, line=20),
        make_finding("AUD-501", accepted_reason="rotated already", file="secrets.py"),
    ]
    unknown = [UnknownItem(category="deep", what="deep analysis of 1 file", why="SyntaxError")]
    page = render_html(build(findings, unknown=unknown, baseline=with_baseline()))
    tail = page[page.index('<h2 id="remaining">') : page.index('<h2 id="unknown">')]
    groups = re.findall(r"<h3>(.*?)</h3>", tail)
    assert groups == [
        "Outside the package",
        "Package control wired or available, but leaves open",
        "Accepted with a recorded reason",
        "Still UNKNOWN",
    ]
    assert "AUD-201 title for AUD-201 -- services/agent/app.py" in tail
    assert "ToolPolicyGuard; leaves open: the approval prompt itself" in tail
    assert "the operator wrote: rotated already" in tail
    assert "UNKNOWN: 1 item; see section" in tail
    since = page[page.index('<h2 id="since">') : page.index('<h2 id="map">')]
    assert "2 open rows in the plan" in since


# ---------------------------------------------------------------------------
# inventory-only, footer, dispatch, templates
# ---------------------------------------------------------------------------


def test_rules_did_not_run_shows_the_banner_and_no_plan():
    page = render_html(build([], rules=[]))
    assert "Rules did not run." in page
    assert 'id="plan"' not in page
    assert "Wiring a control" not in page
    assert "rules ran 0/" in svg_of(page)
    assert "0 of " in page and " rules ran." in page


def test_footer_carries_the_summary_exit_code_and_provenance():
    page = render_html(build(fail_on="high"))
    footer = page[page.index("<footer>") :]
    assert "1 finding (0 below --fail-on high, not counted in exit code); 0 unknown items" in footer
    assert "exit code: 1" in footer
    assert ABSENCE in footer
    assert re.search(r"generated by aisguard [^;]+; the JSON report is authoritative", footer)


def test_inventory_counts_include_own_output_skipped():
    page = render_html(build())
    assert "own output skipped: audit-report.json" in page
    page = render_html(build(inventory=make_inventory(own_output_skipped=[])))
    assert "own output skipped: none" in page


def test_quiet_is_accepted_and_ignored():
    report = build()
    assert render_html(report, quiet=True) == render_html(report, quiet=False)


def test_render_dispatches_html_and_rejects_unknown():
    report = build()
    assert "html" in FORMATS
    assert render(report, "html") == render_html(report)
    with pytest.raises(ValueError, match="pdf"):
        render(report, "pdf")


def test_templates_carry_no_banned_phrase_and_no_banned_word():
    assert check_templates() == []
    assert MARKER in TEMPLATES
    assert ABSENCE in TEMPLATES
    assert set(TEMPLATES) <= set(all_templates())
    for template in TEMPLATES:
        assert template.isascii(), template
        assert not CLEAN_WORD.search(template), template
        assert not FIXED_WORD.search(template), template
        for phrase in BANNED_PHRASES:
            assert phrase not in template.lower(), template


def test_page_carries_no_banned_phrase_or_word():
    page = render_html(build(baseline=with_baseline())).lower()
    for phrase in BANNED_PHRASES:
        assert phrase not in page
    assert not CLEAN_WORD.search(page)


def test_every_inventory_key_name_is_a_template_or_derived_and_free_of_banned_phrases():
    # `_key_name` emits one literal and, for every other key, the key with `_` as a
    # space. The literal is a template so `check_templates` scans it; the derived names
    # come from the fixed `SUBSYSTEMS` tuple, so this pins every one of them instead.
    assert html_mod._T_KEY_MCP in TEMPLATES
    assert html_mod._key_name("mcp") == html_mod._T_KEY_MCP
    keys = {key for sub in SUBSYSTEMS for key in sub.inventory_keys}
    assert "mcp" in keys
    names = {key: html_mod._key_name(key) for key in keys}
    for key, name in names.items():
        assert name.isascii(), key
        assert "_" not in name, key
        assert not CLEAN_WORD.search(name), key
        assert not FIXED_WORD.search(name), key
        for phrase in BANNED_PHRASES:
            assert phrase not in name.lower(), key
        assert name == html_mod._T_KEY_MCP or name == key.replace("_", " "), key
