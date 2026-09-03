"""
tests/unit/test_audit_rules_guards.py
-------------------------------------
AUD-801..805 (guards) against tmp_path trees built here and the shipped audit
fixtures. No shipped fixture wires a guard library, so the positive cases assemble
a small tree: a Python agent importing aisg, a preset YAML, a word-list filter and
a copy of `reports/measure-report.json`.

Pinned here because the design depends on them: AUD-803 reads a report from disk
and is therefore ASSERTED with `evidence_kind: report` and an age, never MEASURED;
nothing in `rules/guards.py` compares a per-guard rate other than
`false_positive_rate` (the module never mentions the p-word except in
`measured_precision`).
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from aisg.core.measurement import Thresholds
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
from aisg.devtools.audit.rules import guards as guards_module
from aisg.devtools.audit.rules import run_rules
from aisg.devtools.audit.rules.guards import (
    RULES,
    GuardFailOpen,
    GuardReportedBelowThreshold,
    GuardUnmeasured,
    KeywordOnlyFilter,
    LLMJudgeWithoutCredentialsOrTimeout,
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

PYPROJECT = '[project]\nname = "guarded"\ndependencies = ["anthropic", "aisg"]\n'

AGENT_PY = """import anthropic
from aisg import GuardrailPipeline, PromptInjectionGuard

client = anthropic.Anthropic()
guard = PromptInjectionGuard(fail_open=True)


def check(text: str) -> bool:
    try:
        GuardrailPipeline.from_config("guardrails.yaml").run_input(text)
    except Exception:
        pass
    return True


def ask(text: str) -> str:
    check(text)
    reply = client.messages.create(
        model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}]
    )
    return reply.content[0].text
"""

PRESET_YAML = """pipeline:
  fail_open: true
input:
  prompt_injection:
    enabled: true
    llm_judge: true
  pii_detector:
    enabled: false
output:
  toxicity_output:
    enabled: true
"""

FILTER_PY = """BANNED_WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]


def is_bad(reply: str) -> bool:
    return any(word in reply.lower() for word in BANNED_WORDS)


def flagged(reply: str) -> bool:
    return reply.lower() in BANNED_WORDS
"""

PRESET_ONLY_AGENT_PY = """import anthropic
from aisg import GuardrailPipeline

client = anthropic.Anthropic()
pipeline = GuardrailPipeline.from_config("guardrails.yaml")


def ask(text: str) -> str:
    pipeline.run_input(text)
    reply = client.messages.create(
        model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}]
    )
    return reply.content[0].text
"""

PLAIN_AGENT_PY = """import anthropic

client = anthropic.Anthropic()


def ask(text: str) -> str:
    reply = client.messages.create(
        model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}]
    )
    return reply.content[0].text
"""


def _write(root: Path, files: dict[str, str]) -> Path:
    for relpath, text in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _guarded(tmp_path: Path, **extra: str) -> Path:
    root = tmp_path / "guarded"
    root.mkdir()
    files = {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "guardrails.yaml": PRESET_YAML}
    files.update(extra)
    return _write(root, files)


def _with_report(root: Path, audit_fixture, name: str = "measure-report.json") -> Path:
    shutil.copy(audit_fixture("reports") / "measure-report.json", root / name)
    return root


def _run(rule, ctx):
    return run_rules([rule], ctx)


def _by_id(findings, display_id: str):
    return [f for f in findings if f.display_id == display_id]


def _locations(findings):
    return [(f.evidence[0].file, f.evidence[0].line) for f in findings]


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_rules_list_is_ordered_and_complete():
    assert [r.id for r in RULES] == ["AUD-801", "AUD-802", "AUD-803", "AUD-804", "AUD-805"]
    assert RULES == [
        GuardUnmeasured,
        GuardFailOpen,
        GuardReportedBelowThreshold,
        LLMJudgeWithoutCredentialsOrTimeout,
        KeywordOnlyFilter,
    ]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    number = rule.id.split("-", 1)[1]
    assert rule.priority == int(number[:-2]) == 8
    assert rule.controls
    for token in rule.controls:
        assert CONTROL_TOKEN.match(token), token
    assert len(rule.recommendation.alternatives) >= 3
    assert any("aisg" not in alt for alt in rule.recommendation.alternatives)
    assert rule.measured_precision is None
    assert set(rule.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule.known_failure_modes
    assert rule.requires_ai_surface is False


def test_803_has_no_rate_comparison_other_than_false_positive_rate():
    source = Path(guards_module.__file__).read_text(encoding="utf-8")
    word = "pre" + "cision"
    assert source.count(word) == source.count("measured_" + word)
    assert "false_positive_rate" in source
    assert GuardReportedBelowThreshold.basis is Basis.MEASURED
    assert GuardReportedBelowThreshold.evidence_kind is EvidenceKind.REPORT


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_empty_context_yields_nothing(rule, tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    instance = rule()
    assert instance.evaluate(ctx) == []
    assert instance.unknown == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_inventory_only_context_with_none_fields_does_not_raise(rule, tmp_path: Path):
    unit = Unit(id="u0", root=".", manifest="pyproject.toml", language="python", ai_surface=True)
    inventory = Inventory(
        units=[unit],
        guardrails=[{"lib": "aisg", "file": "agent.py", "line": 2, "fail_open": True}],
        evals=[{"tool": "promptfoo", "file": "missing.yaml", "in_ci": False, "has_benign": False}],
    )
    ctx = AuditContext(
        root=tmp_path, inventory=inventory, pyfacts=None, config_facts=None, options=None
    )
    for finding in rule().evaluate(ctx):
        assert "\\" not in finding.evidence[0].file


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_silent_on_baseline_and_py_agent(rule, audit_fixture, audit_context, py_agent):
    assert rule().evaluate(audit_context(audit_fixture(BASELINE_FIXTURE))) == []
    assert rule().evaluate(audit_context(py_agent)) == []


# ---------------------------------------------------------------------------
# AUD-801 Guard present but unmeasured
# ---------------------------------------------------------------------------


def test_801_fires_per_enabled_guard_without_a_report(tmp_path: Path, audit_context):
    ctx = audit_context(_guarded(tmp_path))
    assert [g["lib"] for g in ctx.inventory.guardrails] == ["aisg", "aisg_preset"]
    findings, _ = _run(GuardUnmeasured, ctx)
    assert _locations(findings) == [
        ("agent.py", 2),
        ("guardrails.yaml", 4),
        ("guardrails.yaml", 10),
    ]
    notes = [f.notes for f in findings]
    assert "guard prompt_injection is wired in agent.py" in notes[0]
    assert "guard prompt_injection is wired in guardrails.yaml" in notes[1]
    assert "guard toxicity_output is wired in guardrails.yaml" in notes[2]
    assert not any("pii_detector" in n for n in notes)  # enabled: false
    for finding in findings:
        assert finding.severity is Severity.MEDIUM
        assert finding.bucket is Bucket.ASSERTED
        assert finding.confidence.match_kind is MatchKind.STRUCTURED
    assert findings[0].confidence.evidence_kind is EvidenceKind.CODE
    assert findings[1].confidence.evidence_kind is EvidenceKind.CONFIG


def test_801_silent_when_a_measure_report_names_the_guards(
    tmp_path: Path, audit_context, audit_fixture
):
    root = _with_report(_guarded(tmp_path), audit_fixture)
    ctx = audit_context(root)
    assert [r.kind for r in ctx.reports] == ["measure"]
    findings, _ = _run(GuardUnmeasured, ctx)
    assert findings == []


def test_801_eval_file_naming_the_guard_counts(tmp_path: Path, audit_context):
    promptfoo = (
        "# promptfoo eval config\n"
        "description: guard evals\n"
        "tests:\n"
        "  - vars:\n"
        "      guard: prompt_injection\n"
    )
    root = _guarded(tmp_path, **{"promptfooconfig.yaml": promptfoo})
    ctx = audit_context(root)
    assert [e["tool"] for e in ctx.inventory.evals] == ["promptfoo"]
    findings, _ = _run(GuardUnmeasured, ctx)
    assert [f.notes.split(" is wired")[0] for f in findings] == ["guard toxicity_output"]


def test_801_bare_import_without_named_guard_fires_once(tmp_path: Path, audit_context):
    agent = "from aisg import GuardrailPipeline\n\npipeline = GuardrailPipeline()\n"
    root = _write(tmp_path / "bare", {"pyproject.toml": PYPROJECT, "agent.py": agent})
    findings, _ = _run(GuardUnmeasured, audit_context(root))
    assert _locations(findings) == [("agent.py", 1)]
    assert findings[0].confidence.match_kind is MatchKind.GREP
    assert "without naming a guard" in findings[0].notes


def test_801_third_party_guard_library(tmp_path: Path, audit_context):
    agent = "import presidio_analyzer\n\nengine = presidio_analyzer.AnalyzerEngine()\n"
    root = _write(tmp_path / "third", {"pyproject.toml": PYPROJECT, "agent.py": agent})
    findings, _ = _run(GuardUnmeasured, audit_context(root))
    assert _locations(findings) == [("agent.py", 1)]
    assert "guard library presidio" in findings[0].notes
    evals = "# promptfoo\nprompts: [x]\ntests:\n  - description: presidio benign corpus\n"
    root = _write(tmp_path / "third", {"promptfooconfig.yaml": evals})
    findings, _ = _run(GuardUnmeasured, audit_context(root))
    assert findings == []


def test_801_deep_false_gives_same_verdict(tmp_path: Path, audit_context):
    root = _guarded(tmp_path)
    deep, _ = _run(GuardUnmeasured, audit_context(root, deep=True))
    shallow, _ = _run(GuardUnmeasured, audit_context(root, deep=False))
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in shallow]


# ---------------------------------------------------------------------------
# AUD-802 Guard configured fail-open
# ---------------------------------------------------------------------------


def test_802_grep_config_and_ast_tiers(tmp_path: Path, audit_context):
    ctx = audit_context(_guarded(tmp_path))
    assert [s.line for s in ctx.pyfacts.fail_open] == [9]
    findings, _ = _run(GuardFailOpen, ctx)
    assert _locations(findings) == [("agent.py", 5), ("agent.py", 9), ("guardrails.yaml", 2)]
    kinds = [(f.confidence.match_kind, f.confidence.evidence_kind) for f in findings]
    assert kinds == [
        (MatchKind.GREP, EvidenceKind.CODE),
        (MatchKind.AST, EvidenceKind.CODE),
        (MatchKind.GREP, EvidenceKind.CONFIG),
    ]
    assert "fail_open=True" in findings[0].evidence[0].snippet
    assert "exception swallowed" in findings[1].evidence[0].snippet
    assert "check" in findings[1].notes
    assert "fail_open: true" in findings[2].evidence[0].snippet
    for finding in findings:
        assert finding.severity is Severity.HIGH
        assert finding.bucket is Bucket.ASSERTED


def test_802_deep_false_keeps_grep_and_drops_ast(tmp_path: Path, audit_context):
    ctx = audit_context(_guarded(tmp_path), deep=False)
    assert ctx.pyfacts is None
    findings, _ = _run(GuardFailOpen, ctx)
    assert _locations(findings) == [("agent.py", 5), ("guardrails.yaml", 2)]
    assert all(f.confidence.match_kind is MatchKind.GREP for f in findings)


def test_802_ast_wins_over_grep_on_the_same_line(tmp_path: Path, audit_context):
    agent = (
        "from aisg import PromptInjectionGuard\n"
        "\n"
        "def check(text):\n"
        "    try: PromptInjectionGuard(fail_open=True).check(text)\n"
        "    except Exception: pass\n"
    )
    root = _write(tmp_path / "same", {"pyproject.toml": PYPROJECT, "agent.py": agent})
    ctx = audit_context(root)
    assert [(s.file, s.line) for s in ctx.pyfacts.fail_open] == [("agent.py", 4)]
    findings, _ = _run(GuardFailOpen, ctx)
    assert _locations(findings) == [("agent.py", 4)]
    assert findings[0].confidence.match_kind is MatchKind.AST


def test_802_inventory_flag_alone_is_structured_evidence(tmp_path: Path):
    unit = Unit(id="u0", root=".", manifest="pyproject.toml", language="python", ai_surface=True)
    inventory = Inventory(
        units=[unit],
        guardrails=[{"lib": "nemoguardrails", "file": "rails.py", "line": 3, "fail_open": True}],
    )
    findings = GuardFailOpen().evaluate(AuditContext(root=tmp_path, inventory=inventory))
    assert _locations(findings) == [("rails.py", 3)]
    assert findings[0].confidence.match_kind is MatchKind.STRUCTURED


def test_802_on_error_allow_matches(tmp_path: Path, audit_context):
    preset = 'input:\n  prompt_injection:\n    enabled: true\n    on_error: "allow"\n'
    root = _write(tmp_path / "allow", {"pyproject.toml": PYPROJECT, "guardrails.yaml": preset})
    findings, _ = _run(GuardFailOpen, audit_context(root))
    assert _locations(findings) == [("guardrails.yaml", 4)]
    assert "on_error_allow" in findings[0].notes


# ---------------------------------------------------------------------------
# AUD-803 Reported guard below threshold
# ---------------------------------------------------------------------------


def test_803_fires_from_reports_fixture_as_reported_not_measured(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("reports"))
    findings, unknown = _run(GuardReportedBelowThreshold, ctx)
    assert _locations(findings) == [("measure-report-new.json", 0), ("measure-report.json", 0)]
    for finding in findings:
        assert finding.bucket is Bucket.ASSERTED
        assert finding.confidence.evidence_kind is EvidenceKind.REPORT
        assert finding.severity is Severity.HIGH
        assert finding.report is not None
        assert finding.report["schema"] == "aisg/1"
        assert finding.report["age_days"] is not None
        assert finding.report["age_source"] in {"generated_at", "mtime", "git"}
        assert finding.evidence[0].role == "report"
        assert finding.evidence[0].snippet.startswith("prompt_injection: false-positive rate")
        assert "0.143 > 0.05" in finding.notes
        assert "cannot be told" in finding.notes
    assert findings[0].report["age_source"] == "generated_at"
    assert not [u for u in unknown if "AUD-803" in u.rule_ids]


def test_803_names_the_preset_still_wiring_the_guard(tmp_path: Path, audit_context, audit_fixture):
    root = _with_report(_guarded(tmp_path, **{"agent.py": PRESET_ONLY_AGENT_PY}), audit_fixture)
    findings, _ = _run(GuardReportedBelowThreshold, audit_context(root))
    assert len(findings) == 1
    finding = findings[0]
    assert "still wired in guardrails.yaml" in finding.notes
    roles = {e.role: e for e in finding.evidence}
    assert roles["config"].file == "guardrails.yaml" and roles["config"].line == 4
    assert "prompt_injection" in roles["config"].snippet
    assert roles["report"].file == "measure-report.json"


def test_803_direct_construction_counts_as_wired_even_when_the_preset_disables_it(
    tmp_path: Path, audit_context, audit_fixture
):
    preset = PRESET_YAML.replace(
        "prompt_injection:\n    enabled: true", "prompt_injection:\n    enabled: false"
    )
    root = _with_report(_guarded(tmp_path, **{"guardrails.yaml": preset}), audit_fixture)
    findings, _ = _run(GuardReportedBelowThreshold, audit_context(root))
    assert len(findings) == 1
    assert "still wired in agent.py" in findings[0].notes
    roles = {e.role: e for e in findings[0].evidence}
    assert roles["config"].file == "agent.py" and roles["config"].line == 2  # the import
    assert "PromptInjectionGuard" in roles["config"].snippet


def test_803_silent_when_the_failing_guard_is_disabled(
    tmp_path: Path, audit_context, audit_fixture
):
    preset = PRESET_YAML.replace(
        "prompt_injection:\n    enabled: true", "prompt_injection:\n    enabled: false"
    )
    root = _with_report(
        _guarded(tmp_path, **{"guardrails.yaml": preset, "agent.py": PRESET_ONLY_AGENT_PY}),
        audit_fixture,
    )
    findings, _ = _run(GuardReportedBelowThreshold, audit_context(root))
    assert findings == []


@pytest.mark.parametrize("delta,expected", [(0.01, 1), (-0.01, 0)])
def test_803_false_positive_rate_is_compared_to_package_threshold(
    tmp_path: Path, audit_context, audit_fixture, delta, expected
):
    body = json.loads((audit_fixture("reports") / "measure-report.json").read_text("utf-8"))
    limit = Thresholds().max_false_positive_rate
    for guard in body["guards"]:
        guard["threshold_failures"] = []
        guard["false_positive_rate"] = 0.0
    toxicity = next(g for g in body["guards"] if g["name"] == "toxicity_output")
    toxicity["false_positive_rate"] = limit + delta
    root = _guarded(tmp_path)
    (root / "measure-report.json").write_text(json.dumps(body), encoding="utf-8")
    findings, _ = _run(GuardReportedBelowThreshold, audit_context(root))
    assert len(findings) == expected
    if expected:
        assert findings[0].evidence[0].snippet.startswith("toxicity_output:")
        assert f"> {limit}" in findings[0].notes
        assert "still wired in guardrails.yaml" in findings[0].notes


def test_803_over_threshold_but_disabled_guard_is_skipped(
    tmp_path: Path, audit_context, audit_fixture
):
    body = json.loads((audit_fixture("reports") / "measure-report.json").read_text("utf-8"))
    for guard in body["guards"]:
        guard["threshold_failures"] = []
        guard["false_positive_rate"] = 0.0
    pii = next(g for g in body["guards"] if g["name"] == "pii_detector")
    pii["false_positive_rate"] = 0.5  # the preset sets pii_detector `enabled: false`
    root = _guarded(tmp_path)
    (root / "measure-report.json").write_text(json.dumps(body), encoding="utf-8")
    findings, _ = _run(GuardReportedBelowThreshold, audit_context(root))
    assert findings == []


def test_803_unnamed_guard_entry_is_unknown_not_a_finding(
    tmp_path: Path, audit_context, audit_fixture
):
    body = json.loads((audit_fixture("reports") / "measure-report.json").read_text("utf-8"))
    body["guards"] = [{"threshold_failures": ["x"], "false_positive_rate": 0.9}]
    root = _guarded(tmp_path)
    (root / "measure-report.json").write_text(json.dumps(body), encoding="utf-8")
    findings, unknown = _run(GuardReportedBelowThreshold, audit_context(root))
    assert findings == []
    mine = [u for u in unknown if "AUD-803" in u.rule_ids]
    assert len(mine) == 1 and mine[0].category.value == "reports"


def test_803_deep_false_gives_same_verdict(audit_fixture, audit_context):
    deep, _ = _run(GuardReportedBelowThreshold, audit_context(audit_fixture("reports"), deep=True))
    shallow, _ = _run(
        GuardReportedBelowThreshold, audit_context(audit_fixture("reports"), deep=False)
    )
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in shallow]


# ---------------------------------------------------------------------------
# AUD-804 LLM judge without credentials or timeout
# ---------------------------------------------------------------------------


def test_804_fires_no_credentials_and_notes_missing_timeout(tmp_path: Path, audit_context):
    findings, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(_guarded(tmp_path)))
    assert [f.display_id for f in findings] == ["AUD-804/no-credentials"]
    finding = findings[0]
    assert _locations(findings) == [("guardrails.yaml", 6)]
    assert finding.evidence[0].snippet == "llm_judge: true"
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert "*_API_KEY" in finding.notes and "timeout" in finding.notes


def test_804_credentials_in_env_example_and_timeout_silence_it(tmp_path: Path, audit_context):
    env = "ANTHROPIC_API_KEY=\n"
    preset = PRESET_YAML.replace("pipeline:\n", "pipeline:\n  request_timeout: 30.0\n")
    root = _guarded(tmp_path, **{".env.example": env, "guardrails.yaml": preset})
    ctx = audit_context(root)
    assert any(b.name == "ANTHROPIC_API_KEY" for b in ctx.config_facts.env)
    findings, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, ctx)
    assert findings == []


def test_804_no_timeout_sub_finding_when_only_credentials_exist(tmp_path: Path, audit_context):
    settings = 'import os\n\nKEY = os.environ.get("OPENAI_API_KEY")\n'
    root = _guarded(tmp_path, **{"settings.py": settings})
    findings, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(root))
    assert [f.display_id for f in findings] == ["AUD-804/no-timeout"]
    assert "timeout" in findings[0].notes and "*_API_KEY" not in findings[0].notes


def test_804_python_judge_constructor_is_a_site(tmp_path: Path, audit_context):
    agent = (
        "from aisg import ClaudeJudge, LLMInputFilter\n"
        "\n"
        "judge = ClaudeJudge()\n"
        "guard = LLMInputFilter(judge=judge)\n"
    )
    root = _write(tmp_path / "judge", {"pyproject.toml": PYPROJECT, "agent.py": agent})
    findings, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(root))
    assert _locations(findings) == [("agent.py", 3), ("agent.py", 4)]
    assert all(f.confidence.evidence_kind is EvidenceKind.CODE for f in findings)


def test_804_silent_when_no_judge_is_switched_on(tmp_path: Path, audit_context, audit_fixture):
    preset = PRESET_YAML.replace("llm_judge: true", "llm_judge: false")
    root = _guarded(tmp_path, **{"guardrails.yaml": preset})
    findings, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(root))
    assert findings == []
    assert (
        LLMJudgeWithoutCredentialsOrTimeout().evaluate(audit_context(audit_fixture("info_only")))
        == []
    )


def test_804_deep_false_gives_same_verdict(tmp_path: Path, audit_context):
    root = _guarded(tmp_path)
    deep, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(root, deep=True))
    shallow, _ = _run(LLMJudgeWithoutCredentialsOrTimeout, audit_context(root, deep=False))
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in shallow]


# ---------------------------------------------------------------------------
# AUD-805 Keyword-only content filter
# ---------------------------------------------------------------------------


def test_805_fires_on_tested_word_list_without_a_guard_library(tmp_path: Path, audit_context):
    root = _write(
        tmp_path / "words",
        {"pyproject.toml": PYPROJECT, "agent.py": PLAIN_AGENT_PY, "filter.py": FILTER_PY},
    )
    ctx = audit_context(root)
    assert ctx.inventory.guardrails == []
    findings, _ = _run(KeywordOnlyFilter, ctx)
    assert _locations(findings) == [("filter.py", 1)]
    finding = findings[0]
    assert finding.severity is Severity.LOW
    assert finding.confidence.match_kind is MatchKind.GREP
    assert "BANNED_WORDS" in finding.evidence[0].snippet
    assert "BANNED_WORDS" in finding.notes


def test_805_silent_when_the_unit_imports_a_guard_library(tmp_path: Path, audit_context):
    findings, _ = _run(
        KeywordOnlyFilter, audit_context(_guarded(tmp_path, **{"filter.py": FILTER_PY}))
    )
    assert findings == []


def test_805_silent_on_stopwords_and_untested_or_short_lists(
    tmp_path: Path, audit_context, audit_fixture
):
    assert KeywordOnlyFilter().evaluate(audit_context(audit_fixture("noise"))) == []
    untested = 'BLOCKLIST = ["alpha", "bravo", "charlie", "delta", "echo"]\n'
    short = 'BAD_WORDS = ["alpha", "bravo"]\n\n\ndef f(t):\n    return t in BAD_WORDS\n'
    root = _write(
        tmp_path / "quiet",
        {"pyproject.toml": PYPROJECT, "agent.py": PLAIN_AGENT_PY, "a.py": untested, "b.py": short},
    )
    assert KeywordOnlyFilter().evaluate(audit_context(root)) == []


def test_805_use_site_in_another_file_of_the_unit_counts(tmp_path: Path, audit_context):
    # The discover grep is per line, so the first word sits on the opening line; the
    # remaining words are counted across the multi-line literal by the rule itself.
    words = (
        'PROFANITY = frozenset({"alpha",\n'
        '    "bravo",\n'
        '    "charlie",\n'
        '    "delta",\n'
        '    "echo",\n'
        "})\n"
        "\n"
        'OTHER = ("zulu", "yankee")\n'
    )
    use = "from words import PROFANITY\n\n\ndef ok(reply):\n    return reply not in PROFANITY\n"
    root = _write(
        tmp_path / "split",
        {"pyproject.toml": PYPROJECT, "agent.py": PLAIN_AGENT_PY, "words.py": words, "use.py": use},
    )
    findings, _ = _run(KeywordOnlyFilter, audit_context(root))
    assert _locations(findings) == [("words.py", 1)]


def test_805_deep_false_gives_same_verdict(tmp_path: Path, audit_context):
    root = _write(
        tmp_path / "words",
        {"pyproject.toml": PYPROJECT, "agent.py": PLAIN_AGENT_PY, "filter.py": FILTER_PY},
    )
    deep, _ = _run(KeywordOnlyFilter, audit_context(root, deep=True))
    shallow, _ = _run(KeywordOnlyFilter, audit_context(root, deep=False))
    assert [f.fingerprint for f in deep] == [f.fingerprint for f in shallow] and deep


# ---------------------------------------------------------------------------
# Determinism and honesty
# ---------------------------------------------------------------------------


def test_findings_are_deterministic_across_runs(tmp_path: Path, audit_context, audit_fixture):
    root = _with_report(_guarded(tmp_path, **{"filter.py": FILTER_PY}), audit_fixture)
    first, _ = run_rules(RULES, audit_context(root))
    second, _ = run_rules(RULES, audit_context(root))
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    assert len({f.fingerprint for f in first}) == len(first)
    assert {f.id for f in first} == {"AUD-802", "AUD-803", "AUD-804"}


def test_texts_describe_evidence_not_verdicts(tmp_path: Path, audit_context, audit_fixture):
    banned = BANNED_PHRASES  # assembled from fragments in report.py, never a literal here
    assert len(banned) >= 7
    root = _with_report(_guarded(tmp_path, **{"filter.py": FILTER_PY}), audit_fixture)
    findings, _ = run_rules(RULES, audit_context(root))
    for rule in RULES:
        blob = " ".join(
            [rule.title, rule.recommendation.summary, *rule.recommendation.alternatives]
        ).lower()
        for phrase in banned:
            assert phrase not in blob, (rule.id, phrase)
    for finding in findings:
        for evidence in finding.evidence:
            assert evidence.snippet.isascii()
            assert "\\" not in evidence.file
        assert not any(p in (finding.notes or "").lower() for p in banned)
