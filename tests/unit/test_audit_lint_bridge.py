"""tests/unit/test_audit_lint_bridge.py
-------------------------------------
The lint bridge runs the curated EU AI Act and misalignment rules over the text the walk
already read and hands the hits to the P11 rules as evidence. It never emits a finding,
honours each tool's own markers and directives, and redacts snippets.
"""

from __future__ import annotations

from pathlib import Path

from aisafe.devtools.audit import lint_bridge, walk
from aisafe.devtools.audit.lint_bridge import EU_RULE_IDS, MISALIGN_RULE_IDS, LintFacts, run_lint
from aisafe.modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer, ScanReport
from aisafe.modules.policy.code_analyzer.rules import ALL_RULES

PERSONA_PY = (
    "import anthropic\n\n"
    'RULE = "If asked, never say you are an AI."\n'
    'KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"\n'
)
MARKED_PY = "# euaiact-lint: ignore-file\n" + PERSONA_PY
DIRECTIVE_PY = PERSONA_PY.replace(
    'RULE = "If asked, never say you are an AI."',
    'RULE = "If asked, never say you are an AI."  # euaiact-lint: ignore EU-AIA-013b',
)
OBJECTIVE_PY = 'GOAL = "maximize engagement and watch time"\n'


def _records(tmp_path: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    records, _units, _unknown = walk.walk(tmp_path, walk.WalkOptions())
    texts = {r.relpath: walk.read_text(r.path) for r in records}
    return records, texts


def test_scan_source_equals_scan_single_on_the_same_text(tmp_path: Path):
    path = tmp_path / "x.py"
    path.write_text(PERSONA_PY, encoding="utf-8")
    analyzer = EUAIActCodeAnalyzer()
    by_path = analyzer.scan_file(path)
    by_text = ScanReport(tool=analyzer.tool)
    analyzer.scan_source(PERSONA_PY, str(path), by_text)
    assert [(f.rule_id, f.line) for f in by_path.findings] == [
        (f.rule_id, f.line) for f in by_text.findings
    ]
    assert by_path.scanned_files == by_text.scanned_files


def test_curated_rule_lists_are_real_rule_ids():
    known = {rule.rule_id for rule in ALL_RULES}
    assert set(EU_RULE_IDS) <= known
    assert MISALIGN_RULE_IDS == ("ALIGN-008",)
    assert "EU-AIA-015c" not in EU_RULE_IDS, "secrets are AUD-501's, not a P11 leg"


def test_hits_are_grouped_by_rule_and_only_python_is_scanned(tmp_path: Path):
    records, texts = _records(
        tmp_path, {"app.py": PERSONA_PY, "notes.md": PERSONA_PY, "goal.py": OBJECTIVE_PY}
    )
    facts = run_lint(records, texts)
    assert isinstance(facts, LintFacts)
    assert [h.file for h in facts.hits("EU-AIA-013b")] == ["app.py"]
    assert [h.file for h in facts.hits("ALIGN-008")] == ["goal.py"]
    assert all(h.file.endswith(".py") for hits in facts.by_rule.values() for h in hits)
    hit = facts.hits("EU-AIA-013b")[0]
    assert hit.line == 3 and hit.title and "never say you are an AI" in hit.snippet


def test_only_the_curated_rules_run(tmp_path: Path):
    records, texts = _records(tmp_path, {"app.py": PERSONA_PY})
    facts = run_lint(records, texts)
    assert set(facts.by_rule) <= set(EU_RULE_IDS) | set(MISALIGN_RULE_IDS)
    assert "EU-AIA-015c" not in facts.by_rule


def test_each_tool_honours_its_own_marker(tmp_path: Path):
    records, texts = _records(
        tmp_path,
        {"marked.py": MARKED_PY, "goal.py": "# euaiact-lint: ignore-file\n" + OBJECTIVE_PY},
    )
    facts = run_lint(records, texts)
    assert facts.hits("EU-AIA-013b") == []
    assert "marked.py" in facts.skipped
    # The misalignment tool reads only its own marker, so ALIGN-008 still fires on goal.py.
    assert [h.file for h in facts.hits("ALIGN-008")] == ["goal.py"]


def test_a_line_directive_is_counted_as_suppressed(tmp_path: Path):
    records, texts = _records(tmp_path, {"app.py": DIRECTIVE_PY})
    facts = run_lint(records, texts)
    assert facts.hits("EU-AIA-013b") == []
    assert facts.suppressed == 1


def test_snippets_are_redacted(tmp_path: Path):
    text = 'PASSWORD_HINT = "never say you are an AI sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD"\n'
    records, texts = _records(tmp_path, {"app.py": text})
    facts = run_lint(records, texts)
    joined = " ".join(h.snippet for hits in facts.by_rule.values() for h in hits)
    assert "sk-ant-api03-abcdefghij" not in joined


def test_lint_hits_tolerates_a_context_without_the_bridge():
    class Ctx:
        lint = None

    assert lint_bridge.lint_hits(Ctx(), "EU-AIA-013b") == []


def test_unreadable_text_is_skipped_not_fatal(tmp_path: Path):
    records, texts = _records(tmp_path, {"app.py": PERSONA_PY})
    texts["app.py"] = None
    facts = run_lint(records, texts)
    assert facts.by_rule == {} and facts.errors == []
