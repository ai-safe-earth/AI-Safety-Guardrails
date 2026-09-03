"""
tests/unit/test_audit_rules_governance.py
-----------------------------------------
P10 governance rules: AUD-1001 (no system card), AUD-1002 (risk tier
undetermined), AUD-1003 (Annex III keywords without a card category).

None of these is a legal finding, and the tests pin that: the caveat travels
with the finding and no verdict language appears in anything the rules emit.
Extra trees are built under tmp_path; nothing is added under tests/fixtures/audit.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aisg.devtools.audit.model import (  # noqa: E402
    AuditContext,
    Basis,
    Bucket,
    EvidenceKind,
    Inventory,
    MatchKind,
    Severity,
    UnknownCategory,
)
from aisg.devtools.audit.report import BANNED_PHRASES  # noqa: E402
from aisg.devtools.audit.rules import governance, run_rules  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "audit"

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

CONTROL_RE = re.compile(r"^(ASI(0[1-9]|10)|LLM(0[1-9]|10)|EU:Art\.\d+|NIST:[A-Z]+-\d+\.\d+)$")

# Assembled at runtime so the word never appears in this file as a literal.
BANNED_WORD_RE = re.compile(r"\b" + "cl" + "ean" + r"\b", re.IGNORECASE)

CARD = """\
name: scratch-agent
purpose: answer questions
risk_tier: {tier}
annex_iii_category: {category}
incident_contact: security@example.invalid
"""


# ---------------------------------------------------------------------------
# Tree builders (tmp_path only)
# ---------------------------------------------------------------------------


def _ai_tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "pyproject.toml").write_text('[project]\nname = "scratch"\n', encoding="utf-8")
    (root / "agent.py").write_text(
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "resp = client.messages.create(model='claude-3-7-sonnet-latest', max_tokens=5, messages=[])\n",
        encoding="utf-8",
    )
    return root


def _card(root: Path, tier: str = "unknown", category: str = "null") -> Path:
    path = root / "ai-system-card.yaml"
    path.write_text(CARD.format(tier=tier, category=category), encoding="utf-8")
    return path


def _prompt(root: Path, text: str, name: str = "system.md") -> Path:
    (root / "prompts").mkdir(exist_ok=True)
    path = root / "prompts" / name
    path.write_text(text, encoding="utf-8")
    return path


def _findings(rule_cls, ctx):
    rule = rule_cls()
    return rule.evaluate(ctx), rule.unknown


def _all_text(finding) -> str:
    return json.dumps(finding.to_dict(), default=str).lower()


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_cls", governance.RULES)
def test_metadata_contract(rule_cls):
    assert re.fullmatch(r"AUD-\d{3,4}", rule_cls.id)
    assert rule_cls.priority == int(rule_cls.id.split("-")[1][:-2])
    assert rule_cls.priority == 10
    assert rule_cls.controls, "controls must be non-empty"
    assert all(CONTROL_RE.match(c) for c in rule_cls.controls), rule_cls.controls
    assert set(rule_cls.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule_cls.measured_precision is None
    assert len(rule_cls.recommendation.alternatives) >= 3
    assert any("aisg" not in alt.lower() for alt in rule_cls.recommendation.alternatives)
    assert rule_cls.known_failure_modes
    assert isinstance(rule_cls.title, str) and rule_cls.title


def test_rules_list_and_ids():
    assert [r.id for r in governance.RULES] == ["AUD-1001", "AUD-1002", "AUD-1003"]


@pytest.mark.parametrize("rule_cls", governance.RULES)
def test_empty_context_never_raises(rule_cls, tmp_path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    findings, unknown = _findings(rule_cls, ctx)
    assert findings == []
    assert unknown == []


def test_legal_caveat_wording():
    assert "legal determination" in governance.LEGAL_CAVEAT
    assert "not a tool output" in governance.LEGAL_CAVEAT
    assert "Art. 6" in governance.LEGAL_CAVEAT and "Annex III" in governance.LEGAL_CAVEAT


# ---------------------------------------------------------------------------
# AUD-1001  No system card
# ---------------------------------------------------------------------------


def test_1001_fires_on_noise_fixture(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("noise"))
    assert ctx.inventory.system_card is None
    assert any(u.ai_surface for u in ctx.inventory.units)
    findings, unknown = _findings(governance.NoSystemCard, ctx)
    assert unknown == []
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "AUD-1001"
    assert f.severity is Severity.LOW
    assert f.basis is Basis.ABSENCE
    assert f.bucket is Bucket.ASSERTED
    assert f.confidence.evidence_kind is EvidenceKind.ABSENCE
    assert f.confidence.match_kind is MatchKind.STRUCTURED
    assert f.scope.kind == "repo"
    assert f.evidence[0].role == "absence"
    assert f.evidence[0].file == "."
    assert f.evidence[0].line == 0
    assert "aisg init" in f.recommendation.summary


def test_1001_silent_when_card_present(audit_fixture, audit_context, py_agent):
    for root in (py_agent, audit_fixture("info_only")):
        ctx = audit_context(root)
        assert ctx.inventory.system_card is not None
        findings, _ = _findings(governance.NoSystemCard, ctx)
        assert findings == [], root


def test_1001_skipped_without_ai_surface(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("clean_py"))
    assert ctx.inventory.system_card is None
    findings, _ = run_rules([governance.NoSystemCard], ctx)
    assert findings == []
    assert governance.NoSystemCard.requires_ai_surface is True
    assert _findings(governance.NoSystemCard, ctx)[0] == []


def test_1001_unreadable_card_is_unknown_not_absence(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    (root / "ai-system-card.yaml").write_text("risk_tier: [unclosed\n  - : :\n", encoding="utf-8")
    ctx = audit_context(root)
    assert ctx.inventory.system_card is None
    findings, unknown = _findings(governance.NoSystemCard, ctx)
    assert findings == []
    assert [u.what for u in unknown] == ["system card unreadable"]
    assert unknown[0].category is UnknownCategory.REPORTS
    assert unknown[0].file == "ai-system-card.yaml"
    assert unknown[0].rule_ids == ("AUD-1001",)


# ---------------------------------------------------------------------------
# AUD-1002  Risk tier undetermined
# ---------------------------------------------------------------------------


def test_1002_fires_on_py_agent(py_agent, audit_context):
    ctx = audit_context(py_agent)
    assert ctx.inventory.system_card["risk_tier"] == "unknown"
    findings, unknown = _findings(governance.RiskTierUndetermined, ctx)
    assert unknown == []
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "AUD-1002"
    assert f.severity is Severity.INFO
    assert f.basis is Basis.PRESENCE
    assert f.confidence.evidence_kind is EvidenceKind.CONFIG
    assert f.confidence.match_kind is MatchKind.STRUCTURED
    assert f.evidence[0].file == "ai-system-card.yaml"
    assert f.evidence[0].line == 19
    assert f.evidence[0].snippet.startswith("risk_tier:")
    assert "\\" not in f.evidence[0].file
    assert f.notes == governance.LEGAL_CAVEAT
    assert "legal determination" in f.notes


@pytest.mark.parametrize("tier", ["high", "limited", "minimal"])
def test_1002_silent_when_tier_set(tmp_path, audit_context, tier):
    root = _ai_tree(tmp_path / "repo")
    _card(root, tier=tier)
    ctx = audit_context(root)
    assert ctx.inventory.system_card["risk_tier"] == tier
    findings, _ = _findings(governance.RiskTierUndetermined, ctx)
    assert findings == []


@pytest.mark.parametrize("tier", ["TODO", "todo - decide later", "unknown", "tbd", '""'])
def test_1002_placeholder_values_fire(tmp_path, audit_context, tier):
    root = _ai_tree(tmp_path / "repo")
    _card(root, tier=tier)
    ctx = audit_context(root)
    findings, _ = _findings(governance.RiskTierUndetermined, ctx)
    assert [f.id for f in findings] == ["AUD-1002"]
    assert findings[0].evidence[0].line == 3


def test_1002_hand_built_card_without_file_text(tmp_path):
    inventory = Inventory()
    inventory.system_card = {
        "file": "ai-system-card.yaml",
        "risk_tier": None,
        "annex_iii_category": None,
        "incident_contact": None,
    }
    ctx = AuditContext(root=tmp_path, inventory=inventory)
    findings, unknown = _findings(governance.RiskTierUndetermined, ctx)
    assert unknown == []
    assert len(findings) == 1
    assert findings[0].evidence[0].line == 0
    assert "(unset)" in findings[0].evidence[0].snippet


def test_1002_not_gated_on_ai_surface():
    assert governance.RiskTierUndetermined.requires_ai_surface is False


# ---------------------------------------------------------------------------
# AUD-1003  Annex III keywords without a card category
# ---------------------------------------------------------------------------


def test_1003_silent_on_fixtures(audit_fixture, audit_context, py_agent):
    for root in (py_agent, audit_fixture("info_only"), audit_fixture("clean_py")):
        findings, unknown = _findings(governance.AnnexKeywordsWithoutCategory, audit_context(root))
        assert findings == [], root
        assert unknown == [], root


def test_1003_readme_hiring_never_counts(audit_fixture, audit_context):
    root = audit_fixture("noise")
    text = (root / "readme_hiring" / "README.md").read_text(encoding="utf-8").lower()
    assert "hiring" in text
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, audit_context(root))
    assert findings == []


def test_1003_two_keywords_in_prompt_template_fire(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    _card(root)
    _prompt(root, "You screen candidates for hiring.\nRank each recruitment application.\n")
    ctx = audit_context(root)
    findings, unknown = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert unknown == []
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "AUD-1003"
    assert f.severity is Severity.INFO
    assert f.basis is Basis.PRESENCE
    assert f.confidence.evidence_kind is EvidenceKind.CODE
    assert f.confidence.match_kind is MatchKind.GREP
    assert f.scope.kind == "repo"
    assert [(e.file, e.line, e.snippet) for e in f.evidence] == [
        ("prompts/system.md", 1, "annex_iii keyword: hiring"),
        ("prompts/system.md", 2, "annex_iii keyword: recruitment"),
    ]
    assert "2 Annex III keywords (hiring, recruitment)" in f.notes
    assert "card ai-system-card.yaml names no category" in f.notes
    assert "employment_and_worker_management" in f.notes
    assert "not a tool output" in f.notes
    assert "legal determination" in f.notes


def test_1003_silent_when_category_set(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    _card(root, category="employment_and_worker_management")
    _prompt(root, "You screen candidates for hiring.\nRank each recruitment application.\n")
    ctx = audit_context(root)
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert findings == []


def test_1003_single_keyword_is_silent(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    _card(root)
    _prompt(root, "You screen candidates for hiring.\nAnswer politely.\n")
    ctx = audit_context(root)
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert findings == []


def test_1003_fires_without_any_card(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    _prompt(root, "Decide asylum claims.\nCheck immigration status.\n")
    ctx = audit_context(root)
    assert ctx.inventory.system_card is None
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert len(findings) == 1
    assert "no system card" in findings[0].notes
    keys = {e.snippet.split(": ")[1] for e in findings[0].evidence}
    assert keys == {"asylum", "migration"}


def _assembly_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "scratch"\n', encoding="utf-8")
    (root / "agent.py").write_text(
        "from anthropic import Anthropic\n"
        "client = Anthropic()\n"
        "\n"
        "def run(name):\n"
        '    system_prompt = f"You grade exams for the police academy. Candidate: {name}"\n'
        "    return client.messages.create(\n"
        "        model='claude-3-7-sonnet-latest', max_tokens=5, system=system_prompt, messages=[]\n"
        "    )\n",
        encoding="utf-8",
    )
    _card(root)
    return root


def test_1003_python_assembly_deep_is_ast(tmp_path, audit_context):
    root = _assembly_tree(tmp_path)
    ctx = audit_context(root, deep=True)
    assert ctx.pyfacts is not None
    assert any(a.file == "agent.py" and a.line == 5 for a in ctx.pyfacts.prompt_assemblies)
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence.match_kind is MatchKind.AST
    legs = [(e.role, e.file, e.line, e.snippet) for e in f.evidence]
    assert legs == [
        ("ast", "agent.py", 5, "annex_iii keyword: exam_grading"),
        ("ast", "agent.py", 5, "annex_iii keyword: law_enforcement"),
    ]


def test_1003_python_assembly_shallow_is_grep_with_same_keys(tmp_path, audit_context):
    root = _assembly_tree(tmp_path)
    deep, _ = _findings(governance.AnnexKeywordsWithoutCategory, audit_context(root, deep=True))
    shallow, _ = _findings(governance.AnnexKeywordsWithoutCategory, audit_context(root, deep=False))
    assert len(shallow) == 1
    f = shallow[0]
    assert f.confidence.match_kind is MatchKind.GREP
    assert all(e.role == "grep" for e in f.evidence)
    assert [(e.file, e.line, e.snippet) for e in f.evidence] == [
        (e.file, e.line, e.snippet) for e in deep[0].evidence
    ]


def test_1003_yaml_comment_on_card_never_counts(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    shutil.copy(FIXTURES / "py_agent" / "ai-system-card.yaml", root / "ai-system-card.yaml")
    _prompt(root, "Assist the police with law enforcement reports.\n")
    ctx = audit_context(root)
    # The card's template comment names "biometrics"; only law_enforcement is live text.
    findings, _ = _findings(governance.AnnexKeywordsWithoutCategory, ctx)
    assert findings == []


# ---------------------------------------------------------------------------
# Honesty: no verdict language anywhere in what these rules emit
# ---------------------------------------------------------------------------


def test_no_verdict_language(tmp_path, audit_context):
    root = _ai_tree(tmp_path / "repo")
    _card(root)
    _prompt(root, "You screen candidates for hiring.\nRank each recruitment application.\n")
    ctx = audit_context(root)
    findings, _ = run_rules(governance.RULES, ctx)
    assert {f.id for f in findings} == {"AUD-1002", "AUD-1003"}
    noise, _ = run_rules(governance.RULES, audit_context(FIXTURES / "noise"))
    assert "AUD-1001" in {f.id for f in noise}
    for f in findings + noise:
        text = _all_text(f)
        for phrase in BANNED_PHRASES:
            assert phrase not in text, (f.id, phrase)
        assert not BANNED_WORD_RE.search(text), f.id
        assert text.isascii(), f.id
