"""
tests/unit/test_audit_rules_registry.py
---------------------------------------
Registry-level pins for `aisg audit` rules: every module present, ids and
priorities consistent, metadata complete, precision UNMEASURED (never guessed),
every rule safe on an empty context, every rule classified (package and
subsystem), and every package symbol a real name in this distribution.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    NO_PACKAGE,
    PACKAGE_MECHANISMS,
    TRIFECTA_RULE_ID,
    AuditContext,
    Inventory,
    Tier,
    UnknownCategory,
    UnknownItem,
)
from aisg.devtools.audit.report import BANNED_PHRASES
from aisg.devtools.audit.rules import (
    ALL_RULES,
    MISSING_RULE_MODULES,
    NOT_ATTRIBUTED,
    SUBSYSTEM_OF_RULE,
    SUBSYSTEMS,
    AuditRule,
    default_rules,
    experimental_rules,
    is_demoted,
    rule_by_id,
    run_rules,
    select_rules,
    subsystem_of,
)

RULE_ID = re.compile(r"^AUD-\d{3,4}$")

# The one word the design bans outright, assembled from fragments so this file does not
# carry it as a contiguous literal (the self-audit scans tests too).
BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# Package symbols are either a console verb ("aisg measure") or a class name. A verb must
# be a subcommand of the single console script; a class must be reachable from `aisg`.
VERB_RE = re.compile(r"^aisg [a-z]+$")

# The closed set of class names a rule may name: each is exported from `aisg/__init__.py`
# (the plan table and the skill print them as the thing to wire, so they are one import
# away). A new symbol is exported and added here before a rule names it.
CLASS_SYMBOLS = frozenset(
    {
        "AuditLogger",
        "GuardrailPipeline",
        "LLMJudgeBase",
        "LLMOutputFilter",
        "LLMToolFilter",
        "PIIDetector",
        "PIIRestorer",
        "PromptInjectionGuard",
        "RateLimiter",
        "TelemetryProvider",
        "ToolPolicy",
        "ToolPolicyGuard",
    }
)

# Text that would turn a "what remains open" note into a claim of completion.
COMPLETION_CLAIMS = ("resolves", "fixes", "solves", "closes the finding", "guarantees")

EXPECTED_IDS = {
    *(f"AUD-{n}" for n in range(101, 109)),
    *(f"AUD-{n}" for n in range(201, 204)),
    *(f"AUD-{n}" for n in range(301, 304)),
    *(f"AUD-{n}" for n in range(401, 407)),
    *(f"AUD-{n}" for n in range(501, 506)),
    *(f"AUD-{n}" for n in range(601, 607)),
    *(f"AUD-{n}" for n in range(701, 704)),
    *(f"AUD-{n}" for n in range(801, 806)),
    *(f"AUD-{n}" for n in range(901, 905)),
    *(f"AUD-{n}" for n in range(1001, 1004)),
}


def _lint_rule_ids() -> set[str]:
    """Real ids from the two existing linters; `related_lint_rules` must point at these."""
    from aisg.devtools.misalignment.rules import MISALIGNMENT_RULES
    from aisg.modules.policy.code_analyzer.rules import ALL_RULES as LINT_RULES

    ids = {rule.rule_id for rule in LINT_RULES}
    ids |= {rule.rule_id for rule in MISALIGNMENT_RULES}
    return ids


def _empty_context(tmp_path: Path) -> AuditContext:
    return AuditContext(root=tmp_path, inventory=Inventory())


AUDIT_PACKAGE = Path(__file__).resolve().parents[2] / "src" / "aisg" / "devtools" / "audit"
SELF_VOCABULARY_MODULES = sorted(
    p.relative_to(AUDIT_PACKAGE).as_posix() for p in (AUDIT_PACKAGE / "rules").glob("*.py")
) + ["adapters.py"]


# ---------------------------------------------------------------------------
# Self-vocabulary: the rule modules must not audit themselves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relpath", SELF_VOCABULARY_MODULES)
def test_rule_and_adapter_modules_carry_the_ignore_marker(relpath: str) -> None:
    # Rule modules quote the vocabulary they detect (gate bypass keys, fail-open
    # flags, guard names); the marker keeps them out of a self-audit. It must sit
    # in the first five lines, where walk() looks for it.
    from aisg.devtools.audit.patterns import IGNORE_MARKER

    head = (AUDIT_PACKAGE / relpath).read_text(encoding="utf-8").splitlines()[:5]
    assert IGNORE_MARKER in head, f"{relpath} lacks the ignore-file marker in its first five lines"


def test_walk_skips_every_marked_audit_module() -> None:
    from aisg.devtools.audit.walk import walk

    files, _units, _unknown = walk(AUDIT_PACKAGE)
    seen = {record.relpath for record in files}
    assert SELF_VOCABULARY_MODULES
    leaked = sorted(seen & set(SELF_VOCABULARY_MODULES))
    assert leaked == [], f"walk() still yields marked modules: {leaked}"
    # The marker is an opt-out, not a blanket skip: unmarked package modules still walk.
    assert "walk.py" in seen


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_every_rule_module_is_present() -> None:
    assert MISSING_RULE_MODULES == []
    assert len(ALL_RULES) == len(EXPECTED_IDS)


def test_rule_ids_are_unique_well_formed_and_complete() -> None:
    ids = [rule.id for rule in ALL_RULES]
    assert len(ids) == len(set(ids)), "duplicate rule id"
    for rule_id in ids:
        assert RULE_ID.match(rule_id), rule_id
    assert set(ids) == EXPECTED_IDS


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_priority_matches_id(rule: type[AuditRule]) -> None:
    # AUD-<priority><two digits>: AUD-101 is priority 1, AUD-1002 is priority 10.
    assert rule.priority == int(rule.id[4:-2])


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_metadata_is_complete(rule: type[AuditRule]) -> None:
    assert issubclass(rule, AuditRule)
    assert rule.title.strip()
    assert rule.controls, f"{rule.id} has no controls"
    assert rule.tier in tuple(Tier)
    assert rule.recommendation.summary.strip()
    alternatives = rule.recommendation.alternatives
    assert len(alternatives) >= 3, f"{rule.id} needs at least three alternatives"
    assert any("aisg" not in alt.lower() for alt in alternatives), (
        f"{rule.id}: at least one alternative must not point at aisg"
    )
    assert rule.recommendation.tier in tuple(Tier)


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_measured_precision_is_unmeasured(rule: type[AuditRule]) -> None:
    # UNMEASURED is the literal None; a number here must come from a labelled corpus.
    assert rule.measured_precision is None
    assert not is_demoted(rule)
    assert not rule.experimental()


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_related_lint_rules_point_at_real_rules(rule: type[AuditRule]) -> None:
    valid = _lint_rule_ids()
    for lint_id in rule.related_lint_rules:
        assert lint_id in valid, f"{rule.id} references unknown lint rule {lint_id}"


def test_default_and_experimental_partition_the_registry() -> None:
    assert default_rules() == list(ALL_RULES)
    assert experimental_rules() == []
    for rule in ALL_RULES:
        assert rule_by_id(rule.id) is rule
    assert rule_by_id("AUD-000") is None


def test_select_rules_notes_unknown_ids_without_raising() -> None:
    rules, notes = select_rules(["AUD-301", "AUD-999", "AUD-301"])
    assert [r.id for r in rules] == ["AUD-301"]
    assert notes == ["unknown rule id AUD-999"]
    everything, no_notes = select_rules(None)
    assert everything == default_rules()
    assert no_notes == []


# ---------------------------------------------------------------------------
# Evaluation safety
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_rule_is_silent_on_an_empty_context(rule: type[AuditRule], tmp_path: Path) -> None:
    instance = rule()
    assert instance.evaluate(_empty_context(tmp_path)) == []


def test_run_rules_on_empty_context_yields_nothing(tmp_path: Path) -> None:
    findings, unknown = run_rules(ALL_RULES, _empty_context(tmp_path))
    assert findings == []
    assert unknown == []


def test_run_rules_pins_trifecta_first_on_py_agent(py_agent: Path, audit_context) -> None:
    ctx = audit_context(py_agent)
    findings, unknown = run_rules(ALL_RULES, ctx)
    assert findings, "py_agent must produce findings"
    assert findings[0].id == TRIFECTA_RULE_ID
    assert all(item.category is not UnknownCategory.RUNTIME for item in unknown), (
        "no rule may crash on the reference fixture"
    )


def test_rule_exception_becomes_an_unknown_item(tmp_path: Path) -> None:
    class Broken(AuditRule):
        id = "AUD-9999"
        title = "broken on purpose"
        priority = 99

        def evaluate(self, ctx: AuditContext):
            raise RuntimeError("boom")

    findings, unknown = run_rules([Broken], _empty_context(tmp_path))
    assert findings == []
    assert len(unknown) == 1
    item = unknown[0]
    assert isinstance(item, UnknownItem)
    assert item.category is UnknownCategory.RUNTIME
    assert item.what == "rule AUD-9999"
    assert "RuntimeError: boom" in item.why
    assert item.rule_ids == ("AUD-9999",)


# ---------------------------------------------------------------------------
# Package classification: what this distribution offers for each rule
# ---------------------------------------------------------------------------


def _package_symbols() -> list[str]:
    return sorted({symbol for rule in ALL_RULES for symbol in rule.recommendation.package.symbols})


def _rule_texts(rule: type[AuditRule]) -> list[tuple[str, str]]:
    """Every prose field of a rule's recommendation, labelled for the assertion message."""
    rec = rule.recommendation
    out = [("summary", rec.summary), ("leaves_open", rec.package.leaves_open)]
    out += [(f"alternatives[{i}]", alt) for i, alt in enumerate(rec.alternatives)]
    return out


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_every_rule_sets_its_package_explicitly(rule: type[AuditRule]) -> None:
    # The sentinel is the dataclass default; a rule that left it in place was never
    # classified. A rule that offers nothing says so with its own Package("none").
    package = rule.recommendation.package
    assert package is not NO_PACKAGE, f"{rule.id} never set recommendation.package"
    assert package.mechanism in PACKAGE_MECHANISMS
    if package.mechanism == "none":
        assert package.symbols == ()
        assert not package.same_control
        assert package.leaves_open == ""
        # A rule the package cannot help with still names the alternative in aisg terms,
        # so the reader learns that nothing here applies rather than inferring it.
        assert any("aisg" in alt.lower() for alt in rule.recommendation.alternatives), (
            f"{rule.id}: a 'none' package needs an alternative saying nothing in aisg applies"
        )
    else:
        assert package.symbols, f"{rule.id} offers {package.mechanism} but names no symbol"
        assert package.leaves_open.strip(), f"{rule.id} does not say what stays open"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_leaves_open_is_plain_ascii_prose(rule: type[AuditRule]) -> None:
    text = rule.recommendation.package.leaves_open
    if not text:
        return
    assert text.isascii(), f"{rule.id}: leaves_open is not ASCII"
    assert text == text.strip()
    assert text.endswith("."), f"{rule.id}: leaves_open must be one or two full sentences"
    sentences = [s for s in re.split(r"(?<=\.)\s+", text) if s]
    assert 1 <= len(sentences) <= 3, f"{rule.id}: leaves_open is {len(sentences)} sentences"
    lowered = text.lower()
    for claim in COMPLETION_CLAIMS:
        assert claim not in lowered, f"{rule.id}: leaves_open claims completion ({claim!r})"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_recommendation_prose_is_free_of_banned_language(rule: type[AuditRule]) -> None:
    for label, text in _rule_texts(rule):
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, f"{rule.id} {label}: banned phrase {phrase!r}"
        assert not BANNED_WORD_RE.search(text), f"{rule.id} {label}: the banned word"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_same_control_rules_name_a_wirable_symbol_first(rule: type[AuditRule]) -> None:
    # `same_control` means wiring the first symbol IS the control the rule asks for, so
    # the first symbol is what the closing-the-loop fixtures wire; it must be a class
    # or a verb, never prose.
    package = rule.recommendation.package
    if not package.same_control:
        return
    assert package.mechanism != "none"
    first = package.symbols[0]
    assert VERB_RE.match(first) or first.isidentifier(), f"{rule.id}: {first!r}"


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_detector_is_never_same_control_on_a_p1_to_p4_rule(rule: type[AuditRule]) -> None:
    # A detector flags; it does not gate. On the blast-radius, trust-boundary, sink and
    # irreversible-action rules the control the rule asks for is a gate, budget or
    # allowlist, so offering a detector as "the same control" would let the plan's "who"
    # column hand the package a row it cannot close.
    assert "detector" in PACKAGE_MECHANISMS
    package = rule.recommendation.package
    if rule.priority <= 4 and package.mechanism == "detector":
        assert not package.same_control, (
            f"{rule.id}: a detector is not the control at P{rule.priority}"
        )


@pytest.mark.parametrize("rule", ALL_RULES, ids=lambda r: r.id)
def test_sub_findings_inherit_the_parent_package(rule: type[AuditRule]) -> None:
    # `AuditRule.finding()` copies the class-level recommendation into every Finding,
    # so AUD-NNN/<k> carries the same package as AUD-NNN. Pinned on the shared helper so
    # a rule that builds its own Recommendation per finding would show up here.
    instance = rule()
    finding = instance.absence_finding(unit=None, why="probe")
    assert finding.recommendation.package == rule.recommendation.package
    assert finding.recommendation.package is rule.recommendation.package


def test_package_symbols_are_only_verbs_or_class_names() -> None:
    for symbol in _package_symbols():
        assert VERB_RE.match(symbol) or symbol.isidentifier(), symbol
    # Every 'aisg <verb>' is a subcommand of the one console script.
    from aisg.cli import COMMANDS

    verbs = [s for s in _package_symbols() if VERB_RE.match(s)]
    assert verbs, "no rule names a console verb"
    for verb in verbs:
        assert verb.split()[1] in COMMANDS, f"{verb!r} is not an aisg subcommand"


@pytest.mark.parametrize("symbol", sorted(CLASS_SYMBOLS))
def test_class_symbols_are_exported_from_aisg(symbol: str) -> None:
    import aisg

    obj = getattr(aisg, symbol, None)
    assert obj is not None, f"aisg.{symbol} is not exported"
    assert isinstance(obj, type), f"aisg.{symbol} is not a class"
    assert symbol in aisg.__all__


def test_every_class_symbol_is_in_the_closed_set() -> None:
    # Whatever a rule names must be one of the exported classes, or the recommendation
    # lies; the set is closed so a new symbol is exported before a rule names it.
    class_symbols = {s for s in _package_symbols() if not VERB_RE.match(s)}
    assert class_symbols
    assert class_symbols <= CLASS_SYMBOLS, sorted(class_symbols - CLASS_SYMBOLS)
    # And the set does not drift: every entry is a name some rule uses.
    assert CLASS_SYMBOLS <= class_symbols, sorted(CLASS_SYMBOLS - class_symbols)


# ---------------------------------------------------------------------------
# Subsystems: every rule sits in exactly one box on the system map
# ---------------------------------------------------------------------------


def test_subsystem_keys_are_unique_and_ordered_for_drawing() -> None:
    keys = [s.key for s in SUBSYSTEMS]
    assert len(keys) == len(set(keys))
    assert len(keys) == 10
    assert NOT_ATTRIBUTED not in keys, "the catch-all box is not a subsystem"
    for subsystem in SUBSYSTEMS:
        assert subsystem.title.strip()
        assert subsystem.inventory_keys


def test_every_rule_maps_to_exactly_one_subsystem() -> None:
    assert set(SUBSYSTEM_OF_RULE) == {rule.id for rule in ALL_RULES}
    valid = {s.key for s in SUBSYSTEMS}
    for rule_id, key in SUBSYSTEM_OF_RULE.items():
        assert key in valid, f"{rule_id} -> {key!r} is not a subsystem"


def test_subsystem_of_follows_the_parent_for_sub_findings() -> None:
    assert subsystem_of("AUD-103") == "tools"
    assert subsystem_of("AUD-103/2") == "tools"
    assert subsystem_of("AUD-101/docs") == subsystem_of("AUD-101")
    assert subsystem_of("AUD-9999") == NOT_ATTRIBUTED
    assert subsystem_of("") == NOT_ATTRIBUTED
    assert subsystem_of("not-a-rule/x") == NOT_ATTRIBUTED
