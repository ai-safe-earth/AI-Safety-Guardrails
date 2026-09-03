"""
tests/unit/test_audit_rules_registry.py
---------------------------------------
Registry-level pins for `aisg audit` rules: every module present, ids and
priorities consistent, metadata complete, precision UNMEASURED (never guessed),
and every rule safe on an empty context.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    TRIFECTA_RULE_ID,
    AuditContext,
    Inventory,
    Tier,
    UnknownCategory,
    UnknownItem,
)
from aisg.devtools.audit.rules import (
    ALL_RULES,
    MISSING_RULE_MODULES,
    AuditRule,
    default_rules,
    experimental_rules,
    is_demoted,
    rule_by_id,
    run_rules,
    select_rules,
)

RULE_ID = re.compile(r"^AUD-\d{3,4}$")

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
