"""tests/unit/test_system_card_budgets.py
---------------------------------------
The card's `traffic:` and `budgets:` blocks: what the operator expects the system to
carry and can afford. Written by `aisafe init`, read by `aisafe decide`, never verified.
"""

from __future__ import annotations

import yaml

from aisafe.core.measurement import Budget
from aisafe.devtools.system_card import DEFAULT_CARD, NUMERIC_BLOCKS, render_card


def _card(**overrides):
    card = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_CARD.items()}
    card["system"]["id"] = "00000000-0000-0000-0000-000000000000"
    card.update(overrides)
    return card


def test_blocks_render_null_by_default_and_parse_back():
    data = yaml.safe_load(render_card(_card()))
    assert data["traffic"] == {k: None for k in NUMERIC_BLOCKS["traffic"]}
    assert data["budgets"] == {k: None for k in NUMERIC_BLOCKS["budgets"]}
    assert data["deployment"] == "unknown"  # the scalar is untouched by the new blocks
    assert Budget.from_card(data).is_empty()


def test_numbers_round_trip_as_numbers():
    card = _card(
        traffic={"requests_per_day": 1200, "avg_input_tokens": 350.5, "avg_output_tokens": None},
        budgets={
            "p99_ms": 250,
            "monthly_usd": 90.0,
            "max_usd_per_request": None,
            "human_review_capacity_per_day": 20,
            "max_human_rate": 0.05,
        },
    )
    data = yaml.safe_load(render_card(card))
    assert data["traffic"]["requests_per_day"] == 1200
    assert data["traffic"]["avg_input_tokens"] == 350.5
    assert data["traffic"]["avg_output_tokens"] is None
    assert data["budgets"]["max_human_rate"] == 0.05
    budget = Budget.from_card(data)
    assert budget.requests_per_day == 1200 and budget.p99_ms == 250
    assert budget.derived_max_usd_per_request == 90.0 / (1200 * 30)


def test_blocks_sit_after_incident_contact_with_a_comment_saying_they_are_not_verified():
    text = render_card(_card())
    lines = text.splitlines()
    contact = next(i for i, ln in enumerate(lines) if ln.startswith("incident_contact:"))
    traffic = next(i for i, ln in enumerate(lines) if ln == "traffic:")
    budgets = next(i for i, ln in enumerate(lines) if ln == "budgets:")
    assert contact < traffic < budgets
    comment = "\n".join(lines[contact:traffic])
    assert "does" in comment and "not verify" in comment
    assert text.isascii()


def test_legal_caveat_is_still_above_risk_tier():
    lines = render_card(_card()).splitlines()
    tier = next(i for i, ln in enumerate(lines) if ln.startswith("risk_tier:"))
    assert any("LEGAL DETERMINATION" in ln for ln in lines[:tier])


def test_a_card_without_the_blocks_still_reads_as_an_empty_budget():
    old_shape = {k: v for k, v in _card().items() if k not in ("traffic", "budgets")}
    assert Budget.from_card(old_shape).is_empty()
