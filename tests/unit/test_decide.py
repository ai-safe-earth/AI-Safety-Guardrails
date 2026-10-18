"""tests/unit/test_decide.py
--------------------------
`aisg decide` joins the audit's proposed controls with the measure report, a dated
price table and the declared traffic, and gives each control a verdict that is a
deterministic function of the budgets. These tests pin the document shape, the four
verdicts, the honesty rules (unknown never counts, estimates stay labelled, judges
not exercised are UNMEASURED not 0%), the exit codes and the renderers.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from pathlib import Path

import pytest

from aisg.core.measurement import Budget
from aisg.devtools import decide as decide_module
from aisg.devtools.decide import (
    EXIT_FATAL,
    EXIT_OK,
    EXIT_OVER_BUDGET,
    GUARD_FAMILIES,
    NON_GUARD_SYMBOLS,
    NOT_CONFIGURABLE,
    VERDICT_APPLY,
    VERDICT_APPLY_WITH,
    VERDICT_DEFER,
    VERDICT_UNMEASURED,
    Inputs,
    check_templates,
    classify_symbol,
    decide,
    guard_classes,
    main,
    render_json,
    render_markdown,
    render_terminal,
)
from aisg.devtools.prices import load_prices

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "decide"
AUDIT = FIXTURES / "audit-report.json"
MEASURE = FIXTURES / "measure-report.json"
TODAY = dt.date(2026, 10, 19)


def _inputs(measure: Path | None = MEASURE, **budget) -> Inputs:
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))
    measure_doc = json.loads(measure.read_text(encoding="utf-8")) if measure else None
    return Inputs(
        audit_path=AUDIT,
        audit=audit,
        measure_path=measure,
        measure=measure_doc,
        prices=load_prices(),
        card_path=None,
        budget=Budget(**budget),
        traffic_source="flags" if budget else "defaults",
        budgets_source="flags" if budget else "defaults",
        today=TODAY,
    )


def _row(doc: dict, control: str) -> dict:
    return next(c for c in doc["controls"] if c["control"] == control)


class TestDocumentShape:
    def test_schema_and_kind_are_the_first_keys_and_the_order_is_pinned(self):
        doc = decide(_inputs())
        assert list(doc) == [
            "schema",
            "kind",
            "tool",
            "generated_at",
            "disclaimer",
            "inputs",
            "traffic",
            "budgets",
            "controls",
            "selected",
            "totals",
            "unmeasured",
            "exit_code",
        ]
        assert doc["schema"] == "aisg/1" and doc["kind"] == "decision"
        assert list(doc["controls"][0]) == [
            "control",
            "symbol",
            "kind",
            "stage",
            "rules",
            "mechanisms",
            "catch_rate",
            "catch_rate_relevant",
            "catch_rate_meaningful",
            "benign_broken_rate",
            "benign_modified_rate",
            "human_rate",
            "p50_ms",
            "p99_ms",
            "llm_calls_per_request",
            "tokens_in_per_request",
            "tokens_out_per_request",
            "usd_per_request",
            "usd_per_month",
            "usd_basis",
            "fail_mode",
            "provenance",
            "over_budget",
            "recommendation",
        ]
        assert list(doc["totals"]) == [
            "mode",
            "p50_ms",
            "p99_ms_upper_bound",
            "usd_per_request",
            "usd_per_month",
            "human_per_day",
            "human_capacity_per_day",
            "over_budget",
            "excluded_unmeasured",
        ]

    def test_rows_derive_from_package_symbols_one_per_symbol(self):
        doc = decide(_inputs())
        controls = [c["control"] for c in doc["controls"]]
        assert controls == sorted(set(controls), key=controls.index)  # distinct
        tool_policy = _row(doc, "tool_policy")
        assert tool_policy["symbol"] == "ToolPolicyGuard" and tool_policy["kind"] == "guard"
        assert {r["id"] for r in tool_policy["rules"]} >= {"AUD-201", "AUD-103", "AUD-105"}
        assert any(r["same_control"] for r in tool_policy["rules"])
        assert "gate" in tool_policy["mechanisms"] and "budget" in tool_policy["mechanisms"]
        assert _row(doc, "aisg measure")["kind"] == "action"
        assert _row(doc, "AuditLogger")["kind"] == "record"
        assert _row(doc, "ToolPolicy")["kind"] == "config"
        # a `none` package never makes a row
        assert all(c["mechanisms"] != ["none"] for c in doc["controls"])

    def test_symbol_classification_follows_the_registry(self):
        classes = guard_classes()
        from aisg.core.registry import REGISTRY

        for klass, name in classes.items():
            assert REGISTRY[name].__name__ == klass
        assert classify_symbol("PIIDetector", classes) == ("pii_detector", "guard")
        assert classify_symbol("AuditLogger", classes) == ("AuditLogger", "record")
        assert classify_symbol("aisg measure", classes) == ("aisg measure", "action")
        assert classify_symbol("SomethingElse", classes) == ("SomethingElse", "config")
        for symbol in NON_GUARD_SYMBOLS:
            assert symbol not in classes

    def test_guard_families_name_registry_guards_and_corpus_families(self):
        from aisg.devtools.probe import available_families

        classes = guard_classes()
        families = set(available_families())
        for guard, fams in GUARD_FAMILIES.items():
            assert guard in classes.values(), guard
            assert set(fams) <= families, (guard, fams)


class TestVerdicts:
    def test_measured_regex_guard_inside_budgets_is_apply(self):
        doc = decide(_inputs(requests_per_day=1000, p99_ms=250, monthly_usd=100))
        row = _row(doc, "tool_policy")
        assert row["recommendation"]["verdict"] == VERDICT_APPLY
        assert row["provenance"].startswith("MEASURED 2026-")
        assert row["usd_per_request"] == 0.0 and row["usd_basis"] == "none"
        assert row["catch_rate_relevant"] == {"tool_abuse": 1.0}
        assert row["over_budget"] == []

    def test_estimated_judge_row_is_labelled_estimated_and_priced(self):
        doc = decide(_inputs(requests_per_day=20000, avg_input_tokens=400))
        row = _row(doc, "prompt_injection")
        assert row["provenance"].startswith("ESTIMATED 2026-")
        assert row["usd_basis"] == "estimated"
        assert row["usd_per_request"] > 0 and row["usd_per_month"] > 0
        assert row["usd_per_month"] == pytest.approx(row["usd_per_request"] * 20000 * 30)
        assert row["tokens_in_per_request"] > 0

    def test_judge_not_exercised_is_unmeasured_not_zero(self):
        doc = decide(_inputs())
        row = _row(doc, "llm_tool_filter")
        assert row["recommendation"]["verdict"] == VERDICT_UNMEASURED
        assert "did not exercise" in " ".join(row["recommendation"]["reasons"])
        assert row["control"] in {u["control"] for u in doc["unmeasured"]}
        assert (
            "--allow-provider-calls"
            in next(u for u in doc["unmeasured"] if u["control"] == "llm_tool_filter")[
                "how_to_resolve"
            ]
        )

    def test_model_missing_from_the_price_table_is_named(self):
        doc = decide(_inputs())
        row = _row(doc, "llm_tool_filter")
        assert row["usd_basis"] == "unavailable" and row["usd_per_request"] is None
        assert any("not in the price table" in r for r in row["recommendation"]["reasons"])

    def test_over_monthly_budget_suggests_the_config_change_and_exits_1(self):
        doc = decide(_inputs(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50))
        row = _row(doc, "prompt_injection")
        assert "usd/month" in row["over_budget"]
        assert row["recommendation"]["verdict"].startswith(VERDICT_APPLY_WITH)
        assert "llm_judge: false" in row["recommendation"]["config_changes"][0]
        assert "hypothesis" in " ".join(row["recommendation"]["reasons"])
        assert doc["exit_code"] == EXIT_OVER_BUDGET
        assert "usd/month" in doc["totals"]["over_budget"]

    def test_unknown_budget_never_counts_as_exceeded(self):
        doc = decide(_inputs())
        assert doc["totals"]["over_budget"] == [] or doc["totals"]["over_budget"] == ["benign"]
        for c in doc["controls"]:
            assert not any(
                b in c["over_budget"] for b in ("p99", "usd/request", "usd/month", "human")
            )

    def test_benign_breakage_over_threshold_suggests_flag_or_sensitivity(self):
        doc = decide(_inputs())
        row = _row(doc, "pii_detector")  # the EU preset blocks on PII and breaks benign traffic
        assert "benign" in row["over_budget"]
        assert row["recommendation"]["verdict"].startswith(VERDICT_APPLY_WITH)
        assert "action: flag" in row["recommendation"]["config_changes"][0]

    def test_sequential_pipeline_totals_sum_and_parallel_totals_take_the_max(self):
        inputs = _inputs(requests_per_day=100)
        doc = decide(inputs)
        assert doc["totals"]["mode"] == "sequential"  # the EU preset is sequential
        rows = [c for c in doc["controls"] if c["control"] in doc["selected"]]
        assert doc["totals"]["p99_ms_upper_bound"] == pytest.approx(sum(r["p99_ms"] for r in rows))
        parallel = json.loads(MEASURE.read_text(encoding="utf-8"))
        parallel["pipeline"]["parallel_checks"] = True
        inputs_par = Inputs(**{**inputs.__dict__, "measure": parallel})
        doc_par = decide(inputs_par)
        assert doc_par["totals"]["mode"] == "parallel"
        assert doc_par["totals"]["p99_ms_upper_bound"] <= doc["totals"]["p99_ms_upper_bound"]

    def test_human_capacity_is_a_budget(self):
        measure = json.loads(MEASURE.read_text(encoding="utf-8"))
        for g in measure["guards"]:
            if g["name"] == "tool_policy":
                g["human_rate"] = 0.5
        inputs = Inputs(
            **{
                **_inputs(requests_per_day=1000, human_review_capacity_per_day=10).__dict__,
                "measure": measure,
            }
        )
        doc = decide(inputs)
        row = _row(doc, "tool_policy")
        assert "human" in row["over_budget"]
        assert any("require_approval" in c for c in row["recommendation"]["config_changes"])
        assert doc["totals"]["human_per_day"] == pytest.approx(500)
        assert "human" in doc["totals"]["over_budget"]

    def test_defer_when_nothing_in_the_package_changes_the_overrun(self):
        measure = json.loads(MEASURE.read_text(encoding="utf-8"))
        for g in measure["guards"]:
            if g["name"] == "rate_limiter":
                g["p99_latency_ms"] = 900.0
        inputs = Inputs(**{**_inputs(p99_ms=250).__dict__, "measure": measure})
        row = _row(decide(inputs), "rate_limiter")
        assert row["recommendation"]["verdict"] == f"{VERDICT_DEFER} (over budget: p99)"

    def test_without_a_measure_report_every_guard_row_is_unmeasured_and_exit_0(self):
        doc = decide(_inputs(measure=None, requests_per_day=1000, monthly_usd=1))
        for c in doc["controls"]:
            if c["kind"] == "guard":
                assert c["provenance"] == "UNMEASURED"
                assert c["recommendation"]["verdict"] == VERDICT_UNMEASURED
        assert doc["selected"] == []
        assert doc["exit_code"] == EXIT_OK
        assert doc["inputs"]["measure"] is None

    def test_decision_is_deterministic(self):
        a = decide(_inputs(requests_per_day=5000, p99_ms=100))
        b = decide(_inputs(requests_per_day=5000, p99_ms=100))
        a.pop("generated_at")
        b.pop("generated_at")
        assert a == b

    def test_stale_prices_mark_every_usd_cell(self):
        inputs = _inputs(requests_per_day=100, avg_input_tokens=100)
        stale = Inputs(**{**inputs.__dict__, "today": dt.date(2027, 6, 1)})
        doc = decide(stale)
        assert doc["inputs"]["prices"]["stale"] is True
        assert _row(doc, "prompt_injection")["usd_basis"] == "estimated, stale"
        assert "STALE" in render_terminal(doc)


class TestRenderers:
    def test_no_banned_phrase_in_templates_or_source(self):
        from aisg.devtools.audit.report import BANNED_PHRASES

        assert check_templates() == []
        source = (REPO / "src/aisg/devtools/decide.py").read_text(encoding="utf-8").lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in source, phrase

    def test_every_format_is_ascii_and_carries_the_disclaimer_and_the_unmeasured_list(self):
        doc = decide(_inputs(requests_per_day=20000))
        for render in (render_terminal, render_markdown, render_json):
            text = render(doc)
            assert text.isascii()
            assert "Not an assessment of compliance" in text
            assert "UNMEASURED" in text
            assert "Month = 30 days" in text or render is render_json

    def test_json_renderer_round_trips(self):
        doc = decide(_inputs())
        assert json.loads(render_json(doc)) == doc

    def test_markdown_is_a_pipe_table(self):
        text = render_markdown(decide(_inputs()))
        assert text.startswith("## aisg decide")
        assert re.search(r"^\| control \| rules \|", text, re.M)


class TestCLI:
    def test_missing_audit_report_exits_2_with_a_hint(self, tmp_path, capsys):
        rc = main(["--audit", str(tmp_path / "none.json"), "--card", str(tmp_path / "no-card")])
        assert rc == EXIT_FATAL
        assert "run `aisg audit" in capsys.readouterr().err

    def test_bad_schema_exits_2(self, tmp_path, capsys):
        bad = tmp_path / "audit.json"
        bad.write_text(json.dumps({"schema": "aisg/9", "kind": "audit", "findings": []}), "utf-8")
        assert main(["--audit", str(bad), "--card", str(tmp_path / "no-card")]) == EXIT_FATAL
        assert "schema" in capsys.readouterr().err

    def test_writes_the_requested_format_and_returns_the_document_exit_code(self, tmp_path):
        out = tmp_path / "d" / "decision.json"
        rc = main(
            [
                "--audit",
                str(AUDIT),
                "--measure",
                str(MEASURE),
                "--card",
                str(tmp_path / "no-card"),
                "--format",
                "json",
                "-o",
                str(out),
                "--quiet",
            ]
        )
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert list(doc)[:2] == ["schema", "kind"]
        assert rc == doc["exit_code"]

    def test_card_traffic_is_read_and_flags_win(self, tmp_path, capsys):
        card = tmp_path / "ai-system-card.yaml"
        card.write_text(
            "schema: aisg/1\ntraffic:\n  requests_per_day: 100\nbudgets:\n  monthly_usd: 5\n",
            "utf-8",
        )
        rc = main(
            [
                "--audit",
                str(AUDIT),
                "--measure",
                str(MEASURE),
                "--card",
                str(card),
                "--format",
                "json",
                "--requests-per-day",
                "7",
            ]
        )
        doc = json.loads(capsys.readouterr().out)
        assert rc in (EXIT_OK, EXIT_OVER_BUDGET)
        assert doc["traffic"]["requests_per_day"] == 7 and doc["traffic"]["source"] == "flags"
        assert doc["budgets"]["monthly_usd"] == 5 and doc["budgets"]["source"] == "card"
        assert doc["inputs"]["card"] == {"file": str(card)}

    def test_select_totals_only_the_named_controls(self, tmp_path, capsys):
        rc = main(
            [
                "--audit",
                str(AUDIT),
                "--measure",
                str(MEASURE),
                "--card",
                str(tmp_path / "no-card"),
                "--format",
                "json",
                "--select",
                "tool_policy,rate_limiter",
            ]
        )
        doc = json.loads(capsys.readouterr().out)
        assert doc["selected"] == ["tool_policy", "rate_limiter"]
        assert rc == EXIT_OK

    def test_select_is_not_configurable_from_pyproject(self):
        assert NOT_CONFIGURABLE == frozenset({"select"})
        parser = decide_module.build_parser()
        assert "select" in {a.dest for a in parser._actions}

    def test_registered_in_the_cli(self):
        from aisg.cli import _EPILOG, COMMANDS

        assert "decide" in COMMANDS
        assert "decide" in _EPILOG

    def test_debug_runs_the_template_self_check(self, tmp_path):
        rc = main(
            [
                "--debug",
                "--audit",
                str(AUDIT),
                "--measure",
                str(MEASURE),
                "--card",
                str(tmp_path / "x"),
                "--format",
                "json",
                "-o",
                str(tmp_path / "o.json"),
                "-q",
            ]
        )
        assert rc in (EXIT_OK, EXIT_OVER_BUDGET)
