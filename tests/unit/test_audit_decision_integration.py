"""tests/unit/test_audit_decision_integration.py
----------------------------------------------
The `aisg decide` document inside the audit: it is read as a REPORT (evidence about
the declared budgets, `REPORTED <age>`), never as the audit's own output; AUD-806 turns
each over-budget row into one finding per budget kind; AUD-801 adds a `cost` sub-finding
for a judge the measure report never exercised; and `--format html --decision FILE`
adds the Trade table section while every other format stays exactly the JSON.
"""

from __future__ import annotations

import datetime as dt
import json
import shutil
from pathlib import Path

import pytest

from aisg.core.measurement import Budget
from aisg.devtools.audit import discover
from aisg.devtools.audit.main import EXIT_FATAL, main
from aisg.devtools.audit.model import Bucket, EvidenceKind, Inventory
from aisg.devtools.audit.report import _report_entry
from aisg.devtools.audit.rules import run_rules
from aisg.devtools.audit.rules.guards import GuardReportedOverBudget, GuardUnmeasured
from aisg.devtools.decide import Inputs, decide
from aisg.devtools.prices import load_prices

REPO = Path(__file__).resolve().parents[2]
DECIDE_FIXTURES = REPO / "tests" / "fixtures" / "decide"

PYPROJECT = '[project]\nname = "demo"\nversion = "0.0.1"\n'
AGENT_PY = """import anthropic
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
PRESET_YAML = """pipeline:
  parallel_checks: false
input:
  prompt_injection:
    enabled: true
    llm_judge: true
  rate_limiter:
    enabled: true
"""
PRESET_JUDGE_OFF = PRESET_YAML.replace(
    "    enabled: true\n    llm_judge: true", "    enabled: false\n    llm_judge: true"
)


def _decision_doc(**budget) -> dict:
    audit = json.loads((DECIDE_FIXTURES / "audit-report.json").read_text(encoding="utf-8"))
    measure = json.loads((DECIDE_FIXTURES / "measure-report.json").read_text(encoding="utf-8"))
    inputs = Inputs(
        audit_path=DECIDE_FIXTURES / "audit-report.json",
        audit=audit,
        measure_path=DECIDE_FIXTURES / "measure-report.json",
        measure=measure,
        prices=load_prices(),
        card_path=None,
        budget=Budget(**budget),
        traffic_source="flags",
        budgets_source="flags",
        today=dt.date(2026, 10, 19),
    )
    return decide(inputs)


def _tree(
    tmp_path: Path,
    *,
    preset: str = PRESET_YAML,
    decision: dict | None = None,
    measure: bool = False,
) -> Path:
    root = tmp_path / "tree"
    (root / ".aisg-audit").mkdir(parents=True)
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / "agent.py").write_text(AGENT_PY, encoding="utf-8")
    (root / "guardrails.yaml").write_text(preset, encoding="utf-8")
    if decision is not None:
        (root / ".aisg-audit" / "decision-report.json").write_text(
            json.dumps(decision, indent=1), encoding="utf-8"
        )
    if measure:
        shutil.copy(
            DECIDE_FIXTURES / "measure-report.json", root / ".aisg-audit" / "measure-report.json"
        )
    return root


# ---------------------------------------------------------------------------
# The decision document is a report
# ---------------------------------------------------------------------------


class TestDecisionIsAReport:
    def test_kind_detection_and_reader(self, tmp_path):
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        path = tmp_path / "decision-report.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        assert discover._report_kind(doc) == "decision"
        record = discover.read_decision_report(path, tmp_path)
        assert record is not None and record.kind == "decision"
        assert record.file == "decision-report.json"
        assert discover.read_measure_report(path, tmp_path) is None
        assert discover.read_probe_report(path, tmp_path) is None

    def test_decision_is_not_own_output(self, tmp_path):
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        path = tmp_path / "decision-report.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        record, unknown = discover.read_report(path, tmp_path)
        assert record is not None and unknown is None
        assert "decision" not in discover._OWN_OUTPUT_KINDS

    def test_report_entry_lists_only_over_budget_controls(self):
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        entry = _report_entry({"kind": "decision", "file": "d.json", "body": doc})
        assert entry["source"] == "d.json"
        controls = entry["controls"]
        assert "prompt_injection" in controls
        assert "usd/month" in controls["prompt_injection"]["over_budget"]
        assert controls["prompt_injection"]["provenance"].startswith("ESTIMATED")
        assert controls["prompt_injection"]["verdict"].startswith("apply with")
        assert "rate_limiter" not in controls  # inside every budget: not repeated here

    def test_walk_discovers_a_decision_report_under_aisg_audit(self, tmp_path, audit_context):
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        ctx = audit_context(_tree(tmp_path, decision=doc))
        kinds = {r.kind for r in ctx.reports}
        assert "decision" in kinds


# ---------------------------------------------------------------------------
# AUD-806
# ---------------------------------------------------------------------------


class TestAUD806:
    def test_fires_one_finding_per_budget_kind_as_reported(self, tmp_path, audit_context):
        doc = _decision_doc(
            requests_per_day=20000, avg_input_tokens=400, monthly_usd=50, p99_ms=0.5
        )
        ctx = audit_context(_tree(tmp_path, decision=doc))
        findings, unknown = run_rules([GuardReportedOverBudget], ctx)
        by_sub = {(f.evidence[0].snippet.split(":")[0], f.sub) for f in findings}
        assert ("prompt_injection", "cost") in by_sub
        assert ("prompt_injection", "latency") in by_sub
        for finding in findings:
            assert finding.id == "AUD-806" and finding.display_id == f"AUD-806/{finding.sub}"
            assert finding.bucket is Bucket.ASSERTED
            assert finding.confidence.evidence_kind is EvidenceKind.REPORT
            assert finding.report is not None and finding.report["schema"] == "aisg/1"
            assert finding.report["age_days"] is not None
            assert finding.evidence[0].role == "report"
            assert finding.evidence[0].file == ".aisg-audit/decision-report.json"
            if finding.evidence[0].snippet.startswith("prompt_injection"):
                assert "ESTIMATED" in finding.evidence[0].snippet  # the judge was never run
            else:
                assert "MEASURED" in finding.evidence[0].snippet
            assert "decision: apply with" in finding.notes or "decision: defer" in finding.notes
        wired = [f for f in findings if f.evidence[0].snippet.startswith("prompt_injection")]
        assert all(
            any(e.role == "config" and e.file == "guardrails.yaml" for e in f.evidence)
            for f in wired
        )
        assert not [u for u in unknown if "AUD-806" in u.rule_ids]

    def test_silent_without_a_decision_report(self, tmp_path, audit_context):
        ctx = audit_context(_tree(tmp_path))
        findings, _ = run_rules([GuardReportedOverBudget], ctx)
        assert findings == []

    def test_silent_when_nothing_is_over_budget(self, tmp_path, audit_context):
        doc = _decision_doc()  # no budgets declared: nothing can be exceeded
        ctx = audit_context(_tree(tmp_path, decision=doc))
        findings, _ = run_rules([GuardReportedOverBudget], ctx)
        over = [c for c in doc["controls"] if c["over_budget"] and c["over_budget"] != ["benign"]]
        assert over == []
        assert all(f.sub == "benign" for f in findings)

    def test_skips_a_guard_the_preset_disables(self, tmp_path, audit_context):
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        ctx = audit_context(_tree(tmp_path, preset=PRESET_JUDGE_OFF, decision=doc))
        findings, _ = run_rules([GuardReportedOverBudget], ctx)
        assert not [f for f in findings if f.evidence[0].snippet.startswith("prompt_injection")]

    def test_empty_context_is_silent(self, tmp_path):
        from aisg.devtools.audit.model import AuditContext

        rule = GuardReportedOverBudget()
        assert rule.evaluate(AuditContext(root=tmp_path, inventory=Inventory())) == []


# ---------------------------------------------------------------------------
# AUD-801/cost
# ---------------------------------------------------------------------------


class TestAUD801Cost:
    def test_judge_not_exercised_in_the_measure_report_is_a_cost_sub_finding(
        self, tmp_path, audit_context
    ):
        ctx = audit_context(_tree(tmp_path, measure=True))
        findings, _ = run_rules([GuardUnmeasured], ctx)
        cost = [f for f in findings if f.display_id == "AUD-801/cost"]
        assert len(cost) == 1
        finding = cost[0]
        assert "prompt_injection" in finding.notes and "did not exercise" in finding.notes
        assert finding.confidence.evidence_kind is EvidenceKind.REPORT
        assert finding.evidence[0].file == "guardrails.yaml"
        # the plain AUD-801 for a guard the report covers is not raised beside it
        assert not [f for f in findings if f.sub is None and "prompt_injection" in f.notes]

    def test_silent_when_the_report_exercised_the_judge(self, tmp_path, audit_context):
        root = _tree(tmp_path, measure=True)
        path = root / ".aisg-audit" / "measure-report.json"
        measure = json.loads(path.read_text(encoding="utf-8"))
        for g in measure["guards"]:
            g["llm_exercised"] = True
        path.write_text(json.dumps(measure), encoding="utf-8")
        findings, _ = run_rules([GuardUnmeasured], audit_context(root))
        assert not [f for f in findings if f.display_id == "AUD-801/cost"]

    def test_old_measure_report_without_the_keys_raises_no_cost_finding(
        self, tmp_path, audit_context, audit_fixture
    ):
        root = _tree(tmp_path)
        shutil.copy(
            audit_fixture("reports") / "measure-report.json",
            root / ".aisg-audit" / "measure-report.json",
        )
        findings, _ = run_rules([GuardUnmeasured], audit_context(root))
        assert not [f for f in findings if f.display_id == "AUD-801/cost"]


# ---------------------------------------------------------------------------
# --decision and the html Trade table
# ---------------------------------------------------------------------------


class TestHtmlTradeTable:
    @pytest.fixture
    def tree(self, tmp_path, monkeypatch):
        root = _tree(tmp_path)
        doc = _decision_doc(requests_per_day=20000, avg_input_tokens=400, monthly_usd=50)
        decision = tmp_path / "decision-report.json"
        decision.write_text(json.dumps(doc), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        return root, decision

    def test_with_decision_the_page_gains_the_trade_table_and_numbering_shifts(
        self, tree, tmp_path
    ):
        root, decision = tree
        plain = tmp_path / "plain.html"
        traded = tmp_path / "traded.html"
        assert (
            main(
                [
                    str(root),
                    "--format",
                    "html",
                    "--no-external",
                    "--fail-on",
                    "never",
                    "-o",
                    str(plain),
                    "-q",
                ]
            )
            == 0
        )
        assert (
            main(
                [
                    str(root),
                    "--format",
                    "html",
                    "--no-external",
                    "--fail-on",
                    "never",
                    "--decision",
                    str(decision),
                    "-o",
                    str(traded),
                    "-q",
                ]
            )
            == 0
        )
        p, t = plain.read_text(encoding="utf-8"), traded.read_text(encoding="utf-8")
        assert "Trade table" not in p
        assert "Trade table" in t and 'id="trade"' in t
        assert "prompt_injection" in t and "ESTIMATED" in t
        assert "Over budget: usd/month" in t
        assert decision.name in t
        assert t.isascii() and p.isascii()
        # the trade section sits after the plan and the sections after it move down by one
        assert t.index('id="plan"') < t.index('id="trade"') < t.index('id="unknown"')
        import re

        def number_of(page: str, anchor: str) -> int:
            return int(re.search(rf'<h2 id="{anchor}">(\d+)\.', page).group(1))

        assert number_of(t, "unknown") == number_of(p, "unknown") + 1
        assert number_of(t, "trade") == number_of(t, "plan") + 1

    def test_other_formats_ignore_the_decision(self, tree, tmp_path):
        root, decision = tree
        out = tmp_path / "r.json"
        assert (
            main(
                [
                    str(root),
                    "--format",
                    "json",
                    "--no-external",
                    "--fail-on",
                    "never",
                    "--decision",
                    str(decision),
                    "-o",
                    str(out),
                    "-q",
                ]
            )
            == 0
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "trade" not in json.dumps(data).lower() or "Trade table" not in out.read_text(
            encoding="utf-8"
        )
        assert list(data)[0] == "schema"

    def test_a_non_decision_file_is_refused_with_exit_2(self, tree, tmp_path, capsys):
        root, _decision = tree
        bogus = tmp_path / "not-a-decision.json"
        bogus.write_text(json.dumps({"schema": "aisg/1", "kind": "audit"}), encoding="utf-8")
        rc = main(
            [
                str(root),
                "--format",
                "html",
                "--no-external",
                "--fail-on",
                "never",
                "--decision",
                str(bogus),
                "-o",
                str(tmp_path / "x.html"),
                "-q",
            ]
        )
        assert rc == EXIT_FATAL
        assert "kind is not decision" in capsys.readouterr().err
        missing = main(
            [
                str(root),
                "--format",
                "html",
                "--no-external",
                "--decision",
                str(tmp_path / "missing.json"),
                "-q",
            ]
        )
        assert missing == EXIT_FATAL
