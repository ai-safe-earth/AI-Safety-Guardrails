"""
src/aisafe/devtools/decide.py
---------------------------
`aisafe decide` -- what each proposed control costs, and whether it fits the budget.

    aisafe decide                                    # .aisafe-audit/audit-report.json + measure-report.json
    aisafe decide --requests-per-day 20000 --p99-budget-ms 250 --monthly-budget-usd 300
    aisafe decide --format markdown -o .aisafe-audit/decision.md
    aisafe decide --format json -o .aisafe-audit/decision-report.json

The audit says which controls a repository lacks and names the package symbol that
wires each one (`recommendation.package`). `aisafe measure` says what each guard
catches, breaks, costs in latency and spends in tokens. This tool joins the two with
a dated price table and a traffic profile the operator declared (flags, or the
system card's `traffic:` and `budgets:` blocks), and gives every candidate control
one of four verdicts, each a deterministic function of the declared budgets:

    apply                           inside every budget that is known
    apply with <config change>      over a budget, and a configuration change exists
                                    that is likely to bring it back (a hypothesis
                                    until `aisafe measure` is re-run on the new config)
    defer (over budget: <which>)    over a budget, and nothing in the package changes that
    unmeasured (run aisafe measure first)   no measurement, or a judge that was never exercised

Every figure carries its basis. Latency and catch rates come from a measure report
and are MEASURED on its date; tokens are MEASURED (provider usage on a real call) or
ESTIMATED (offline, from the exact prompt); dollars are tokens priced against a table
whose `as_of` date is printed, and marked `stale` when the table is past its shelf
life. An unknown budget never counts as exceeded, an unknown figure never counts as
zero, and the UNMEASURED list is printed in every format. The decision never hides a
trade-off: the numbers are what they are, and `apply` is a reading of them, not a
verdict about safety. Never a model call, never a socket.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aisafe.core.measurement import DAYS_PER_MONTH, Budget, Thresholds
from aisafe.devtools._config import apply_tool_config
from aisafe.devtools.prices import PricesError, PriceTable, load_prices, price_call, usd_label

SCHEMA_VERSION = "aisg/1"
KIND = "decision"
TOOL_NAME = "aisafe-decide"
DEFAULT_AUDIT = ".aisafe-audit/audit-report.json"
DEFAULT_MEASURE = ".aisafe-audit/measure-report.json"
DEFAULT_CARD = "ai-system-card.yaml"
FORMATS = ("terminal", "json", "markdown")
# A selection is a per-decision act: a pyproject default would make every run total
# a subset the operator did not choose this time, and set the exit code from it.
NOT_CONFIGURABLE = frozenset({"select"})

EXIT_OK = 0
EXIT_OVER_BUDGET = 1
EXIT_FATAL = 2
EXIT_INTERRUPTED = 130

VERDICT_APPLY = "apply"
VERDICT_APPLY_WITH = "apply with"
VERDICT_DEFER = "defer"
VERDICT_UNMEASURED = "unmeasured (run aisafe measure first)"

# Package symbols that are not guards: what the row stands for when no measure row
# can exist for it. `aisafe <verb>` symbols are actions and are classified by regex.
NON_GUARD_SYMBOLS: dict[str, str] = {
    "AuditLogger": "record",
    "TelemetryProvider": "record",
    "LLMJudgeBase": "config",
    "ToolPolicy": "config",
    "GuardrailPipeline": "config",
}
_VERB_RE = re.compile(r"^aisafe [a-z]+$")

# Which attack families a guard is meant to catch; the per-family rate shown beside
# the headline rate. Pinned by tests against the registry and the corpus families.
GUARD_FAMILIES: dict[str, tuple[str, ...]] = {
    "prompt_injection": ("prompt_injection", "system_prompt_extraction", "encoding_bypass"),
    "pii_detector": ("pii_echo",),
    "pii_restorer": (),
    "rate_limiter": (),
    "tool_policy": ("tool_abuse",),
    "llm_tool_filter": ("tool_abuse",),
    "toxicity_output": ("toxicity_elicitation",),
    "llm_output_filter": ("toxicity_elicitation",),
    "llm_input_filter": ("prompt_injection", "toxicity_elicitation", "encoding_bypass"),
    "eu_ai_act": (),
    "nist_ai_rmf": (),
    "nemo_rails": (),
}

# The symbols whose row IS the judge: without an exercised judge their measurement
# says nothing about what they catch.
_JUDGE_SYMBOLS = frozenset({"LLMToolFilter", "LLMOutputFilter", "LLMInputFilter"})

DISCLAIMER = (
    "Figures are measured against the shipped corpora or estimated offline, as each "
    "row's label says, and compared with figures you declared. Not an assessment of "
    "compliance with any regulation. Absence of a finding is not evidence of safety."
)
MONTH_NOTE = f"Month = {DAYS_PER_MONTH} days."

# Every fixed string a renderer prints; `check_templates` scans these and nothing else.
TEMPLATES: tuple[str, ...] = (
    DISCLAIMER,
    MONTH_NOTE,
    "aisafe decide",
    "Trade table: what each proposed control costs against the declared budgets.",
    "control",
    "rules",
    "catch",
    "benign broken",
    "human",
    "p50/p99 ms",
    "tokens in/out",
    "usd/request",
    "usd/month",
    "fail mode",
    "provenance",
    "recommendation",
    "Selected controls, together:",
    "UNMEASURED (no figure exists; nothing here is a pass):",
    "Prices as of {as_of}{stale}.",
    "the sum of per-guard p99s bounds the pipeline p99; it is not the pipeline p99",
    "not a pipeline guard; aisafe measure does not time it",
    "the change is a hypothesis until aisafe measure is re-run on the new config",
    "measure report absent: every guard row is UNMEASURED",
    "budget not declared",
)


def check_templates() -> list[str]:
    """Banned phrases in this tool's own fixed strings (never in the data it reads)."""
    from aisafe.devtools.audit.report import BANNED_PHRASES

    found: list[str] = []
    for template in TEMPLATES:
        lowered = template.lower()
        for phrase in BANNED_PHRASES:
            if phrase in lowered and phrase not in found:
                found.append(phrase)
    return found


class DecideError(Exception):
    """A fatal input problem; the message is for stderr and the exit code is 2."""


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


def _read_json(path: Path, what: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DecideError(f"{what} not readable: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise DecideError(f"{what} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        raise DecideError(f"{what} does not carry schema {SCHEMA_VERSION!r}: {path}")
    return data


def read_audit(path: Path) -> dict:
    if not path.is_file():
        raise DecideError(
            f"audit report not found: {path}\n"
            f"run `aisafe audit . --format json -o {DEFAULT_AUDIT}` first"
        )
    data = _read_json(path, "audit report")
    if data.get("kind") != "audit" or not isinstance(data.get("findings"), list):
        raise DecideError(f"not an audit report (kind != audit): {path}")
    return data


def read_measure(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    data = _read_json(path, "measure report")
    guards = data.get("guards")
    if not isinstance(guards, list):
        raise DecideError(f"not a measure report (no guards list): {path}")
    return data


def read_card(path: Path | None) -> dict | None:
    if path is None or not path.is_file():
        return None
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DecideError(f"system card not readable: {path}: {exc}") from exc
    return doc if isinstance(doc, dict) else None


def _num(value: Any) -> float | None:
    if value is None or isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _date_of(iso: Any) -> str:
    text = str(iso or "")
    return text[:10] if len(text) >= 10 else text


def _age_days(iso: Any, today: _dt.date) -> int | None:
    try:
        return (today - _dt.date.fromisoformat(_date_of(iso))).days
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


@dataclass
class Row:
    control: str
    symbol: str
    kind: str  # guard | config | record | action
    stage: str | None = None
    rules: list[dict] = field(default_factory=list)
    mechanisms: set[str] = field(default_factory=set)
    measure: dict | None = None
    # derived
    catch_rate: float | None = None
    catch_rate_relevant: dict[str, float | None] = field(default_factory=dict)
    catch_rate_meaningful: bool | None = None
    benign_broken_rate: float | None = None
    benign_modified_rate: float | None = None
    human_rate: float | None = None
    p50_ms: float | None = None
    p99_ms: float | None = None
    llm_calls_per_request: float | None = None
    tokens_in_per_request: float | None = None
    tokens_out_per_request: float | None = None
    usd_per_request: float | None = None
    usd_per_month: float | None = None
    usd_basis: str = "none"
    fail_mode: str = "n/a"
    provenance: str = "UNMEASURED"
    over_budget: list[str] = field(default_factory=list)
    verdict: str = VERDICT_UNMEASURED
    reasons: list[str] = field(default_factory=list)
    config_changes: list[str] = field(default_factory=list)

    @property
    def unmeasured(self) -> bool:
        return self.verdict == VERDICT_UNMEASURED

    def to_dict(self) -> dict:
        return {
            "control": self.control,
            "symbol": self.symbol,
            "kind": self.kind,
            "stage": self.stage,
            "rules": self.rules,
            "mechanisms": sorted(self.mechanisms),
            "catch_rate": self.catch_rate,
            "catch_rate_relevant": self.catch_rate_relevant,
            "catch_rate_meaningful": self.catch_rate_meaningful,
            "benign_broken_rate": self.benign_broken_rate,
            "benign_modified_rate": self.benign_modified_rate,
            "human_rate": self.human_rate,
            "p50_ms": self.p50_ms,
            "p99_ms": self.p99_ms,
            "llm_calls_per_request": self.llm_calls_per_request,
            "tokens_in_per_request": self.tokens_in_per_request,
            "tokens_out_per_request": self.tokens_out_per_request,
            "usd_per_request": self.usd_per_request,
            "usd_per_month": self.usd_per_month,
            "usd_basis": self.usd_basis,
            "fail_mode": self.fail_mode,
            "provenance": self.provenance,
            "over_budget": list(self.over_budget),
            "recommendation": {
                "verdict": self.verdict,
                "reasons": list(self.reasons),
                "config_changes": list(self.config_changes),
            },
        }


def guard_classes() -> dict[str, str]:
    """`{class name: registry name}` for every registered guard; the registry is the truth."""
    import aisafe  # noqa: F401  registers every shipped guard
    from aisafe.core.registry import REGISTRY

    try:  # the NeMo guard registers only when its integration module is imported
        import aisafe.integrations.nemo_rails  # noqa: F401
    except Exception:
        pass
    return {cls.__name__: name for name, cls in REGISTRY.items()}


def classify_symbol(symbol: str, classes: dict[str, str]) -> tuple[str, str]:
    """(control name, kind) for a package symbol."""
    if symbol in classes:
        return classes[symbol], "guard"
    if symbol in NON_GUARD_SYMBOLS:
        return symbol, NON_GUARD_SYMBOLS[symbol]
    if _VERB_RE.match(symbol):
        return symbol, "action"
    return symbol, "config"


def candidate_rows(audit: dict, classes: dict[str, str]) -> list[Row]:
    """One row per distinct package symbol the audit's findings name."""
    rows: dict[str, Row] = {}
    order: list[str] = []
    for finding in audit.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        package = ((finding.get("recommendation") or {}).get("package")) or {}
        mechanism = str(package.get("mechanism") or "none")
        if mechanism == "none":
            continue
        rule_id = str(finding.get("display_id") or finding.get("id") or "")
        for symbol in package.get("symbols") or []:
            symbol = str(symbol)
            if symbol not in rows:
                control, kind = classify_symbol(symbol, classes)
                rows[symbol] = Row(control=control, symbol=symbol, kind=kind)
                order.append(symbol)
            row = rows[symbol]
            row.mechanisms.add(mechanism)
            entry = {
                "id": rule_id,
                "same_control": bool(package.get("same_control", False)),
                "mechanism": mechanism,
            }
            if entry not in row.rules:
                row.rules.append(entry)
    return [rows[s] for s in order]


# ---------------------------------------------------------------------------
# The join: measure rows, prices and traffic
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Inputs:
    audit_path: Path
    audit: dict
    measure_path: Path | None
    measure: dict | None
    prices: PriceTable
    card_path: Path | None
    budget: Budget
    traffic_source: str
    budgets_source: str
    today: _dt.date


def _measure_rows(measure: dict | None) -> dict[str, dict]:
    if measure is None:
        return {}
    return {
        str(g.get("name")): g
        for g in measure.get("guards") or []
        if isinstance(g, dict) and g.get("name")
    }


def _stage_tokens(stage: str | None, budget: Budget) -> float | None:
    if stage == "output":
        return budget.avg_output_tokens
    return budget.avg_input_tokens


def join_row(row: Row, inputs: Inputs, measure_rows: dict[str, dict], stale: bool) -> None:
    """Fill the measured, estimated and priced figures of one row."""
    if row.kind != "guard":
        row.provenance = "UNMEASURED"
        row.usd_basis = "none"
        return
    m = measure_rows.get(row.control)
    row.measure = m
    if m is None or m.get("unavailable"):
        row.provenance = "UNMEASURED"
        return
    date = _date_of(inputs.measure.get("generated_at") if inputs.measure else "")
    configured = bool(m.get("llm_configured", False))
    exercised = bool(m.get("llm_exercised", False))
    row.stage = str(m.get("stage") or "") or None
    row.catch_rate = _num(m.get("catch_rate"))
    row.catch_rate_meaningful = (
        bool(m["catch_rate_meaningful"]) if "catch_rate_meaningful" in m else None
    )
    by_family = m.get("catch_rate_by_family") or {}
    for family in GUARD_FAMILIES.get(row.control, ()):
        entry = by_family.get(family) if isinstance(by_family, dict) else None
        row.catch_rate_relevant[family] = (
            _num(entry.get("rate")) if isinstance(entry, dict) else None
        )
    row.benign_broken_rate = _num(m.get("false_positive_rate"))
    row.benign_modified_rate = _num(m.get("benign_modified_rate"))
    row.human_rate = _num(m.get("human_rate"))
    row.p50_ms = _num(m.get("p50_latency_ms"))
    row.p99_ms = _num(m.get("p99_latency_ms"))
    row.fail_mode = str(m.get("fail_mode") or "n/a")
    row.provenance = f"ESTIMATED {date}" if configured and not exercised else f"MEASURED {date}"

    if not configured:
        # A guard that calls no model costs exactly nothing in tokens.
        row.llm_calls_per_request = 0.0
        row.tokens_in_per_request = 0.0
        row.tokens_out_per_request = 0.0
        row.usd_per_request = 0.0
        row.usd_per_month = 0.0 if inputs.budget.requests_per_day is not None else None
        row.usd_basis = "none"
        return

    calls = _num(m.get("llm_calls_per_case"))
    tokens_in_call = _num(m.get("tokens_in_per_call"))
    tokens_out_call = _num(m.get("tokens_out_per_call"))
    overhead = _num(m.get("prompt_overhead_tokens"))
    cap_chars = _num(m.get("content_cap_chars"))
    avg_tokens = _stage_tokens(row.stage, inputs.budget)
    row.llm_calls_per_request = calls
    if calls is not None:
        if avg_tokens is not None and overhead is not None:
            content_tokens = avg_tokens
            if cap_chars is not None:
                content_tokens = min(content_tokens, cap_chars / 4.0)
            row.tokens_in_per_request = calls * (overhead + content_tokens)
        elif tokens_in_call is not None:
            row.tokens_in_per_request = calls * tokens_in_call
            row.reasons.append("tokens at the corpus content length; no avg_input_tokens declared")
        if tokens_out_call is not None:
            row.tokens_out_per_request = calls * tokens_out_call
    basis = str(m.get("cost_basis") or "unavailable")
    price = inputs.prices.get(str(m.get("model") or ""))
    row.usd_per_request = price_call(price, row.tokens_in_per_request, row.tokens_out_per_request)
    if price is None and m.get("model"):
        row.reasons.append(
            f"model {m.get('model')} is not in the price table (as of {inputs.prices.as_of})"
        )
    row.usd_basis = usd_label(basis, price, stale)
    if row.usd_per_request is not None and inputs.budget.requests_per_day is not None:
        row.usd_per_month = row.usd_per_request * inputs.budget.requests_per_day * DAYS_PER_MONTH


# ---------------------------------------------------------------------------
# The recommendation: a deterministic function of the declared budgets
# ---------------------------------------------------------------------------


def recommend(row: Row, inputs: Inputs, thresholds: Thresholds) -> None:
    """Set `verdict`, `reasons`, `config_changes` and `over_budget` on `row`."""
    budget = inputs.budget
    if row.kind != "guard":
        row.verdict = VERDICT_APPLY
        row.reasons.append("not a pipeline guard; aisafe measure does not time it")
        return
    m = row.measure
    if m is None or m.get("unavailable"):
        row.verdict = VERDICT_UNMEASURED
        if m is not None and m.get("unavailable"):
            row.reasons.append(f"measure report: {m.get('unavailable')}")
        return
    configured = bool(m.get("llm_configured", False))
    exercised = bool(m.get("llm_exercised", False))
    judge_is_the_control = row.symbol in _JUDGE_SYMBOLS or any(
        r["id"].startswith("AUD-804") for r in row.rules
    )
    if configured and not exercised and judge_is_the_control:
        row.verdict = VERDICT_UNMEASURED
        row.reasons.append(
            "the control is the judge and the measure report did not exercise it; "
            "re-run `aisafe measure --allow-provider-calls`"
        )
        return

    over: list[str] = []
    if budget.p99_ms is not None and row.p99_ms is not None and row.p99_ms > budget.p99_ms:
        over.append("p99")
    cap = thresholds.max_usd_per_request
    if cap is not None and row.usd_per_request is not None and row.usd_per_request > cap:
        over.append("usd/request")
    if (
        budget.monthly_usd is not None
        and row.usd_per_month is not None
        and row.usd_per_month > budget.monthly_usd
    ):
        over.append("usd/month")
    human_cap = thresholds.max_human_rate
    if row.human_rate is not None:
        if human_cap is not None and row.human_rate > human_cap:
            over.append("human")
        elif (
            budget.requests_per_day is not None
            and budget.human_review_capacity_per_day is not None
            and row.human_rate * budget.requests_per_day > budget.human_review_capacity_per_day
        ):
            over.append("human")
    failures = m.get("threshold_failures") or []
    fpr_cap = Thresholds().max_false_positive_rate
    if failures or (row.benign_broken_rate is not None and row.benign_broken_rate > fpr_cap):
        over.append("benign")
    row.over_budget = over
    if not over:
        row.verdict = VERDICT_APPLY
        return

    changes = _config_changes(row, over, inputs)
    if changes:
        row.config_changes = changes
        row.verdict = f"{VERDICT_APPLY_WITH} {changes[0]}"
        row.reasons.append(
            "the change is a hypothesis until aisafe measure is re-run on the new config"
        )
    else:
        row.verdict = f"{VERDICT_DEFER} (over budget: {', '.join(over)})"


def _config_changes(row: Row, over: list[str], inputs: Inputs) -> list[str]:
    """The deterministic table of configuration changes that address an overrun."""
    m = row.measure or {}
    site = str(m.get("llm_site") or "")
    changes: list[str] = []
    cost_or_latency = any(x in over for x in ("p99", "usd/request", "usd/month"))
    if cost_or_latency and site == "prompt_injection:inline":
        changes.append(
            "prompt_injection: llm_judge: false (re-measure: the report measured the judge path)"
        )
    if cost_or_latency and site == "toxicity_output:inline":
        changes.append(
            "toxicity_output: use_llm_judge: false (re-measure: the report measured the judge path)"
        )
    if any(x in over for x in ("usd/request", "usd/month")) and row.symbol in _JUDGE_SYMBOLS:
        changes.append(
            "wrap the judge: CachedJudge(judge, max_size=512, ttl=3600); the saving scales with the "
            "repeat rate of your traffic, which this report does not know"
        )
    pipeline = (inputs.measure or {}).get("pipeline") or {}
    if "p99" in over and pipeline.get("parallel_checks") is False and bool(m.get("llm_configured")):
        regex_guards = sorted(
            g["name"]
            for g in (inputs.measure or {}).get("guards") or []
            if isinstance(g, dict) and not g.get("llm_configured") and g.get("name") != row.control
        )
        names = ", ".join(regex_guards) or "the regex guards"
        changes.append(
            f"order the stage so {names} run before {row.control}: sequential mode "
            "short-circuits on the first BLOCK"
        )
    if "benign" in over:
        if row.control == "prompt_injection":
            changes.append("prompt_injection: sensitivity: low, allow_security_discussion: true")
        else:
            changes.append(f"{row.control}: action: flag (route instead of rejecting)")
    if "human" in over:
        changes.append(
            "narrow require_approval to the irreversible tools, or raise "
            "human_review_capacity_per_day in the card"
        )
    return changes


# ---------------------------------------------------------------------------
# Totals over the selected set
# ---------------------------------------------------------------------------


def totals(rows: list[Row], selected: list[str], inputs: Inputs, thresholds: Thresholds) -> dict:
    budget = inputs.budget
    parallel = bool(((inputs.measure or {}).get("pipeline") or {}).get("parallel_checks", True))
    chosen = [r for r in rows if r.control in selected and r.kind == "guard"]
    excluded = [r.control for r in chosen if r.p50_ms is None or r.p99_ms is None]
    timed = [r for r in chosen if r.p50_ms is not None and r.p99_ms is not None]
    by_stage: dict[str, list[Row]] = {}
    for r in timed:
        by_stage.setdefault(r.stage or "unknown", []).append(r)
    p50 = p99 = 0.0
    for stage, group in by_stage.items():
        if parallel and stage != "processing":
            p50 += max(r.p50_ms for r in group)  # type: ignore[type-var]
            p99 += max(r.p99_ms for r in group)  # type: ignore[type-var]
        else:
            p50 += sum(r.p50_ms for r in group)  # type: ignore[misc]
            p99 += sum(r.p99_ms for r in group)  # type: ignore[misc]
    priced = [r for r in chosen if r.usd_per_request is not None]
    for r in chosen:
        if r.usd_per_request is None and r.control not in excluded:
            excluded.append(r.control)
    usd_request = sum(r.usd_per_request for r in priced)  # type: ignore[misc]
    usd_month = (
        usd_request * budget.requests_per_day * DAYS_PER_MONTH
        if budget.requests_per_day is not None
        else None
    )
    human_rates = [r.human_rate for r in chosen if r.human_rate is not None]
    human_per_day = (
        sum(human_rates) * budget.requests_per_day
        if human_rates and budget.requests_per_day is not None
        else None
    )
    over: list[str] = []
    if budget.p99_ms is not None and timed and p99 > budget.p99_ms:
        over.append("p99")
    if budget.monthly_usd is not None and usd_month is not None and usd_month > budget.monthly_usd:
        over.append("usd/month")
    cap = thresholds.max_usd_per_request
    if cap is not None and priced and usd_request > cap:
        over.append("usd/request")
    if (
        human_per_day is not None
        and budget.human_review_capacity_per_day is not None
        and human_per_day > budget.human_review_capacity_per_day
    ):
        over.append("human")
    return {
        "mode": "parallel" if parallel else "sequential",
        "p50_ms": p50 if timed else None,
        "p99_ms_upper_bound": p99 if timed else None,
        "usd_per_request": usd_request if priced else None,
        "usd_per_month": usd_month if priced else None,
        "human_per_day": human_per_day,
        "human_capacity_per_day": budget.human_review_capacity_per_day,
        "over_budget": over,
        "excluded_unmeasured": sorted(set(excluded)),
    }


# ---------------------------------------------------------------------------
# The decision document
# ---------------------------------------------------------------------------


def decide(inputs: Inputs, select: list[str] | None = None) -> dict:
    """The decision document (`kind: decision`), keys in the pinned order."""
    from aisafe import __version__

    classes = guard_classes()
    rows = candidate_rows(inputs.audit, classes)
    measure_rows = _measure_rows(inputs.measure)
    stale = inputs.prices.is_stale(inputs.today)
    thresholds = inputs.budget.thresholds()
    for row in rows:
        join_row(row, inputs, measure_rows, stale)
        recommend(row, inputs, thresholds)
    if select is None:
        selected = [
            r.control for r in rows if r.verdict.startswith(VERDICT_APPLY) and r.kind == "guard"
        ]
    else:
        selected = [s for s in select if s]
    summary = totals(rows, selected, inputs, thresholds)
    unmeasured = [
        {
            "control": r.control,
            "why": "; ".join(r.reasons) or "no measure report row for this guard",
            "how_to_resolve": (
                "aisafe measure --config <pipeline yaml> -o .aisafe-audit/measure-report.json"
                + (" --allow-provider-calls" if any("judge" in x for x in r.reasons) else "")
            ),
        }
        for r in rows
        if r.unmeasured
    ]
    for r in rows:
        if r.kind != "guard" and r.control not in {u["control"] for u in unmeasured}:
            unmeasured.append(
                {
                    "control": r.control,
                    "why": "not a pipeline guard; aisafe measure does not time it",
                    "how_to_resolve": "none needed: the row is applied for what it records or configures",
                }
            )
    over = bool(summary["over_budget"]) or any(
        r.over_budget and r.control in selected for r in rows
    )
    exit_code = EXIT_OVER_BUDGET if over else EXIT_OK
    measure_block = None
    if inputs.measure is not None:
        measure_block = {
            "file": str(inputs.measure_path),
            "generated_at": inputs.measure.get("generated_at"),
            "measured_on": inputs.measure.get("measured_on"),
            "age_days": _age_days(inputs.measure.get("generated_at"), inputs.today),
            "provider_calls": bool(((inputs.measure.get("corpus") or {}).get("provider_calls"))),
        }
    return {
        "schema": SCHEMA_VERSION,
        "kind": KIND,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "disclaimer": DISCLAIMER,
        "inputs": {
            "audit": {
                "file": str(inputs.audit_path),
                "generated_at": inputs.audit.get("generated_at"),
                "findings": len(inputs.audit.get("findings") or []),
            },
            "measure": measure_block,
            "prices": {
                "file": inputs.prices.path,
                "as_of": inputs.prices.as_of.isoformat(),
                "age_days": inputs.prices.age_days(inputs.today),
                "stale": stale,
                "stale_after_days": inputs.prices.stale_after_days,
            },
            "card": {"file": str(inputs.card_path)} if inputs.card_path else None,
        },
        "traffic": {
            "requests_per_day": inputs.budget.requests_per_day,
            "avg_input_tokens": inputs.budget.avg_input_tokens,
            "avg_output_tokens": inputs.budget.avg_output_tokens,
            "source": inputs.traffic_source,
        },
        "budgets": {
            "p99_ms": inputs.budget.p99_ms,
            "monthly_usd": inputs.budget.monthly_usd,
            "max_usd_per_request": thresholds.max_usd_per_request,
            "human_review_capacity_per_day": inputs.budget.human_review_capacity_per_day,
            "max_human_rate": thresholds.max_human_rate,
            "source": inputs.budgets_source,
        },
        "controls": [r.to_dict() for r in rows],
        "selected": selected,
        "totals": summary,
        "unmeasured": unmeasured,
        "exit_code": exit_code,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def _ms(a: float | None, b: float | None) -> str:
    if a is None and b is None:
        return "-"
    return f"{a:.2f}/{b:.2f}" if a is not None and b is not None else "-"


def _tok(a: float | None, b: float | None) -> str:
    if a is None and b is None:
        return "-"
    left = f"{a:.0f}" if a is not None else "?"
    right = f"{b:.0f}" if b is not None else "?"
    return f"{left}/{right}"


def _usd(value: float | None, basis: str) -> str:
    if value is None:
        return f"- ({basis})"
    return f"{value:.5f} ({basis})"


def _table_rows(doc: dict) -> list[tuple[str, ...]]:
    rows = []
    for c in doc["controls"]:
        catch = _pct(c["catch_rate"])
        relevant = ", ".join(
            f"{fam} {_pct(rate)}" for fam, rate in (c["catch_rate_relevant"] or {}).items()
        )
        if relevant:
            catch = f"{catch} ({relevant})"
        rows.append(
            (
                c["control"],
                " ".join(r["id"] for r in c["rules"]),
                catch,
                _pct(c["benign_broken_rate"]),
                _pct(c["human_rate"]),
                _ms(c["p50_ms"], c["p99_ms"]),
                _tok(c["tokens_in_per_request"], c["tokens_out_per_request"]),
                _usd(c["usd_per_request"], c["usd_basis"]),
                _usd(c["usd_per_month"], c["usd_basis"]) if c["usd_per_month"] is not None else "-",
                c["fail_mode"],
                c["provenance"],
                c["recommendation"]["verdict"],
            )
        )
    return rows


_HEADER = (
    "control",
    "rules",
    "catch",
    "benign broken",
    "human",
    "p50/p99 ms",
    "tokens in/out",
    "usd/request",
    "usd/month",
    "fail mode",
    "provenance",
    "recommendation",
)


def _totals_lines(doc: dict) -> list[str]:
    t = doc["totals"]
    lines = ["Selected controls, together:"]
    lines.append(f"  controls: {', '.join(doc['selected']) or '(none)'}")
    lines.append(f"  latency mode: {t['mode']}")
    if t["p50_ms"] is not None:
        lines.append(
            f"  p50 {t['p50_ms']:.2f} ms, p99 upper bound {t['p99_ms_upper_bound']:.2f} ms "
            "(the sum of per-guard p99s bounds the pipeline p99; it is not the pipeline p99)"
        )
    if t["usd_per_request"] is not None:
        lines.append(f"  usd/request {t['usd_per_request']:.5f}")
    if t["usd_per_month"] is not None:
        lines.append(f"  usd/month {t['usd_per_month']:.2f}")
    if t["human_per_day"] is not None:
        cap = t["human_capacity_per_day"]
        lines.append(
            f"  human reviews/day {t['human_per_day']:.1f}"
            + (f" of capacity {cap:.0f}" if cap is not None else " (budget not declared)")
        )
    if t["over_budget"]:
        lines.append(f"  OVER BUDGET: {', '.join(t['over_budget'])}")
    if t["excluded_unmeasured"]:
        lines.append(f"  excluded (no figure): {', '.join(t['excluded_unmeasured'])}")
    return lines


def _footer_lines(doc: dict) -> list[str]:
    prices = doc["inputs"]["prices"]
    stale = ", STALE" if prices["stale"] else ""
    lines = [MONTH_NOTE + " " + f"Prices as of {prices['as_of']}{stale}."]
    if doc["inputs"]["measure"] is None:
        lines.append("measure report absent: every guard row is UNMEASURED")
    lines.append(DISCLAIMER)
    return lines


def render_terminal(doc: dict) -> str:
    rows_all = [_HEADER, *_table_rows(doc)]
    widths = [max(len(str(r[i])) for r in rows_all) for i in range(len(_HEADER))]
    out = ["aisafe decide", "===========", ""]
    out.append("Trade table: what each proposed control costs against the declared budgets.")
    out.append("")
    for i, r in enumerate(rows_all):
        out.append("  ".join(str(c).ljust(widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    out.append("")
    out.extend(_totals_lines(doc))
    out.append("")
    out.append("UNMEASURED (no figure exists; nothing here is a pass):")
    if doc["unmeasured"]:
        for u in doc["unmeasured"]:
            out.append(f"  {u['control']}: {u['why']}")
            out.append(f"    resolve: {u['how_to_resolve']}")
    else:
        out.append("  (none)")
    out.append("")
    out.extend(_footer_lines(doc))
    return "\n".join(out) + "\n"


def render_markdown(doc: dict) -> str:
    out = [
        "## aisafe decide",
        "",
        "Trade table: what each proposed control costs against the declared budgets.",
        "",
    ]
    out.append("| " + " | ".join(_HEADER) + " |")
    out.append("|" + "|".join(" --- " for _ in _HEADER) + "|")
    for r in _table_rows(doc):
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    out.append("")
    out.extend(_totals_lines(doc))
    out.append("")
    out.append("UNMEASURED (no figure exists; nothing here is a pass):")
    out.append("")
    if doc["unmeasured"]:
        for u in doc["unmeasured"]:
            out.append(f"- {u['control']}: {u['why']} (resolve: {u['how_to_resolve']})")
    else:
        out.append("- (none)")
    out.append("")
    out.extend(_footer_lines(doc))
    return "\n".join(out) + "\n"


def render_json(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


RENDERERS = {"terminal": render_terminal, "markdown": render_markdown, "json": render_json}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisafe decide",
        description="What each proposed control costs, and whether it fits the declared budgets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads the audit report (which controls, which symbols), the measure report\n"
            "(what each guard catches, breaks, costs in latency and spends in tokens),\n"
            "a dated price table and a traffic profile from flags or the system card.\n"
            "Every figure carries its basis; an unknown budget never counts as exceeded.\n"
            "Exit 0 rendered, 1 a selected control or the total exceeds a budget, 2 fatal.\n"
        ),
    )
    p.add_argument("--audit", default=DEFAULT_AUDIT, help=f"audit report JSON ({DEFAULT_AUDIT})")
    p.add_argument(
        "--measure", default=DEFAULT_MEASURE, help=f"measure report JSON ({DEFAULT_MEASURE})"
    )
    p.add_argument(
        "--prices",
        default=None,
        help="price table YAML (default: AISAFE_PRICES, pyproject, packaged)",
    )
    p.add_argument(
        "--card", default=DEFAULT_CARD, help=f"system card with traffic/budgets ({DEFAULT_CARD})"
    )
    traffic = p.add_argument_group("traffic and budgets (flags beat the card)")
    traffic.add_argument("--requests-per-day", type=float, default=None)
    traffic.add_argument("--avg-input-tokens", type=float, default=None)
    traffic.add_argument("--avg-output-tokens", type=float, default=None)
    traffic.add_argument("--p99-budget-ms", type=float, default=None)
    traffic.add_argument("--monthly-budget-usd", type=float, default=None)
    traffic.add_argument("--max-usd-per-request", type=float, default=None)
    traffic.add_argument("--human-review-capacity-per-day", type=float, default=None)
    traffic.add_argument("--max-human-rate", type=float, default=None)
    p.add_argument(
        "--select",
        default=None,
        help="CSV of controls to total (default: every row recommended apply). "
        "Not settable from pyproject.",
    )
    p.add_argument("--format", choices=FORMATS, default="terminal")
    p.add_argument(
        "--output", "-o", default=None, help="write the rendering here instead of stdout"
    )
    p.add_argument("--quiet", "-q", action="store_true", help="no stdout besides the rendering")
    p.add_argument(
        "--debug", action="store_true", help="also run the template self-check (exit 2 on a hit)"
    )
    return p


def _resolve_inputs(args: argparse.Namespace, today: _dt.date | None = None) -> Inputs:
    today = today or _dt.date.today()
    audit_path = Path(args.audit)
    audit = read_audit(audit_path)
    measure_path = Path(args.measure) if args.measure else None
    measure = read_measure(measure_path)
    if measure is None:
        measure_path = None
    card_path = Path(args.card) if args.card else None
    card = read_card(card_path)
    if card is None:
        card_path = None
    try:
        prices = load_prices(args.prices)
    except PricesError as exc:
        raise DecideError(str(exc)) from exc
    budget = Budget.from_card(card) if card is not None else Budget()
    card_had_traffic = not Budget.from_card(card).is_empty() if card is not None else False
    flags = dict(
        requests_per_day=args.requests_per_day,
        avg_input_tokens=args.avg_input_tokens,
        avg_output_tokens=args.avg_output_tokens,
        p99_ms=args.p99_budget_ms,
        monthly_usd=args.monthly_budget_usd,
        max_usd_per_request=args.max_usd_per_request,
        human_review_capacity_per_day=args.human_review_capacity_per_day,
        max_human_rate=args.max_human_rate,
    )
    merged = budget.merged(**flags)
    traffic_flags = any(
        flags[k] is not None for k in ("requests_per_day", "avg_input_tokens", "avg_output_tokens")
    )
    budget_flags = any(
        flags[k] is not None
        for k in flags
        if k not in ("requests_per_day", "avg_input_tokens", "avg_output_tokens")
    )
    traffic_source = "flags" if traffic_flags else ("card" if card_had_traffic else "defaults")
    budgets_source = "flags" if budget_flags else ("card" if card_had_traffic else "defaults")
    return Inputs(
        audit_path=audit_path,
        audit=audit,
        measure_path=measure_path,
        measure=measure,
        prices=prices,
        card_path=card_path,
        budget=merged,
        traffic_source=traffic_source,
        budgets_source=budgets_source,
        today=today,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    apply_tool_config(parser, "aisafe-decide", exclude=NOT_CONFIGURABLE)
    args = parser.parse_args(argv)
    if args.debug:
        hits = check_templates()
        if hits:
            print(f"aisafe decide: template self-check failed: {hits}", file=sys.stderr)
            return EXIT_FATAL
    try:
        inputs = _resolve_inputs(args)
        select = [s.strip() for s in args.select.split(",")] if args.select else None
        doc = decide(inputs, select)
        rendered = RENDERERS[args.format](doc)
    except DecideError as exc:
        print(f"aisafe decide: {exc}", file=sys.stderr)
        return EXIT_FATAL
    except KeyboardInterrupt:
        print("aisafe decide: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    if args.output:
        try:
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            print(f"aisafe decide: could not write {args.output}: {exc}", file=sys.stderr)
            return EXIT_FATAL
        if not args.quiet:
            print(f"aisafe decide: {args.format} written to {args.output}")
    else:
        sys.stdout.write(rendered)
    return int(doc["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
