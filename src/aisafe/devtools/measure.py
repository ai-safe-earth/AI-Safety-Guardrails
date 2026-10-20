"""
src/aisafe/devtools/measure.py
----------------------------
`aisafe measure` -- run the attack and benign corpora through a real pipeline,
in-process, and report per guard what it catches, what it breaks, and what it
costs.

    aisafe measure
    aisafe measure --config config/eu_high_risk.yaml
    aisafe measure --max-p99-ms 50
    aisafe measure --allow-provider-calls      # let judge-backed guards call their model

A guardrail is a trade. Measuring only the attack corpus makes "block
everything" the winning strategy: every attack caught, nothing got through, a
clean report. The benign corpus is what stops that being a passing grade.

White-box on purpose. `aisafe probe` is black-box over HTTP and can only see what
came back, so it cannot tell a guard blocking a request from a model declining
it. Here the pipeline runs in-process, so `blocked`, `passed` and the sanitized
output are exact rather than inferred.

Each guard is measured in ISOLATION, not through the assembled pipeline: a
sequential pipeline short-circuits on the first block, so guards after it would
never see the payload and would score a spurious zero.

Cost is the third column of the trade, and it is measured honestly or not at
all. By default no provider is called: a judge-backed guard's tokens are
ESTIMATED offline from the exact prompt it would send (`llm_judges/estimate.py`),
its catch rate is reported as not exercised rather than as 0%, and the report
says so in `measured_on` and per guard. `--allow-provider-calls` runs the judges
for real, which costs money and needs credentials, and then the tokens are
MEASURED from the providers' usage fields. Tokens, never dollars: pricing is
`aisafe decide`'s offline join against a dated table.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aisafe.core.base import Action, GuardrailBase
from aisafe.core.measurement import LLMUsage, Profile, Thresholds, weakest_basis
from aisafe.core.pipeline import GuardrailPipeline
from aisafe.devtools.probe import ProbeCase, load_corpus, utc_now_iso
from aisafe.modules.llm_judges import estimate
from aisafe.modules.llm_judges.base import JudgeVerdict, LLMJudgeBase

SCHEMA_VERSION = "aisg/1"
DEFAULT_REPORT = "measure-report.json"

# Guard-config keys that name an LLM-judge model. `judge_model` is what the
# LLM*Filter guards take, `llm_judge_model` is PromptInjectionGuard's and
# ToxicityFilter's; the other two are the plain spellings a hand-written config
# might use.
MODEL_KEYS = ("model", "model_name", "judge_model", "llm_judge_model")
STAGE_KEYS = ("input", "processing", "output", "policy")

__all__ = [
    "main",
    "build_parser",
    "build_report",
    "measure_guard",
    "describe_measurement",
    "TIMING_PASSES",
    "config_digest",
    "config_models",
    "pipeline_settings",
    "GuardMeasurement",
    "collect_guards",
    "fail_mode_of",
]


@dataclass
class GuardMeasurement:
    guard_name: str
    stage: str
    attacks_seen: int = 0
    attacks_caught: int = 0
    benign_seen: int = 0
    benign_broken: int = 0
    benign_modified: int = 0
    latencies_ms: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    broken_examples: list[dict] = field(default_factory=list)
    missed_examples: list[dict] = field(default_factory=list)
    unavailable: str = ""
    # Every guard sees every attack, including families outside its remit --
    # pii_detector is not supposed to catch prompt injection. A single
    # catch-rate over all 48 therefore understates every guard. The per-family
    # split is what makes the number legible.
    per_family: dict = field(default_factory=dict)
    # --- cost: what the guard spent on model calls, verdict pass only ---------
    llm_configured: bool = False  # the guard would call a model as configured
    llm_exercised: bool = False  # ...and this run actually let it
    llm_site: str | None = None
    model: str | None = None
    provider: str | None = None
    tokens_out_cap: int | None = None
    prompt_overhead_tokens: int | None = None
    content_cap_chars: int | None = None
    cases_with_verdict: int = 0
    llm_calls: int = 0
    llm_calls_attack: int = 0
    llm_calls_benign: int = 0
    cache_hits: int = 0
    tokens_in: list[int] = field(default_factory=list)
    tokens_out: list[int] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    human: int = 0
    fail_mode: str = "n/a"
    notes: list[str] = field(default_factory=list)
    # Output cases (model responses) reach OUTPUT-stage guards only; a manipulative one
    # is counted here and in `per_family`, never in the input headline above.
    output_seen: int = 0
    output_caught: int = 0

    @property
    def catch_rate(self) -> float | None:
        return self.attacks_caught / self.attacks_seen if self.attacks_seen else None

    @property
    def false_positive_rate(self) -> float | None:
        return self.benign_broken / self.benign_seen if self.benign_seen else None

    @property
    def output_catch_rate(self) -> float | None:
        return self.output_caught / self.output_seen if self.output_seen else None

    @property
    def benign_modified_rate(self) -> float | None:
        return self.benign_modified / self.benign_seen if self.benign_seen else None

    @property
    def human_rate(self) -> float | None:
        return self.human / self.cases_with_verdict if self.cases_with_verdict else None

    @property
    def p50(self) -> float | None:
        return statistics.median(self.latencies_ms) if self.latencies_ms else None

    @property
    def p99(self) -> float | None:
        if not self.latencies_ms:
            return None
        ordered = sorted(self.latencies_ms)
        idx = min(len(ordered) - 1, int(round(0.99 * (len(ordered) - 1))))
        return ordered[idx]

    # --- cost figures ------------------------------------------------------
    @property
    def llm_calls_per_case(self) -> float | None:
        if not self.llm_configured or not self.cases_with_verdict:
            return None
        return self.llm_calls / self.cases_with_verdict

    @property
    def llm_calls_per_attack(self) -> float | None:
        if not self.llm_configured or not self.attacks_seen:
            return None
        return self.llm_calls_attack / self.attacks_seen

    @property
    def llm_calls_per_benign(self) -> float | None:
        if not self.llm_configured or not self.benign_seen:
            return None
        return self.llm_calls_benign / self.benign_seen

    @property
    def tokens_in_per_call(self) -> int | None:
        return int(statistics.median(self.tokens_in)) if self.tokens_in else None

    @property
    def tokens_out_per_call(self) -> int | None:
        return int(statistics.median(self.tokens_out)) if self.tokens_out else None

    @property
    def cost_basis(self) -> str:
        """The weakest basis among the calls made; `none` for a guard that made none."""
        return weakest_basis(self.bases) if self.bases else "none"

    @property
    def cache_hit_rate(self) -> float | None:
        total = self.llm_calls + self.cache_hits
        return self.cache_hits / total if total else None

    def record_usage(self, usage: LLMUsage | None, kind: str) -> None:
        """Fold one verdict-pass usage record into the cost figures."""
        if usage is None:
            return
        if usage.cache_hit:
            self.cache_hits += 1
            return
        if usage.calls < 1:
            return
        self.llm_calls += usage.calls
        if kind == "attack":
            self.llm_calls_attack += usage.calls
        else:
            self.llm_calls_benign += usage.calls
        self.bases.append(usage.cost_basis)
        if usage.tokens_in is not None:
            self.tokens_in.append(usage.tokens_in)
        if usage.tokens_out is not None:
            self.tokens_out.append(usage.tokens_out)

    def to_profile(self, measured_on: str) -> Profile:
        return Profile(
            false_positive_rate=self.false_positive_rate,
            benign_modified_rate=self.benign_modified_rate,
            p50_latency_ms=round(self.p50, 3) if self.p50 is not None else None,
            p99_latency_ms=round(self.p99, 3) if self.p99 is not None else None,
            tokens_in_per_call=self.tokens_in_per_call,
            tokens_out_per_call=self.tokens_out_per_call,
            cost_basis=self.cost_basis if self.llm_configured else None,
            human_rate=self.human_rate,
            sample_size=len(self.latencies_ms) or None,
            measured_on=measured_on,
        )


# How many timed calls each case gets. The recorded latency is the median of
# them: with one call per case, p99 over a 90-case corpus is the second-slowest
# call, and a single scheduler hiccup on a shared CI runner fails the build
# while telling nothing about the guard. A case that is slow every time still
# shows; a call that was slow once does not.
TIMING_PASSES = 3

OFFLINE_NOTE_INLINE = (
    "judge not exercised: offline run; latency excludes the judge call; tokens estimated "
    "from the prompt the guard would send. Pass --allow-provider-calls to measure them."
)
OFFLINE_NOTE_FILTER = (
    "judge not exercised: offline run; verdicts are not measured and the catch rate is "
    "not meaningful; tokens estimated. Pass --allow-provider-calls to measure them."
)
OFFLINE_NOTE_NEMO = "offline: NeMo needs a live model; pass --allow-provider-calls"
OFFLINE_NOTE_UNKNOWN_JUDGE = (
    "judge not exercised: offline run, and the judge's prompt is not one this tool can "
    "render, so its tokens are unavailable rather than estimated. Pass "
    "--allow-provider-calls to measure them."
)
CACHE_NOTE = (
    "a CachedJudge wraps the judge; it was cleared before every timing pass so the latency "
    "and tokens describe the judge, not the cache"
)
APPROVAL_NOTE = (
    "approval gate auto-approves without an approval_callback; human_rate is not exercised"
)


def _context_for(case: ProbeCase, tag: str) -> dict:
    # A fresh context per call: the pipeline threads one dict through a
    # request, and reusing it here would let PII token maps, session counters
    # and rate-limiter buckets leak between unrelated measurements. The stage
    # key is what `_run_stage` writes for `run_input`, where policy guards run.
    stage = "output" if case.kind == "output" else "input"
    ctx: dict = {"user_id": f"measure-{case.id}-{tag}", "role": "admin", "guardrail_stage": stage}
    if case.family == "tool_abuse":
        ctx["tool_call"] = {"name": "send_email", "arguments": {"body": case.payload}}
    return ctx


class _OfflineJudge(LLMJudgeBase):
    """
    Stands in for a real judge in an offline run: it never calls anything, answers
    `safe` with no claim of having judged, and records the ESTIMATED usage of the
    call the real judge would have made. The measurement marks the guard as not
    exercised, so the safe answer is never read as a verdict. A judge whose prompt
    the estimator cannot render (a third-party class) records `unavailable`: the
    call is counted, its tokens are not invented.
    """

    def __init__(self, site: estimate.CallSite | None, inner: Any) -> None:
        super().__init__(
            fail_open=bool(getattr(inner, "fail_open", True)),
            timeout=float(getattr(inner, "timeout", 10.0) or 10.0),
        )
        self._site = site
        self.name = str(getattr(inner, "name", "") or "judge")
        self.model = site.model if site is not None else str(getattr(inner, "model", "") or "")
        self.provider = (
            site.provider if site is not None else str(getattr(inner, "provider", "") or "")
        )

    async def _call(self, content, role, conversation_history) -> JudgeVerdict:
        if self._site is None:
            usage = LLMUsage.unavailable_for(self.model, self.provider)
        else:
            usage = estimate.estimate_call(self._site, content, conversation_history)
        return JudgeVerdict(safe=True, judge_name=self.name, usage=usage)


def _inner_judge(guard: GuardrailBase) -> Any:
    return getattr(guard, "_judge", None)


def _cache_of(judge: Any) -> Any:
    """The outermost CachedJudge in a judge chain, or None."""
    current = judge
    while current is not None:
        if hasattr(current, "clear") and hasattr(current, "_cache"):
            return current
        current = getattr(current, "_judge", None)
    return None


def fail_mode_of(guard: GuardrailBase) -> str:
    """
    What the guard does when its model call fails: `open` lets traffic through,
    `closed` blocks it, `mixed` depends on the tool (LLMToolFilter's
    high_risk_fail_closed), `n/a` for a guard that calls no model.
    """
    name = getattr(guard, "name", "")
    if name == "prompt_injection":
        return "open" if getattr(guard, "llm_judge", False) else "n/a"
    if name == "toxicity_output":
        return "open" if getattr(guard, "use_llm_judge", False) else "n/a"
    if name == "nemo_rails":
        return "open" if getattr(guard, "_fail_open", True) else "closed"
    judge = _inner_judge(guard)
    if judge is None:
        return "n/a"
    fail_open = bool(getattr(judge, "fail_open", True))
    if name == "llm_tool_filter" and fail_open and getattr(guard, "high_risk_fail_closed", None):
        return "mixed"
    return "open" if fail_open else "closed"


def _prepare_offline(
    guard: GuardrailBase, site: estimate.CallSite | None, judge: Any, m: GuardMeasurement
):
    """
    Switch a judge-backed guard to its offline shape for the run. Returns a
    callable that restores the guard, and the function that says whether a case
    WOULD have called the judge (None when the guard records its own usage).
    """
    name = getattr(guard, "name", "")
    if name == "prompt_injection":
        guard.llm_judge = False  # type: ignore[attr-defined]
        m.notes.append(OFFLINE_NOTE_INLINE)

        def restore() -> None:
            guard.llm_judge = True  # type: ignore[attr-defined]

        return restore, (lambda result: result.action == Action.ALLOW)
    if name == "toxicity_output":
        guard.use_llm_judge = False  # type: ignore[attr-defined]
        m.notes.append(OFFLINE_NOTE_INLINE)

        def restore() -> None:
            guard.use_llm_judge = True  # type: ignore[attr-defined]

        return restore, (lambda result: result.action == Action.ALLOW)
    if judge is not None:
        guard._judge = _OfflineJudge(site, judge)  # type: ignore[attr-defined]
        m.notes.append(OFFLINE_NOTE_FILTER if site is not None else OFFLINE_NOTE_UNKNOWN_JUDGE)

        def restore() -> None:
            guard._judge = judge  # type: ignore[attr-defined]

        return restore, None
    return (lambda: None), None


async def measure_guard(
    guard: GuardrailBase,
    cases: list[ProbeCase],
    timing_passes: int = TIMING_PASSES,
    *,
    provider_calls: bool = False,
) -> GuardMeasurement:
    """
    Run every case through one guard, alone, and record what it did.

    Verdicts come from the first call of each case; the latency recorded for a
    case is the median of `timing_passes` calls. A single slow call -- a lazily
    compiled pattern on the very first case, a scheduler hiccup on a shared CI
    host -- is then one outlying sample, not the case's latency, and cannot set
    the guard's p99 on its own.

    `provider_calls=False` (the default) never lets a judge call its model: the
    guard runs on its regex path, the tokens the judge would have spent are
    estimated from the exact prompt, and `llm_exercised` stays False.
    """
    m = GuardMeasurement(
        guard_name=guard.name,
        stage=getattr(guard.stage, "value", str(guard.stage)),
    )
    timing_passes = max(1, timing_passes)
    verdicts_failed = 0

    site = estimate.site_for(guard)
    judge = _inner_judge(guard)
    # A guard is judge-backed when the estimator knows its call site OR it holds a
    # judge object the estimator cannot render; the two differ only in whether an
    # offline run can estimate the tokens.
    m.llm_configured = site is not None or judge is not None
    m.fail_mode = fail_mode_of(guard)
    if site is not None:
        m.llm_site = site.id
        m.model = site.model or None
        m.provider = site.provider or None
        m.tokens_out_cap = site.max_tokens
        m.content_cap_chars = site.content_cap
        m.prompt_overhead_tokens = estimate.prompt_overhead_tokens(site)
    elif judge is not None:
        m.llm_site = f"judge:{getattr(judge, 'name', '') or 'unknown'}"
        m.model = str(getattr(judge, "model", "") or "") or None
        m.provider = str(getattr(judge, "provider", "") or "") or None
    if getattr(guard, "name", "") == "tool_policy" and getattr(guard, "require_approval", None):
        if getattr(guard, "approval_callback", None) is None:
            m.notes.append(APPROVAL_NOTE)

    restore = lambda: None  # noqa: E731
    would_call = None
    if m.llm_configured and not provider_calls:
        if site is not None and site.id == "nemo_rails":
            m.unavailable = OFFLINE_NOTE_NEMO
            return m
        restore, would_call = _prepare_offline(guard, site, judge, m)
    cache = _cache_of(judge) if provider_calls else None
    if cache is not None:
        m.notes.append(CACHE_NOTE)

    try:
        for case in cases:
            if case.kind == "output" and m.stage != "output":
                continue  # a response is not this guard's traffic
            samples: list[float] = []
            result = None
            for pass_no in range(timing_passes):
                if cache is not None:
                    cache.clear()
                started = time.perf_counter()
                try:
                    outcome = await guard(case.payload, _context_for(case, f"t{pass_no}"))
                except Exception as exc:  # noqa: BLE001 - report, never crash the run
                    # Every failed call is recorded, timing passes included: a
                    # guard that raises on its second call per payload is a
                    # finding, not a warm-up to hide. Only the verdict pass counts
                    # towards `unavailable`, which means "could not get verdicts".
                    m.errors.append(f"{case.id}/t{pass_no}: {type(exc).__name__}: {exc}")
                    if pass_no == 0:
                        verdicts_failed += 1
                        if verdicts_failed >= 3 and not m.unavailable:
                            m.unavailable = f"{type(exc).__name__}: {exc}"[:120]
                    continue
                samples.append((time.perf_counter() - started) * 1000)
                if pass_no == 0:
                    result = outcome
            if result is None:
                continue
            # The median of the calls that completed; a failed timing pass is in
            # `errors` above, and the case's figure rests on fewer samples.
            m.latencies_ms.append(statistics.median(samples))
            m.cases_with_verdict += 1

            if m.llm_configured:
                if would_call is not None and site is not None:
                    # The inline judges run only when the regex layer found nothing.
                    if would_call(result):
                        m.record_usage(estimate.estimate_call(site, case.payload), case.kind)
                else:
                    usage = LLMUsage.from_metadata(result.metadata.get("llm_usage"))
                    m.record_usage(usage, case.kind)
                    if (
                        provider_calls
                        and usage is not None
                        and (usage.calls > 0 or usage.cache_hit)
                    ):
                        m.llm_exercised = True
                    error = result.metadata.get("judge_error")
                    if provider_calls and error:
                        m.errors.append(f"{case.id}/judge: {error}")

            fired = result.action != Action.ALLOW
            if result.action == Action.HUMAN:
                m.human += 1
            sanitized = (
                result.sanitized_content if result.sanitized_content is not None else case.payload
            )

            if case.kind == "output" and case.verdict == "manipulative":
                m.output_seen += 1
                fam = m.per_family.setdefault(case.family, {"seen": 0, "caught": 0})
                fam["seen"] += 1
                if fired:
                    m.output_caught += 1
                    fam["caught"] += 1
                elif len(m.missed_examples) < 5:
                    m.missed_examples.append({"id": case.id, "family": case.family})
            elif case.kind == "attack":
                m.attacks_seen += 1
                fam = m.per_family.setdefault(case.family, {"seen": 0, "caught": 0})
                fam["seen"] += 1
                if fired:
                    m.attacks_caught += 1
                    fam["caught"] += 1
                elif len(m.missed_examples) < 5:
                    m.missed_examples.append({"id": case.id, "family": case.family})
            else:
                m.benign_seen += 1
                blocked = result.action == Action.BLOCK
                lost = bool(case.must_survive) and case.must_survive not in sanitized
                if blocked or lost:
                    m.benign_broken += 1
                    if len(m.broken_examples) < 5:
                        m.broken_examples.append(
                            {
                                "id": case.id,
                                "tempts": case.tempts,
                                "reason": "blocked" if blocked else "redacted required text",
                                "payload": case.payload[:120],
                            }
                        )
                elif fired:
                    # Redacted or flagged, but the request still goes through and
                    # the text that had to survive did. Not a break.
                    m.benign_modified += 1
    finally:
        restore()

    return m


def describe_measurement(
    attacks: int, benign: int, *, output: int = 0, provider_calls: bool = False
) -> str:
    """The `measured_on` provenance string: corpus size, how latency was sampled,
    and whether judge calls were made or estimated."""
    mode = (
        "provider calls allowed" if provider_calls else "offline (judge calls estimated, not made)"
    )
    return (
        f"aisafe probe corpus ({attacks} attack + {benign} benign"
        + (f" + {output} output" if output else "")
        + "), "
        f"latency = per-case median of {TIMING_PASSES} calls; {mode}"
    )


def collect_guards(
    pipeline: GuardrailPipeline, include_policy: bool = False
) -> list[GuardrailBase]:
    """
    The guards a config enables, each once. Policy-stage guards run inside
    `run_input` in the real pipeline but are measured only on request: the EU
    guard's prohibited-practice patterns block adversarially benign cases, and
    switching them into the default run would move the CI ratchet in the same
    change.
    """
    groups: list[list[GuardrailBase]] = [
        pipeline.input_guards,
        pipeline.processing_guards,
        pipeline.output_guards,
    ]
    if include_policy:
        groups.append(pipeline.policy_guards)
    seen, guards = set(), []
    for group in groups:
        for g in group:
            if id(g) not in seen:
                seen.add(id(g))
                guards.append(g)
    return guards


# ---------------------------------------------------------------------------
# Report provenance: what was measured, from which config, naming which models
# ---------------------------------------------------------------------------


def config_digest(config_path: str | Path | None) -> str | None:
    """
    sha256 of the config file's bytes, or None when there is no file to digest.

    Pins a report to the exact config it measured. A report whose digest no
    longer matches the deployed config describes a pipeline that is not the
    one running, however recent its `generated_at`.
    """
    if config_path is None:
        return None
    try:
        return hashlib.sha256(Path(config_path).read_bytes()).hexdigest()
    except OSError:
        return None


def _load_config(config_path: str | Path | None) -> dict:
    if config_path is None:
        return {}
    try:
        cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return cfg if isinstance(cfg, dict) else {}


def config_models(config_path: str | Path | None) -> list[str]:
    """
    Model ids the config NAMES for its LLM judges, sorted and unique.

    Only what an enabled guard's config spells out under one of MODEL_KEYS
    counts. A guard's built-in default model is never reported: an empty list
    means the config names no model, not that no model would run. Unreadable
    or malformed configs also yield [] -- the pipeline build reports those.
    """
    cfg = _load_config(config_path)
    names: set[str] = set()
    for stage in STAGE_KEYS:
        stage_cfg = cfg.get(stage)
        if not isinstance(stage_cfg, dict):
            continue
        for guard_cfg in stage_cfg.values():
            if not isinstance(guard_cfg, dict) or not guard_cfg.get("enabled", True):
                continue
            for key in MODEL_KEYS:
                value = guard_cfg.get(key)
                if isinstance(value, str) and value.strip():
                    names.add(value.strip())
    return sorted(names)


def pipeline_settings(config_path: str | Path | None) -> dict:
    """
    The `pipeline:` block as `GuardrailPipeline.from_config` reads it:
    `parallel_checks` (default true), `fail_open` (default false) and
    `request_timeout` (null when unset or 0). `aisafe decide` needs
    `parallel_checks` to know whether guard latencies add up or overlap.
    """
    block = _load_config(config_path).get("pipeline")
    block = block if isinstance(block, dict) else {}
    timeout = block.get("request_timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        timeout = None
    return {
        "parallel_checks": bool(block.get("parallel_checks", True)),
        "fail_open": bool(block.get("fail_open", False)),
        "request_timeout": float(timeout) if timeout is not None else None,
    }


def build_report(
    measurements: list[GuardMeasurement],
    config_path: str | Path | None,
    attacks: int,
    benign: int,
    thresholds: Thresholds,
    *,
    provider_calls: bool = False,
    include_policy: bool = False,
    output: int = 0,
) -> dict:
    """
    The JSON document `aisafe measure` writes. Pure: no I/O beyond reading the
    config file for its digest, named models and pipeline block.

    Deliberately absent: any precision figure (the corpus is a stand-in and
    cannot ground one), any dollar figure (prices are `aisafe decide`'s dated
    table, not a measurement) and any compliance verdict.
    """
    measured_on = describe_measurement(
        attacks, benign, output=output, provider_calls=provider_calls
    )
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "measured_on": measured_on,
        "models": config_models(config_path),
        "config_digest": config_digest(config_path),
        "config": str(config_path),
        "pipeline": pipeline_settings(config_path),
        "corpus": {
            "attacks": attacks,
            "benign": benign,
            "output": output,
            "timing_passes": TIMING_PASSES,
            "provider_calls": provider_calls,
            "policy_guards_included": include_policy,
        },
        "thresholds": {
            "min_precision": thresholds.min_precision,
            "max_false_positive_rate": thresholds.max_false_positive_rate,
            "max_p99_latency_ms": thresholds.max_p99_latency_ms,
        },
        "disclaimer": (
            "Measured against the shipped corpora, which stand in for real traffic "
            "and do not replace it. Not an assessment of compliance with any "
            "regulation, and not evidence that untested inputs are handled."
        ),
        "guards": [
            {
                "name": m.guard_name,
                "stage": m.stage,
                "unavailable": m.unavailable,
                "attacks_seen": m.attacks_seen,
                "attacks_caught": m.attacks_caught,
                "catch_rate": m.catch_rate,
                "catch_rate_by_family": {
                    fam: {**v, "rate": v["caught"] / v["seen"] if v["seen"] else None}
                    for fam, v in sorted(m.per_family.items())
                },
                "benign_seen": m.benign_seen,
                "benign_broken": m.benign_broken,
                "benign_modified": m.benign_modified,
                "false_positive_rate": m.false_positive_rate,
                "p50_latency_ms": m.p50,
                "p99_latency_ms": m.p99,
                "threshold_failures": thresholds.failures(m.to_profile(measured_on)),
                # An output guard inspects responses: its input catch rate measures the
                # wrong thing unless the output corpus reached it (`output_catch_rate`);
                # a judge that was not exercised produced no verdicts worth a rate.
                "catch_rate_meaningful": (m.stage != "output" or m.output_seen > 0)
                and not (m.llm_configured and not m.llm_exercised),
                "broken_examples": m.broken_examples,
                "missed_examples": m.missed_examples,
                "errors": m.errors[:5],
                "llm_configured": m.llm_configured,
                "llm_exercised": m.llm_exercised,
                "llm_site": m.llm_site,
                "model": m.model,
                "provider": m.provider,
                "llm_calls_per_case": m.llm_calls_per_case,
                "llm_calls_per_attack": m.llm_calls_per_attack,
                "llm_calls_per_benign": m.llm_calls_per_benign,
                "tokens_in_per_call": m.tokens_in_per_call,
                "tokens_out_per_call": m.tokens_out_per_call,
                "tokens_out_cap": m.tokens_out_cap,
                "prompt_overhead_tokens": m.prompt_overhead_tokens,
                "content_cap_chars": m.content_cap_chars,
                "cost_basis": m.cost_basis,
                "cache_hit_rate": m.cache_hit_rate,
                "human_rate": m.human_rate,
                "fail_mode": m.fail_mode,
                "benign_modified_rate": m.benign_modified_rate,
                "notes": list(m.notes),
                "output_seen": m.output_seen,
                "output_caught": m.output_caught,
                "output_catch_rate": m.output_catch_rate,
            }
            for m in measurements
        ],
    }


def _fmt_tokens(m: GuardMeasurement) -> str:
    if not m.llm_configured:
        return "-"
    if m.tokens_in_per_call is None and m.tokens_out_per_call is None:
        return "?"
    return f"{m.tokens_in_per_call if m.tokens_in_per_call is not None else '?'}/" + (
        f"{m.tokens_out_per_call if m.tokens_out_per_call is not None else '?'}"
    )


def render_table(rows: list[GuardMeasurement], thresholds: Thresholds) -> str:
    header = (
        "guard",
        "stage",
        "attacks",
        "caught (all)",
        "benign",
        "broken",
        "modified",
        "p50 ms",
        "p99 ms",
        "llm calls/case",
        "tok in/out",
        "basis",
        "default-on",
    )
    body = []
    for m in rows:
        if m.unavailable:
            body.append(
                (
                    m.guard_name,
                    m.stage,
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "unavailable",
                )
            )
            continue
        fails = thresholds.failures(m.to_profile(""))
        body.append(
            (
                m.guard_name,
                m.stage,
                str(m.attacks_seen),
                f"{m.attacks_caught} ({m.catch_rate:.0%})" if m.attacks_seen else "-",
                str(m.benign_seen),
                f"{m.benign_broken} ({m.false_positive_rate:.0%})" if m.benign_seen else "-",
                str(m.benign_modified) if m.benign_seen else "-",
                f"{m.p50:.2f}" if m.p50 is not None else "-",
                f"{m.p99:.2f}" if m.p99 is not None else "-",
                f"{m.llm_calls_per_case:.2f}" if m.llm_calls_per_case is not None else "-",
                _fmt_tokens(m),
                m.cost_basis if m.llm_configured else "-",
                "yes" if not fails else "NO",
            )
        )
    # An output guard inspects model responses, not user input. Scoring it
    # against an input corpus measures the wrong thing, so say so rather
    # than print a number that looks like a grade.

    rows_all = [header, *body]
    widths = [max(len(r[i]) for r in rows_all) for i in range(len(header))]
    out = []
    for i, r in enumerate(rows_all):
        out.append("  ".join(c.ljust(widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            out.append("  ".join("-" * w for w in widths))
    return "\n".join(out)


def render_family_matrix(rows: list[GuardMeasurement]) -> str:
    """
    Catch rate per attack family.

    The headline column scores every guard against all 48 attacks, which is not
    the question anyone is asking: pii_detector has 8 PII cases to catch, not
    48. Read a guard along its own row and judge it on the families it is
    responsible for.
    """
    families = sorted({f for m in rows for f in m.per_family})
    if not families:
        return ""
    short = {f: f.replace("_", " ")[:12] for f in families}
    header = ("guard", *[short[f] for f in families])
    body = []
    for m in rows:
        if m.unavailable:
            continue
        cells = []
        for f in families:
            v = m.per_family.get(f)
            cells.append(f"{v['caught']}/{v['seen']}" if v and v["seen"] else "-")
        body.append((m.guard_name, *cells))
    if not body:
        return ""
    rows_all = [header, *body]
    widths = [max(len(r[i]) for r in rows_all) for i in range(len(header))]
    out = ["caught, by attack family:"]
    for i, r in enumerate(rows_all):
        out.append("  " + "  ".join(c.ljust(widths[j]) for j, c in enumerate(r)).rstrip())
        if i == 0:
            out.append("  " + "  ".join("-" * w for w in widths))
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisafe measure",
        description=("Measure what each guard catches, what it breaks, and what it costs."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Numbers are measured against the shipped corpora, which are a proxy\n"
            "for your traffic, not a substitute for it. Point --config at the\n"
            "pipeline you actually deploy. Judge-backed guards do not call their\n"
            "provider unless --allow-provider-calls is given; their tokens are\n"
            "then estimated from the prompt they would send, and the report says so.\n"
        ),
    )
    p.add_argument(
        "--config",
        default=None,
        help="Pipeline YAML to measure (default: the packaged default.yaml preset)",
    )
    p.add_argument("--families", nargs="*", default=None, help="Limit the attack families")
    p.add_argument(
        "--no-benign",
        action="store_true",
        help="Skip the benign corpus. Not recommended -- it is the half that catches over-blocking.",
    )
    p.add_argument(
        "--max-p99-ms",
        type=float,
        default=None,
        metavar="MS",
        help="Latency budget. A guard exceeding it is reported as not default-on.",
    )
    p.add_argument(
        "--allow-provider-calls",
        action="store_true",
        help=(
            "Let judge-backed guards call their model (costs money, needs credentials). "
            "Default: offline, with tokens estimated and the judge marked not exercised."
        ),
    )
    p.add_argument(
        "--include-policy",
        action="store_true",
        help="Also measure the policy-stage guards (eu_ai_act, nist_ai_rmf, nemo_rails).",
    )
    p.add_argument("--output", "-o", default=DEFAULT_REPORT, help=f"Report path ({DEFAULT_REPORT})")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.config:
        config_path = Path(args.config)
        if not config_path.is_file():
            print(f"Error: config not found: {config_path}", file=sys.stderr)
            return 2
    else:
        from aisafe.config import preset_path

        config_path = preset_path("default.yaml")

    try:
        pipeline = GuardrailPipeline.from_config(config_path)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: could not build a pipeline from {config_path}: {exc}", file=sys.stderr)
        return 2

    guards = collect_guards(pipeline, include_policy=args.include_policy)
    if not guards:
        print(f"Error: {config_path} enables no guards.", file=sys.stderr)
        return 2

    cases = load_corpus(args.families, include_benign=not args.no_benign, include_output=True)
    attacks = [c for c in cases if c.kind == "attack"]
    benign = [c for c in cases if c.kind == "benign"]
    output = [c for c in cases if c.kind == "output"]

    print(f"config : {config_path}")
    print(f"guards : {len(guards)}")
    print(f"corpus : {len(attacks)} attack + {len(benign)} benign + {len(output)} output")
    print(
        "judges : "
        + (
            "provider calls allowed (tokens measured)"
            if args.allow_provider_calls
            else "offline; tokens estimated, judges not exercised"
        )
        + "\n"
    )
    if not benign:
        print(
            "WARNING: measuring attacks only. A guard that blocks everything scores\n"
            "         perfectly against this corpus. Drop --no-benign.\n",
            file=sys.stderr,
        )

    thresholds = Thresholds(max_p99_latency_ms=args.max_p99_ms)
    measurements = [
        asyncio.run(measure_guard(g, cases, provider_calls=args.allow_provider_calls))
        for g in guards
    ]

    print(render_table(measurements, thresholds))
    print()
    print(render_family_matrix(measurements))

    output_stage = [
        m for m in measurements if m.stage == "output" and not m.unavailable and not m.output_seen
    ]
    if output_stage:
        names = ", ".join(m.guard_name for m in output_stage)
        print(
            f"\nNOTE: {names} run at the OUTPUT stage. They inspect model "
            "responses,\n      and the shipped corpus is user input, so their "
            "catch rate above\n      measures the wrong thing. Their benign and "
            "latency columns are\n      still valid. A response corpus is needed "
            "for a fair catch rate."
        )
    not_exercised = [
        m for m in measurements if m.llm_configured and not m.llm_exercised and not m.unavailable
    ]
    if not_exercised:
        names = ", ".join(m.guard_name for m in not_exercised)
        print(
            f"\nNOTE: {names} would call a model and did not: offline run. Their\n"
            "      tokens are estimates of the prompt they send; their catch rate\n"
            "      counts the regex path only. Re-run with --allow-provider-calls\n"
            "      to measure the judge."
        )

    measured_on = describe_measurement(
        len(attacks), len(benign), output=len(output), provider_calls=args.allow_provider_calls
    )
    report = build_report(
        measurements,
        config_path,
        len(attacks),
        len(benign),
        thresholds,
        provider_calls=args.allow_provider_calls,
        include_policy=args.include_policy,
        output=len(output),
    )

    demoted = [m for m in measurements if thresholds.failures(m.to_profile(measured_on))]
    unavailable = [m for m in measurements if m.unavailable]

    print()
    for m in measurements:
        if m.broken_examples:
            print(f"{m.guard_name} broke legitimate traffic:")
            for ex in m.broken_examples:
                print(f"  {ex['id']:<9} ({ex['reason']}, tempts {ex['tempts']}) {ex['payload']}")
            print()

    if unavailable:
        print("Not measured:")
        for m in unavailable:
            print(f"  {m.guard_name:<24} {m.unavailable}")
        print("  (these usually need provider credentials or --allow-provider-calls)\n")

    if demoted:
        print("Below threshold -- set the measured profile and they stop firing by default:\n")
        for m in demoted:
            reasons = "; ".join(thresholds.failures(m.to_profile(measured_on)))
            print(f"# {m.guard_name}: {reasons}")
            print(m.to_profile(measured_on).as_source(indent=""))
            print()

    try:
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Report: {args.output}")
        print(f"generated_at: {report['generated_at']}")
    except OSError as exc:
        print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
        return 2

    print(
        "\nThese are measurements against a stand-in corpus, not a safety claim.\n"
        "A guard is a trade: read the caught, broken, latency and token columns together."
    )
    return 1 if demoted else 0


if __name__ == "__main__":
    sys.exit(main())
