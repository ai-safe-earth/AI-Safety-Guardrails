"""
src/aisg/devtools/measure.py
----------------------------
`aisg measure` -- run the attack and benign corpora through a real pipeline,
in-process, and report per guard what it catches, what it breaks, and what it
costs.

    aisg measure
    aisg measure --config config/eu_high_risk.yaml
    aisg measure --max-p99-ms 50

A guardrail is a trade. Measuring only the attack corpus makes "block
everything" the winning strategy: every attack caught, nothing got through, a
clean report. The benign corpus is what stops that being a passing grade.

White-box on purpose. `aisg probe` is black-box over HTTP and can only see what
came back, so it cannot tell a guard blocking a request from a model declining
it. Here the pipeline runs in-process, so `blocked`, `passed` and the sanitized
output are exact rather than inferred.

Each guard is measured in ISOLATION, not through the assembled pipeline: a
sequential pipeline short-circuits on the first block, so guards after it would
never see the payload and would score a spurious zero.
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

import yaml

from aisg.core.base import Action, GuardrailBase
from aisg.core.measurement import Profile, Thresholds
from aisg.core.pipeline import GuardrailPipeline
from aisg.devtools.probe import ProbeCase, load_corpus, utc_now_iso

SCHEMA_VERSION = "aisg/1"
DEFAULT_REPORT = "measure-report.json"

# Guard-config keys that name an LLM-judge model. `judge_model` is what the
# LLM*Filter guards take, `llm_judge_model` is PromptInjectionGuard's; the
# other two are the plain spellings a hand-written config might use.
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
    "GuardMeasurement",
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

    @property
    def catch_rate(self) -> float | None:
        return self.attacks_caught / self.attacks_seen if self.attacks_seen else None

    @property
    def false_positive_rate(self) -> float | None:
        return self.benign_broken / self.benign_seen if self.benign_seen else None

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

    def to_profile(self, measured_on: str) -> Profile:
        return Profile(
            false_positive_rate=self.false_positive_rate,
            p50_latency_ms=round(self.p50, 3) if self.p50 is not None else None,
            p99_latency_ms=round(self.p99, 3) if self.p99 is not None else None,
            sample_size=len(self.latencies_ms) or None,
            measured_on=measured_on,
        )


# How many timed calls each case gets. The recorded latency is the median of
# them: with one call per case, p99 over a 90-case corpus is the second-slowest
# call, and a single scheduler hiccup on a shared CI runner fails the build
# while telling nothing about the guard. A case that is slow every time still
# shows; a call that was slow once does not.
TIMING_PASSES = 3


def _context_for(case: ProbeCase, tag: str) -> dict:
    # A fresh context per call: the pipeline threads one dict through a
    # request, and reusing it here would let PII token maps, session counters
    # and rate-limiter buckets leak between unrelated measurements.
    ctx: dict = {"user_id": f"measure-{case.id}-{tag}", "role": "admin"}
    if case.family == "tool_abuse":
        ctx["tool_call"] = {"name": "send_email", "arguments": {"body": case.payload}}
    return ctx


async def measure_guard(
    guard: GuardrailBase, cases: list[ProbeCase], timing_passes: int = TIMING_PASSES
) -> GuardMeasurement:
    """
    Run every case through one guard, alone, and record what it did.

    Verdicts come from the first call of each case; the latency recorded for a
    case is the median of `timing_passes` calls. A single slow call -- a lazily
    compiled pattern on the very first case, a scheduler hiccup on a shared CI
    host -- is then one outlying sample, not the case's latency, and cannot set
    the guard's p99 on its own.
    """
    m = GuardMeasurement(
        guard_name=guard.name,
        stage=getattr(guard.stage, "value", str(guard.stage)),
    )
    timing_passes = max(1, timing_passes)
    verdicts_failed = 0

    for case in cases:
        samples: list[float] = []
        result = None
        for pass_no in range(timing_passes):
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

        fired = result.action != Action.ALLOW
        sanitized = (
            result.sanitized_content if result.sanitized_content is not None else case.payload
        )

        if case.kind == "attack":
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

    return m


def describe_measurement(attacks: int, benign: int) -> str:
    """The `measured_on` provenance string: corpus size and how latency was sampled."""
    return (
        f"aisg probe corpus ({attacks} attack + {benign} benign), "
        f"latency = per-case median of {TIMING_PASSES} calls"
    )


def collect_guards(pipeline: GuardrailPipeline) -> list[GuardrailBase]:
    seen, guards = set(), []
    for group in (pipeline.input_guards, pipeline.processing_guards, pipeline.output_guards):
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


def config_models(config_path: str | Path | None) -> list[str]:
    """
    Model ids the config NAMES for its LLM judges, sorted and unique.

    Only what an enabled guard's config spells out under one of MODEL_KEYS
    counts. A guard's built-in default model is never reported: an empty list
    means the config names no model, not that no model would run. Unreadable
    or malformed configs also yield [] -- the pipeline build reports those.
    """
    if config_path is None:
        return []
    try:
        cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    if not isinstance(cfg, dict):
        return []
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


def build_report(
    measurements: list[GuardMeasurement],
    config_path: str | Path | None,
    attacks: int,
    benign: int,
    thresholds: Thresholds,
) -> dict:
    """
    The JSON document `aisg measure` writes. Pure: no I/O beyond reading the
    config file for its digest and named models.

    Deliberately absent: any precision figure (the corpus is a stand-in and
    cannot ground one) and any compliance verdict.
    """
    measured_on = describe_measurement(attacks, benign)
    return {
        "schema": SCHEMA_VERSION,
        "generated_at": utc_now_iso(),
        "models": config_models(config_path),
        "config_digest": config_digest(config_path),
        "config": str(config_path),
        "corpus": {"attacks": attacks, "benign": benign, "timing_passes": TIMING_PASSES},
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
                "catch_rate_meaningful": m.stage != "output",
                "broken_examples": m.broken_examples,
                "missed_examples": m.missed_examples,
                "errors": m.errors[:5],
            }
            for m in measurements
        ],
    }


def render_table(rows: list[GuardMeasurement], thresholds: Thresholds) -> str:
    header = (
        "guard",
        "stage",
        "attacks",
        "caught (all)",
        "benign",
        "broken",
        "p50 ms",
        "p99 ms",
        "default-on",
    )
    body = []
    for m in rows:
        if m.unavailable:
            body.append((m.guard_name, m.stage, "-", "-", "-", "-", "-", "-", "unavailable"))
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
                f"{m.p50:.2f}" if m.p50 is not None else "-",
                f"{m.p99:.2f}" if m.p99 is not None else "-",
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
        prog="aisg measure",
        description=("Measure what each guard catches, what it breaks, and what it costs."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Numbers are measured against the shipped corpora, which are a proxy\n"
            "for your traffic, not a substitute for it. Point --config at the\n"
            "pipeline you actually deploy.\n"
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
        from aisg.config import preset_path

        config_path = preset_path("default.yaml")

    try:
        pipeline = GuardrailPipeline.from_config(config_path)
    except Exception as exc:  # noqa: BLE001
        print(f"Error: could not build a pipeline from {config_path}: {exc}", file=sys.stderr)
        return 2

    guards = collect_guards(pipeline)
    if not guards:
        print(f"Error: {config_path} enables no guards.", file=sys.stderr)
        return 2

    cases = load_corpus(args.families, include_benign=not args.no_benign)
    attacks = [c for c in cases if c.kind == "attack"]
    benign = [c for c in cases if c.kind == "benign"]

    print(f"config : {config_path}")
    print(f"guards : {len(guards)}")
    print(f"corpus : {len(attacks)} attack + {len(benign)} benign\n")
    if not benign:
        print(
            "WARNING: measuring attacks only. A guard that blocks everything scores\n"
            "         perfectly against this corpus. Drop --no-benign.\n",
            file=sys.stderr,
        )

    thresholds = Thresholds(max_p99_latency_ms=args.max_p99_ms)
    measurements = [asyncio.run(measure_guard(g, cases)) for g in guards]

    print(render_table(measurements, thresholds))
    print()
    print(render_family_matrix(measurements))

    output_stage = [m for m in measurements if m.stage == "output" and not m.unavailable]
    if output_stage:
        names = ", ".join(m.guard_name for m in output_stage)
        print(
            f"\nNOTE: {names} run at the OUTPUT stage. They inspect model "
            "responses,\n      and the shipped corpus is user input, so their "
            "catch rate above\n      measures the wrong thing. Their benign and "
            "latency columns are\n      still valid. A response corpus is needed "
            "for a fair catch rate."
        )

    measured_on = describe_measurement(len(attacks), len(benign))
    report = build_report(measurements, config_path, len(attacks), len(benign), thresholds)

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
        print("  (these usually need provider credentials)\n")

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
        "A guard is a trade: read the caught, broken and latency columns together."
    )
    return 1 if demoted else 0


if __name__ == "__main__":
    sys.exit(main())
