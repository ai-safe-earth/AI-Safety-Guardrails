# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). `scripts/bump_version.py` rewrites every
place the version lives and moves the Unreleased entries under a dated heading;
`python scripts/bump_version.py --check` fails when any of them disagree.

## [Unreleased]

## [0.1.0] - 2026-10-19

The first tagged release. The distribution is `aisguard`; the import name and the
console script are `aisg`.

### Added

- Runtime guardrail pipeline (`GuardrailPipeline`, four stages, YAML presets
  `default.yaml` and `eu_high_risk.yaml`) with twelve guards: PII detect / redact /
  tokenize / restore, prompt injection (regex, advanced detectors, mention-vs-use,
  optional LLM judge), rate limiting, LLM input / output / tool filters over
  LlamaGuard, Claude or OpenAI moderation judges, toxicity, tool policy with
  approval gates and session budgets, EU AI Act and NIST AI RMF policy guards,
  NeMo Guardrails integration; LangChain, FastAPI and Anthropic middlewares;
  OpenTelemetry telemetry and a JSONL audit logger.
- `aisg lint` (EU AI Act static linter, 19 rules, SARIF / JSON / markdown /
  terminal) and `aisg misalign` (ALIGN-001..008), with explicit, observable
  suppression directives and pyproject-sourced defaults.
- `aisg init` (the operator's `ai-system-card.yaml`; risk tier recorded as a legal
  determination, never classified by the tool), `aisg probe` (a fixed attack corpus
  against a live endpoint; reflection is not compliance; only `passed` means passed)
  and `aisg measure` (what each guard catches, what it breaks on an adversarially
  benign corpus, and its p50 / p99 latency; `Profile` and `Thresholds`).
- `aisg audit`: 47 rules (AUD-101..AUD-1003) ordered by blast radius over a
  walk -> discover -> Python deep analysis -> rules -> external adapters ->
  baseline -> report pipeline; MEASURED / ASSERTED / UNKNOWN buckets; every rule
  `[UNMEASURED]` until a labelled corpus exists; `recommendation.package` on every
  finding; terminal, JSON, SARIF, markdown and html documents; baselines with
  operator reasons (`--write-baseline`, `--baseline`, `--amend-baseline --accept`);
  never a compliance verdict, never a model call, never an install or a socket.
- The `ai-safety-audit` agent skill (survey, document 1, apply one row per
  approval, document 2, verify), shipped in the wheel and mirrored into
  `.claude/skills/` and `.agents/skills/`; `aisg skill install|list|diff|path`.
- A performance pass on the audit: 3-4x faster on three real repositories with
  identical findings; `import aisg` loads the OpenTelemetry-backed telemetry lazily.
- `docs/PLAN.md` and `docs/plan/`: the plan for the complete solution (decision
  tool, hooks and plugin, persons-and-manipulation rules, attestation, fleet).
- Token accounting end to end: `LLMUsage` (`core/measurement.py`) on every
  judge-backed `CheckResult` as `metadata["llm_usage"]`, with a `cost_basis` of
  `none`, `measured`, `estimated` or `unavailable`; `metadata["guard_name"]` on every
  result; the OpenTelemetry meters `guardrail.guard.llm_calls`, `.tokens` and
  `.tokens_per_call`; token fields on the JSONL audit record. Tokens are counted at
  runtime, dollars only offline, from a dated price table (`prices.yaml`: `as_of`,
  `sources`, `stale_after_days`; `aisg.devtools.prices`).
- `aisg measure` reports, per guard, tokens in and out, the price at the table's
  rates, the fail mode and whether the judge was exercised. It is offline by default:
  judge calls are estimated from each guard's hoisted prompt constants
  (`llm_judges/estimate.py`, chars / 4) and never made, and a judge that never ran is
  `llm_exercised: false`, which the report and the audit read as UNMEASURED, never as
  0%. `--allow-provider-calls` and `--include-policy` opt in.
- `aisg decide`: reads the audit report, the measure report, the price table and a
  traffic profile (flags, or the `traffic:` / `budgets:` blocks `aisg init` now
  writes) and gives every candidate control one of four verdicts, a deterministic
  function of the declared budgets: `apply`, `apply with <config change>`, `defer
  (over budget: ...)`, `unmeasured (run aisg measure first)`. An unknown budget never
  counts as exceeded and an unknown figure never as zero. The decision document
  (`"kind": "decision"`) is evidence the audit reads back.
- `Budget` and `Thresholds.max_usd_per_request` / `max_human_rate`;
  `GuardrailPipeline(thresholds=...)` (or `pipeline.thresholds:` in a preset) is the
  opt-in runtime demotion of a guard whose MEASURED profile fails the bar; an
  unmeasured guard always runs.
- AUD-806 "Reported guard over the declared budget" (high, `REPORTED <age>`) reads the
  decision document's over-budget rows; AUD-801/cost marks a judge-backed guard whose
  measure report never exercised the judge; `aisg audit --format html --decision FILE`
  adds the Trade table to the page.

### Changed

- AUD-801 counts an eval file's mention of a guard as evidence that the guard is
  exercised only when the file is an eval tool's config, a data file or a test module.
  A README or a tool's own source that names the guard no longer silences the rule.
- AUD-601 does not read the model ids listed in an `aisg/1` price table as
  deployments.
- `PromptInjectionGuard` and `ToxicityFilter` record a failed judge call in
  `metadata["judge_error"]`, with `unavailable` usage, instead of swallowing it
  silently; the two AUD-802 entries on them left the self-audit baseline.

[Unreleased]: https://github.com/ai-safe-earth/AI-Safety-Guardrails/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ai-safe-earth/AI-Safety-Guardrails/releases/tag/v0.1.0
