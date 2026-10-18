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
- `aisg audit`: 46 rules (AUD-101..AUD-1003) ordered by blast radius over a
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

[Unreleased]: https://github.com/ai-safe-earth/AI-Safety-Guardrails/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ai-safe-earth/AI-Safety-Guardrails/releases/tag/v0.1.0
