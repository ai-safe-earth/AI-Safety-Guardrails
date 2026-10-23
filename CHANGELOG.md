# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). `scripts/bump_version.py` rewrites every
place the version lives and moves the Unreleased entries under a dated heading;
`python scripts/bump_version.py --check` fails when any of them disagree.

## [Unreleased]

### Changed

- The Claude Code plugin is now called `aisafe`, like the package:
  `claude plugin install aisafe@ai-safe-earth`. It lives in `plugins/aisafe/`. Anyone who
  installed `ai-safety-audit@ai-safe-earth` should uninstall it and install `aisafe`. The
  skill inside keeps its name, `ai-safety-audit`.
- The repository no longer carries copies of the skill in `.claude/skills/` and
  `.agents/skills/`; `aisafe skill install` writes them where a host needs them. The
  plugin's copy is the only mirror. The contributor-only skills, the editor hook and the
  planning documents under `docs/` are gone; `CLAUDE.md` is now a short statement of the
  mission and the principles, and `docs/REFERENCE.md` is the one reference document.

- The GitLab template (`.gitlab-ci-euaiact.yml`) installs `aisafe[devtools]` from PyPI,
  pinned to `AISAFE_VERSION`, instead of from the repository's git tag, now that 0.1.0
  is published. The `AISAFE_SOURCE` variable is gone; a pipeline that set it can drop it.

### Fixed

- The hook bootstrap (`hook.sh`, `hook.ps1`) now fails open when uvx or pipx cannot fetch
  the pinned `aisafe` release, for example offline. Before, the launcher's error status
  reached the agent host: Claude Code reported a hook error, and Cursor could read the
  empty answer to a permission hook as a block. It already failed open when no launcher
  was found or a foreign `aisafe` rejected `hook run`.

## [0.1.0] - 2026-10-19

The first tagged release. The project is AnyAISafe; the distribution, the import
name and the console script are all `aisafe`. (Renamed twice before any release: the
project was "AI Safety Guardrails" with the distribution `aisguard`, then briefly the
distribution `anyaisafe` with the import and command `aisg`; none was published.)

### Added

- Runtime guardrail pipeline (`GuardrailPipeline`, four stages, YAML presets
  `default.yaml` and `eu_high_risk.yaml`) with twelve guards: PII detect / redact /
  tokenize / restore, prompt injection (regex, advanced detectors, mention-vs-use,
  optional LLM judge), rate limiting, LLM input / output / tool filters over
  LlamaGuard, Claude or OpenAI moderation judges, toxicity, tool policy with
  approval gates and session budgets, EU AI Act and NIST AI RMF policy guards,
  NeMo Guardrails integration; LangChain, FastAPI and Anthropic middlewares;
  OpenTelemetry telemetry and a JSONL audit logger.
- `aisafe lint` (EU AI Act static linter, 19 rules, SARIF / JSON / markdown /
  terminal) and `aisafe misalign` (ALIGN-001..008), with explicit, observable
  suppression directives and pyproject-sourced defaults.
- `aisafe init` (the operator's `ai-system-card.yaml`; risk tier recorded as a legal
  determination, never classified by the tool), `aisafe probe` (a fixed attack corpus
  against a live endpoint; reflection is not compliance; only `passed` means passed)
  and `aisafe measure` (what each guard catches, what it breaks on an adversarially
  benign corpus, and its p50 / p99 latency; `Profile` and `Thresholds`).
- `aisafe audit`: 47 rules (AUD-101..AUD-1003) ordered by blast radius over a
  walk -> discover -> Python deep analysis -> rules -> external adapters ->
  baseline -> report pipeline; MEASURED / ASSERTED / UNKNOWN buckets; every rule
  `[UNMEASURED]` until a labelled corpus exists; `recommendation.package` on every
  finding; terminal, JSON, SARIF, markdown and html documents; baselines with
  operator reasons (`--write-baseline`, `--baseline`, `--amend-baseline --accept`);
  never a compliance verdict, never a model call, never an install or a socket.
- The `ai-safety-audit` agent skill (survey, document 1, apply one row per
  approval, document 2, verify), shipped in the wheel and mirrored into
  `.claude/skills/` and `.agents/skills/`; `aisafe skill install|list|diff|path`.
- A performance pass on the audit: 3-4x faster on three real repositories with
  identical findings; `import aisafe` loads the OpenTelemetry-backed telemetry lazily.
- `docs/PLAN.md` and `docs/plan/`: the plan for the complete solution (decision
  tool, hooks and plugin, persons-and-manipulation rules, attestation, fleet).
- Token accounting end to end: `LLMUsage` (`core/measurement.py`) on every
  judge-backed `CheckResult` as `metadata["llm_usage"]`, with a `cost_basis` of
  `none`, `measured`, `estimated` or `unavailable`; `metadata["guard_name"]` on every
  result; the OpenTelemetry meters `guardrail.guard.llm_calls`, `.tokens` and
  `.tokens_per_call`; token fields on the JSONL audit record. Tokens are counted at
  runtime, dollars only offline, from a dated price table (`prices.yaml`: `as_of`,
  `sources`, `stale_after_days`; `aisafe.devtools.prices`).
- `aisafe measure` reports, per guard, tokens in and out, the price at the table's
  rates, the fail mode and whether the judge was exercised. It is offline by default:
  judge calls are estimated from each guard's hoisted prompt constants
  (`llm_judges/estimate.py`, chars / 4) and never made, and a judge that never ran is
  `llm_exercised: false`, which the report and the audit read as UNMEASURED, never as
  0%. `--allow-provider-calls` and `--include-policy` opt in.
- `aisafe decide`: reads the audit report, the measure report, the price table and a
  traffic profile (flags, or the `traffic:` / `budgets:` blocks `aisafe init` now
  writes) and gives every candidate control one of four verdicts, a deterministic
  function of the declared budgets: `apply`, `apply with <config change>`, `defer
  (over budget: ...)`, `unmeasured (run aisafe measure first)`. An unknown budget never
  counts as exceeded and an unknown figure never as zero. The decision document
  (`"kind": "decision"`) is evidence the audit reads back.
- `Budget` and `Thresholds.max_usd_per_request` / `max_human_rate`;
  `GuardrailPipeline(thresholds=...)` (or `pipeline.thresholds:` in a preset) is the
  opt-in runtime demotion of a guard whose MEASURED profile fails the bar; an
  unmeasured guard always runs.
- AUD-806 "Reported guard over the declared budget" (high, `REPORTED <age>`) reads the
  decision document's over-budget rows; AUD-801/cost marks a judge-backed guard whose
  measure report never exercised the judge; `aisafe audit --format html --decision FILE`
  adds the Trade table to the page.
- `aisafe audit --only PATH`: the file-scoped run (walk as usual, filter the records, run
  the file-local rules) whose fingerprints equal the full run's; an unseen path is an
  UNKNOWN row; `target.only` and a "partial run" line say the document is partial.
- `aisafe hook run|install|uninstall|list` (`devtools/hook.py`, host table in
  `devtools/hosts.py`): one adapter for Claude Code, Cursor and Gemini CLI command
  hooks. Secret-shaped literals and `curl | sh`-style commands are denied, protected
  paths and permission-bypass flags ask, edited files are re-audited against the
  baseline, the posture is injected at session start, and a Stop with a new finding
  at or above `fail-on` blocks once. Fails open on its own errors and records them
  in `.aisafe-audit/hook-state.json`; never a model call, an install or a socket;
  `install` prints the diff and writes only with `--yes`. `[tool.aisafe-hook]`.
- The Claude Code plugin (`.claude-plugin/marketplace.json`, `plugins/ai-safety-audit/`
  with `hooks/hooks.json` and the skill as its third mirror): `claude plugin
  marketplace add ai-safe-earth/AnyAISafe`, `claude plugin install
  ai-safety-audit@ai-safe-earth`.
- `action.yml` (composite GitHub Action: JSON, SARIF and markdown documents, job
  summary, Code Scanning upload, optional sticky PR comment, exit code = the audit's),
  `.pre-commit-hooks.yaml` (`aisafe-audit`, `aisafe-lint`, `aisafe-misalign`), the
  `aisafe-audit` GitLab job, and the skill's `scripts/hook.sh` / `hook.ps1` bootstrap.

- P11 "persons and manipulation": AUD-1101..1107 (`rules/persons.py`, 54 rules now, an
  eleventh subsystem on Fig. 1) report a person profile bound into a prompt, emotion or
  biometric inference, scoring or automated decisions about persons, an engagement
  objective (`/vulnerable` critical), a concealed AI nature or no disclosure on the
  response path, no manipulation control, and no recorded prompt review. Three evidence
  tiers: grep (`person_signals`), AST (`PromptLiteral` spans) and the EU AI Act linter
  plus ALIGN-008 run in-process through `lint_bridge` as evidence legs. Prompt-material
  gating and mention-vs-use keep a regex vocabulary from reading as a prompt. Every
  finding carries the caveat that none of it is a legal determination.
- `ManipulationGuard` (`manipulation_output`: six influence tactics, FLAG by default,
  mention-aware, optional `ClaudeJudge(mode="manipulation")` whose failure is a recorded
  FLAG) and `AIDisclosureGuard` (`ai_disclosure_output`: human-identity claims flagged,
  rewritten or blocked, disclosure appended via REDACT). Both presets wire both.
- Corpora: attack family `manipulation_elicitation` (7 families), six benign cases, and
  `manipulation_responses.yaml` (`kind: output`, model responses with a verdict) that
  `aisafe measure` routes to output-stage guards (`output_seen/output_caught/
  output_catch_rate`); `aisafe probe` never sends it.
- `ai-system-card.yaml` gains `prompt_audit` (reviewer, reviewed_at, scope, notes);
  `aisafe init` asks for it. `discover` passes `affected_persons` and `prompt_audit` through.
- `aisafe attest` (`devtools/attest.py`): the deterministic half of declaring a system.
  It reads the audit report and baseline, the measure, probe and decision reports and
  the system card, evaluates the criteria of `attest-levels.yaml` (levels 0 audited,
  1 triaged, 2 measured, 3 governed; 14 criterion kinds; shipped in the wheel and
  mirrored at `config/`) and writes `attestation.json` / `.md` / `.html` and a
  shields.io `badge.json` signed by `--owner`. The level is the highest with every
  criterion of it and below met; each row says what was read and what is missing. Only
  reasoned baseline entries count as accepted, absent inputs are recorded as absent,
  `--owner` and `--check` can never come from `pyproject.toml` (`[tool.aisafe-attest]`
  defaults the rest), `--check --require-level N` is the CI form (exit 1 below N), and
  the disclaimer says the tool checked the listed criteria and nothing else. No model
  call, no install, no socket; git is read through `walk.git_meta`.
- The seven-phase `ai-safety-audit` skill: survey, document 1, decide, apply, document
  2, verify, attest, plus a closing step that offers `aisafe hook install` and the
  GitHub Action by name. Two new hard rules: the bootstrap prints which `aisafe` ran
  (path, version, pin) and the skill stops on a mismatch; nothing is pushed, the
  `gh pr create` line is printed for the user (the PR path: a branch, one commit per
  row with its re-audit result, `pr-body.md` from document 2). New
  `scripts/attest.sh|ps1`; `references/levels.md` generated from the criteria file by
  `scripts/levels_md.py` (`--check` in the release gate); the decision and
  attestation documents in `report-format.md`; `AISAFE_VERIFY_SKIP_TESTS=1` makes
  `verify.sh|ps1` run the offline measure alone, which is how phase 3 gets figures.
- `docs/SYSTEM.md` (the flow on one page: what each step reads, writes and never
  does) and `CONTRIBUTING.md`; `SECURITY.md` scope now covers `decide`, `hook`,
  `attest`, the plugin and the CI surface.
- `aisafe fleet LIST` (`devtools/fleet.py`): the audit over many repositories, one
  `aisafe audit --no-external` subprocess each under a wall-clock cap, from a YAML or CSV
  list the operator wrote (`bench/corpus.yaml` is a valid list);
  `fleet-report.{json,csv,md}` (`kind: fleet`) with counts, rule frequencies, inventory
  highlights and report paths, never a snippet; `--jobs`, `--resume`, `--proposal` (a PR
  body per repository), `--fail-on-findings`. Exit 0 when every repository was audited,
  1 when one could not be. The fleet never searches for targets, pushes or opens a PR.
  `devtools/_git.py` is the shared pinned-fetch implementation (moved from
  `bench/run.py`).
- `bench/run.py --tool audit` and `bench/score.py --tool audit`: the same corpus, label
  loop and scorer for the `AUD-*` rules (`findings-audit.csv` with `sub` and the
  redacted `snippet`; `precision-audit.md`; a paste block keyed by class name). No row
  is labelled yet; every audit rule stays UNMEASURED.

### Changed

- Renamed the project to AnyAISafe, and the distribution, the import and the
  command to `aisafe` (were `aisguard`/`anyaisafe`, `aisg` and `aisg`): the
  repository `github.com/ai-safe-earth/AnyAISafe` (was `AI-Safety-Guardrails`), the
  OpenTelemetry service-name default `aisafe`, `.aisafe-audit/`, `.aisafe-fleet/`,
  `[tool.aisafe-*]`, `# aisafe-audit: ignore-file`, the `AISAFE_*` variables, the
  hook bootstrap `aisafe-hook.sh` and the pre-commit hook ids `aisafe-audit`,
  `aisafe-lint` and `aisafe-misalign`. The old spellings are still read, never
  written. The `aisg/1` schema marker, the probe canaries and the skill name are
  unchanged.
- Art. 5(1) letters in the EU AI Act policy guard and the linter now follow Regulation
  (EU) 2024/1689: real-time remote biometric identification is (h), criminal-risk
  profiling is (d).
- `EUAIActCompliance` and `NISTAIRMFCompliance` return REDACT when they append their
  transparency disclosure on the output stage, so the text reaches `final_content`.
- `EUAIActCodeAnalyzer.scan_source(source, filename, report)` scans text in hand.
- `walk` and `discover` treat `"kind": "attestation"` as the toolchain's own output,
  like the audit report and the inventory; `attestation.html` carries the html marker.
- `measure-report.json`, written into the repository root by a bare `aisafe measure` during
  a gate run and committed by mistake in the skill commit, is removed; the default
  `measure-report.json` / `probe-report.json` output paths are gitignored.
- `scripts/audit.sh|ps1` print `aisafe: <path> version <v> (pinned <v>)` on stderr
  before running. The skill's phases are renumbered: apply is 4, document 2 is 5,
  verify is 6; the offline `aisafe measure` may run in phase 3 with approval.
- AUD-801 counts an eval file's mention of a guard as evidence that the guard is
  exercised only when the file is an eval tool's config, a data file or a test module.
  A README or a tool's own source that names the guard no longer silences the rule.
- AUD-601 does not read the model ids listed in an `aisg/1` price table as
  deployments.
- `PromptInjectionGuard` and `ToxicityFilter` record a failed judge call in
  `metadata["judge_error"]`, with `unavailable` usage, instead of swallowing it
  silently; the two AUD-802 entries on them left the self-audit baseline.

[Unreleased]: https://github.com/ai-safe-earth/AnyAISafe/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ai-safe-earth/AnyAISafe/releases/tag/v0.1.0
