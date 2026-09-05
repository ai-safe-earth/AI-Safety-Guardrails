# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Layout

`src/` layout. The only importable top-level name is `aisg` — everything is
`aisg.core.*`, `aisg.modules.*`, `aisg.integrations.*`, `aisg.devtools.*`,
`aisg.config.*`. Nothing is importable as a bare `core`/`modules`/`config`,
and it must stay that way: those names would collide with users' own modules
once published to PyPI.

**The distribution name is `aisguard`; the import name and the console script
are `aisg`.** `pip install "aisguard[devtools]"`, then `import aisg` and
`aisg audit .`. They differ because both `ai-safety-guardrails` and `aisg` are
taken on PyPI by unrelated projects — `aisg` there is an AI-gateway SDK that
also imports as `aisg`, so an environment with both installed is broken. Any
install spec, `importlib.metadata` lookup or `pip show` must say `aisguard`
(`audit/report.py:DISTRIBUTION` is the constant); anything a user types or
imports says `aisg`. The prose name of the project stays "AI Safety
Guardrails", and so does the repo, `github.com/ai-safe-earth/AI-Safety-Guardrails`.

`tests/conftest.py` puts `src/` on `sys.path`, so the suite runs without an
install; `examples/*.py` still self-bootstrap with `sys.path.insert(..., "src")`.
Run commands from the repo root.

YAML presets exist twice on purpose: `src/aisg/config/*.yaml` ships in the
wheel as package data (read it with `aisg.config.preset_path()` /
`load_preset()`, never a hard-coded path), and repo-root `config/` is the
local-dev copy. Keep the two in sync when editing either.

## Commands

No Makefile, no script runner — everything is ad-hoc.

```bash
pytest                                                    # ~2700 tests, ~2 min, no API keys (all LLM calls mocked)
python -m pytest tests/unit/test_pii_tokenization.py::TestPIIRestorer -q   # single test
python -m pytest tests/unit/test_pii_tokenization.py -k "roundtrip" -q

ruff format <file>                                        # authoritative formatter
ruff check --fix <file>

aisg lint src/                                            # EU AI Act compliance linter
aisg misalign src/                                        # ALIGN-001..008 rule set
aisg audit .                                              # AI-surface audit, AUD-101..1003 (see below)
aisg skill list                                           # where each agent host keeps skills
```

`aisg` is not on PATH in a bare checkout; `PYTHONPATH=src python -m aisg.cli <verb> ...` is
the equivalent. Set `PYTHONIOENCODING=utf-8` on Windows.

`aisg` is the single console script (`aisg.cli:main`); `euaiact-lint` and
`misalignment-check` remain as aliases. Both subcommands share flags: `--staged`, `--diff`,
`--errors-only`, `--fail-on-warnings`, `--format terminal|json|sarif|markdown`,
`--output <path>`, `--list-rules`. The CLI passes everything after the subcommand through
verbatim (`argparse.REMAINDER`), so `aisg lint --help` shows the linter's own help.
Exit codes: `0` clean, `1` findings, `2` fatal. A path that does not exist is fatal
(exit 2), not a warning, and so is a failing `git diff` under `--staged`/`--diff`:
scanning nothing and exiting 0 reads as a clean result in CI.
Their defaults come from `[tool.euaiact-lint]` / `[tool.misalignment-check]` in
`pyproject.toml` via `src/aisg/devtools/_config.py`, resolved from the CWD (so `paths`
from pyproject do not resolve from a subdirectory; the exit-2 message says where they
came from); an explicit CLI flag always wins, but a `true` boolean there cannot be
switched back off from the command line. `exclude` entries are POSIX path fragments
matched as consecutive segments (`tests/fixtures`) or bare directory names matched
anywhere (`__pycache__`); `analyzer.is_excluded` is the single implementation and
`scan_diff` honours it too, so the pre-commit hook does not block a commit that touches a
fixture the full scan excludes.

**Verify before reporting done:** `pytest`, `ruff check` on changed files, then both `devtools/`
CLIs on the changed modules, then the self-audit:

```bash
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
```

It must exit 0. A non-zero exit means a new finding at `high` or above that is not in the
baseline; either fix it or add it to `audit-baseline.json` with a reason (see below). CI
(`tests.yml`) runs pytest on 3.10 and 3.13, ruff, `aisg measure --max-p99-ms 25` and the
same audit gate; `eu-ai-act-compliance.yml` runs `aisg lint src examples` and fails on
errors only (see "EU AI Act linter suppression" for what is and is not in that gate);
mypy and `aisg misalign` are local-only.

Two CI-only failure modes worth knowing: git's `%cI` writes a UTC committer date with a
`Z` suffix, which `datetime.fromisoformat` only accepts from 3.11 (`audit/walk.py`
normalises it -- 3.10 is in the matrix), and the measure ratchet's p99 over 90 cases is the
second-slowest sample, so one scheduler hiccup on a shared runner used to fail it.

## EU AI Act linter suppression

`aisg lint` and `aisg misalign` share `EUAIActCodeAnalyzer`, and each honours only its
own markers (`analyzer.tool`, default `euaiact-lint`; misalign passes
`misalignment-check`). Two forms, both explicit:

- `# euaiact-lint: ignore-file` within the first five lines skips the file. It is for
  the files that ARE the rule vocabulary -- `code_analyzer/rules/__init__.py` and
  `modules/policy/eu_ai_act.py` spell out every prohibited-practice phrase and would
  otherwise report themselves; `# misalignment-check: ignore-file` sits on
  `devtools/misalignment/rules/__init__.py` for the same reason. A test pins that exactly
  those files under `src/` carry each marker; a real finding anywhere else gets a line
  directive, not the marker.
- `# euaiact-lint: ignore EU-AIA-005a[, ...]` on the finding's own line suppresses that
  rule there. **The rule id is required**; a bare `ignore` is not honoured, so every
  suppression says what it silences. Not spelled `noqa`: ruff parses every `# noqa`
  comment and warns on codes it does not know.

Suppression stays observable: skipped files land in `ScanReport.skipped_files`, silenced
findings in `ScanReport.suppressed_count`, and the JSON summary, terminal and markdown
reporters all print them. A clean run says what it did not look at.

Line numbers are physical lines: the directive lookup, the `source_lines` handed to
`check_ast` and every text rule go through `analyzer.physical_lines()` (`split("\n")`),
never `str.splitlines()`. The latter also breaks on form feed, NEL and U+2028/2029, which
`ast.parse` does not, so after one of those a directive on the finding's line was missed
and one on the line above silenced the *next* finding. A new text rule must use the helper.

The compliance gate scans `src` and `examples`, errors only. `tests/` is outside it on
purpose -- the suite asserts on the very phrases the rules match, and `tests/fixtures/`
is deliberately non-compliant linter input (the pyproject `exclude` keeps it out of a
bare `aisg lint .` too). `tests/unit/test_euaiact_lint.py::TestComplianceGate` runs the
same scan, so a new error in `src`/`examples` fails `pytest` before it fails CI.
`.gitlab-ci-euaiact.yml` is the downstream template of the same gate (pinned PyPI
install, `SCAN_PATH`, errors-only, `|| [ $? -eq 1 ]` after every report call);
`TestCITemplates` parses both files and pins the template's version to `pyproject.toml`.

## Style

- **ruff-format is authoritative**, `line-length = 100`, `target-version = "py310"`. `black>=24.0`
  is in dev deps but has no config and no hook; ignore it — its default of 88 would fight ruff.
- Ruff lint selects `["E", "F", "W", "I"]` and ignores `E501`. Import sorting (`I`) is enforced.
- Codebase conventions not enforced by any config: `from __future__ import annotations` at the top
  of every module, PEP 604 unions (`str | None`), double quotes, and a
  `"""module/path.py\n---------\n"""` docstring header on every file.
- mypy is configured but non-strict and **nothing runs it**.
- `tests/fixtures/` is excluded from both ruff and mypy — it holds deliberately broken linter
  input. `tests/*` and `examples/*` carry a `per-file-ignores` for `E402`, since they must
  call `sys.path.insert` before importing the package.

## Pipeline invariants

These are enforced by the code but easy to violate:

- **`_run_stage` mutates the caller's context dict** (`ctx["guardrail_stage"]`), which
  `eu_ai_act.py` and `nist_ai_rmf.py` read. Passing a shared dict is required, not optional.
- **Reuse one context dict across `run_input`/`run_processing`/`run_output`** (fresh per request).
  PII tokenization (`_pii_token_map`), tool session budgets (`_tool_session_counters`), and the
  rate-limiter key all depend on it.
- **`parallel=True` changes semantics.** Guards see the *original* content and redactions are
  folded in afterwards, so redaction chains do not compose; sequential mode short-circuits on the
  first `BLOCK`, parallel does not. `GuardrailStage.PROCESSING` is always forced sequential.
- **`Action.HUMAN` sets `passed=False` but not `blocked`.** `ToolPolicyGuard` (approval
  denied/timeout), `EUAIActCompliance` (Art. 14) and `NISTAIRMFCompliance` return it. `.blocked`
  stays narrow — a hard rejection — while `PipelineResult.requires_human` and
  `.human_review_reasons` carry the approval signal. `run_full()` raises rather than calling the
  LLM past an approval gate; inspect `exc.result.requires_human` to tell it from a block.
- **`run_processing` takes the tool call as an argument or in the context.** It used to overwrite
  `context["tool_call"]` with `{}` when the argument was omitted, silently disabling every tool
  policy while still reporting a pass. The explicit argument wins when both are given.
- **`fail_open=True` swallows guard exceptions entirely** — no `CheckResult`, no finding, nothing
  in the audit log.
- Judge fail-open is layered and the layers disagree: `LLMJudgeBase.judge()` returns a safe
  fallback, but `LLMToolFilter.high_risk_fail_closed` blocks anyway for
  `send_email`/`database_write`/`payment_process`/`shell_command`/`deploy`.
- `CachedJudge` overrides `_call`, not `judge()`, so it bypasses the wrapped judge's own
  try/except and latency instrumentation.
- `PIIDetector(action="tokenize")` is always regex-only — `_regex_tokenize` runs before the
  `use_presidio` branch.
- `RateLimiter` is in-process only (`deque` + `asyncio.Lock`); no cross-worker coordination, no
  restart survival. "Tokens" are `len(content.split())` — words, not real tokens.
- `TelemetryProvider.__init__` calls the **global** `set_tracer_provider()`/`set_meter_provider()`
  — construct at most one per process.
- `AuditLogger.log()` is `async def` but writes with blocking `open()`/`write` — it stalls the loop.

## Config

Nothing is required — every `Settings` field has a default and the library runs keyless.
`config/settings.py` raises `ImportError` at import if `pydantic-settings` is missing and builds a
module-level `settings = Settings()` singleton at import time. `.env` resolves to the repo root.

`GUARDRAILS_MOCK_JUDGES` and `GUARDRAILS_DISABLE_ALL` are declared in `Settings` and documented in
`.env.example` but **nothing in `core/` or `modules/` reads them** — they are inert.

## Known-broken (do not work around; do not fix unasked)

1. `.secrets.baseline` is gitignored and absent, so `pre-commit run --all-files` fails on the
   `detect-secrets` hook in any fresh clone.
2. (Cleared in `48ded50`: `ruff check .` passes; the `claude_judge.py` `reason` and
   `openai_mod.py` `flags` defects it listed are fixed. Kept so the numbering below stays
   stable.)
3. `examples/advanced_injection_demo.py:68` raises `AttributeError` — it calls `.encode()` on
   the `bytes` returned by `base64.b64encode`. Examples are not covered by pytest.
4. Console output uses `✓`/`✗`, which crashes on a cp1252 Windows terminal. Run examples with
   `PYTHONIOENCODING=utf-8`.
5. (Cleared: GitHub's `codeql-action@v4` upload now validates SARIF strictly and rejected
   the root `"schema": "aisg/1"` key and `region.snippet: null`. Both SARIF emitters --
   `code_analyzer/reporters.py` and `audit/report.py` -- now carry the marker as
   `runs[0].properties.aisg_schema` and omit empty optional fields instead of nulling them;
   every other machine-readable document still starts with `"schema"`. Tests pin the shape;
   the real 2.1.0 schema validates all three CLIs' output. Kept for numbering.)

## `aisg init` and `aisg probe`

`init` (`devtools/system_card.py`) writes `ai-system-card.yaml` -- what the
operator *asserts* about their system. The rendered file carries an inline
caveat above `risk_tier` saying classification is a legal determination, not a
tool output. That caveat is load-bearing and pinned by a test; do not drop it.
`--defaults` is the non-interactive path, and without it the command refuses to
run when stdin is not a tty rather than hanging in CI.

`probe` (`devtools/probe.py`) sends a fixed corpus at a live HTTP endpoint and
reports what got through. Rules that hold:

- **No LLM, ever.** Fixed payloads, fixed detectors, deterministic verdicts.
- **A detector hit means the attack SUCCEEDED**, so a hit is a failure. Exit 1
  if any case got through.
- **Non-2xx is `error`, never `passed`.** A case that never reached a working
  endpoint has not been tested; calling it a pass is a false clean bill of
  health. Only 2xx and `REJECTION_CODES` (400/403/406/409/413/422, i.e. the
  endpoint rejecting the payload) run the detector. A run with errors exits 2.
- A preflight request runs first, so a dead or wrong endpoint fails fast
  instead of producing N misleading rows.
- **Reflection is not compliance.** Most canaries live inside the payload, so an
  endpoint that echoes input reproduces them without the model ever complying.
  When a marker comes back and `reflection_ratio` >= 0.6, the case is
  `inconclusive` -- never `failed`, never `passed`. `pii_echo` is the sole
  exception (`reflection_is_success: true`): there, reflection IS the finding.
  Token overlap rather than verbatim stripping, because a guard that redacts
  something inside the payload breaks an exact match while still echoing.
- **`system_prompt_extraction` needs `--system-canary`.** The secret is the
  target's own prompt, so there is nothing to match without a planted token.
  Those cases are `skipped`, never passed.
- **Only `passed` means passed.** `inconclusive`, `skipped` and `error` are
  counted separately and force exit 2.
- **Never claims compliance.** The report has no verdict field and carries a
  disclaimer; a test greps the JSON for compliance language.
- Non-loopback targets are refused unless `--i-have-authorization` is passed. A
  hostname that is not a literal IP counts as remote even if it would resolve
  to loopback.

The corpus is `src/aisg/probes/*.yaml`, one file per family, 48 cases seeded
from the guards this package already ships -- INJECTION_PATTERNS, PII_PATTERNS,
TOXICITY_PATTERNS, AdvancedInjectionDetectors, high_risk_fail_closed. Every case
records its `seed_pattern`; keep that link when adding cases, and add a case when
adding a detection pattern.

## Measurement: a guard is a trade

`aisg measure` (`devtools/measure.py`) runs the attack **and benign** corpora
through a real pipeline in-process and reports, per guard, what it catches, what
it breaks, and what it costs. Rules that hold:

- **The benign corpus is not optional.** Attacks alone make "block everything"
  optimal. `src/aisg/probes/benign_traffic.yaml` is *adversarially* benign --
  text a naive guard would flag. A benign case fails when the guard BLOCKS it,
  or when `must_survive` text is redacted away; both exact, neither heuristic.
- **Guards are measured in isolation**, not through the assembled pipeline: a
  sequential pipeline short-circuits on the first block, so later guards would
  score a spurious zero.
- **The headline catch rate is scored against all 48 attacks**, including
  families outside a guard's remit. Read the per-family matrix, not the
  headline. Output-stage guards are flagged: they inspect responses, and the
  corpus is user input, so their catch rate measures the wrong thing.
- **`Profile` (`core/measurement.py`) is the shared vocabulary** for guards and
  lint rules: precision, false-positive rate, p50/p99, sample size, provenance.
  `None` is UNMEASURED, never good; unmeasured still fires. `GuardrailBase.
  fires_by_default(thresholds)` demotes a guard for being imprecise, noisy, or
  over a latency budget. Latency has no default cap -- it is deployment-specific.
- **A case's latency is the median of `TIMING_PASSES` (3) calls**; its verdict
  comes from the first. p99 over the 90-case corpus is the second-slowest
  sample, so with one call per case a single scheduler hiccup on a shared CI
  runner set p99 to 32 ms for a 1 ms guard and failed the ratchet. The median
  makes one slow call an outlier, not the figure; a guard that is always slow
  still shows. `sample_size` stays the number of cases, and the report's
  `corpus.timing_passes` and provenance string name the sampling. There is no
  separate warm-up call: it would need to swallow the guard's exception
  (AUD-802), and the median already absorbs a slow first call. For the same
  reason a failed timing pass is not swallowed either: every raising call
  lands in `errors` as `<case>/t<pass>`, and only verdict-pass (`t0`) failures
  count towards `unavailable`.
- Populate a Profile from `aisg measure` output. Never by hand.

Two findings this produced, both still true of the shipped code: the
`prompt_injection` guard breaks ~14% of benign traffic (it blocks security
engineers asking how to defend against injection), and with `llm_judge: true`
and no credentials it costs seconds per request while silently swallowing the
failure at `prompt_injection.py:123`.

Every shipped preset must load: `eu_high_risk.yaml` enabled seven guards that
do not exist and had never been loadable. Tests pin that both presets build a
pipeline and that `config/` and `src/aisg/config/` stay identical.

## Mention vs use

`PromptInjectionGuard` distinguishes text that DISCUSSES an attack from text
attempting one. Without it the guard blocked 14% of benign traffic -- security
engineers asking how to defend against injection, unit tests asserting a phrase
is rejected, docs using `### System:` as a heading. A guard unusable by the
people deploying it is not a guard.

Two signals: the match sits inside a quoted span, or a discussion cue precedes
it. A mention is downgraded to FLAG, never dropped -- the finding stays in the
result so behaviour remains observable.

**`_CONTENT_CUES` vetoes both.** Indirect injection arrives as quoted content
the model is asked to act on ("summarise this ticket: '...'"), so quoting is
precisely how untrusted input reaches a model. The corpus caught this: tool-006
was downgraded to a flag until the veto landed. When in doubt, treat the payload
as live.

`aisg measure` is the arbiter. The fix costs zero attack coverage (21/48 either
way) and takes benign breakage from 10% to 0%. A test asserts the lenient and
strict guards return identical verdicts on every attack case.

Also fixed here: `TokenSmugglingDetector`'s `space_injection` was
`[a-z]+(?: [a-z]+){3,}`, matching any four English words -- "what is the
capital of france" fired it. It was the only advanced technique producing benign
hits. Real space smuggling separates single characters.

## Rule precision gating

Every `euaiact-lint` rule carries `measured_precision: float | None` (on
`BaseRule`). Below `MIN_PRECISION` (0.80, in `code_analyzer/analyzer.py`) a rule
only runs with `aisg lint --experimental`.

**`None` means UNMEASURED, not perfect, and never guess a value for it.**
Unmeasured rules keep firing by default — silencing a rule needs evidence, and
gating everything unmeasured would mute the linter entirely. As of now every
rule is `None`: the corpus exists but has not been hand-labelled.

Selection is via `select_rules()` / `default_rules()` / `experimental_rules()`
in `code_analyzer/rules/__init__.py`. These evaluate on every call rather than
snapshotting at import — a stale snapshot gates the wrong rules silently.
`--rules` naming a demoted rule explicitly still runs it, with a note on stderr.

Precision comes from `bench/` and nowhere else: `bench/run.py` scans a
SHA-pinned corpus of 20 LLM repos, a human labels `bench/findings.csv`
(`tp`/`fp`/`unclear`), and `bench/score.py` emits `bench/precision.md` plus a
paste-ready `measured_precision = ...` line. `score.py` refuses to run on a
partly-labelled CSV.

`findings.csv` is a **sample** — at most 40 findings per rule, drawn round-robin
across repos. The unsampled 25,568 live in `findings-all.csv`. Sampling is
deterministic and nested, so re-running or lowering `--sample-per-rule` never
orphans a labelled row; tests pin both properties. See `bench/README.md`.

## aisg audit and the skill

`aisg audit <path>` (`src/aisg/devtools/audit/`) is walk -> discover -> pydeep ->
rules -> adapters -> baseline -> report. 46 rules, `AUD-<priority><NN>` from
AUD-101 to AUD-1003, ordered by blast radius; the registry lists them all and
`--list-rules` prints them. Invariants the tests pin:

- **Three buckets, all counted.** MEASURED = an adapter ran *during this
  audit*. ASSERTED = one of our own regex/AST rules, a system-card claim, or
  a report read from disk (`evidence_kind: report`), which additionally carries
  `REPORTED <age>` -- a report is never rendered as if the audit had just
  measured it. UNKNOWN = what could not be established (categories `tools`,
  `deep`, `reports`, `runtime`); it is listed, never hidden, and a run with no
  findings still prints it. "Absence of a finding is not evidence of safety"
  is in every renderer.
- **`measured_precision` is `None` on every rule** and rendered `[UNMEASURED]`.
  `None` means unmeasured, never good, and an unmeasured rule still fires.
  Never type a number in; `bench/` will produce one when a labelled corpus
  exists (it does not yet).
- **`"schema": "aisg/1"` is the first key** of every JSON document (report,
  inventory, baseline), same as the other CLIs. SARIF is the one exception:
  its root admits no extra keys and Code Scanning rejects the upload on one,
  so there the marker is `runs[0].properties.aisg_schema`.
- **Exit codes:** `0` no counted finding, `1` a finding at or above `--fail-on`
  or an UNKNOWN item in a `--fail-on-unknown` category, `2` fatal, `130`
  interrupted. Constants are `EXIT_OK` / `EXIT_FINDINGS` / `EXIT_FATAL` /
  `EXIT_INTERRUPTED` in `main.py`. Findings below `--fail-on` are still
  reported; the summary line says how many were not counted.
- **No LLM, no install, no socket, ever**, from the audit process. External
  scanners run only if already on PATH or importable; each `AdapterResult`
  records `network`. `adapters.FORBIDDEN_LAUNCHERS` (`pip`, `pip3`, `uv`,
  `uvx`, `npx`, `pipx`) may never be `argv[0]`, and no argv token may be or
  start with `install`; a test enumerates every adapter. `install_hint` is
  text for the UNKNOWN row, nothing runs it.
- **`--no-redact` is refused** (exit 2, `_REDACT_REFUSED`). Secret-shaped
  snippets are redacted in every format; there is no flag that prints them.
- **`patterns.IGNORE_MARKER`** (`# aisg-audit: ignore-file`) in the first five
  lines makes `walk` skip the file, and no flag re-includes it
  (`--include-ignored` only overrides `.gitignore`). It sits on `rules/*.py`,
  `adapters.py`, `discover.py`, `patterns.py`, `vocab.py`, the skill scripts
  and their tests, because those files *are* the audit's vocabulary: they
  spell out every over-grant literal, secret shape, launcher name and guard
  registry name the audit looks for, and would otherwise report themselves.
  Nothing else should carry it; a real finding goes in the baseline with a
  reason, not behind the marker.
- **`[tool.aisg-audit]` in `pyproject.toml` is resolved from the CWD**, like
  `lint` and `misalign`, not from the audited path. Ours sets `exclude` and
  `fail-on = "high"`, so a fixture run from the repo root inherits them; run
  fixtures from a temporary cwd or pass `--fail-on` explicitly.
- **The word the audit tests ban** must not appear anywhere under
  `src/aisg/devtools/audit/` (`EXIT_OK`, not the obvious name), and neither
  may any of `report.BANNED_PHRASES`; `report.check_templates()` self-checks
  the renderers and `--debug` turns a hit into exit 2. Do not spell the
  phrases out in prose -- point at `BANNED_PHRASES`.
- **Fingerprints are stable across line renumbering.** `model.fingerprint()`
  is `sha1(rule_id | posix relpath | normalised snippet)[:16]`, where the
  normalisation collapses whitespace and strips digits from identifiers of
  three or more characters. Line numbers are not part of it, on purpose.
- **The skill has one canonical copy**, `src/aisg/skills/ai-safety-audit/`
  (ships in the wheel). `.claude/skills/ai-safety-audit/` and
  `.agents/skills/ai-safety-audit/` are byte-identical mirrors pinned by
  `tests/unit/test_skill_package.py::test_mirror_is_byte_identical`; edit the
  canonical copy and run `python scripts/sync_skill.py` (`--check` lists
  drift and exits 1). The bootstrap scripts pin `AISG_VERSION` to the
  pyproject version, so **every version bump must be followed by
  `python scripts/sync_skill.py`** or `test_version_pinned_to_pyproject`
  fails. `aisg skill install --host <name>|all` copies from the installed
  package and `aisg skill diff --host <name>|all` compares; `path` and `list`
  take no host. `codex` and `antigravity` locations are marked unverified and
  say so on stderr.
- **`audit-baseline.json` is the accepted-findings list** for the self-audit
  gate (`aisg audit . --no-external --fail-on high --baseline
  audit-baseline.json`). Every entry carries a reason; a fingerprint without
  one is a suppression, not an acceptance. `--write-baseline` records, it
  does not judge (it exits 0 on purpose); a full JSON report is also accepted
  as a baseline. The baseline file is itself scanned by the self-audit (it is
  not excluded, and `read_report` skips it only as a *report*), so a reason
  must describe the evidence without quoting the literal that produced the
  finding -- otherwise the baseline reproduces the finding it accepts;
  `test_committed_baseline_does_not_reproduce_the_findings_it_accepts` pins
  this. Fingerprints ignore line numbers, but the `file` field on an accepted
  entry does not: regenerate it when an anchor moves.

## Adding a guard

Subclass `GuardrailBase`, set `name`/`stage`, decorate with `@register_guard("name")`, implement
`async def check`, wire the name into **all four** YAML presets (`config/` and `src/aisg/config/`),
export from `src/aisg/__init__.py`, add tests. `GuardrailPipeline.from_config` fails loudly on an
unregistered name.

## Git

Commit directly to `main` — no branch/PR ceremony. `gh` is installed. CI triggers reference
`develop` and `release/**`, but neither branch exists on the remote.
