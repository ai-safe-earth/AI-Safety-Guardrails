# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Layout

`src/` layout. The only importable top-level name is `aisafe` — everything is
`aisafe.core.*`, `aisafe.modules.*`, `aisafe.integrations.*`, `aisafe.devtools.*`,
`aisafe.config.*`. Nothing is importable as a bare `core`/`modules`/`config`,
and it must stay that way: those names would collide with users' own modules
once published to PyPI.

**The project is AnyAISafe. The distribution, the import name and the console
script are all `aisafe`.** `pip install "aisafe[devtools]"`, then `import aisafe` and
`aisafe audit .`; `audit/report.py:DISTRIBUTION` is the constant for any
`importlib.metadata` lookup. The prose name of the project is "AnyAISafe" and the
repo is `github.com/ai-safe-earth/AnyAISafe`. One clash remains on PyPI: the
unrelated `aisafeguard` also installs a console script called `aisafe`, so two
installs in one environment overwrite each other's command. `uvx aisafe` and `pipx
run aisafe` always run this package; `uv tool install` and `pipx install` keep the
environments apart but link both commands into the same bin directory, where the
second install refuses (or, with `--force`, replaces the first). That is why the
bootstrap scripts print which `aisafe` ran, the skill stops on a version mismatch,
and `hook.sh`/`hook.ps1` fail open when the `aisafe` they found rejects `hook run`. History: the project was
"AI Safety Guardrails" with the distribution `aisguard` until 2026-10-19, then the
distribution `anyaisafe` with the import and command `aisg` until 2026-10-20; none
of them was ever published. `aisg` went because PyPI's `aisg` (an AI-gateway SDK)
imports under the same name. The local folder may still carry the oldest name.

Format labels did not change with the rename and must not: `"schema": "aisg/1"`,
its SARIF carriers `aisg_schema` and `aisgFingerprint/v1`, and the html meta names
`aisg-schema` and `aisg-tool` name a document format, not the product, and every
reader matches them. The probe canaries (`AISG_CANARY_*`, `AISG-SP-*`) are opaque
tokens and stay too. Everything else moved to `aisafe` (`.aisafe-audit/`,
`[tool.aisafe-*]`, `# aisafe-audit: ignore-file`, `AISAFE_*`, `aisafe-hook.sh`), and
the old spellings are READ, never written: `[tool.aisg-*]` when the new table is
absent (with a stderr note; `_config.LEGACY_SECTION_PREFIX`), the old ignore marker
and html marker line and `.aisg-audit/` as an evidence directory
(`patterns.LEGACY_*`), hook entries an `aisg hook install` wrote (`hook.
COMMAND_MARKER_RE`), the semgrep keys `aisg_rule(_id)` and `AISG_PRICES`.

`tests/conftest.py` puts `src/` on `sys.path`, so the suite runs without an
install; `examples/*.py` still self-bootstrap with `sys.path.insert(..., "src")`.
Run commands from the repo root.

`import aisafe` loads `AuditLogger` and `TelemetryProvider` lazily (PEP 562
`__getattr__` in `src/aisafe/__init__.py`): `otel.py` pulls in the OpenTelemetry
SDK, a quarter of a second every CLI run and every agent hook would otherwise
pay. Guards stay eager because `@register_guard` fills the registry
`GuardrailPipeline.from_config` reads; `tests/unit/test_package_lazy.py` pins
both halves. Keep new heavy, non-guard imports lazy the same way.

YAML presets exist twice on purpose: `src/aisafe/config/*.yaml` ships in the
wheel as package data (read it with `aisafe.config.preset_path()` /
`load_preset()`, never a hard-coded path), and repo-root `config/` is the
local-dev copy. Keep the two in sync when editing either.

## Commands

No Makefile, no script runner — everything is ad-hoc.

```bash
pytest                                                    # ~3600 tests, ~3.5 min, no API keys (all LLM calls mocked)
python -m pytest tests/unit/test_pii_tokenization.py::TestPIIRestorer -q   # single test
python -m pytest tests/unit/test_pii_tokenization.py -k "roundtrip" -q

ruff format <file>                                        # authoritative formatter
ruff check --fix <file>

aisafe lint src/                                            # EU AI Act compliance linter
aisafe misalign src/                                        # ALIGN-001..008 rule set
aisafe audit .                                              # AI-surface audit, AUD-101..1003 (see below)
aisafe skill list                                           # where each agent host keeps skills
aisafe attest . --check                                     # which level the written documents reach, and why not more
python scripts/levels_md.py --check                       # the skill's references/levels.md equals the criteria file
aisafe fleet bench/corpus.yaml --jobs 4 --proposal          # the audit over a list of repositories; clones only what is listed
python scripts/bump_version.py --check                    # every version site equals pyproject; CHANGELOG has the heading
```

`aisafe` is not on PATH in a bare checkout; `PYTHONPATH=src python -m aisafe.cli <verb> ...` is
the equivalent. Set `PYTHONIOENCODING=utf-8` on Windows.

`aisafe` is the single console script (`aisafe.cli:main`); `euaiact-lint` and
`misalignment-check` remain as aliases. Both subcommands share flags: `--staged`, `--diff`,
`--errors-only`, `--fail-on-warnings`, `--format terminal|json|sarif|markdown`,
`--output <path>`, `--list-rules`. The CLI passes everything after the subcommand through
verbatim (`argparse.REMAINDER`), so `aisafe lint --help` shows the linter's own help.
Exit codes: `0` clean, `1` findings, `2` fatal. A path that does not exist is fatal
(exit 2), not a warning, and so is a failing `git diff` under `--staged`/`--diff`:
scanning nothing and exiting 0 reads as a clean result in CI.
Their defaults come from `[tool.euaiact-lint]` / `[tool.misalignment-check]` in
`pyproject.toml` via `src/aisafe/devtools/_config.py`, resolved from the CWD (so `paths`
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
aisafe audit . --no-external --fail-on high --baseline audit-baseline.json
```

It must exit 0. A non-zero exit means a new finding at `high` or above that is not in the
baseline; either fix it or add it to `audit-baseline.json` with a reason (see below). Run
`aisafe measure` with `-o` pointing outside the tree (or delete `measure-report.json`
afterwards, now gitignored): a report left in the root is read by the next self-audit as
evidence and reports the seven AUD-801 acceptances as `no longer reported`. CI
(`tests.yml`) runs pytest on 3.10 and 3.13, ruff, `aisafe measure --max-p99-ms 25` and the
same audit gate; `eu-ai-act-compliance.yml` runs `aisafe lint src examples` and fails on
errors only (see "EU AI Act linter suppression" for what is and is not in that gate);
mypy and `aisafe misalign` are local-only.

Two CI-only failure modes worth knowing: git's `%cI` writes a UTC committer date with a
`Z` suffix, which `datetime.fromisoformat` only accepts from 3.11 (`audit/walk.py`
normalises it -- 3.10 is in the matrix), and the measure ratchet's p99 over 90 cases is the
second-slowest sample, so one scheduler hiccup on a shared runner used to fail it.

## EU AI Act linter suppression

`aisafe lint` and `aisafe misalign` share `EUAIActCodeAnalyzer`, and each honours only its
own markers (`analyzer.tool`, default `euaiact-lint`; misalign passes
`misalignment-check`). Two forms, both explicit:

- `# euaiact-lint: ignore-file` within the first five lines skips the file. It is for
  the files that ARE the rule vocabulary -- `code_analyzer/rules/__init__.py` and
  `modules/policy/eu_ai_act.py` spell out every prohibited-practice phrase and would
  otherwise report themselves; `# misalignment-check: ignore-file` sits on
  `devtools/misalignment/rules/__init__.py` for the same reason, and
  `devtools/audit/persons_patterns.py` carries all three markers (aisafe, lint, misalign):
  it spells out the P11 phrases. A test pins that exactly those files under `src/` carry
  each marker; a real finding anywhere else gets a line directive, not the marker.
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
bare `aisafe lint .` too). `tests/unit/test_euaiact_lint.py::TestComplianceGate` runs the
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

## `aisafe init` and `aisafe probe`

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

The corpus is `src/aisafe/probes/*.yaml`, one file per family, 48 cases seeded
from the guards this package already ships -- INJECTION_PATTERNS, PII_PATTERNS,
TOXICITY_PATTERNS, AdvancedInjectionDetectors, high_risk_fail_closed. Every case
records its `seed_pattern`; keep that link when adding cases, and add a case when
adding a detection pattern.

## Measurement: a guard is a trade

`aisafe measure` (`devtools/measure.py`) runs the attack **and benign** corpora
through a real pipeline in-process and reports, per guard, what it catches, what
it breaks, and what it costs. Rules that hold:

- **The benign corpus is not optional.** Attacks alone make "block everything"
  optimal. `src/aisafe/probes/benign_traffic.yaml` is *adversarially* benign --
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
- Populate a Profile from `aisafe measure` output. Never by hand.
- **Cost is the third column, measured honestly or not at all.** `aisafe measure` runs
  OFFLINE by default: a judge-backed guard's provider is not called, its regex path is
  timed, its tokens are ESTIMATED from the exact prompt it would send
  (`modules/llm_judges/estimate.py` renders the hoisted prompt constants of
  `prompt_injection`, `toxicity`, `ClaudeJudge`, `LlamaGuardJudge`, `OpenAIModerationJudge`)
  and the guard is `llm_exercised: false`, which renders UNMEASURED, never 0%.
  `--allow-provider-calls` runs the judges for real (money, credentials) and then
  tokens are MEASURED from the providers' usage fields; a `CachedJudge` is cleared
  before every timing pass so the figure is the judge's. The report carries
  `measured_on` (the mode is in the string), a `pipeline` block, and per guard
  `llm_configured`, `llm_exercised`, `llm_site`, `model`, `llm_calls_per_case`,
  `tokens_in/out_per_call`, `cost_basis`, `human_rate`, `fail_mode`,
  `benign_modified_rate` (beside the ratchet's FPR, whose definition is unchanged).
  Policy-stage guards are measured only with `--include-policy`. A judge the estimator
  cannot render is `unavailable`, not estimated; NeMo offline is `unavailable`.
- **Tokens in the runtime, dollars only offline.** Every judge call records
  `metadata["llm_usage"]` (`LLMUsage`: tokens in/out, model, provider, `cost_basis` in
  `COST_BASIS = none|measured|estimated|unavailable`, `cache_hit`, `calls`);
  `GuardrailBase.__call__` stamps `metadata["guard_name"]`; `PipelineResult.llm_usage`
  sums a stage; the audit logger and the otel instruments read the same key. No module
  under `src/` prices anything except `devtools/decide.py`, which joins tokens with the
  dated table `config/prices.yaml` (mirrored in `src/aisafe/config/`, `as_of`, `sources`,
  `stale_after_days`); a model not in the table renders `unavailable` and names
  itself, never a guess, and nothing ever fetches a price.

Two findings this produced, both still true of the shipped code: the
`prompt_injection` guard breaks ~14% of benign traffic (it blocks security
engineers asking how to defend against injection), and with `llm_judge: true`
and no credentials it costs seconds per request; since wave 1 the failure is
recorded (`metadata["judge_error"]`, usage `unavailable`) instead of swallowed,
and `aisafe measure` reports it as `fail_mode: open` with the judge not exercised.

Every shipped preset must load: `eu_high_risk.yaml` enabled seven guards that
do not exist and had never been loadable. Tests pin that both presets build a
pipeline and that `config/` and `src/aisafe/config/` stay identical.

## `aisafe decide`: the trade, priced against declared budgets

`aisafe decide` (`devtools/decide.py`) reads the audit report, the measure report, the
price table and a traffic profile (flags, or the system card's `traffic:` and
`budgets:` blocks that `aisafe init` writes; `deployment` stays the scalar it was) and
gives every candidate control (one row per `recommendation.package` symbol, guard rows
joined to measure rows through the registry) one of four verdicts, a deterministic
function of the declared budgets: `apply`, `apply with <config change>`, `defer (over
budget: <which>)`, `unmeasured (run aisafe measure first)`. Rules that hold:

- An unknown budget never counts as exceeded; an unknown figure never counts as zero;
  the UNMEASURED list prints in every format.
- `Budget.thresholds()` derives `max_usd_per_request` and `max_human_rate` from the
  monthly ceiling and the review capacity; `Thresholds.failures()` judges a dollar
  figure only when its tokens were `measured` (an estimate is not evidence for
  demotion; decide still reports estimated overruns, labelled).
- Totals: sequential stages sum guard latencies, parallel stages take the max; the
  pipeline p99 is an upper bound and says so; month = 30 days, stated.
- The decision document (`"schema": "aisg/1"`, `"kind": "decision"`) is EVIDENCE: the
  walker reads it as a report (`REPORTED <age>`), not as own output; AUD-806 "Reported
  guard over the declared budget" (`guardrails`, subs `latency|cost|human|benign`)
  reads its over-budget rows, and AUD-801/cost marks a judge the measure report never
  exercised. `aisafe audit --format html --decision FILE` adds the Trade table after the
  plan (numbering shifts by one, every other format ignores the flag; a non-decision
  file is refused with exit 2); the page is byte-identical without it.
- `[tool.aisafe-decide]` in pyproject defaults every flag except `select`
  (`NOT_CONFIGURABLE`); `prices` there, `AISAFE_PRICES` or `--prices` point at another
  table. Exit 0 rendered, 1 a selected control or the total exceeds a budget, 2 fatal.
- `GuardrailPipeline(thresholds=...)` / `pipeline.thresholds:` is the opt-in runtime
  demotion: a guard whose MEASURED Profile fails the bar does not run and is announced
  on stderr; an unmeasured guard always runs.

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

`aisafe measure` is the arbiter. The fix costs zero attack coverage (21/48 either
way) and takes benign breakage from 10% to 0%. A test asserts the lenient and
strict guards return identical verdicts on every attack case.

Also fixed here: `TokenSmugglingDetector`'s `space_injection` was
`[a-z]+(?: [a-z]+){3,}`, matching any four English words -- "what is the
capital of france" fired it. It was the only advanced technique producing benign
hits. Real space smuggling separates single characters.

## Rule precision gating

Every `euaiact-lint` rule carries `measured_precision: float | None` (on
`BaseRule`). Below `MIN_PRECISION` (0.80, in `code_analyzer/analyzer.py`) a rule
only runs with `aisafe lint --experimental`.

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

## aisafe audit and the skill

`aisafe audit <path>` (`src/aisafe/devtools/audit/`) is walk -> discover -> pydeep ->
rules -> adapters -> baseline -> report. 54 rules, `AUD-<priority><NN>` from
AUD-101 to AUD-1107 (AUD-806 reads the decision document; AUD-1101..1107 are the
P11 persons-and-manipulation rules), ordered by blast radius;
the registry lists them all and `--list-rules` prints them. Invariants the tests pin:

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
- **`patterns.IGNORE_MARKER`** (`# aisafe-audit: ignore-file`) in the first five
  lines makes `walk` skip the file, and no flag re-includes it
  (`--include-ignored` only overrides `.gitignore`). It sits on `rules/*.py`,
  `adapters.py`, `discover.py`, `patterns.py`, `vocab.py`, the skill scripts
  and their tests, because those files *are* the audit's vocabulary: they
  spell out every over-grant literal, secret shape, launcher name and guard
  registry name the audit looks for, and would otherwise report themselves.
  Nothing else should carry it; a real finding goes in the baseline with a
  reason, not behind the marker.
- **`[tool.aisafe-audit]` in `pyproject.toml` is resolved from the CWD**, like
  `lint` and `misalign`, not from the audited path. Ours sets `exclude` and
  `fail-on = "high"`, so a fixture run from the repo root inherits them; run
  fixtures from a temporary cwd or pass `--fail-on` explicitly.
- **The word the audit tests ban** must not appear anywhere under
  `src/aisafe/devtools/audit/` (`EXIT_OK`, not the obvious name), and neither
  may any of `report.BANNED_PHRASES`; `report.check_templates()` self-checks
  the renderers and `--debug` turns a hit into exit 2. Do not spell the
  phrases out in prose -- point at `BANNED_PHRASES`.
- **Fingerprints are stable across line renumbering.** `model.fingerprint()`
  is `sha1(rule_id | posix relpath | normalised snippet)[:16]`, where the
  normalisation collapses whitespace and strips digits from identifiers of
  three or more characters. Line numbers are not part of it, on purpose.
- **The skill has one canonical copy**, `src/aisafe/skills/ai-safety-audit/`
  (ships in the wheel). `.claude/skills/ai-safety-audit/`,
  `.agents/skills/ai-safety-audit/` and
  `plugins/ai-safety-audit/skills/ai-safety-audit/` (the Claude Code plugin's
  copy) are byte-identical mirrors pinned by
  `tests/unit/test_skill_package.py::test_mirror_is_byte_identical`; edit the
  canonical copy and run `python scripts/sync_skill.py` (`--check` lists
  drift and exits 1). The six bootstrap scripts (`audit`, `verify`, `hook`,
  `.sh` and `.ps1`) pin `AISAFE_VERSION` to the pyproject version and
  `sync_skill.py` also pins `plugin.json`'s `version`, so **every version bump
  must be followed by `python scripts/sync_skill.py`** or
  `test_version_pinned_to_pyproject` fails. `aisafe skill install --host <name>|all` copies from the installed
  package and `aisafe skill diff --host <name>|all` compares; `path` and `list`
  take no host. `codex` and `antigravity` locations are marked unverified and
  say so on stderr.
- **`audit-baseline.json` is the accepted-findings list** for the self-audit
  gate (`aisafe audit . --no-external --fail-on high --baseline
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
- **`--write-baseline` renders first.** It writes the `-o` report in the
  requested format, then the baseline, then exits 0. The baseline carries an
  `index` (`{fingerprint: {rule, file, title}}`) so a later `--baseline` run can
  name what is `no_longer_reported` -- that is the phrase; a rename or a move
  produces it too, so no renderer calls it anything stronger. Reasons are
  carried over, not retyped: from the `--baseline` document the run compared
  against (when it is an audit-baseline) and from the file being refreshed; a
  reason whose fingerprint is no longer reported is dropped and the stderr
  note says how many. It refuses (exit 2) to overwrite a file that is not an
  audit-baseline. `read_baseline` rejects a reason carrying verdict language
  or a secret shape, the same check as `--accept`. `diff()` also fills the
  baseline block's `kind` (`audit-baseline`, or `audit` when a full report was
  the baseline -- a report carries no reasons, so `accepted` is empty and the
  html says "the baseline was a report"), `accepted` (only reasons whose
  finding was reported this run; the rest go under `no_longer_reported`),
  `generated_at` (the compared document's own timestamp) and sets `Finding.
  accepted_reason` from the baseline's reasons. The block is `{file, kind,
  new, unchanged, accepted, generated_at, no_longer_reported}`: no count key
  for the gone fingerprints, the list's length is the count, and every
  renderer's line reads `baseline: N new, N unchanged, N no longer reported
  (file)` (`report._T_BASELINE`). Terminal and markdown print `accepted:
  <reason>` under an accepted finding, so the reason is in every format.
  `report.target` carries the resolved `exclude` list so two documents
  produced from different working directories show the mismatch.
- **`--amend-baseline PATH --accept FP="reason"`** edits a baseline in place:
  no scan, no render. It refuses (exit 2) a file whose `kind` is not
  `audit-baseline`, a fingerprint the file does not hold, an empty, non-ASCII
  or secret-shaped reason, one containing a `BANNED_PHRASES` entry, and
  `--accept` without `--amend-baseline`; a second `--accept` for the same
  fingerprint replaces the reason. A reason is what turns a suppression into
  an acceptance, which is why the flag cannot be given without one.
- **`recommendation.package`** (`model.Package`) is on every finding:
  `mechanism` from `PACKAGE_MECHANISMS`, `symbols`, `same_control`,
  `leaves_open`. `same_control` is a bool, never a score, and `True` (eleven
  rules) means wiring the symbol IS the control the rule asks for -- not that
  the finding goes away; the re-audit decides that. `leaves_open` is required
  text whenever the mechanism is not `none` and is rendered every time the
  symbol is offered. `none` carries no symbols and no `leaves_open`. A
  detector is never `same_control` on a P1-P4 rule. The plan's "who" column
  derives from it: `package` only when `same_control`, the finding's language
  is Python (by the file's extension; else its unit's language; else, for a
  repo-scoped finding, the root unit's) and `patterns.is_protected_path()` is
  false; `you, approval needed` when the path is protected; `you` otherwise.
  Protected paths are the host permission and MCP files (`.claude/settings*.
  json`, `.codex/config.toml`, `.cursor/*`, `.gemini/*`, `.mcp.json`,
  `.vscode/mcp.json`, `claude_desktop_config.json`), CI workflows and pipeline
  files (`.github/workflows/*`, `.gitlab-ci*.yml`, `.circleci/config.yml`,
  `Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`,
  `.travis.yml`), `.env*`, `.secrets*` and `.pre-commit-config.yaml`. An
  accepted finding is neither package work nor an open row in the html plan;
  it sits under the accepted group.
- **`SUBSYSTEM_OF_RULE` is an exact cover** of the registry: its keys equal
  the set of rule ids, every value is one of the eleven `SUBSYSTEMS` (the eleventh,
  `persons`, is appended so the two five-box rows keep their slices and `html._svg`
  draws `SUBSYSTEMS[10:]` on row three beside the not-attributed strip), and
  `subsystem_of()` looks up the parent id (before `/`) so `AUD-301/structured`
  lands where AUD-301 does. Everything else draws in the `NOT_ATTRIBUTED`
  box. Adding a rule without a row here fails the test, on purpose.
- **`--format html`** (`audit/html.py`, `render_html(report, quiet=False)`)
  is a document, not a dashboard: ASCII only, no severity colour (order is
  the priority), `[UNMEASURED]` on every Fig. 1 box, the disclaimer above
  the figure, and the two document-2 sections ("Since the baseline",
  "Remaining actions") only when `--baseline` was given. Line 1 is exactly
  `patterns.OWN_HTML_MARKER_LINE` (`<!-- # aisafe-audit: ignore-file -->`), so a
  re-audit skips it by the marker. The JSON is authoritative; the html carries
  nothing the JSON does not. `--inventory-only --format html` renders the
  page with the no-rules banner and the inventory; every other format writes
  the inventory JSON (`kind: inventory`). `--inventory-only` refuses (exit 2)
  `--baseline` and `--write-baseline`: no rule runs, so neither can do what
  it says.
- **`walk` skips the audit's own output** -- a `.json` whose head carries
  `"schema": "aisg/1"` and `"kind": "audit"`, `"inventory"` or `"attestation"`, and an
  html whose first line is `OWN_HTML_MARKER_LINE` -- and lists it in
  `inventory.own_output_skipped`, rendered as one inventory line in every
  format; SARIF carries it at `runs[0].properties.own_output_skipped`.
  `.aisafe-audit/` (`patterns.AUDIT_DIR`) is deliberately NOT in `SKIP_DIRS`
  and is never pruned by `.gitignore` (the walker exempts it like `.env*`;
  the `gitignored` flag still says so): measure and probe reports written
  there must be discovered as evidence (`REPORTED <age>`) whether or not they
  are committed, so the skip is by content, not by directory.
- **The audit's run time is budgeted** (2026-10-19: this repo 8 s, AdalFlow 428
  files 11 s, VaiVia 342 files 9 s, down from 28/45/19 s) because hooks, CI and
  the fleet all pay for it. Four caches hold the figure and none changes a result:
  `patterns.comment_spans` is `lru_cache`d per `(text, lang)` and its dict is
  read-only for every caller; `AuditContext.cache` holds derived views several
  rules share (`guards.sites`, returned as copies); `_Module.unparse` memoises
  `ast.unparse` per node for the module's lifetime; and pydeep's gate-text pass
  checks `vocab.GATE_TEXT_ANCHORS` against a node's full rendering before paying
  for the collapsed one, which is sound because collapsing only removes
  characters. Every branch of `APPROVAL_SYMBOLS` / `GATE_BYPASS` must keep an
  anchor there -- `test_audit_pydeep.py` pins one example per branch -- and the
  anchors live in `vocab.py`, not in `pydeep.py`, because the self-audit reads a
  bypass literal in a non-vocabulary file as a finding. `guards._python_guards`
  scans a file once with one alternation over all registry and class names,
  anchored on the first code occurrence.
- **AUD-801's eval evidence is a harness, not prose.** An `evals[]` entry silences
  "guard present but unmeasured" for the guards it names only when its file is an
  eval tool's config or data file, or a test module (`test_*.py`, `*_test.py`,
  `conftest.py`, or any `.py` under a `tests`/`evals` directory;
  `rules/guards._eval_evidence_file`). A README that says `aisafe measure` and lists
  the guards measures nothing, and neither does a tool's own source: this repo's
  `decide.py` and `measure.py` name every guard and had silenced the rule for all
  of them. The self-audit baseline therefore accepts AUD-801 for the five guards the
  default preset wires: CI measures them on every push but keeps the report as a
  build artifact, which an audit of the tree cannot read (the rule's first known
  failure mode). Committing `.aisafe-audit/measure-report.json` is the alternative.
- **A price table is not a deployment.** `discover._is_price_table` (`schema: aisg/1`
  and `kind: prices` in the first 4 KiB) skips the model-id scan for `prices.yaml`,
  so AUD-601 does not report the ids it lists in order to price them; every other
  config file is scanned as before.
- **pydeep reads the approval gate literally.** `ToolPolicyGuard(
  require_approval=[])`, `None` or `()` is an inert gate ("require_approval
  is empty") and `approval_callback=None` is no callback, so AUD-201 fires;
  `ToolPolicyGuard(**cfg)` is not recorded as a gate and yields an UNKNOWN
  item (category `deep`) saying the approval configuration could not be
  resolved, so AUD-201 fires and the UNKNOWN row says why. `run_processing`
  mutates the caller's context dict and clears the `tool_call` it set when the
  call returns; `ToolPolicyGuard.setup` coerces dict policies to `ToolPolicy`.
- **The system card has an `incident_contact` field** (a `TODO` placeholder
  from `aisafe init`). A blank or `TODO`-prefixed value still counts as absent
  for AUD-703 (`discover._incident_contact`, `rules/observability.py`), but
  the inventory records the raw placeholder string, not `None`, when no other
  contact key (`contact`, `security_contact`, `incident.contact`) names
  anyone; the AUD-703 snippet then reads `has an unfilled incident_contact`,
  and a card with no contact key at all reads `has no incident_contact`. The
  card's fields are the system id, name and purpose, role, `risk_tier` (with
  its caveat), `annex_iii_category`, `affected_persons`, deployment,
  `incident_contact`, and the `traffic:` / `budgets:` blocks `aisafe decide` reads
  (null = unknown, never assumed); there is no model or data field, and the skill
  docs must not invent one.
- **`--only PATH` is the file-scoped run the hook uses after an edit.** The
  tree is walked exactly as in a full run (excludes, gitignore, marker, size
  limit, units), only the records are filtered (`WalkOptions.only`), and the
  rule set is `main.FILE_LOCAL_RULES` (AUD-101, 108, 501, 502, 505, 602, 605)
  unless `--rules` is given: the presence rules whose fingerprint is
  `sha1(rule | this file | this snippet)`, so a partial run reports exactly
  the fingerprints the full run gives those files and a baseline written by
  the full run applies unchanged (`test_audit_only.py` pins the equality on
  the py_agent fixture). Left out on purpose: AUD-601 and AUD-504 (grouped
  per unit, anchored on the first file by path), AUD-503 (needs the unit
  inventory) and every absence rule. A path the walk never saw is one UNKNOWN
  row (`--only path not walked`, category `runtime`), never silence;
  `target.only` lists the files and the terminal and markdown renderers print
  `report._T_ONLY` ("partial run: ..."); a full run carries an empty list.
- **Per-invocation actions are never pyproject defaults.**
  `main.NOT_CONFIGURABLE` (`write_baseline`, `inventory_only`, `list_rules`,
  `only`, with `amend_baseline` and `accept`) is excluded from
  `[tool.aisafe-audit]` resolution: a `true` there would make every audit
  rewrite a baseline, run no rule, or print the catalogue and exit 0, with no
  flag to undo it, and an `only` there would make every audit partial. Two
  more things the walk never hides: a file over `max_size` is not read, and
  that is an UNKNOWN row (`walk._oversize_item`) plus the inventory line
  `oversize files skipped: N` (`report._T_INV_OVERSIZE`, from
  `target.oversize_files`; a document without the key says so rather than
  printing 0); and the audit's own SARIF output is recognised as own output
  by the run's property bag, which `to_sarif` emits first with `aisg_schema`
  then `own_output_skipped` in that order (`walk._OWN_SARIF_RE`) -- the lint
  SARIF carries `aisg_schema` too, so the marker alone would skip a document
  that is not ours.
- **The skill runs seven phases** (survey, document 1, decide, apply, document
  2, verify, attest; design 03 part D), then a closing step that offers `aisafe
  hook install` and the Action by name. Every artefact is under `.aisafe-audit/`
  and every command runs from the repo root, because `[tool.aisafe-audit]`
  resolves from the CWD. Phase 3 runs `aisafe decide` (and, with a yes, the
  offline `aisafe measure` through `verify.sh` with `AISAFE_VERIFY_SKIP_TESTS=1`)
  so rows are chosen with their cost; phase 4 walks the plan table top-down,
  one row per approval, and reads `recommendation.package` from the JSON --
  never the html prose -- to pick between the package idiom
  (`references/apply/python.md`, keyed by the first symbol), "in addition to,
  not instead of", and the outside-package action; after each diff the
  re-audit, not the diff, is the evidence. Phase 7 runs `attest.sh --owner`
  and reads every unmet criterion's `missing` text aloud
  (`references/levels.md`). Hard rule 8: `audit.sh` and `attest.sh` print
  `aisafe: <path> version <v> (pinned <v>)` on stderr and the skill stops on a
  mismatch (on PyPI the unrelated `aisafeguard` also installs an `aisafe`
  command); rule 9: it never pushes,
  the `gh pr create` line is printed for the user. The skill proposes the
  `.gitignore` line for `.aisafe-audit/` as a diff and never edits `.gitignore`
  itself. `test_skill_package.py` pins the seven titles in order, the
  vocabulary (`.aisafe-audit/`, `--amend-baseline`, `--accept`, `--format html`,
  `recommendation.package`, `leaves_open`, `same_control`, `aisafe decide`,
  `aisafe attest`, `--owner`, `--require-level`, `attestation.json`,
  `pr-body.md`, `gh pr create`, `aisafe hook install`) and that `controls.md`'s
  Package column covers every registry rule.
- **`controls.md` copies the registry, and the copy is generated.** The
  severity word in each rule heading, every `- Mapping:` line (the rule's
  `controls` tuple, joined `, `, ending `.`) and every `Leaves open:` text
  (`recommendation.package.leaves_open`, verbatim up to re-wrapping) come from
  `ALL_RULES`. Edit the rule, then run `python scripts/controls_md.py`
  (`--check` lists the drift and exits 1) and `python scripts/sync_skill.py`;
  `test_skill_package.py` parses the file against the registry, so hand-edited
  drift fails. `apply/python.md`'s "Leaves open" bullets are a summary; the
  wording to quote in a plan row is the JSON's `leaves_open`.
  `references/levels.md` is generated the same way, but whole: `python
  scripts/levels_md.py` renders it from `attest-levels.yaml` (through
  `attest.load_levels`) and `attest.CRITERION_READS` (what each criterion kind
  reads; a test pins its keys equal `CRITERION_KINDS`); `--check` is in the
  release gate and `test_levels_md.py` pins the committed file equals the
  output. Edit the YAML or the table, never the markdown.

## `aisafe hook`, the plugin and the CI surface

`aisafe hook` (`devtools/hook.py`) is the one adapter between an agent host's command
hooks and the audit; `devtools/hosts.py` is the host table it shares with `aisafe skill`
(`Host.hooks: HookSupport | None`; keys stay `claude, agents, codex, cursor, gemini,
antigravity`, pinned, and `references/hosts.md` names every host and source URL).
Rules that hold:

- **It fails OPEN on its own errors** (payload not JSON, audit exception, state
  unwritable): exit 0, nothing on stdout, the error recorded in
  `.aisafe-audit/hook-state.json` (`kind: hook-state`, last 20 errors and sessions,
  everything redacted and ASCII, written tmp+`os.replace`) and surfaced as one line at
  the next SessionStart. A hook is a gate on someone else's editor; one that fails
  closed on its own bug teaches people to reach for the bypass flags `HOST_OVERGRANT`
  flags. Two exceptions, both positive: the secret-literal `deny` stays a deny, and a
  Cursor permission hook gets an explicit `{"permission": "allow"}` on error because
  there an empty answer is a block. `UnverifiedHostError` (codex) is the same path.
- **No model, no install, no socket.** The audit runs `--no-external`; `walk._git`
  is the only child process; the prompt policy drives the injection guard's coroutine
  with `send(None)` instead of `asyncio.run`, because the loop's internal socket pair
  on Windows would trip the "no socket" test; nothing imports a provider SDK.
  `test_hook.py` pins all of it, including that `run` writes only under
  `.aisafe-audit/`.
- **Policies re-use the audit's tables, nothing is re-spelled**: `patterns.
  is_protected_path`, `UNSAFE_HOOK_PATTERNS` (deny on `curl_pipe_sh`, `wget_pipe_sh`,
  `wget_stdout`, `pip_http`, `pip_trusted_host`; ask on `npx_y`), `HOST_OVERGRANT["*"]`
  (ask), and `discover.grep_file` over the introduced text with a synthetic
  `FileRecord` for the secret tables (`secret` -> deny, `secret_var` -> ask;
  `discover.is_excluded_secret_file` applies, so `.env.example` is not a secret but is
  still a protected path). Deny wins over ask; one decision per event.
- **The stdout matrix is the contract** (`_emit_claude` / `_emit_cursor` /
  `_emit_gemini`): JSON only when there is a decision or context, plain text only on
  Claude SessionStart, Gemini never prose and never an `ask` (`ask-fallback`), Cursor
  permission events always answer. Claude Stop blocks with `{"decision": "block",
  "reason"}` once per session (`blocked_at`; never when `stop_hook_active`) and only
  when a baseline resolves; Cursor's stop is a `followup_message`; Cursor's
  `afterFileEdit` has no documented answer channel, so the recheck is recorded and
  surfaces at stop.
- **The recheck is `aisafe audit --only <file>`** in-process with stdout and stderr
  captured (the audit prints its terminal summary when `-o` is given), debounced per
  file, or the full tree when a baseline resolves and the last full run took at most
  `max-audit-seconds`; `.aisafe-audit/hook-recheck.json` and `hook-stop.json` are the
  audit's own output and a later walk skips them by content.
- **`install` never silently edits a protected file.** It loads the host config as
  strict JSON, merges only under `hooks` (and Cursor's `version: 1`), identifies its
  own entries by `COMMAND_MARKER_RE` (the bootstrap name followed by `run`, or the
  module/console form), replaces them, prints a unified diff and writes only with
  `--yes` or an interactive yes (exit 1 otherwise, exit 2 on an unparsable file or an
  unknown host). Project configs get the portable bootstrap (`sh "${CLAUDE_PROJECT_DIR}
  /.claude/hooks/aisafe-hook.sh" run ...`, copied from the packaged skill); `--global`
  and `--local` get `sys.executable -m aisafe.cli hook run ... --origin interpreter:...`.
  `hook.sh` passes `--origin` and `--expect-version`; `run` records `version_mismatch`
  in the state instead of spawning a second process. Codex: `install` prints why
  nothing is written and exits 1.
- **`[tool.aisafe-hook]`** (`HookConfig.load`, from the pyproject at or above the
  resolved root; `fail-on` falls back to `[tool.aisafe-audit]`): a bad value is a
  recorded problem printed at session start, never a crash. `DEFAULT_POLICIES` are
  on; `prompt_injection` is opt-in because the agent's own user is the trusted party on
  a prompt and the guard's benign breakage would be noise.
- **The Claude Code plugin** is `.claude-plugin/marketplace.json` (name
  `ai-safe-earth`) plus `plugins/ai-safety-audit/{.claude-plugin/plugin.json,
  hooks/hooks.json, README.md, skills/ai-safety-audit/**}`; the skill copy is mirror #3
  of `sync_skill.py`, which also pins `plugin.json`'s version (`bump_version.py` lists
  it as a site). Hook commands use `sh "${CLAUDE_PLUGIN_ROOT}/skills/ai-safety-audit/
  scripts/hook.sh"`. No `.mcp.json`: the audit has nothing to serve.
- **The CI surface**: `action.yml` (composite; `version` default pinned to pyproject by
  a test; `install-from: action-path` for dogfooding; three `aisafe audit` calls each
  `|| [ $? -eq 1 ]`; the verdict step exits with the JSON's `summary.exit_code`),
  `.pre-commit-hooks.yaml` (`aisafe-audit` at `pre-push`, `aisafe-lint`, `aisafe-misalign`),
  the `aisafe-audit` job in `.gitlab-ci-euaiact.yml` (git pin until wave 6) and the
  `action` dogfood job in `tests.yml`. `test_ci_surface.py` pins the shapes.

## Persons and manipulation (P11)

AUD-1101..1107 (`rules/persons.py`, subsystem `persons`, vocabulary in
`persons_patterns.py`) report where the code or the prompts touch PEOPLE: a profile bound
into a prompt, emotion or biometric inference, scoring or automated decisions about
persons, an engagement objective (`/vulnerable` critical when a vulnerable-group word
co-occurs in the same file or prompt literal), a concealed AI nature (`/persona`) or no
disclosure symbol in a user-facing unit (`/no-disclosure`, LOW, unit-level), no
manipulation control on the response path, no recorded prompt review on the card.
Every finding carries `persons.LEGAL_CAVEAT`: none of this is a legal determination.
Rules that hold:

- **Prompt-material gating is what keeps this repository quiet.** The kinds in
  `persons_patterns.PROMPT_KINDS` (scoring, engagement, vulnerable, persona, profile
  placeholders and names) and the prose disclosure rows count in code only on a prompt
  line (a `prompt_assembly` hit or `patterns._PROMPT_LHS`); elsewhere discover records a
  `person_signal_candidate` that the rule promotes only when a pydeep `PromptLiteral`
  (`SYSTEM_PROMPT = "..."`, with its line span) covers it, or when a prompt assembly reads
  the profile name. `eu_ai_act.py` and the linter rules spell these phrases inside
  `re.compile(...)` calls, which are neither, so they produce nothing. Docs are scanned
  only under `PROMPT_FILE_GLOBS`, and a template by path (`prompts/x.jinja`) is prompt
  material whatever its extension. Candidates are not mention-filtered: a triple-quoted
  prompt literal looks like a docstring to the span finder; the literal gate does that job.
- **Mention vs use in prompt material.** A doc or config hit inside a quoted span or
  near a `patterns.DISCUSSION_CUES` word ("explain how we detect social scoring") is a
  mention and does not count; in code only the cue window applies, because a prompt
  literal is quoted by nature.
- **The lint tier is evidence, never a second finding.** `lint_bridge.run_lint` runs the
  curated EU-AIA/ALIGN rules (`EU_RULE_IDS`, `MISALIGN_RULE_IDS`) through the new
  `EUAIActCodeAnalyzer.scan_source` seam over the walked Python text, one analyzer per
  tool so each honours only its own markers and directives; `ctx.lint` holds the hits.
  A hit in a file that already carries a grep signal of the same kind is a `role: lint`
  leg; one with no P11 site of its own in that file anchors a candidate, so 013b alone
  still produces `AUD-1105/persona`. `tests/conftest.py`'s `audit_context` runs the bridge
  too.
- **Art. 5(1) letters** are those of Regulation (EU) 2024/1689: (a) manipulation, (b)
  exploiting vulnerabilities, (c) social scoring, (d) criminal-risk profiling, (e) facial
  scraping, (f) emotion recognition at work or school, (g) biometric categorisation, (h)
  real-time remote biometric identification. `eu_ai_act.py` and the linter's 005b used to
  label biometric identification (d) and predictive policing (e); fixed and pinned.
- **The two output guards** (`ManipulationGuard`, `manipulation_output`;
  `AIDisclosureGuard`, `ai_disclosure_output`) are regex tables, FLAG by default, mention-
  aware, UNMEASURED (`profile = Profile()`), refuse unknown options, and never spell the
  audit's objective or persona phrases in their source (a test reads
  `persons_patterns.ENGAGEMENT_OBJECTIVE` against the module). `ManipulationGuard`'s
  optional judge is `ClaudeJudge(mode="manipulation")`; a failed call is an
  `llm_judge_error` FLAG, never a swallowed exception. `AIDisclosureGuard` returns REDACT
  whenever it changed the text (a replaced claim or an appended disclosure), because the
  pipeline takes `sanitized_content` only on REDACT; the EU AI Act and NIST policy guards
  now return REDACT for the same reason when they append their disclosure on the output
  stage. Both presets wire both guards; `eu_high_risk` sets `append_when: never` so the
  policy guard's disclosure is the only one.
- **The output corpus** (`probes/manipulation_responses.yaml`, `kind: output`) holds model
  RESPONSES with a `verdict` (`manipulative` counts as an attack, `benign` as traffic that
  must survive). `load_corpus(include_output=True)` loads it; `aisafe probe` never does, and
  `available_families()` never lists it. `aisafe measure` routes output cases to OUTPUT-
  stage guards only and counts them in `output_seen/output_caught/output_catch_rate` and
  in the family matrix, never in the input headline; `catch_rate_meaningful` is true for an
  output guard once output cases reached it, and the terminal NOTE about output guards
  prints only when none did. `manipulation_elicitation` is attack family 7 (CI pins 7).
- **The card's `prompt_audit` block** (`reviewed_at`, `reviewer`, `scope`, `notes`) is
  what AUD-1107 reads through `discover._build_system_card`, which also passes
  `affected_persons` through; `aisafe init` writes it with a `TODO` reviewer and asks two
  more questions interactively.

## `aisafe attest`: levels, criteria and a named owner

`aisafe attest` (`devtools/attest.py`) is the deterministic half of "declaring" a system.
It reads the documents the other commands wrote (`.aisafe-audit/audit-report-after.json`,
falling back to `audit-report.json` with a stderr note; `audit-baseline.json`;
`measure-report.json`; `probe-report.json`; `decision-report.json`; `ai-system-card.yaml`),
evaluates the criteria in `attest-levels.yaml` (shipped in the wheel, mirrored at
`config/`, pinned identical; `--level-criteria PATH` for another file) and writes
`attestation.json`, `attestation.md`, `badge.json` and, with `--html`, `attestation.html`
under `--out-dir` (`.aisafe-audit/`). Rules that hold:

- **A level is a list of criteria met on a date, signed by a person.** Levels 0 audited,
  1 triaged, 2 measured, 3 governed; the level reached is the highest N with every
  criterion of 0..N met, so a hole at level 1 caps the result at 0 whatever level 3 says.
  Each criterion row carries `met`, `evidence` and `missing` so a reader sees why. The
  statement reads "<owner> states that <path> at commit <sha> meets the AnyAISafe level N
  (<name>) criteria on <date>."; when level 0 is not met it says so and the badge reads
  "no level". The disclaimer extends the audit's: the tool checked the listed criteria
  and nothing else. Nothing in the module's fixed strings may contain a
  `report.BANNED_PHRASES` entry or the banned word; `check_templates()` is the self-check
  and `--debug` turns a hit into exit 2.
- **`--owner` is required to write and is never a pyproject default.** `NOT_CONFIGURABLE`
  is `owner` and `check`: a signature and "write nothing" cannot come from a file. The
  owner is printable ASCII, at most 200 characters. `--check` runs unsigned, prints every
  criterion, writes nothing, and `--require-level N` makes it exit 1 when N is not
  reached (the CI form). Criterion kinds are `CRITERION_KINDS` (14), one evaluator each,
  and `validate_levels` refuses a criteria file naming a rule id the registry does not
  know or a card path `DEFAULT_CARD` does not have (exit 2).
- **A bare fingerprint is a suppression, not an acceptance.** Only baseline entries with
  a reason count as accepted: `L1.no_open_high` keeps a reason-free finding open and
  `L1.reasons` names how many fingerprints have no reason. `accepted_risks` copies the
  baseline's reasons (with `rule` and `file` from its `index`) next to the owner; attest
  never edits a baseline, `aisafe audit --amend-baseline --accept` is the only way in.
- **Absent is recorded, never fatal; wrong is fatal.** A missing measure, probe, decision
  or card makes the criteria that need it unmet and appears in `inputs` with null `file`,
  `generated_at` and `age_days`. A missing audit report is fatal (exit 2) with the command
  to run; a document of the wrong schema or kind, unparseable JSON or an invalid baseline
  is fatal too, because ignoring it silently would read as "met".
- **Freshness is relative to the run.** `max_age_days` on `report_present`,
  `document_present` and `card_section_fresh` (its `date_field`) is read against the
  run's clock; `next_review_by` is `review_interval_days` (90) after `generated_at`.
  `report_names_head` compares `target.git_sha` with HEAD and `tree_clean` fails on
  uncommitted changes; both read git through `walk.git_meta`, the command's only
  subprocess. No model, no install, no socket.
- **The attestation is the toolchain's own output.** `"kind": "attestation"` is in
  `discover._OWN_OUTPUT_KINDS` and `walk._OWN_KIND_RE`, and `attestation.html` starts with
  `OWN_HTML_MARKER_LINE`, so a re-audit skips both and lists them in `own_output_skipped`;
  `attestation.md` and `badge.json` stay scanned. `badge.json` is a shields.io endpoint:
  `informational` above level 0, `lightgrey` at 0 or none, never green or red.
- **Document keys, in order:** `schema`, `kind`, `tool`, `target`, `generated_at`,
  `owner`, `level` (`reached`, `name`, `statement`, `criteria`), `inputs`,
  `accepted_risks`, `unknown`, `residual`, `next_review_by`, `notes`, `disclaimer`.
  `[tool.aisafe-attest]` defaults every other flag. Exit 0 written or met, 1 `--check`
  not met, 2 fatal, 130 interrupted. `scripts/attest.sh|ps1` is the skill's
  bootstrap for phase 7 (same resolver chain and pin as `audit.sh`), and
  `references/levels.md` is the generated table of the criteria.

On this repository `aisafe attest . --check` reads level 0: the self-audit runs
`--no-external` (L1.scanners fails), and there is no committed measure or decision
document and no system card. That is the honest reading, not a defect.

## `aisafe fleet` and the audit bench

`aisafe fleet LIST` (`devtools/fleet.py`) audits many repositories, one `aisafe audit`
subprocess each, and aggregates counts, names and report paths into
`.aisafe-fleet/fleet-report.{json,csv,md}` (`"kind": "fleet"`). Rules that hold:

- **The operator writes the list; the fleet never searches.** `LIST` is YAML (`repos:`
  with `name`, `url` or `path`, optional `sha` and `branch`; `bench/corpus.yaml` is a
  valid list) or CSV (`name,url|path,sha`). Its only network action is `git clone` of the
  URLs listed, through `devtools/_git.fetch_pinned` (shared with `bench/run.py`: init +
  fetch-by-sha, branch fallback at depth 50, `.aisafe-bench-sha` stamp, one-line
  `GitError`). A local `path` is audited in place and never written into.
- **One subprocess per repository**: `sys.executable -m aisafe.cli audit . --format json
  --no-external --fail-on <level> -o <out>/<name>/audit-report.json` with the clone as cwd
  (the target's own `[tool.aisafe-audit]` applies) and `--per-repo-timeout` as the
  wall-clock cap, because an in-process audit cannot be interrupted and one pathological
  repository must not take the fleet down; never a launcher from
  `adapters.FORBIDDEN_LAUNCHERS`; `--jobs` is a thread pool over subprocesses; the child
  gets this process's `aisafe` on `PYTHONPATH` so a source checkout works without an install.
- **Findings are the survey's content, not its failure.** Exit 0 when every repository
  was audited, 1 when one was not (`clone_failed`, `timeout`, `fatal`: an incomplete
  survey must not look complete), 2 fatal (unreadable list, `git` missing, `--out`
  unwritable). `--fail-on-findings` adds exit 1 when a repository's own audit exited 1,
  for a team gating its own repositories.
- **No snippet leaves the per-repo report.** The fleet documents carry `summary` counts,
  `rule_frequency` by display id, inventory highlights (languages, providers, frameworks,
  tool and MCP-server counts, hosts, guardrails, evals), `git_sha`, duration, status and
  the report path; `fleet-report.json` keys are `schema, kind, tool, generated_at,
  options, totals, disclaimer, repos`. `--proposal` writes `<out>/<name>/proposal.md` (a
  severity table, the plan table with the html plan's `who` rule, a blank decide table,
  the exact command, how to apply) with `file:line` and never evidence text. The fleet
  never pushes or opens a PR; `--resume` skips a repository whose report already parses;
  `check_templates()` guards the fixed strings; `[tool.aisafe-fleet]` defaults the flags.
- **`bench/run.py --tool audit`** runs `aisafe audit . --no-external --fail-on never` over
  the same SHA-pinned corpus into `bench/results-audit/` and `findings-audit.csv`
  (`rule_id` = the parent rule, plus `sub` and the redacted first-evidence `snippet`);
  `bench/score.py --tool audit` writes `precision-audit.md` and a paste block keyed by
  class name (`# AUD-501 SecretLiteral: ...`). `sample_per_rule` is unchanged (keys on
  rule, repo, file, line) so the deterministic, nested draw holds for both CSVs. No audit
  row is labelled yet: `measured_precision` stays `None` everywhere, by design.

## Adding a guard

Subclass `GuardrailBase`, set `name`/`stage`, decorate with `@register_guard("name")`, implement
`async def check`, wire the name into **all four** YAML presets (`config/` and `src/aisafe/config/`),
export from `src/aisafe/__init__.py`, add tests. `GuardrailPipeline.from_config` fails loudly on an
unregistered name. Then teach the audit the name (`discover._AISAFE_GUARD_RE`,
`rules/guards._GUARD_CLASSES`), add a probe case per detection pattern with its `seed_pattern`
(an OUTPUT guard's cases go in a `kind: output` corpus), accept the new guard's AUD-801 group in
`audit-baseline.json` with a reason, and, if an audit rule names the class, add it to
`CLASS_SYMBOLS` and give `apply/python.md` a heading. The full checklist is
`.claude/skills/add-guard/SKILL.md`.

## Git

Commit directly to `main` — no branch/PR ceremony. `gh` is installed. CI triggers reference
`develop` and `release/**`, but neither branch exists on the remote.

**Releases.** The version lives in seven places plus the skill's bootstrap scripts and
mirrors; `python scripts/bump_version.py X.Y.Z` rewrites all of them, retitles the
`CHANGELOG.md` Unreleased section and runs `sync_skill.py`, and `--check` is part of the
verify gate. A `vX.Y.Z` tag pushed to `origin` runs `.github/workflows/release.yml`:
gate (version sites equal the tag, sync checks, pytest, self-audit), build, publish to
PyPI through trusted publishing on the `pypi` environment (a required reviewer approves;
no token exists anywhere), a GitHub release with the CHANGELOG section, and a smoke job
that runs the published wheel through `uvx` the way the skill's bootstrap does. Tagging
is the user's act, never done unasked: it publishes.
