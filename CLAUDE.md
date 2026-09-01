# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Layout

`src/` layout. The only importable top-level name is `aisg` — everything is
`aisg.core.*`, `aisg.modules.*`, `aisg.integrations.*`, `aisg.devtools.*`,
`aisg.config.*`. Nothing is importable as a bare `core`/`modules`/`config`,
and it must stay that way: those names would collide with users' own modules
once published to PyPI.

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
pytest                                                    # 472 tests, ~3s, no API keys (all LLM calls mocked)
python -m pytest tests/unit/test_pii_tokenization.py::TestPIIRestorer -q   # single test
python -m pytest tests/unit/test_pii_tokenization.py -k "roundtrip" -q

ruff format <file>                                        # authoritative formatter
ruff check --fix <file>

aisg lint src/                                            # EU AI Act compliance linter
aisg misalign src/                                        # ALIGN-001..008 rule set
```

`aisg` is the single console script (`aisg.cli:main`); `euaiact-lint` and
`misalignment-check` remain as aliases. Both subcommands share flags: `--staged`, `--diff`,
`--errors-only`, `--fail-on-warnings`, `--format terminal|json|sarif|markdown`,
`--output <path>`, `--list-rules`. The CLI passes everything after the subcommand through
verbatim (`argparse.REMAINDER`), so `aisg lint --help` shows the linter's own help.
Exit codes: `0` clean, `1` findings, `2` fatal.
Their defaults come from `[tool.euaiact-lint]` / `[tool.misalignment-check]` in
`pyproject.toml` via `src/aisg/devtools/_config.py`; an explicit CLI flag always wins, but a `true`
boolean there cannot be switched back off from the command line.

**Verify before reporting done:** `pytest`, `ruff check` on changed files, then both `devtools/`
CLIs on the changed modules. CI runs *only* `euaiact_lint.py` — no pytest, no ruff, no mypy — so
local verification is the only real gate.

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
- **`Action.HUMAN` does not set `PipelineResult.blocked`.** `ToolPolicyGuard` (approval
  denied/timeout) and `EUAIActCompliance` (Art. 14 gate) return `HUMAN` with `passed=False`, yet
  `.blocked` stays `False` and `.passed` stays `True`. Callers must inspect
  `result.checks[*].requires_human` — checking `.blocked` alone lets human-review requests through.
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
2. `ruff check .` reports 8 `F841` unused-variable findings, left in place deliberately. Two
   look like real bugs rather than dead code: `aisg/modules/llm_judges/claude_judge.py` parses
   `reason` from the model's JSON but `JudgeVerdict` has no such field, so the explanation is
   dropped; `aisg/modules/llm_judges/openai_mod.py` parses per-category `flags` and never uses
   them. Do not blind-delete the rest — some are side-effecting calls in tests.
3. `examples/advanced_injection_demo.py:68` raises `AttributeError` — it calls `.encode()` on
   the `bytes` returned by `base64.b64encode`. Examples are not covered by pytest.
4. Console output uses `✓`/`✗`, which crashes on a cp1252 Windows terminal. Run examples with
   `PYTHONIOENCODING=utf-8`.
5. Every machine-readable CLI document starts with `"schema": "aisg/1"`. In SARIF this is an
   extra root property the 2.1.0 spec does not define — GitHub Code Scanning accepts it, a
   strict schema validator may not.

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
partly-labelled CSV. See `bench/README.md`.

## Adding a guard

Subclass `GuardrailBase`, set `name`/`stage`, decorate with `@register_guard("name")`, implement
`async def check`, wire the name into **all four** YAML presets (`config/` and `src/aisg/config/`),
export from `src/aisg/__init__.py`, add tests. `GuardrailPipeline.from_config` fails loudly on an
unregistered name.

## Git

Commit directly to `main` — no branch/PR ceremony. `gh` is installed. CI triggers reference
`develop` and `release/**`, but neither branch exists on the remote.
