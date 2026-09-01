# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Layout

Packages live at the repo **root** — there is no `src/`. Imports are top-level absolute:
`from core.pipeline import GuardrailPipeline`, `from modules.input.pii_detector import PIIDetector`.

The package is **not installable** (see Known-broken below). Every test file and `examples/*.py`
self-bootstraps with `sys.path.insert(0, ".../..")`, and there is no `conftest.py`. **Run every
command from the repo root** — `pytest`'s `testpaths` and both `devtools/` CLIs assume it.

`config/` and the root `__init__.py` are excluded from `[tool.setuptools.packages.find]`; only
`core*`, `modules*`, `integrations*`, `devtools*` ship.

## Commands

No Makefile, no script runner — everything is ad-hoc.

```bash
pytest                                                    # 472 tests, ~3s, no API keys (all LLM calls mocked)
python -m pytest tests/unit/test_pii_tokenization.py::TestPIIRestorer -q   # single test
python -m pytest tests/unit/test_pii_tokenization.py -k "roundtrip" -q

ruff format <file>                                        # authoritative formatter
ruff check --fix <file>

python devtools/euaiact_lint.py modules/                  # EU AI Act compliance linter
python devtools/misalignment_check.py modules/            # ALIGN-001..008 rule set
```

Both `devtools/` CLIs share flags: `--staged`, `--diff`, `--errors-only`, `--fail-on-warnings`,
`--format terminal|json|sarif|markdown`, `--output <path>`, `--list-rules`.
Exit codes: `0` clean, `1` findings, `2` fatal.
Their defaults come from `[tool.euaiact-lint]` / `[tool.misalignment-check]` in
`pyproject.toml` via `devtools/_config.py`; an explicit CLI flag always wins, but a `true`
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
2. README API drift: `from modules.output.pii_detector import PIIRestorer` (it lives in
   `modules/input/`), `AnthropicGuardrailMiddleware(client=..., pipeline=...)` (the real class is
   `AnthropicGuardrail(pipeline=..., **client_kwargs)`), and "415 tests" (actually 475).
3. `config/` is excluded from `[tool.setuptools.packages.find]`, so `default.yaml` /
   `eu_high_risk.yaml` do not ship in the wheel — `GuardrailPipeline.from_config("config/...")`
   works from a checkout but not from an installed package.
4. `ruff check .` reports 8 `F841` unused-variable findings, left in place deliberately. Two
   look like real bugs rather than dead code: `modules/llm_judges/claude_judge.py` parses
   `reason` from the model's JSON but `JudgeVerdict` has no such field, so the explanation is
   dropped; `modules/llm_judges/openai_mod.py` parses per-category `flags` and never uses
   them. Do not blind-delete the rest — some are side-effecting calls in tests.
5. `examples/advanced_injection_demo.py:68` raises `AttributeError` — it calls `.encode()` on
   the `bytes` returned by `base64.b64encode`. Examples are not covered by pytest.
6. Console output uses `✓`/`✗`, which crashes on a cp1252 Windows terminal. Run examples with
   `PYTHONIOENCODING=utf-8`.

## Adding a guard

Subclass `GuardrailBase`, set `name`/`stage`, decorate with `@register_guard("name")`, implement
`async def check`, wire the name into **both** `config/default.yaml` and `config/eu_high_risk.yaml`,
export from the root `__init__.py`, add tests. `GuardrailPipeline.from_config` fails loudly on an
unregistered name.

## Git

Commit directly to `main` — no branch/PR ceremony. `gh` is installed. CI triggers reference
`develop` and `release/**`, but neither branch exists on the remote.
