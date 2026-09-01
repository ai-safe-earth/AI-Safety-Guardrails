---
name: add-guard
description: Checklist for adding a new guardrail to this repo — subclassing GuardrailBase, registering it, wiring both YAML configs, and exporting it. Use whenever adding, renaming, or removing a guard module.
---

# Adding a guard

The pipeline resolves guards by name through a registry, and `GuardrailPipeline.from_config` fails
loudly on an unregistered name. Missing any step below produces a runtime failure, not a lint error.

## Steps

1. **Create the module** under the stage it belongs to: `modules/input/`, `modules/processing/`,
   `modules/output/`, or `modules/policy/`. Start with the repo's file header convention:

   ```python
   """
   modules/<stage>/<name>.py
   -------------------------
   <one-line purpose>
   """

   from __future__ import annotations
   ```

2. **Subclass `GuardrailBase`** (`core/base.py`). Set `name` and `stage` (a `GuardrailStage`), and
   implement:

   ```python
   async def check(self, content: str, context: dict) -> CheckResult:
   ```

   Return a `CheckResult` with the right `Action`. Note that **`Action.HUMAN` does not set
   `PipelineResult.blocked`** — if the guard needs a hard stop, return `Action.BLOCK`.

3. **Register it** with `@register_guard("<name>")` from `core/registry.py`. The string is the key
   used in YAML config — keep it identical to the class's `name`.

4. **Wire it into BOTH configs** — `config/default.yaml` *and* `config/eu_high_risk.yaml`. Adding it
   to only one is the most common mistake. `eu_high_risk.yaml` sets `parallel_checks: false`
   deliberately ("Sequential for high-risk — ensures full chain logging"); do not flip it.

5. **Export it** from the root `__init__.py` alongside the other guards.

6. **Add tests** in `tests/unit/`. `asyncio_mode = "auto"`, so `async def test_...` needs no
   decorator. There is no `conftest.py` — copy the `sys.path.insert` bootstrap from a neighbouring
   test file. Mock any LLM call; the suite must stay keyless.

## Context-dict rules

If the guard stores per-request state, put it in the shared `context` dict under an underscore-
prefixed key (the existing ones are `_pii_token_map` and `_tool_session_counters`). The same dict is
threaded through `run_input`/`run_processing`/`run_output`, and `_run_stage` writes
`context["guardrail_stage"]` into it — never copy or replace the dict mid-pipeline.

## Parallel-mode caveat

If the guard **redacts or rewrites content**, it only composes correctly in sequential mode. Under
`parallel=True` every guard sees the original content and redactions are merged afterwards, so a
downstream guard will not see your sanitized output. Say so in the guard's docstring.

## Verify

Run `/verify-guardrails` when done.
