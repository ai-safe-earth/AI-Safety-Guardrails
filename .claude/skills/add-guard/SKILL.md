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

7. **Add a probe case per detection pattern** in `src/aisafe/probes/` with its `seed_pattern`,
   and a benign case in `benign_traffic.yaml` when the pattern can misfire (mention vs use).
   An OUTPUT guard gets its cases in `manipulation_responses.yaml` (`kind: output`, with a
   `verdict`) or a sibling output corpus; `aisafe measure` is what scores it.

8. **Teach the audit the name**: `discover._AISAFE_GUARD_RE` and `rules/guards._GUARD_CLASSES`
   (registry name -> class name), so `aisafe audit` sees the guard wired in a preset or in code.

9. **If an audit rule names the class** in its `recommendation.package`, export it from
   `aisafe.__all__`, add it to `CLASS_SYMBOLS` in `tests/unit/test_audit_rules_registry.py`, and
   give `references/apply/python.md` a `## \`Name\`` heading; `same_control: True` needs a pair
   in `tests/unit/test_audit_rules_package.py`.

10. **Run the self-audit** (`aisafe audit . --no-external --fail-on high --baseline
    audit-baseline.json`): the new guard is an AUD-801 group (unmeasured) and needs an
    accepted reason in `audit-baseline.json`.

11. **The module docstring must not spell the audit's prompt-objective or persona phrases**
    (`persons_patterns.ENGAGEMENT_OBJECTIVE`, `PERSONA_CONCEALMENT`); describe categories, not
    objectives, or the self-audit reads the guard as a prompt.

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
