---
name: verify-guardrails
description: Run the full local verification gate for this repo — pytest, ruff on changed files, the EU AI Act linter, and the misalignment check. Use before reporting any code change complete, since CI only runs the compliance linter.
---

# Verify

Run all four gates from the **repo root**, in this order. Report each one's result explicitly —
do not stop at the first failure unless it makes the later gates meaningless.

## 1. Tests

```bash
pytest
```

472 tests, ~3s, no API keys needed (all LLM calls are mocked). `asyncio_mode = "auto"`, so async
tests need no decorator. If a test fails, run it alone for detail:
`python -m pytest <file>::<Class>::<test> -q`.

## 2. Lint the files you changed

```bash
git diff --name-only HEAD -- '*.py'
```

Then, for each changed `.py` file:

```bash
ruff check <file>
ruff format --check <file>
```

**Only files touched by this change.** The tree is not lint-clean repo-wide (~156 pre-existing
ruff errors, 52 of 65 files unformatted), so a repo-wide run buries the real diff. Ignore
`tests/fixtures/noncompliant_sample.py` — its 7 `F821` are deliberate linter input.

## 3. EU AI Act compliance

```bash
aisg lint <changed dirs>
```

This is the only gate CI enforces. Exit `0` clean, `1` findings, `2` fatal. Use `--errors-only` to
see just the blocking Art. 5 / security findings, `--list-rules` to look up a rule ID.

## 4. Misalignment

```bash
aisg misalign <changed dirs>
```

`ALIGN-001`, `005`, `006`, `008` are ERROR severity; the rest are warnings. Same flags and exit
codes as the linter above.

## Reporting

State the outcome of each gate plainly. If a gate fails, quote the actual output — do not
paraphrase it as "some issues". If a failure is pre-existing (present on `HEAD` before the change),
say so and confirm it by checking whether the finding is in a file you touched.
