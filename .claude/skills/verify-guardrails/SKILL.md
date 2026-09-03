---
name: verify-guardrails
description: Run the full local verification gate for this repo -- pytest, ruff on changed files, the EU AI Act linter, the misalignment check, and the self-audit against the baseline. Use before reporting any code change complete; CI runs pytest, ruff and the audit gate but not the misalignment check.
---

# Verify

Run all five gates from the **repo root**, in this order. Report each one's result explicitly --
do not stop at the first failure unless it makes the later gates meaningless.

## 1. Tests

```bash
pytest
```

About 2700 tests, about two minutes, no API keys needed (all LLM calls are mocked). `asyncio_mode = "auto"`, so async
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

CI enforces this in `eu-ai-act-compliance.yml`. Exit `0` no findings, `1` findings, `2` fatal. Use `--errors-only` to
see just the blocking Art. 5 / security findings, `--list-rules` to look up a rule ID.

## 4. Misalignment

```bash
aisg misalign <changed dirs>
```

`ALIGN-001`, `005`, `006`, `008` are ERROR severity; the rest are warnings. Same flags and exit
codes as the linter above.

## 5. Self-audit

```bash
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
```

Must exit `0`. `1` means a finding at `high` or above whose fingerprint is not in
`audit-baseline.json`: fix it, or add the fingerprint with a reason if it is accepted. Never
silence it with the ignore marker. `2` is fatal (unreadable baseline, bad path). CI runs the
same command in `tests.yml`. Every finding is `[UNMEASURED]` and the UNKNOWN section lists
the scanners `--no-external` skipped; neither is a failure, and neither is a pass.

## Reporting

State the outcome of each gate plainly. If a gate fails, quote the actual output — do not
paraphrase it as "some issues". If a failure is pre-existing (present on `HEAD` before the change),
say so and confirm it by checking whether the finding is in a file you touched.
