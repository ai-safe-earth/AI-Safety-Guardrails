# Status — 2026-09-05

Where the work stands, what is verified, and what is waiting on a decision.
Written as a handoff: a fresh session should be able to pick up from here plus
`CLAUDE.md`.

## Head

`main` at `6d7f7e7` ("Make the SARIF output valid SARIF"), pushed to
`origin` (`github.com/ai-safe-earth/AI-Safety-Guardrails`). Working tree clean.

Recent history, newest first:

| commit | what |
| --- | --- |
| `6d7f7e7` | SARIF is valid SARIF: marker moved off the root, empty optional fields omitted |
| `d2e1e76` | Compliance gate repaired; every suppression explicit and observable |
| `43c0e41` | The two CI failures: py3.10 `Z`-suffix date parsing, p99 set by one scheduler hiccup |
| `cc01830` | `aisg audit` / `aisg skill` wired into the CLI, self-audit in CI |

## Green

Both workflows pass on `6d7f7e7`:

- **Tests** (run 33847197716) — pytest on 3.10 and 3.13, ruff, wheel builds and
  exposes only `aisg`, `aisg measure --max-p99-ms 25`, the `aisg audit` gate.
- **EU AI Act Compliance** (run 33847197641) — SARIF accepted by Code Scanning
  ("Analysis upload status is complete"), verdict
  `Scanned 80 file(s): 0 error(s), 82 warning(s), 0 info. 2 file(s) skipped by
  ignore-file, 1 finding(s) suppressed by a line directive.`

Locally: **2799 passed, 1 skipped** (~2 min), ruff clean, `aisg lint src examples`
exit 0, `aisg misalign` clean on changed modules, self-audit
(`aisg audit . --no-external --fail-on high --baseline audit-baseline.json`)
exit 0, `scripts/sync_skill.py --check` in sync (version 0.1.0, 13 files, 2 mirrors).

## What the last three commits fixed

1. **py3.10 date parsing** — git's `%cI` writes a `Z` suffix that
   `datetime.fromisoformat` only accepts from 3.11; `audit/walk.py` normalises it.
2. **The measure ratchet** — a case's latency is now the median of
   `TIMING_PASSES` (3) calls, verdict from the first, so one scheduler hiccup on a
   shared runner no longer sets p99. Every raising call lands in `errors` as
   `<case>/t<pass>`; only verdict-pass (`t0`) failures count towards `unavailable`.
3. **Physical lines** — `analyzer.physical_lines()` (`split("\n")`) replaces
   `str.splitlines()` everywhere, because the latter also breaks on FF/VT/NEL and
   U+2028/2029 while `ast.parse` does not, which silently shifted suppression
   directives onto the wrong finding.
4. **SARIF validity** — `codeql-action@v4` validates strictly and rejected the
   root `"schema": "aisg/1"` key and `region.snippet: null`. Both emitters
   (`code_analyzer/reporters.py`, `audit/report.py`) now carry the marker as
   `runs[0].properties.aisg_schema` and omit empty optional fields rather than
   nulling them. Every other machine-readable document still starts with
   `"schema"`. Validated against the real SARIF 2.1.0 JSON schema: 0 errors for
   `lint`, `misalign` and `audit` output.

## Settled — the distribution is `aisguard`

**Decided 2026-09-05.** Both obvious names are taken on PyPI by unrelated
projects: `ai-safety-guardrails` (v1.0.0, a NeMo Guardrails wrapper) and `aisg`
itself (v0.1.1, uploaded 2026-08-07, the Occludra "AI Security Gateway" SDK,
which also imports as `aisg` and is in the same problem domain). So:

- **Distribution: `aisguard`** (free on PyPI, unclaimed as of this date).
- **Import name and console script: `aisg`**, unchanged. No code moved.

Every install spec now names `aisguard`: `pyproject.toml`, the extras'
self-references, `audit/report.py:DISTRIBUTION` (and `pip show`), the skill
bootstrap scripts, `.gitlab-ci-euaiact.yml`, README and SECURITY.md.

The `aisg`/`aisguard` split is a real hazard worth remembering: installing the
PyPI `aisg` alongside this package puts two different top-level `aisg` modules
in one environment. CLAUDE.md "Layout" carries the rule.

Still open, and unblocked by the rename:

- Nothing is published yet, so the skill bootstrap's
  `uvx --from "aisguard==0.1.0"` still cannot resolve — it now fails with a 404
  instead of risking someone else's code, which is the safe failure.
  `.gitlab-ci-euaiact.yml` keeps the `git+https://…@v${AISG_VERSION}` install
  for the same reason, and **no `v0.1.0` tag exists on the remote yet.**
- To finish: tag `v0.1.0`, then either publish `aisguard` to PyPI or leave the
  git install as the only path.

## Known-broken, deliberately left

See CLAUDE.md "Known-broken" — items 1 (`.secrets.baseline` absent), 3
(`examples/advanced_injection_demo.py:68`) and 4 (cp1252 console) still stand.
Items 2 and 5 are cleared, kept for numbering.

Also left alone on purpose, each pre-existing and documented in the review notes:
the ALIGN-006 hit in `misalignment_check.py`'s epilog, `--rules` dropping unknown
ids silently, a suppression directive followed by trailing prose failing closed
(the documented grammar is rule ids only), the file marker being a substring
test, a BOM breaking `ast.parse`, and `scan_diff(base_dir=".")` scanning nothing
when run from a subdirectory.

## How to verify from a cold start

```bash
pytest                                    # ~2800 tests, ~2 min, no API keys
ruff check src tests
aisg lint src examples --errors-only
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
gh run list --limit 4
```
