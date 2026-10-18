# Status — 2026-10-19

Where the work stands, what is verified, and what is waiting on a decision.
Written as a handoff: a fresh session should be able to pick up from here plus
`CLAUDE.md` and `docs/PLAN.md`.

## The plan, and where we are in it

`docs/PLAN.md` (committed 2026-10-19) is the plan for the complete solution the
user asked for on 2026-10-18: audit any software for AI safety, propose and
price the controls, apply them with a human in the loop, attest a level with a
named owner, hook into coding agents and CI, and run at scale. Seven waves; the
detailed designs are `docs/plan/01..03`. Four decisions were settled with the
user and are recorded in the plan's section 2; do not re-open them without a
reason written there.

| wave | scope | state |
| --- | --- | --- |
| 0 | performance pass, CHANGELOG, `bump_version.py`, `release.yml`, README truth-up, `v0.1.0` | code done; **the tag is the user's act** (below) |
| 1 | tokens and prices, `aisg measure` extension, `aisg decide`, `Budget`, AUD-806 | next |
| 2 | `aisg hook`, Claude Code plugin, Cursor/Gemini installers, Action, pre-commit source | |
| 3 | P11 persons-and-manipulation rules, two output guards, corpora | |
| 4 | `aisg attest` with levels and a named owner | |
| 5 | seven-phase skill, SYSTEM.md, CONTRIBUTING, README | |
| 6 | `aisg fleet`, bench `--tool audit`, `v0.2.0` | |

## Landed 2026-10-19

- **`perf(audit)` (`9fad7b6`)**: a full audit is 3-4x faster with identical
  findings (this repo 28.5 s -> 8.4 s; AdalFlow, 428 files, 44.6 s -> 10.9 s;
  VaiVia, 342 files, 18.9 s -> 9.3 s; `import aisg` 0.50 s -> 0.29 s). Four
  caches, none changing a result; the invariants are in CLAUDE.md ("The audit's
  run time is budgeted"). The gate-text anchors had to move into `vocab.py`:
  the self-audit read a bypass literal in `pydeep.py` as AUD-202, which is the
  vocabulary rule working as designed.
- **`release` (`1f33bfe`)**: `scripts/bump_version.py` (seven version sites plus
  the skill scripts and mirrors through `sync_skill.py`; `--check` is in the
  gate), `.github/workflows/release.yml` (trusted publishing behind the `pypi`
  environment, GitHub release from the CHANGELOG section, `uvx` smoke on two
  fixtures with exact exit codes), `CHANGELOG.md` with the 0.1.0 section, the
  README corrected (install says `aisguard`, extras match pyproject, the tree
  and the skill phases are current), SECURITY.md says how a release is made.
- **`docs(plan)` (`7a89478`)**: `docs/PLAN.md` and `docs/plan/`.

## What the user has to do for `v0.1.0`

Nothing is uploaded without these steps; the plan prepared them and stops here.

1. On pypi.org: Your projects -> Publishing -> Add a new pending publisher:
   project `aisguard`, owner `ai-safe-earth`, repository `AI-Safety-Guardrails`,
   workflow `release.yml`, environment `pypi`. Check `aisguard` is still
   unclaimed first (`pip index versions aisguard` should find nothing; it was
   free on 2026-09-05).
2. On GitHub: Settings -> Environments -> `pypi` -> required reviewers: you.
   This is the approval step; the publish job waits on it.
3. `git tag v0.1.0 && git push origin v0.1.0`, approve the `pypi` run, watch
   the `smoke` job print `smoke: aisguard==0.1.0 audits as expected`.

Until then the skill's bootstrap resolves only against a local checkout or
`pip install "aisguard[devtools] @ git+https://github.com/ai-safe-earth/AI-Safety-Guardrails"`,
and `.gitlab-ci-euaiact.yml` keeps its git-tag install (flipped to PyPI in wave 6).

## Head

`main` at `1f33bfe` plus this status commit. Pushed to `origin`
(`github.com/ai-safe-earth/AI-Safety-Guardrails`). No tags yet.

## Green

Locally on `1f33bfe` (2026-10-19): **3675 passed, 1 skipped** (2m29s; the
suite grew by 40 tests), `ruff check` / `ruff format --check` on `src tests
scripts`, `aisg lint src examples --errors-only` no issues, `aisg misalign` on
the changed modules reports only the twelve pre-existing ALIGN-004 warnings in
`src/aisg/__init__.py`'s docstring (present at `ce2ab43` too), self-audit
`baseline: 0 new, 22 unchanged, 0 no longer reported`, `sync_skill.py --check`
and `controls_md.py --check` in sync, `bump_version.py --check` in sync at 7
sites, the 25 new release tests green.

## Left open on purpose

- The VaiVia walkthrough in `docs/handoff.md` is still at phase 3 row 2 of 11;
  the plan's wave 5 verification re-runs it with the seven-phase skill.
- `AUD-602`, `AUD-605` and `AUD-106` still report per occurrence; two findings
  can still share a fingerprint (digits stripped). Both are in the plan's risks.
- `measured_precision` is `None` on every rule; `bench/` has 0 labelled rows;
  wave 6 adds `bench --tool audit`.
- The stale `~/.claude/skills/ai-safety-audit` copy on this machine (installed
  Oct 4) is refreshed by `aisg skill install --global --force` once wave 5 lands.

## Known-broken, deliberately left

See CLAUDE.md "Known-broken": items 1 (`.secrets.baseline` is in fact tracked;
the note there is stale), 3 (`examples/advanced_injection_demo.py:68`) and 4
(cp1252 console) still stand.

## How to verify from a cold start

```bash
pytest                                    # ~3675 tests, ~2.5 min, no API keys
ruff check src tests scripts && ruff format --check src tests scripts
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
python scripts/bump_version.py --check
gh run list --limit 4
```
