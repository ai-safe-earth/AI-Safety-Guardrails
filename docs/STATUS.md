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
| 1 | tokens and prices, `aisg measure` offline + cost columns, `aisg decide`, `Budget`, AUD-806 | committed `e748021` |
| 2 | `aisg audit --only`, `aisg hook`, Claude Code plugin, Cursor/Gemini installers, Action, pre-commit, GitLab job | committed 2026-10-19 (the commit after `e748021`) |
| 3 | P11 persons-and-manipulation rules, two output guards, corpora | next |
| 4 | `aisg attest` with levels and a named owner | |
| 5 | seven-phase skill, SYSTEM.md, CONTRIBUTING, README | |
| 6 | `aisg fleet`, bench `--tool audit`, `v0.2.0` | |

## Landed 2026-10-19

- **wave 2, `feat(hook)`**: design `docs/plan/02`, sections 1-5.
  - `aisg audit --only PATH` (`main.FILE_LOCAL_RULES`, `WalkOptions.only`,
    `target.only`, the "partial run" line, an UNKNOWN row for an unseen path;
    `only` joins `NOT_CONFIGURABLE`). `test_audit_only.py` pins that a partial
    run's fingerprints equal the full run's on the py_agent fixture.
  - `devtools/hosts.py`: the host table shared by `aisg skill` and `aisg hook`
    (`Host.hooks: HookSupport | None`; keys unchanged). Hook facts verified
    against the Claude Code, Cursor and Gemini CLI docs on 2026-10-19; Codex has
    no documented command hooks and the row says so.
  - `devtools/hook.py`: `aisg hook run|install|uninstall|list`. Policies re-use
    the audit's tables (protected paths, secret literals via `discover.grep_file`,
    unsafe hook patterns, host over-grant literals), the recheck is
    `aisg audit --only` in-process, the posture reads the last report, the Stop
    gate is a full audit against the baseline that blocks once. Fails open on
    its own errors and records them in `.aisg-audit/hook-state.json`; no model,
    no install, no socket (the prompt policy drives the guard's coroutine
    without an event loop); writes only under `.aisg-audit/`. `install` prints
    the diff and writes only with `--yes`; an agent running the installer is
    itself an `ask`. `[tool.aisg-hook]` documented in pyproject (all defaults).
  - Canonical skill gains `scripts/hook.sh` / `hook.ps1` (pinned bootstrap,
    `--origin`, `--expect-version`, fail-open; Cursor gets an explicit allow).
  - Claude Code plugin: `.claude-plugin/marketplace.json` (`ai-safe-earth`),
    `plugins/ai-safety-audit/{.claude-plugin/plugin.json, hooks/hooks.json,
    README.md, skills/ai-safety-audit/**}`; the skill copy is mirror #3 of
    `sync_skill.py`, which also pins `plugin.json` (`bump_version.py`: 9 sites).
  - CI surface: `action.yml` (composite, version pinned to pyproject by a test,
    `install-from: action-path`, three audit calls each `|| [ $? -eq 1 ]`,
    verdict = the JSON's exit code), `.pre-commit-hooks.yaml` (`aisg-audit`
    pre-push, `aisg-lint`, `aisg-misalign`), our own pre-push audit hook, the
    `aisg-audit` GitLab job (git pin until wave 6), the `action` dogfood job in
    `tests.yml`.
  - Baseline: 5 new entries accepted with reasons (the plugin mirror's AUD-101
    docs mention; four AUD-202 on the installer's confirmation flag in `cli.py`
    and `hook.py`). 145 new tests.
- **wave 1, `feat(decide)` (`e748021`)**: `LLMUsage` on every judge-backed
  result, `aisg measure` offline by default with cost columns, `prices.yaml`,
  `aisg decide`, `Budget`, AUD-806, two audit corrections (AUD-801 eval
  evidence, AUD-601 price table).
- **`perf(audit)` (`9fad7b6`)**, **`release` (`1f33bfe`)**, **`docs(plan)`
  (`7a89478`)**: see the git log.

## What the user has to do for `v0.1.0`

Nothing is uploaded without these steps; the plan prepared them and stops here.
The 0.1.0 CHANGELOG section now includes waves 1 and 2, since the tag does not
exist yet and will point at a `main` that carries them. Once the tag exists,
`uses: ai-safe-earth/AI-Safety-Guardrails@v0.1.0` (Action), `rev: v0.1.0`
(pre-commit) and `claude plugin marketplace add ai-safe-earth/AI-Safety-Guardrails`
all resolve; the plugin works from `main` today.

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

`main` at the wave-2 commit (after `e748021`). Pushed to `origin`
(`github.com/ai-safe-earth/AI-Safety-Guardrails`). No tags yet.

## Green

Locally on the wave-2 tree (2026-10-19): **4020 passed, 2 skipped** (2m29s),
`ruff format --check .` and `ruff check .`, `aisg lint src examples
--errors-only` no issues, `aisg misalign` on the changed modules no issues
(the pre-existing ALIGN warnings in `src/aisg/__init__.py` and
`llm_judges/base.py` are unchanged), self-audit `baseline: 0 new, 31
unchanged, 0 no longer reported` (30 fingerprints, 30 reasons; one fingerprint
anchors two sites), `aisg measure --max-p99-ms 25` exit 0, `sync_skill.py
--check` (15 files, 3 mirrors), `controls_md.py --check` (47 rules) and
`bump_version.py --check` (9 sites) in sync.

## Left open on purpose

- The hook's Cursor `afterFileEdit` has no documented answer channel, so the
  recheck result is recorded and surfaces at `stop` as a `followup_message`.
  Gemini has no `ask`; `ask-fallback` decides. Codex: nothing is written until
  the vendor documents command hooks. All three are stated in `hosts.md`.
- The hooks have not yet been exercised against a live Claude Code session on
  this machine (the matrix is pinned by `test_hook.py` against the documented
  envelopes); the wave 5 verification does that on the VaiVia clone.
- AUD-801 is accepted in the baseline for the five guards `default.yaml` wires
  (CI measures them but keeps the report as a build artifact); committing a
  measure report under `.aisg-audit/` is the alternative. Decide in wave 5.
- AUD-202 fires on the installer's own confirmation flag; four acceptances say
  why. A vocabulary that distinguishes an operator's CLI confirmation from an
  agent approval bypass is a rule change for the bench, not a baseline entry.
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
pytest                                    # ~4020 tests, ~2.5 min, no API keys
ruff check . && ruff format --check .
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
python scripts/bump_version.py --check
aisg hook list                            # the host table and which aisg this is
gh run list --limit 4
```
