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
| 1 | tokens and prices, `aisg measure` offline + cost columns, `aisg decide`, `Budget`, AUD-806 | code done, committed 2026-10-19 |
| 2 | `aisg hook`, Claude Code plugin, Cursor/Gemini installers, Action, pre-commit source | next |
| 3 | P11 persons-and-manipulation rules, two output guards, corpora | |
| 4 | `aisg attest` with levels and a named owner | |
| 5 | seven-phase skill, SYSTEM.md, CONTRIBUTING, README | |
| 6 | `aisg fleet`, bench `--tool audit`, `v0.2.0` | |

## Landed 2026-10-19

- **wave 1, `feat(decide)`** (the commit after `b33dc68`): the cost layer of
  `docs/plan/01-decide-cost-latency-metrics.md`.
  - `LLMUsage` (`core/measurement.py`) on every judge-backed `CheckResult` as
    `metadata["llm_usage"]`; `cost_basis` in `none|measured|estimated|unavailable`;
    `metadata["guard_name"]` stamped by `GuardrailBase.__call__`;
    `PipelineResult.llm_usage`; otel meters `guardrail.guard.llm_calls`,
    `.tokens`, `.tokens_per_call`; token fields on the JSONL audit record. All
    five judges and the NeMo integration report usage; `CachedJudge` reports a
    hit as zero-token `from_cache`.
  - `aisg measure` is OFFLINE by default: judge calls are estimated from the
    hoisted prompt constants (`llm_judges/estimate.py`, chars / 4), never made;
    `llm_exercised: false` renders UNMEASURED, never 0%. `--allow-provider-calls`
    and `--include-policy` opt in. Per guard: tokens, price at the table's rates,
    `fail_mode`, `human_rate`, `benign_modified_rate`. The ratchet
    (`--max-p99-ms 25`) is unchanged and green.
  - Dated price table `config/prices.yaml` = `src/aisg/config/prices.yaml`
    (`as_of`, `sources`, `stale_after_days`), read by `devtools/prices.py`.
    Nothing fetches a price; a model not in the table is `unavailable` and
    names itself.
  - `aisg decide` (`devtools/decide.py`): four verdicts, deterministic from the
    declared budgets; the decision document (`kind: decision`) is evidence the
    audit reads back; `aisg audit --format html --decision FILE` adds the Trade
    table. `Budget` and `Thresholds.max_usd_per_request` / `max_human_rate`;
    `aisg init` asks for `traffic:` and `budgets:`;
    `GuardrailPipeline(thresholds=...)` is the opt-in runtime demotion.
  - AUD-806 "Reported guard over the declared budget" (47 rules now) and the
    AUD-801/cost sub-finding for a judge the measure report never exercised.
  - Two audit corrections the new tool forced, both pinned by
    `tests/unit/test_audit_wave1_rules.py`: AUD-801 counts an eval file's mention
    of a guard as evidence only when the file is an eval config, a data file or a
    test module (`decide.py` and `measure.py` name every guard and had silenced
    the rule for all of them; a README does the same in a user's repo), and
    AUD-601 does not read the ids in an `aisg/1` price table as deployments.
  - `audit-baseline.json` refreshed with `--write-baseline` (18 reasons carried
    over) and `--amend-baseline --accept` for the 7 new AUD-801 entries: the five
    guards the default preset wires (CI measures them on every push but keeps the
    report as a build artifact the audit cannot read; committing
    `.aisg-audit/measure-report.json` is the alternative) and two re-anchored
    entries (`llm_input_filter`, `nemo_rails`, now anchored on `decide.py`'s
    guard-family table). Gone from the baseline: the two AUD-802 fail-open
    findings on `prompt_injection.py` and `toxicity.py`, which now record the
    judge failure (`metadata["judge_error"]`) instead of swallowing it.
- **`perf(audit)` (`9fad7b6`)**: a full audit is 3-4x faster with identical
  findings (this repo 28.5 s -> 8.4 s; AdalFlow, 428 files, 44.6 s -> 10.9 s;
  VaiVia, 342 files, 18.9 s -> 9.3 s; `import aisg` 0.50 s -> 0.29 s). Four
  caches, none changing a result; the invariants are in CLAUDE.md ("The audit's
  run time is budgeted").
- **`release` (`1f33bfe`)**: `scripts/bump_version.py`, `release.yml` (trusted
  publishing behind the `pypi` environment), `CHANGELOG.md`, README corrected,
  SECURITY.md says how a release is made.
- **`docs(plan)` (`7a89478`)**: `docs/PLAN.md` and `docs/plan/`.

## What the user has to do for `v0.1.0`

Nothing is uploaded without these steps; the plan prepared them and stops here.
The 0.1.0 CHANGELOG section now includes wave 1, since the tag does not exist
yet and will point at a `main` that carries it.

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

`main` at the wave-1 commit (after `b33dc68`). Pushed to `origin`
(`github.com/ai-safe-earth/AI-Safety-Guardrails`). No tags yet.

## Green

Locally on the wave-1 tree (2026-10-19): **3875 passed, 2 skipped** (2m39s; the
suite grew by 200 tests this wave), `ruff format --check .` and `ruff check .`
on the whole tree, `aisg lint src examples --errors-only` no issues,
`aisg misalign` on the changed devtools modules no issues (the twelve
pre-existing ALIGN-004 warnings in `src/aisg/__init__.py`'s docstring and the
two ALIGN-001 in `llm_judges/base.py` are unchanged from `b33dc68`), self-audit
`baseline: 0 new, 25 unchanged, 0 no longer reported`, `aisg measure
--max-p99-ms 25` exit 0, `sync_skill.py --check`, `controls_md.py --check` (47
rules) and `bump_version.py --check` (7 sites) in sync.

## Left open on purpose

- AUD-801 is accepted in the baseline for the five guards `default.yaml` wires.
  The honest alternative is committing a measure report under `.aisg-audit/`
  so a fresh clone's audit reads it as `REPORTED <age>`; it would go stale on
  every guard change, so it was not done. Decide in wave 5 with the skill rework.
- AUD-801 anchors on the first guard site by path (a documented known failure
  mode of the rule), so a new file that names a guard and sorts first moves the
  fingerprint; two entries were re-accepted this wave for that reason.
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
pytest                                    # ~3875 tests, ~2.5 min, no API keys
ruff check . && ruff format --check .
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
python scripts/bump_version.py --check
gh run list --limit 4
```
