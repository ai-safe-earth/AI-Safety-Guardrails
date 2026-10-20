# Status — 2026-10-20

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
| 0 | performance pass, CHANGELOG, `bump_version.py`, `release.yml`, README truth-up, `v0.1.0` | tagged `v0.1.0` at `89706a6`; `aisafe` 0.1.0 on PyPI 2026-10-20 |
| 1 | tokens and prices, `aisafe measure` offline + cost columns, `aisafe decide`, `Budget`, AUD-806 | committed `e748021` |
| 2 | `aisafe audit --only`, `aisafe hook`, Claude Code plugin, Cursor/Gemini installers, Action, pre-commit, GitLab job | committed `40af8c1` |
| 3 | P11 persons-and-manipulation rules, `ManipulationGuard`, `AIDisclosureGuard`, corpora, `prompt_audit` | committed `ed7b41b` |
| 4 | `aisafe attest` with levels and a named owner | committed `e5ef805` |
| 5 | seven-phase skill, SYSTEM.md, CONTRIBUTING, README | committed `ab19e68` |
| 6 | `aisafe fleet`, bench `--tool audit`, `v0.2.0` | fleet and bench committed 2026-10-19 (the commit after `ab19e68`); GitLab template on the PyPI pin 2026-10-20; `0.2.0` is the next release, the user's act |

## Landed 2026-10-20

- **rename, `chore(name)`**: the distribution, the import name and the command are
  all `aisafe` (were `anyaisafe`, `aisg`, `aisg`; none ever published). `aisafe` was
  free on PyPI on 2026-10-20, including PyPI's look-alike rule (no project name
  normalises to the same string), and no package installs an `aisafe` module; the
  unrelated `aisafeguard` does install an `aisafe` command. Renamed with them:
  `.aisafe-audit/`, `.aisafe-fleet/`, `[tool.aisafe-*]`, `# aisafe-audit:
  ignore-file`, the `AISAFE_*` variables, the hook bootstrap `aisafe-hook.sh`, the
  pre-commit ids `aisafe-audit`, `aisafe-lint` and `aisafe-misalign`, and "AnyAISafe
  level" in the attestation statement. The old spellings are read, never written
  (`patterns.LEGACY_*`, `_config.LEGACY_SECTION_PREFIX`, the hook marker, the semgrep
  keys, `AISG_PRICES`). Kept: `"schema": "aisg/1"` with its SARIF and html carriers,
  and the probe canaries.
- **the `v0.1.0` release run failed at the upload** (`invalid-publisher`: PyPI had
  no pending publisher for the repository). Nothing reached PyPI; the tag `v0.1.0`
  exists on `origin` at `a81b3b2`, with the old names.
- **`aisafe` 0.1.0 published** from `v0.1.0` moved to `89706a6` (see "The first
  release" below).
- **the GitLab template installs from PyPI**: `pip install --quiet
  "aisafe[devtools]==${AISAFE_VERSION}"`; `AISAFE_SOURCE` and the git-tag install are
  gone, `TestCITemplates` pins the exact install line and that no `aisafe` install in
  the file is unpinned. The four jobs were run in `python:3.11-slim` (docker) against
  this repository with the PyPI 0.1.0: full scan 0 errors exit 0, merge-request scan
  exit 0, weekly audit exit 1 on warnings (`allow_failure: true`, as designed),
  `aisafe-audit` exit 0 with the baseline and 1 without it.
- **`bump_version.py 0.2.0` not run, on purpose.** It would pin the skill bootstraps
  (`uvx --from aisafe==0.2.0`), the hook's `--expect-version`, the Action's default
  `version`, the plugin manifest and the GitLab template to a version PyPI does not
  have, and date a 0.2.0 CHANGELOG section that was never released. Plugin users
  follow `main`, so they would get the broken pins at once. Rule from here on: run
  `bump_version.py X.Y.Z` only in the commit that is tagged `vX.Y.Z` right after.

## Landed 2026-10-19

- **rename, `chore(name)` (`a81b3b2`)**: the project is AnyAISafe. Distribution
  `anyaisafe` (was `aisguard`, never published), repository
  `github.com/ai-safe-earth/AnyAISafe` (GitHub redirects the old name), the
  OpenTelemetry service-name default and prose everywhere. The import name and the
  `aisg` command were kept that day; 2026-10-20 renamed them (above).
- **wave 6, `feat(fleet)`**: design `docs/plan/02` sections 6 and 7.
  - `devtools/_git.py` (`fetch_pinned`, `clone_shallow`, one-line `GitError`; the
    bench's fetch moved into the package, two callers) and `devtools/fleet.py`,
    `aisafe fleet LIST`: YAML or CSV list the operator wrote (`bench/corpus.yaml` is
    valid), one `aisafe audit --no-external` subprocess per repository under a
    wall-clock cap, `--jobs`, `--resume`, `--proposal` (a PR body with the plan
    and a blank decide table, `file:line` only), `--fail-on-findings`;
    `fleet-report.{json,csv,md}` (`kind: fleet`) with counts, rule frequencies,
    inventory highlights and report paths, never a snippet. Exit 0 when every
    repository was audited, 1 when one could not be, 2 fatal. Never searches,
    pushes or opens a PR; never writes into a local path. 26 fleet tests, 5 git
    tests (a local origin, no network).
  - `bench/run.py --tool audit` / `bench/score.py --tool audit`: the same corpus,
    sampling and label loop for the `AUD-*` rules (`findings-audit.csv` with `sub`
    and the redacted `snippet`; `precision-audit.md`; a paste block keyed by class
    name). No audit row is labelled; `measured_precision` stays `None`.
  - Docs: CLAUDE.md section, README section and structure block, `docs/SYSTEM.md`
    fleet row, `SECURITY.md` scope, `bench/README.md`, CHANGELOG.
  - One mistake found and undone: the wave-5 gate's bare `aisafe measure` wrote
    `measure-report.json` into the repository root and `git add -A` committed it in
    `ab19e68`; the next self-audit read it as evidence and reported seven AUD-801
    acceptances as `no longer reported`. The file is removed, `/measure-report.json`
    and `/probe-report.json` are gitignored, and CLAUDE.md says to run measure with
    `-o` outside the tree.
  - **Not done, on purpose**: the GitLab template's flip to the PyPI pin and
    `bump_version.py 0.2.0`. Both presuppose a published `v0.1.0`, which is the
    user's act (below); until then the 0.1.0 CHANGELOG section carries waves 1-6
    and the template installs from the git tag.
- **wave 5, `feat(skill)` (`ab19e68`)**: design `docs/plan/03` part D.
  - `SKILL.md` runs seven phases (survey, document 1, decide, apply, document 2,
    verify, attest) and a closing step that offers `aisafe hook install` and the
    Action by name. Hard rule 8 (which aisafe ran: `audit.sh` / `attest.sh` print
    `aisafe: <path> version <v> (pinned <v>)` on stderr, the skill stops on a
    mismatch) and rule 9 (never push; the PR path commits on a branch and prints
    the `gh pr create` line). Phase 3 prices the plan with `aisafe decide` after
    the offline measure (`AISAFE_VERIFY_SKIP_TESTS=1` on `verify.sh|ps1`); phase 7
    reads every unmet criterion's `missing` text aloud.
  - New `scripts/attest.sh|ps1` (same chain and pin as `audit.sh`);
    `references/levels.md` generated whole from the criteria file by
    `scripts/levels_md.py` (`--check` in the release gate, `test_levels_md.py`);
    `report-format.md` documents the decision and attestation documents;
    `apply/python.md` has the `aisafe attest` idiom; phase numbers renumbered in
    every reference. `test_skill_package.py` pins the seven titles in order, the
    new vocabulary, the stderr line and the skip-tests switch.
  - `docs/SYSTEM.md` (the flow on one page), `CONTRIBUTING.md`, `SECURITY.md`
    scope (decide, hook, attest, plugin, CI surface), README and CLAUDE.md.
  - Two fixes the end-to-end run forced: `aisafe attest` printed a sub-finding's
    display id twice and matched `rules_closed` against display ids instead of
    rule ids; AUD-903 raised `report models unknown` on every decision document
    (it names no model by design).
  - End-to-end on a throwaway clone of VaiVia (`9cdceed`, 349 tracked files),
    deterministic phases only: phase 1 wrote the report and baseline (14 findings,
    4 high, 5 UNKNOWN items), phase 2 the before document, phase 3 the decision
    table (5 `apply`, 3 `unmeasured`; no budgets declared, no pipeline config so
    no measure report), phase 5 document 2 with the Trade table (0 new, 14
    unchanged), phase 7 level 0 `audited` with nine unmet criteria named; the
    re-audit skipped `attestation.json` and `attestation.html` as own output and
    reported nothing new. Phases 4 and 6 need a person and were not run.
  - `~/.claude/skills/ai-safety-audit` refreshed from this tree
    (`aisafe skill install --host claude --global --force`; `diff` identical).
- **wave 4, `feat(attest)` (`e5ef805`)**: design `docs/plan/03` part C.
  - `devtools/attest.py`, `aisafe attest`: reads `.aisafe-audit/audit-report-after.json`
    (falls back to the survey report with a note), the baseline, the measure, probe
    and decision reports and the system card; evaluates `attest-levels.yaml` (levels
    0 audited, 1 triaged, 2 measured, 3 governed; 14 criterion kinds, one evaluator
    each; shipped in the wheel, mirrored at `config/`, pinned identical and validated
    against the rule registry and `DEFAULT_CARD`); writes `attestation.json` / `.md`
    / `.html` (marker on line 1) and a shields.io `badge.json`. The level is
    cumulative; every criterion row says what was read and what is missing.
  - Honesty rules pinned by 78 tests: a bare fingerprint is a suppression, not an
    acceptance; an absent input is recorded with nulls and fails its criteria, never
    the run; a wrong-kind or unparseable document is fatal; `--owner` (printable
    ASCII) is required to write and, with `--check`, can never come from
    `pyproject.toml`; `--check --require-level N` is the CI form; the statement and
    every template pass the audit's banned-phrase check; the badge is never green or
    red; `walk.git_meta` is the only subprocess, no socket.
  - `"kind": "attestation"` joined `discover._OWN_OUTPUT_KINDS` and `walk._OWN_KIND_RE`;
    `cli.COMMANDS["attest"]`; docs in CLAUDE.md, README and the CHANGELOG.
  - On this repository `aisafe attest . --check` reads level 0: the self-audit runs
    `--no-external`, no measure or decision document is committed, no card. The
    skill's attest phase (wave 5) writes those under `.aisafe-audit/`.
- **wave 3, `feat(persons)` (`ed7b41b`)**: design `docs/plan/03`, parts A and B.
  - `rules/persons.py`, AUD-1101..1107 (54 rules), the eleventh subsystem
    `persons` drawn on a third row of Fig. 1, vocabulary in
    `persons_patterns.py` (all three ignore markers). Three evidence tiers: grep
    (`inventory.person_signals`, candidates promoted through pydeep
    `PromptLiteral` spans), AST (prompt assemblies), lint (`lint_bridge.py`
    runs the curated EU-AIA/ALIGN rules in-process through the new
    `EUAIActCodeAnalyzer.scan_source`; hits are `role: lint` legs, never
    findings). Prompt-material gating and mention-vs-use keep this repository's
    own regex vocabulary quiet: the self-audit reports no P11 finding on itself.
    Every finding carries `LEGAL_CAVEAT`.
  - `ManipulationGuard` (`manipulation_output`) and `AIDisclosureGuard`
    (`ai_disclosure_output`), both presets, exports, `CLASS_SYMBOLS`, package
    pairs for AUD-1105/1106; `ClaudeJudge(mode="manipulation")`; the EU AI Act
    and NIST policy guards return REDACT when they append their disclosure so it
    reaches `final_content` (a long-standing bug).
  - Corpora: attack family `manipulation_elicitation` (7 families, CI pins 7),
    six benign cases (ben-043..048), `manipulation_responses.yaml`
    (`kind: output`, 12 manipulative + 8 benign responses) that `aisafe measure`
    routes to output-stage guards (`output_seen/output_caught/output_catch_rate`,
    `corpus.output`); `aisafe probe` never sends it.
  - `ai-system-card.yaml` gains `prompt_audit` (reviewer, reviewed_at, scope,
    notes); `aisafe init` asks for it; discover passes `affected_persons` and
    `prompt_audit` through for AUD-1107.
  - Art. 5(1) letters fixed in the policy guard and the linter (biometric
    identification is (h), criminal-risk profiling is (d)), pinned by a test.
  - Two refinements the self-audit forced: AUD-1103/decision requires the
    person noun in the function signature or on a code line with a decision
    verb, string literals stripped (the hook's "approve this" messages tripped
    it); the lint tier's EU-AIA-013b matches within one line, so multi-line
    prompt literals are the grep tier's (`persons_companion/app.py` carries one
    single-line instruction so the lint leg is exercised).
  - Baseline: two AUD-801 acceptances for the new guards (CI measures them,
    report not committed). Fixtures `persons_companion` (fires 1101, 1104,
    1104/vulnerable, 1105/persona, 1105/no-disclosure, 1106, 1107) and
    `persons_benign` (silent). 215 new tests.
- **wave 2, `feat(hook)` (`40af8c1`)**: `aisafe audit --only`, `aisafe hook` for
  Claude Code/Cursor/Gemini, `devtools/hosts.py`, the Claude Code plugin,
  `action.yml`, `.pre-commit-hooks.yaml`, the GitLab job.
- **wave 1, `feat(decide)` (`e748021`)**: `LLMUsage`, offline `aisafe measure`
  with cost columns, `prices.yaml`, `aisafe decide`, `Budget`, AUD-806.
- **`perf(audit)` (`9fad7b6`)**, **`release` (`1f33bfe`)**, **`docs(plan)`
  (`7a89478`)**: see the git log.

## The first release (done 2026-10-20)

**`aisafe` 0.1.0 is on PyPI** (wheel and sdist, with attestations), published by
release run `39416623344` from the tag `v0.1.0` at `89706a6`, after the user approved
the `pypi` environment. The smoke job printed `smoke: aisafe==0.1.0 audits as
expected`; the GitHub release is
https://github.com/ai-safe-earth/AnyAISafe/releases/tag/v0.1.0. `uv tool install
aisafe` installs it. The steps below are kept as the record of how it got there.

The 0.1.0 CHANGELOG section includes waves 1-6 and both renames.

1. On pypi.org: Your account -> Publishing -> Add a new pending publisher:
   project `aisafe`, owner `ai-safe-earth`, repository `AnyAISafe`,
   workflow `release.yml`, environment `pypi`. A pending publisher does not
   reserve the name, so check `aisafe` is still unclaimed first (`pip index
   versions aisafe` should find nothing; it was free on 2026-10-20).
2. On GitHub: Settings -> Environments -> `pypi` -> required reviewers: you.
   This is the approval step; the publish job waits on it. On 2026-10-20 the
   environment had no protection rule, so the publish job ran without waiting.
3. Done on 2026-10-20 (see below). The tag `v0.1.0` was at `a81b3b2`, with the old names.
   Its `.pre-commit-hooks.yaml` defines `aisg-audit`, `aisg-lint` and `aisg-misalign`,
   and its `action.yml` installs `anyaisafe`. Prefer moving the tag to the current
   `main` (`git tag -f v0.1.0 && git push -f origin v0.1.0`): README.md (`rev: v0.1.0`
   with the `aisafe-*` hook ids, and `uses: ai-safe-earth/AnyAISafe@v0.1.0`), the
   example comments in `action.yml` and `.pre-commit-hooks.yaml`, the GitLab
   template's git pin and the CHANGELOG's `[0.1.0]` section all describe a `v0.1.0`
   that carries the `aisafe` names. Releasing `0.1.1` instead (`python
   scripts/bump_version.py 0.1.1`, commit, `git tag v0.1.1 && git push origin v0.1.1`)
   also means editing those `v0.1.0` example refs by hand, since `bump_version.py`
   does not rewrite them, and moving the 0.1.0 CHANGELOG entries under 0.1.1. Approve
   the `pypi` run and watch the `smoke` job print `smoke: aisafe==<version> audits as
   expected`.

**The 2026-10-20 attempt.** The tag `v0.1.0` was moved to `89706a6` and pushed (run
`39416623344`). The gate and the build passed; the upload failed with `400 Non-user
identities cannot create new projects`. The pending publisher on PyPI named
`anyaisafe`, not `aisafe`. PyPI used it anyway: it created an empty project
`anyaisafe` (no files) and turned the pending publisher into a normal publisher of
that project, and a token from that publisher cannot create `aisafe`. The user then
added the pending publisher for `aisafe`, removed the publisher from `anyaisafe`, set
themselves as the `pypi` reviewer and reran the failed jobs; the third attempt
published. The empty `anyaisafe` project stays, so the name of the project cannot be
taken by someone else.

Wave 6 is complete: the GitLab template was switched to the PyPI pin on 2026-10-20.
The next release (0.2.0 or 0.1.1) is `bump_version.py X.Y.Z` in the commit that gets
tagged, then the tag; both the user's act.

## Head

`main` after the `aisafe` rename commit `89706a6`. Pushed to `origin`
(`github.com/ai-safe-earth/AnyAISafe`). Tag `v0.1.0` at `89706a6` (moved there on
2026-10-20), published to PyPI as `aisafe` 0.1.0.

## Green

After the `aisafe` rename (2026-10-20): **4403 passed, 2 skipped**; `ruff format
--check .` and `ruff check .` clean; `aisafe lint src examples --errors-only` no
issues; `aisafe misalign` reports the same findings as before the rename; self-audit
`baseline: 0 new, 33 unchanged, 0 no longer reported` (32 fingerprints, 32 reasons);
`aisafe measure --max-p99-ms 25 -o <scratch>` exit 0; `controls_md.py`,
`levels_md.py`, `sync_skill.py` and `bump_version.py` `--check` in sync; a clean
wheel build ships only the `aisafe` package and the `aisafe` console script.

Locally on the wave-6 tree (2026-10-19): **4392 passed, 2 skipped** (the wave-5
entry used to say 4314 here by mistake; that run was 4355 passed, 2 skipped),
`ruff format --check .` and `ruff check .`, `aisafe lint src examples
--errors-only` no issues, `aisafe misalign` on the changed modules no issues (the
two pre-existing ALIGN-006 hits in `llm_judges/claude_judge.py` are unchanged),
self-audit `baseline: 0 new, 33 unchanged, 0 no longer reported` (32
fingerprints, 32 reasons), `aisafe measure --max-p99-ms 25 -o <scratch>` exit 0,
`aisafe attest . --check` level 0 (self-audit is `--no-external`, no committed
measure or decision document, no card), `sync_skill.py --check` (18 files, 3
mirrors), `controls_md.py --check` (54 rules), `levels_md.py --check` (16
criteria) and `bump_version.py --check` (9 sites) in sync.

## Left open on purpose

- The P11 rules are UNMEASURED like every rule; the fixtures are examples, not
  a precision figure. The known weak spots are written into each rule's
  `known_failure_modes`: the profile NAME is the signal; `/vulnerable` rests on
  two regex co-occurrences; a disclosure shown by the UI is reported as absent.
- The lint tier's EU-AIA-013b matches within one physical line, so a
  concealment instruction inside a multi-line prompt literal reaches AUD-1105
  through the grep tier only. Fixing the linter rule is a bench item, not a
  wave-3 change.
- `ManipulationGuard`'s English stock-phrase tables miss paraphrase and
  multi-turn escalation; the judge mode is off in both presets (one model call
  per response). `aisafe measure` scores both guards on the 20-case output corpus.
- The hook's Cursor `afterFileEdit` has no documented answer channel; Gemini
  has no `ask`; Codex writes nothing (`hosts.md`).
- AUD-801 is accepted in the baseline for the seven guards `default.yaml`
  wires (CI measures them, keeps the report as a build artifact); committing a
  measure report under `.aisafe-audit/` is the alternative, and it is also what
  `aisafe attest` level 2 reads. Decide in wave 5.
- The attest criteria file is a first cut: the rule lists (`L2.evals_ci`,
  `L3.controls`), the 30/180-day freshness limits and the 90-day review interval
  are defaults for operators to override with `--level-criteria`, not measured
  figures. `measure_thresholds` reads the measure report's own threshold
  failures; it does not judge the thresholds.
- AUD-202 fires on the installer's own confirmation flag; four acceptances say
  why.
- The VaiVia walkthrough in `docs/handoff.md` (five-phase skill) stopped at
  apply row 2 of 11; wave 5 re-ran the deterministic phases of the seven-phase
  skill on a fresh clone (above). The apply and verify phases, and `aisafe
  attest --owner` with a real owner, need a person at the keyboard.
- `AUD-602`, `AUD-605` and `AUD-106` still report per occurrence; two findings
  can still share a fingerprint (digits stripped). Both are in the plan's risks.
- `measured_precision` is `None` on every rule; `bench/` has 0 labelled rows;
  wave 6 adds `bench --tool audit`.
- `aisafe decide` has no bootstrap script of its own; the skill runs it as `aisafe
  decide` (or through `uvx --from 'aisafe==<pin>'`). A `decide.sh` twin is a
  small follow-up if a host turns out to need it.
- `aisafe fleet` has not been run over the 20-repo bench corpus from this machine
  (it clones 20 repositories); the tests cover two local fixtures, `--jobs 2`,
  `--resume`, `--proposal` and the exit-code rule. Running it is the natural
  first use of `bench/run.py --tool audit`, which produces the labelling CSV.
- The next release: `python scripts/bump_version.py X.Y.Z` in the very commit that
  is tagged `vX.Y.Z` (bumping earlier points every pin on `main` at a version PyPI
  does not have); the tag is the user's act.

## Known-broken, deliberately left

See CLAUDE.md "Known-broken": items 1 (`.secrets.baseline` is in fact tracked;
the note there is stale), 3 (`examples/advanced_injection_demo.py:68`) and 4
(cp1252 console) still stand.

## How to verify from a cold start

```bash
pytest                                    # ~4235 tests, ~3 min, no API keys
ruff check . && ruff format --check .
aisafe lint src examples --errors-only
aisafe misalign src
aisafe audit . --no-external --fail-on high --baseline audit-baseline.json
aisafe measure --max-p99-ms 25 -o /tmp/measure-report.json   # never bare: the root copy is read as evidence
aisafe attest . --check                     # level 0 here; each unmet criterion says why
aisafe fleet bench/corpus.yaml --help       # the fleet over a list; clones only what is listed
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
python scripts/levels_md.py --check
python scripts/bump_version.py --check
aisafe audit tests/fixtures/audit/persons_companion --no-external   # the P11 fixture, from a neutral cwd
gh run list --limit 4
```
