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
| 2 | `aisg audit --only`, `aisg hook`, Claude Code plugin, Cursor/Gemini installers, Action, pre-commit, GitLab job | committed `40af8c1` |
| 3 | P11 persons-and-manipulation rules, `ManipulationGuard`, `AIDisclosureGuard`, corpora, `prompt_audit` | committed 2026-10-19 (the commit after `40af8c1`) |
| 4 | `aisg attest` with levels and a named owner | next |
| 5 | seven-phase skill, SYSTEM.md, CONTRIBUTING, README | |
| 6 | `aisg fleet`, bench `--tool audit`, `v0.2.0` | |

## Landed 2026-10-19

- **wave 3, `feat(persons)`**: design `docs/plan/03`, parts A and B.
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
    (`kind: output`, 12 manipulative + 8 benign responses) that `aisg measure`
    routes to output-stage guards (`output_seen/output_caught/output_catch_rate`,
    `corpus.output`); `aisg probe` never sends it.
  - `ai-system-card.yaml` gains `prompt_audit` (reviewer, reviewed_at, scope,
    notes); `aisg init` asks for it; discover passes `affected_persons` and
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
- **wave 2, `feat(hook)` (`40af8c1`)**: `aisg audit --only`, `aisg hook` for
  Claude Code/Cursor/Gemini, `devtools/hosts.py`, the Claude Code plugin,
  `action.yml`, `.pre-commit-hooks.yaml`, the GitLab job.
- **wave 1, `feat(decide)` (`e748021`)**: `LLMUsage`, offline `aisg measure`
  with cost columns, `prices.yaml`, `aisg decide`, `Budget`, AUD-806.
- **`perf(audit)` (`9fad7b6`)**, **`release` (`1f33bfe`)**, **`docs(plan)`
  (`7a89478`)**: see the git log.

## What the user has to do for `v0.1.0`

Nothing is uploaded without these steps; the plan prepared them and stops here.
The 0.1.0 CHANGELOG section now includes waves 1-3, since the tag does not
exist yet and will point at a `main` that carries them.

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

`main` at the wave-3 commit (after `40af8c1`). Pushed to `origin`
(`github.com/ai-safe-earth/AI-Safety-Guardrails`). No tags yet.

## Green

Locally on the wave-3 tree (2026-10-19): **4235 passed, 2 skipped** (2m45s),
`ruff format --check .` and `ruff check .`, `aisg lint src examples
--errors-only` no issues (the compliance gate scans the new modules; one
rule-description line was reworded so a rule about workplace emotion
recognition does not trip the linter's own 005c), `aisg misalign` on the
changed modules reports only the two pre-existing ALIGN-006 hits in
`llm_judges/claude_judge.py` (lines 1 and 55, identical at `40af8c1`),
self-audit `baseline: 0 new, 33 unchanged, 0 no longer reported` (32
fingerprints, 32 reasons), `aisg measure --max-p99-ms 25` exit 0 with the two
new guards and the output corpus, `sync_skill.py --check` (15 files, 3
mirrors), `controls_md.py --check` (54 rules) and `bump_version.py --check`
(9 sites) in sync.

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
  per response). `aisg measure` scores both guards on the 20-case output corpus.
- The hook's Cursor `afterFileEdit` has no documented answer channel; Gemini
  has no `ask`; Codex writes nothing (`hosts.md`).
- AUD-801 is accepted in the baseline for the seven guards `default.yaml`
  wires (CI measures them, keeps the report as a build artifact); committing a
  measure report under `.aisg-audit/` is the alternative. Decide in wave 5.
- AUD-202 fires on the installer's own confirmation flag; four acceptances say
  why.
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
pytest                                    # ~4235 tests, ~3 min, no API keys
ruff check . && ruff format --check .
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
python scripts/bump_version.py --check
aisg audit tests/fixtures/audit/persons_companion --no-external   # the P11 fixture, from a neutral cwd
gh run list --limit 4
```
