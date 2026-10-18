# Plan: from guardrails library to a complete AI-safety solution

Written 2026-10-19 at `ce2ab43`. This is the plan the user asked for: turn this repo into
the tool behind a portable coding-agent skill that audits any software for AI safety,
proposes solutions, prices them, applies them with a human in the loop, and ends with an
owner-signed attestation at an explicit level. It also has to run at scale over any
open-source repository and be usable by anyone on private software, locally.

The three detailed designs it consolidates are in `docs/plan/`:

| file | scope |
| --- | --- |
| `docs/plan/01-decide-cost-latency-metrics.md` | token accounting, price table, `aisg measure` extension, `aisg decide`, budgets, AUD-806 |
| `docs/plan/02-hooks-plugin-ci-publishing-fleet.md` | `aisg hook`, Claude Code plugin, Cursor/Gemini/Codex installers, GitHub Action, pre-commit, release, `aisg fleet`, bench for audit precision |
| `docs/plan/03-persons-manipulation-attest-skill.md` | the P11 rule family (profiling, manipulation, persona), two runtime guards, `aisg attest`, the seven-phase skill |

Read `CLAUDE.md` for the invariants the tests pin and `docs/STATUS.md` for the state at
the previous handoff. Every decision below was made once; do not re-open it without a
reason recorded here.

## 1. Context

The repo today is a Python guardrails library (`aisg` runtime: 12 guards, judges,
pipeline) plus developer tools (`aisg lint|misalign|init|probe|measure|audit|skill`) and
a five-phase agent skill (`ai-safety-audit`) that runs the deterministic `aisg audit`
(46 rules, AUD-101..1003), renders a before document, applies controls one row per
approval, renders an after document, and verifies. Nothing is published: no git tag,
`aisguard` not on PyPI, so the skill's bootstrap cannot resolve outside this checkout.

What the user asked for on 2026-10-18, in their words and mapped to what exists:

| ask | today | gap |
| --- | --- | --- |
| audit any software for AI safety | `aisg audit`, 46 rules, Python-deep, grep for TS/JS/Go | no rules for profiling of people, manipulation, persona substitution |
| propose solutions, human in the loop | `recommendation.package` per finding; skill applies one row per approval | no cost or latency figure on any proposal |
| guardrails, anonymisation | runtime guards, `PIIDetector(action="tokenize")` | no guard reads model output for manipulation or denial of AI nature |
| control of prompts (manipulation) | `PromptInjectionGuard`; AUD-302/303 | prompt-side engagement objectives and persona concealment undetected |
| hooks for coding agents | one dev hook (`ruff_fix.py`) | no `aisg hook`; no plugin; no Action; no pre-commit source |
| decision tool: cost (tokens), latency, other metrics | `aisg measure` (latency p50/p99, catch rate, benign breakage) | nothing records tokens or dollars anywhere; no trade table; no budgets |
| final evaluation that declares a level | the skill never issues a verdict (by design) | no `aisg attest`; no criteria; no owner stamp |
| any open-source repo at scale; anyone on private software | one repo per run, local only | no batch runner, no publish, no CI surface for other repos |

Measured on 2026-10-18 on this machine (Windows 11, Python 3.13):

| measurement | value |
| --- | --- |
| test suite | 3635 passed, 1 skipped, 2m59s |
| `aisg audit . --no-external` on this repo (140 files) | 28.5 s |
| same on AdalFlow (428 files) | 44.6 s (15.8 s with `--deep none`) |
| same on VaiVia (342 files) | 18.9 s |
| `import aisg` warm | 1.1 s (otel 0.5 s, core 0.5 s) |
| where the 31 s go on this repo | pydeep 16 s, discover 6 s, rules 8 s (guards.py `_named` 3.7 s, AUD-803 2.3 s) |

Two consequences are fixed into the design: a hook on every edit cannot run the full
audit, so a file-scoped audit mode exists and the full re-audit runs only at the end of a
turn; and a performance pass comes first because hooks, CI and the fleet all pay for it.

## 2. Decisions

Settled with the user on 2026-10-18:

1. **The final declaration is `aisg attest`**: levels with explicit, machine-checkable
   criteria, stamped by a named risk owner with date and commit. "AI safe" in the user's
   system means "meets AISG level N". The compliance-claim phrases in
   `report.BANNED_PHRASES` stay banned everywhere, including the attestation.
2. **"User profiling" means detecting software that profiles people**: behavioural
   profiles fed to prompts, emotion or biometric inference, social scoring, engagement or
   addiction optimisation, persona substitution. Audit rules plus runtime guards. Not
   user-tier-aware guard strictness.
3. **Hooks: one `aisg hook` adapter speaking each host's protocol**, shipped first as a
   Claude Code plugin (skill + hooks), installers for Cursor and Gemini CLI, Codex when
   its format is verified, plus a GitHub Action and a pre-commit hook source for CI.
4. **Publish early**: tag `v0.1.0` and set up PyPI trusted publishing from GitHub Actions
   in the first wave; the user approves the actual release step (a required reviewer on
   the `pypi` environment). Nothing is uploaded without them.

Design decisions taken while consolidating (each with its reason):

5. **Tokens in the runtime, dollars only offline.** Judge calls record
   `metadata["llm_usage"]` (tokens in/out, model, provider, `cost_basis`, `cache_hit`);
   prices are a dated package-data table (`prices.yaml`, `as_of`, `sources`, staleness
   label) joined by `aisg decide`. Prices change; a dollar figure frozen into telemetry
   would be wrong within months. Prices are never fetched: the audit and decide never
   open a socket.
6. **Four honesty labels on every cost figure**: `measured` (tokens from a real call
   during `aisg measure --allow-provider-calls`), `estimated` (computed offline from the
   real prompt constants, chars/4), `unavailable` (a call happened, usage not returned),
   `none` (no call: regex path or cache hit, exactly zero). `aisg measure` is offline by
   default; a judge that was not exercised shows an UNMEASURED catch rate, never 0%.
7. **The decision is a deterministic function of declared budgets.** `aisg decide`
   reads the audit report, the measure report, the price table and a traffic profile
   (flags or the system card) and gives each candidate control one of `apply`,
   `apply with <config change>`, `defer (over budget: <which>)`, `unmeasured (run aisg
   measure first)`. It never hides a trade-off and always lists what is UNMEASURED.
8. **System card blocks are `traffic:`, `budgets:` and `prompt_audit:`; `deployment`
   stays the scalar it is today.** The two designs disagreed (`deployment` as a mapping
   vs new blocks); `deployment` is a pinned scalar read by existing code and cards, so the
   new figures get their own blocks. Attest's L3 reads `deployment` as the scalar.
9. **The decision document is evidence, the attestation is own output.** `kind:
   decision` is discovered as a report (`REPORTED <age>`) so AUD-806 can read it; `kind:
   attestation` and `attestation.html` are skipped like the audit's own output.
10. **An 11th subsystem, `persons`,** joins the ten in Fig. 1 so the user's headline
    concern is visible on the system map; the cost is one geometry change and one pinned
    count. AUD-806 lands on `guardrails`.
11. **Hooks fail open on their own errors and record them**; a positive detection
    (secret-shaped literal, `curl | sh`) is a deny. A gate that fails closed on its own
    bug blocks all editing and teaches people the bypass flags the audit flags.
12. **No MCP server in this plan.** The audit is a CLI with no socket; an MCP server is a
    second process with its own permission surface, exactly what AUD-602/603 audit in
    other repos. Revisit only if a host cannot run command hooks.
13. **The fleet never chooses targets and never opens PRs.** It clones the URLs the
    operator wrote down, audits each in a subprocess with a wall-clock cap, aggregates,
    and writes a PR body per repo. A human or the skill, with approval, pushes.
14. **No precision number is typed anywhere.** `bench --tool audit` builds the pipeline
    (run, label, score, paste) that produces one from human labels; until then every rule
    stays `[UNMEASURED]` and still fires.
15. **Version plan**: `v0.1.0` for the current code once the release pipeline exists,
    `v0.2.0` when decide, hooks, persons, attest and the skill rework land.

## 3. The complete solution, end to end

```
                      +-----------------------------------------------------------+
   coding agent       |  skill: ai-safety-audit (7 phases)                        |
   (Claude Code,      |  1 survey  2 document 1  3 decide  4 apply (1 row/approval)|
    Cursor, Gemini,   |  5 document 2  6 verify  7 attest  -> offer hooks + CI     |
    Codex...)         +----+--------+---------+---------+---------+---------+------+
                           |        |         |         |         |         |
   aisg CLI (local,   audit     audit     decide    (edits)    measure   attest
   no LLM, no socket) --format  --format  --format             probe     --owner
                      json      html      json|md              decide    --check
                           \        |         |                  |         |
   artefacts          .aisg-audit/{audit-report.json, audit-baseline.json, audit-before.html,
   (all under one     decision-report.json, decision.md, audit-report-after.json, audit-after.html,
    directory)        measure-report.json, probe-report.json, attestation.{json,md,html}, badge.json,
                      hook-state.json, pr-body.md}

   hooks (same vocabulary as the audit: patterns.py)
     PreToolUse   edit of a protected path -> ask; secret-shaped literal -> deny; curl|sh -> deny
     PostToolUse  file-scoped re-audit (--only) -> additionalContext with NEW findings
     SessionStart posture: age of report, counts, top 3, UNKNOWN count, baseline?
     Stop         full re-audit vs baseline; NEW finding >= fail-on -> block (never twice)

   CI surface for any repo        scale
     action.yml (composite)         aisg fleet LIST  -> fleet-report.{json,csv,md} + proposal.md per repo
     .pre-commit-hooks.yaml         bench --tool audit -> findings-audit.csv -> human labels -> precision
     .gitlab-ci job                 release.yml -> PyPI (trusted publishing, user approves)
```

Verbs after the plan: `lint`, `misalign`, `init`, `probe`, `measure`, `audit`, `skill`
(existing) plus `decide`, `hook`, `attest`, `fleet`. Rules: 46 + AUD-806 + AUD-1101..1107
= 54. Guards: 12 + `manipulation_output` + `ai_disclosure_output`. Subsystems: 11.

## 4. Waves

Each wave ends green on the full gate (section 6), is committed to `main`, and updates
`docs/STATUS.md`. Sizes are the designers' estimates of non-test lines / tests.

### Wave 0: foundation and `v0.1.0`

Why first: everything downstream installs the package (skill bootstrap, Action,
pre-commit, uvx smoke), and every later wave pays the audit's run time.

- **Performance pass on `aisg audit`** (new): cache `comment_spans` per file text, compile
  the `_named` regexes once and scan each text once in `rules/guards.py`, cache physical
  lines in `_code_line_of`, and look for the obvious waste in `pydeep._scopes`
  (`_unparse` per decorator) and `discover._matches` (152k regex searches: union the
  tables per language). Target: this repo under 10 s, AdalFlow under 15 s, byte-identical
  JSON (minus `generated_at`) on the three timing reports kept in the scratchpad. No
  behaviour change; the suite is the safety net; a test pins that two runs are identical.
- `CHANGELOG.md` (Keep a Changelog) with `## [0.1.0]`.
- `scripts/bump_version.py` (sites: pyproject, `aisg/__init__.py`, the two legacy CLI
  version strings, SARIF reporter version, gitlab pin, later `action.yml` and
  `plugin.json`; then runs `sync_skill.main()`; `--check`, `--tag`,
  `--changelog-section`) + `tests/unit/test_bump_version.py`.
- `.github/workflows/release.yml`: gate (checks, pytest, self-audit, sync checks), build,
  publish (`pypa/gh-action-pypi-publish`, OIDC, `environment: pypi`, no password), GitHub
  release with the changelog section, smoke (`uvx --from aisguard==X aisg --version`,
  `clean_py` exit 0, `py_agent` exit 1). `tests/unit/test_ci_surface.py` pins it.
- README truth-up: absolute brand image URL (PyPI long description), install says
  `aisguard`, extras table matches pyproject, devtools tree and test list current, skill
  phases current, test count current, PyPI note.
- The user, once: PyPI pending publisher for `aisguard` (owner `ai-safe-earth`, repo
  `AI-Safety-Guardrails`, workflow `release.yml`, environment `pypi`), GitHub environment
  `pypi` with themselves as required reviewer. Then `git tag v0.1.0 && git push origin
  v0.1.0`, approve, watch smoke. **This step is theirs; the plan prepares it.**

Size: ~700 lines / ~25 tests plus the performance pass.

### Wave 1: cost, latency and the decision tool (design 01)

- `core/measurement.py`: `LLMUsage`, `COST_BASIS`, `weakest_basis`, `Budget`;
  `Profile` gains tokens/usd/cost_basis/human_rate/benign_modified_rate; `Thresholds`
  gains `max_usd_per_request`, `max_human_rate` (judged only on `measured`).
- Judges record usage (`JudgeVerdict.usage`; readers for Anthropic, OpenAI-compatible,
  Ollama; HF and moderation `unavailable`; `CachedJudge` hit = `none`, `cache_hit`);
  `prompt_injection` and `toxicity` hoist their inline prompts to constants and record
  usage; `toxicity` gets `llm_judge_model` instead of a hard-coded id; the three
  `LLM*Filter` guards and `nemo_rails` write `metadata["llm_usage"]`;
  `GuardrailBase.__call__` sets `metadata["guard_name"]` (fixes the audit logger's
  check-id-prefix bug); `PipelineResult.llm_usage`; otel token instruments; audit logger
  token fields.
- `modules/llm_judges/estimate.py`: offline estimator per call site from the real prompt
  constants; imports no provider SDK (test).
- `prices.yaml` (package data + `config/` mirror, `as_of`, `sources`, `stale_after_days`,
  the seven default judge model ids; figures copied by hand from the provider pages on
  the day, an unverifiable provider is left out, never guessed) + `devtools/prices.py`.
- `aisg measure`: `--allow-provider-calls` (default offline), `--include-policy`,
  `measured_on` and `pipeline` in the JSON, per-guard `llm_*`, `tokens_*`, `cost_basis`,
  `human_rate`, `fail_mode`, `benign_modified_rate`; `CachedJudge.clear()` between timing
  passes; FPR definition unchanged so the CI ratchet holds.
- `aisg init`: `traffic:` and `budgets:` blocks (null by default, asked interactively).
- `aisg decide` (`devtools/decide.py`): rows per candidate control from
  `recommendation.package` symbols joined to measure rows via the registry; traffic
  join; recommendation function; totals (sequential sums, parallel max); terminal, json
  (`kind: decision`), markdown; exit 0/1/2; `[tool.aisg-decide]`;
  `NOT_CONFIGURABLE = {select}`.
- Audit: `kind: decision` read as a report; **AUD-806** "Reported guard over the declared
  budget" (subs latency/cost/human/benign, `guardrails`); **AUD-801/cost** sub-finding
  when a judge was configured but not exercised; `aisg audit --format html --decision
  PATH` adds the "Trade table" section; `controls.md` regenerated.
- `GuardrailPipeline(thresholds=...)` opt-in demotion (`pipeline.thresholds` in YAML);
  default behaviour unchanged.

Size: ~2,600 lines / ~160 tests.

### Wave 2: hooks, plugin and the CI surface (design 02, sections 1-5)

- `devtools/hosts.py`: `Host` + `HookSupport` table shared by `skill.py` and the hook
  installer (keys unchanged; `hosts.md` pinned).
- `aisg audit --only PATH` (file-scoped run of `FILE_LOCAL_RULES`: AUD-101, 108, 501,
  502, 505, 602, 605; same fingerprints as a full run, pinned; an unseen path is an
  UNKNOWN row; `only` joins `NOT_CONFIGURABLE`; `target.only` in the report).
- `devtools/hook.py`: `aisg hook run --host claude|cursor|gemini|codex --event E`
  (normalise stdin payload, policies, emit per the host matrix, `hook-state.json` under
  `.aisg-audit/`, debounce, version/origin line, fail open on own errors);
  `install|uninstall|list` (prints the unified diff, writes only with `--yes` or an
  interactive yes, never silently edits a protected file; portable bootstrap in
  project configs, `sys.executable` in global/local ones); `[tool.aisg-hook]`.
- Canonical skill gains `scripts/hook.sh|hook.ps1` (bootstrap chain, pinned version,
  `--origin`, `--expect-version`).
- Claude Code plugin: `.claude-plugin/marketplace.json` at the root,
  `plugins/ai-safety-audit/{.claude-plugin/plugin.json, hooks/hooks.json, README.md,
  skills/ai-safety-audit/**}`; the skill copy is mirror #3 of `scripts/sync_skill.py`,
  which also pins `plugin.json`'s version. Install: `claude plugin marketplace add
  ai-safe-earth/AI-Safety-Guardrails` then `claude plugin install
  ai-safety-audit@ai-safe-earth`.
- Cursor (`.cursor/hooks.json`: shell gate enforced, file checks advisory after the
  edit), Gemini (`settings.json` hooks; prints the two enable flags it will not flip),
  Codex (prints what it would write; exit 1 without `--unverified`).
- `action.yml` composite Action (inputs path, fail-on, baseline, version pinned to
  pyproject, install-from pypi|action-path, SARIF upload, step summary, optional sticky
  PR comment; exit code = `summary.exit_code`); dogfood job in `tests.yml`.
- `.pre-commit-hooks.yaml` (`aisg-audit` pre-push, `aisg-lint`, `aisg-misalign`) so other
  repos can point `repo:` at this one; local pre-push audit hook in our own config.
- `.gitlab-ci-euaiact.yml` gains an `aisg-audit` job (git pin until wave 6).
- Tests: `test_hook.py` (fixture payloads per host and event under
  `tests/fixtures/hooks/`), `test_hosts.py`, `test_plugin_package.py`,
  `test_ci_surface.py`, `--only` pins.

Size: ~1,900 lines / ~120 tests.

### Wave 3: persons and manipulation (design 03, parts A and B)

- `audit/persons_patterns.py` (carries the aisg, lint and misalign ignore markers: it is
  vocabulary): person-signal regex tables (profile SDKs and names, placeholders,
  affect/biometric inference, biometric categorisation, scoring of persons, engagement
  objectives, vulnerable-group qualifier, persona concealment, disclosure, manipulation
  controls, review symbols). Prompt-material gating so this repo's own regex vocabulary
  does not read as instructions to a model.
- `discover.py`: person-signal scans, `profile_to_prompt`, `Inventory.person_signals`;
  `pydeep.PromptLiteral`.
- `audit/lint_bridge.py` + `EUAIActCodeAnalyzer.scan_source`: the EU AI Act linter and
  ALIGN-008 run in-process over the files the walk already read; hits become evidence
  legs (`role: lint`) on P11 findings, never second findings. Fix the Art. 5 letter
  labels in the linter and the runtime guard (biometric ID is (h), predictive policing
  is (d) in Regulation (EU) 2024/1689).
- `rules/persons.py`, **AUD-1101..1107**, 11th subsystem `persons`, Fig. 1 row 3:
  1101 person profile bound into a prompt; 1102 emotion or biometric inference on
  persons (`/workplace`, `/categorisation` critical); 1103 scoring, ranking or automated
  decision about persons; 1104 engagement or retention objective in prompt or code
  (`/vulnerable` critical); 1105 AI nature concealed or no disclosure on the response
  path (`same_control` with `AIDisclosureGuard`); 1106 no manipulation control on the
  response path (`same_control`); 1107 prompt and algorithm audit not recorded
  (`aisg init`, `prompt_audit:` block). Fixtures `persons_companion` and
  `persons_benign`.
- Runtime guards: `ManipulationGuard` (`manipulation_output`, six categories, default
  FLAG, mention-vs-use, optional `ClaudeJudge(mode="manipulation")`, judge failure is a
  recorded FLAG) and `AIDisclosureGuard` (`ai_disclosure_output`, identity claims,
  optional disclosure append via REDACT). Fix: the EU and NIST policy guards return
  REDACT when they append a disclosure so it reaches `final_content`. Both preset pairs
  wired; exports; `CLASS_SYMBOLS` += 2; `apply/python.md` headings; `add-guard`
  checklist; baseline AUD-801 acceptances for the two new unmeasured guards.
- Corpora: `manipulation_elicitation.yaml` (family 7; CI `>= 40 across 7 families`),
  six benign cases, `manipulation_responses.yaml` (`kind: output`, consumed by `aisg
  measure` only, never sent by `probe`); measure routes output cases to output-stage
  guards and reports `output_seen/output_caught`.
- `aisg init`: `prompt_audit:` block.

Size: ~2,400 lines / ~190 tests.

### Wave 4: `aisg attest` (design 03, part C)

- `devtools/attest.py`, `config/attest-levels.yaml` (+ mirror): levels 0 audited,
  1 triaged, 2 measured, 3 governed; eight criterion kinds (report present and fresh,
  report names HEAD, UNKNOWN listed, no open findings at or above a severity, external
  tools attempted, accepted reasons present, documents present and fresh, measure within
  thresholds, probe passing if present, rules closed, card fields set, card section
  fresh, accepted risks owned, tree clean). Level reached = highest N with every
  criterion of 0..N met.
- Inputs: after-report (fallback to the survey report with a note), baseline, measure,
  probe, decision, card, `git rev-parse` via `walk.git_meta`. `--owner "Name <role>"`
  required to write; `--check --require-level N` for CI (exit 1 when not met, writes
  nothing).
- Outputs: `attestation.json` (`kind: attestation`, statement "<owner> states that <path>
  at commit <sha> meets the AISG level N (<name>) criteria on <date>."), `attestation.md`,
  `attestation.html` (own-output marker on line 1), `badge.json` (shields endpoint,
  never green or red). `DISCLAIMER` plus "an attestation is a statement by the named
  owner; the tool checked the listed criteria and nothing else."
- A test pins the shipped YAML: ids unique, kinds implemented, every rule id in
  `ALL_RULES`, every card path resolvable, no banned phrase.

Size: ~1,000 lines / ~60 tests.

### Wave 5: the seven-phase skill and the docs (design 03, part D)

- `SKILL.md`: Survey, Document 1, **Decide**, Apply, Document 2, Verify, **Attest**;
  hard rules 8 (print which `aisg` ran, from where, which version; stop on a mismatch
  with the pinned version) and 9 (never push without approval); the PR path (branch
  `aisg-audit/<date>`, one commit per row with the re-audit result, `pr-body.md`,
  the `gh pr create` line printed for the user); the closing offer of `aisg hook
  install` and the Action.
- References: `report-format.md` (decision and attestation documents, eleven boxes),
  `controls.md` (P11 sections, regenerated), `apply/python.md` (new symbols, decide
  idioms), `hosts.md` (hook install), new `levels.md` generated by
  `scripts/levels_md.py --check`; scripts `attest.sh|ps1`; `sync_skill.py` pins all.
- `tests/unit/test_skill_package.py`: seven phases, new needles, new scripts, levels doc.
- Docs: `docs/SYSTEM.md` (one page: audit, decide, apply, attest, hooks, fleet; which
  artefact each step reads and writes), `CONTRIBUTING.md`, `SECURITY.md` scope (hooks,
  Action, fleet), README sections for every new verb, `CLAUDE.md` invariants, the stale
  `~/.claude/skills/ai-safety-audit` copy refreshed with `aisg skill install --global`.

Size: ~900 lines / ~30 tests.

### Wave 6: scale and `v0.2.0` (design 02, sections 6-8)

- `devtools/_git.py` (shallow pinned fetch, moved from `bench/run.py`),
  `devtools/fleet.py`: `aisg fleet LIST` (yaml or csv of URLs or local paths with
  optional sha), subprocess audit per repo with a wall-clock cap, `--jobs`, `--resume`,
  `--keep-clones`, `fleet-report.{json,csv,md}` (`kind: fleet`), `--proposal` writes a PR
  body per repo (plan table, decide table, the command that produced it). Exit 0 when
  every repo was audited, 1 when one could not be, 2 fatal; `--fail-on-findings` for
  teams gating their own repos.
- `bench/run.py --tool audit` and `bench/score.py --tool audit`: `findings-audit.csv`
  with a redacted snippet column so a labeller needs no clone; nested deterministic
  sampling reused; paste-ready `measured_precision` lines for `AuditRule` classes.
- `.gitlab-ci-euaiact.yml` flips to the PyPI pin; `TestCITemplates` updated.
- `bump_version.py 0.2.0`, CHANGELOG, tag `v0.2.0` (user approves the release).

Size: ~1,200 lines / ~45 tests.

## 5. Cross-cutting invariants (new ones; the existing list is in CLAUDE.md)

- Every new JSON document starts with `"schema": "aisg/1"` and carries a `kind`
  (`prices`, `decision`, `hook-state`, `attestation`, `attest-levels`, `fleet`).
- Every cost figure carries its basis (`measured|estimated|unavailable|none`) and the
  price table's `as_of`; a stale table marks every dollar cell `stale`.
- `aisg decide`, `aisg hook`, `aisg attest`, `aisg fleet` never call a model, install
  anything or open a socket; the fleet's only network action is `git clone` of listed
  URLs; the tests wrap `socket.socket` the way `test_audit_cli.py` does.
- Hooks write only under `.aisg-audit/`, fail open on their own errors, record them, and
  surface them at the next session start.
- A hook's stdout is JSON only when there is a decision or context to convey, plain text
  only on Claude SessionStart, and on Gemini never prose.
- The attestation statement, the level names and every renderer are scanned against
  `report.BANNED_PHRASES` by a `check_templates` twin.
- `measured_precision` stays `None` on all 54 rules until `bench --tool audit` has a
  labelled corpus; the two new guards ship with an empty `Profile` and an AUD-801
  acceptance in the self-audit baseline with a reason.
- The canonical skill has three mirrors (`.claude/skills`, `.agents/skills`,
  `plugins/ai-safety-audit/skills`) and `scripts/sync_skill.py` is the only writer.

## 6. Verification

Per wave, from the repo root, all green before the commit:

```bash
pytest -q                                                     # no API keys, no network
ruff check src tests scripts && ruff format --check src tests scripts
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json   # exit 0
aisg measure --max-p99-ms 25                                  # the CI ratchet
python scripts/controls_md.py --check
python scripts/sync_skill.py --check
python scripts/levels_md.py --check                           # from wave 5
python scripts/bump_version.py --check                        # from wave 0
```

End to end, after wave 5, on a throwaway clone of VaiVia (the half-finished walkthrough
in `docs/handoff.md`): run the seven phases, including `aisg decide` with the card's
traffic figures and `aisg attest --owner` with the user as owner; install the hooks in
that clone and confirm a planted secret-shaped literal is denied, a protected-path edit
asks, and a Stop with a new high finding blocks once. Then `aisg fleet` over the bench
corpus list with `--jobs 4` and confirm the aggregate renders and exits 0.

## 7. Risks and open questions

- **Price figures** must be copied by hand with the date; an unverifiable provider is
  left out of `prices.yaml` (renders `unavailable` and names itself) rather than guessed.
- **Gemini hook output shape and Cursor payload fields** are each isolated in one
  function; verify against the vendor docs when implementing and pin the shape in the
  fixture tests. Codex stays unverified.
- **Hook latency**: ~1.2 s warm import before any policy. A follow-up outside this plan
  is lazy-loading otel and the audit logger in `aisg/__init__.py` (PEP 562).
- **Two findings can share a fingerprint** (digits stripped in normalisation); known,
  unchanged by this plan, worth fixing before the fleet labels a corpus.
- **Self-audit noise from the new vocabulary**: `persons_patterns.py`, `prices.yaml` and
  the hoisted judge prompts may surface findings in this repo; each goes in the baseline
  with a reason that does not quote the literal, or the rule is fixed.
- **`aisguard` must still be free on PyPI** at publish time (free on 2026-09-05).
- **Windows**: committed hook commands use `sh` and `$CLAUDE_PROJECT_DIR` (Claude Code on
  Windows requires Git Bash); `--shell powershell` is the escape hatch.
- **Severity of AUD-1104/vulnerable (critical) rests on two regex co-occurrences**; the
  finding names both matches; fallback is high with a note.
