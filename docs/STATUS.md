# Status — 2026-09-10

Where the work stands, what is verified, and what is waiting on a decision.
Written as a handoff: a fresh session should be able to pick up from here plus
`CLAUDE.md`.

## Landed -- the two-document audit flow (2026-09-06 to 2026-09-10)

The audit now produces a *before* and an *after* document of the user's system
and the skill walks the plan between them. Settled design, implemented in
parallel slices on top of `0acc0db`, then two adversarial review rounds (every
finding reproduced by one agent and refuted by another before it counted) and
their fix rounds; the whole thing is one commit on `main`. CLAUDE.md "aisg
audit and the skill" carries the invariants; this is the map.

What landed:

- **`recommendation.package`** on every finding (`model.Package`: `mechanism`,
  `symbols`, `same_control`, `leaves_open`) says what this package can wire for
  the rule and, in words, what that still leaves open. Eleven rules are
  `same_control: true`; a detector never is on a P1-P4 rule. `SUBSYSTEM_OF_RULE`
  places every rule on one of ten subsystem boxes, exact cover, test-pinned.
- **`--format html`** (`audit/html.py`): Fig. 1 subsystem schematic, one section
  per subsystem, the plan table in blast-radius order, "Since the baseline" and
  "Remaining actions" when `--baseline` is given. ASCII, no colour, the ignore
  marker on line 1. The JSON stays authoritative.
- **Baseline as a record**: `--write-baseline` renders the `-o` report first and
  writes an `index`; `--baseline` reports `kind`, `accepted`, `generated_at`
  and `no_longer_reported` (named by rule, file, title), and `report.target`
  now lists the resolved `exclude`; `--amend-baseline PATH
  --accept FP="reason"` records an acceptance in the user's words and refuses
  anything else. `Finding.accepted_reason` carries the reason into every format.
- **Own-output skip** in `walk`: the audit's own JSON report is skipped by
  content and listed in `inventory.own_output_skipped`; `.aisg-audit/` is not a
  skipped directory, so measure and probe reports there still count as evidence.
- **The skill** (`src/aisg/skills/ai-safety-audit/`, mirrors synced): five
  phases -- survey, document 1, apply one row per approval, document 2, verify --
  every artefact under `.aisg-audit/`, every command from the repo root.
  `references/report-format.md` documents the html and the new keys,
  `references/controls.md` has a Package column for all 46 rules, and
  `references/apply/python.md` is keyed by symbol with idioms checked against the
  real constructors (`ToolPolicyGuard`, `PIIDetector`, `PromptInjectionGuard`,
  `RateLimiter`, `AuditLogger`, `TelemetryProvider`, `LLMJudgeBase`,
  `GuardrailPipeline`, the `aisg` verbs); the other three say aisg symbols are
  Python-only and the control still applies.
- **The review round on top of that**: `--write-baseline` carries operator
  reasons over from the compared baseline and the refreshed file, drops the
  ones no longer reported (the note says how many) and refuses to overwrite a
  file that is not an audit-baseline; the baseline block has no count key for
  gone fingerprints and every renderer says "no longer reported"; terminal and
  markdown print `accepted: <reason>`; `--inventory-only` renders html or the
  inventory JSON and refuses the baseline flags; `walk` skips the html and the
  inventory document as own output too (SARIF carries the list as a run
  property) and never lets `.gitignore` prune `.aisg-audit/`; the plan's who
  column takes the finding's language from its file, unit or root unit and the
  protected-path list grew (CircleCI, Jenkins, Azure, Bitbucket, Travis, VS
  Code and Claude Desktop MCP files); pydeep reads an empty `require_approval`
  as an inert gate and `ToolPolicyGuard(**cfg)` as UNKNOWN; the system card
  has `incident_contact`: a blank or TODO value still counts as absent for
  AUD-703, but the inventory keeps the raw placeholder and the finding says
  "unfilled" rather than "no". `controls.md`'s severity, mapping and
  leaves-open text are now regenerated from the registry by
  `scripts/controls_md.py` and test-pinned; SKILL.md, `report-format.md` and
  `apply/python.md` say the same things as the code.
- **Doc drift closed against the code**: the verify scripts write
  `.aisg-audit/measure-report.json` and `.aisg-audit/probe-report.json` (they
  used to write to the repository root, which no other doc named) and detect a
  pipeline config by the stage keys `from_config` reads (`input:`,
  `processing:`, `output:`, `policy:`; `guards:` was never read);
  `report-format.md` quotes the real `controls: <items>` line and the two
  masking shapes, `<redacted:PREFIX...LAST4>` for secrets and `<pii:ENTITY>`
  for PII. `write_baseline`, `inventory_only` and `list_rules` are
  `NOT_CONFIGURABLE` from pyproject; oversize files are an UNKNOWN row and an
  inventory count; the audit's own SARIF is recognised by `aisg_schema` first
  in the run's properties.
- **The second review round** (13 confirmed defects, all closed with tests):
  pydeep no longer records a phantom live gate at the statement line when a
  `ToolPolicyGuard(**cfg)` or `require_approval=[]` sits on a later line of a
  multi-line statement (nested calls are opaque to the outer pass, so AUD-201
  fires and the UNKNOWN row appears); `ToolPolicy` and `_coerce_policy` check
  value shapes, so `allow: "read_*"` is refused instead of iterating the string
  and letting `*` allow everything; `ToolPolicyGuard.setup` refuses unknown
  options (a typo used to disable the control silently); the LangChain callback
  runs `run_processing` on the shared context, so session budgets trip through
  it; `_run_stage`, `GuardrailBase.__call__`, the callback and `nemo_rails`
  treat a caller's empty dict as the caller's dict (`is not None`, not `or {}`);
  `--write-baseline` creates the parent directory, refuses to share a path with
  `-o`, and a reason with a control character is refused like a non-ASCII one;
  the html plan uses `patterns.LANG_BY_EXT` (a `.rs`/`.java` file in a
  Python unit is no longer package work); a BOM before the marker no longer
  defeats own-output detection; `vocab.is_unset` is the one placeholder
  predicate for the card readers, `contact_named` and governance; the
  `**cfg` UNKNOWN row carries `rule_ids` so it lands on the tools box.

The verify gate for the round, from the repo root:

```bash
pytest                                                    # full suite once every slice is in
ruff check src tests
python scripts/controls_md.py --check                     # controls.md matches the rule registry
python scripts/sync_skill.py --check                      # mirrors byte-identical, version pinned
python -m pytest tests/unit/test_skill_package.py tests/unit/test_audit_report.py -q
aisg audit . --no-external --fail-on high --baseline audit-baseline.json     # exit 0
aisg audit . --format html -o .aisg-audit/audit-before.html                  # line 1 is the marker
```

Next: run the flow end to end on one outside repository (survey, before
document, two or three plan rows, after document) and fix what the html gets
wrong before anyone else sees it; label a corpus so `measured_precision` stops
being `None` on every rule; tag `v0.1.0` (see "Settled" below).

Left open by the review, on purpose and small:

- Only `ToolPolicyGuard.setup` refuses unknown options. `PIIDetector`,
  `ToxicityFilter`, `PromptInjectionGuard`, `RateLimiter` and `NemoRailsGuard`
  still swallow a misspelled key through `**kwargs`; same failure, same fix,
  one guard at a time.
- There is no `--max-size` flag: `WalkOptions.max_size` (2 MiB) is reachable
  from Python only. The self-audit now reports `bench/findings-all.csv` as its
  one oversize file, which is correct -- it was always skipped, silently.
- `--write-baseline` prefers the compared document's reason over the refreshed
  file's when both hold one for a fingerprint; documented and tested, not a bug.

## Head

`main` at `f96086c`, pushed to `origin`
(`github.com/ai-safe-earth/AI-Safety-Guardrails`) on 2026-09-11. Both
workflows green on it (Tests run 34624633198, EU AI Act Compliance run
34624633209).

Recent history, newest first:

| commit | what |
| --- | --- |
| `f96086c` | `own_output_skipped` sorted in `walk`: `os.walk` name order is OS-dependent |
| `d97fae6` | Status point for the round |
| `c06d810` | The two-document audit flow: html documents, baseline as a record, the five-phase skill, two review rounds |
| `0acc0db` | docs: the audit and the portable skill explained |
| `de78fd3` | The `explain-doc` project skill |
| `b6332e6` | Distribution renamed to `aisguard`; the import stays `aisg` |
| `c145984` | Status point to resume from |
| `6d7f7e7` | SARIF is valid SARIF: marker moved off the root, empty optional fields omitted |
| `d2e1e76` | Compliance gate repaired; every suppression explicit and observable |
| `43c0e41` | The two CI failures: py3.10 `Z`-suffix date parsing, p99 set by one scheduler hiccup |
| `cc01830` | `aisg audit` / `aisg skill` wired into the CLI, self-audit in CI |

## Green

Locally on the round's commit (2026-09-10): **3579 passed, 8 skipped**
(~3.5 min), `ruff format --check` and `ruff check` on `src tests scripts`
pass, `aisg lint src examples --errors-only` no issues (81 files), `aisg
misalign` no issues on the changed modules, self-audit
(`aisg audit . --no-external --fail-on high --baseline audit-baseline.json`)
exit 0 with `baseline: 0 new, 23 unchanged, 0 no longer reported`,
`scripts/sync_skill.py --check` in sync (version 0.1.0, 13 files, 2 mirrors),
`scripts/controls_md.py --check` in sync (46 rules).

On CI, the round first failed on Linux and passed on Windows: two new walk
tests compared `own_output_skipped` to a sorted list, and `os.walk` returns
names in directory order, which is sorted on NTFS but not on ext4. `walk` now
sorts the sink itself (`f96086c`), so every caller gets the same list on every
OS -- `main.py` sorted it before putting it in the inventory, but the tests
read the sink directly. A local pass on Windows alone does not clear a list
that came from the filesystem.

The last CI runs are from `6d7f7e7` (both workflows passed: Tests run
33847197716, EU AI Act Compliance run 33847197641, SARIF accepted by Code
Scanning). The round's commit has not been through CI yet; check
`gh run list --limit 4` after the push.

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
pytest                                    # ~3600 tests, ~3.5 min, no API keys
ruff check src tests scripts
aisg lint src examples --errors-only
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
aisg measure --max-p99-ms 25
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
gh run list --limit 4
```
