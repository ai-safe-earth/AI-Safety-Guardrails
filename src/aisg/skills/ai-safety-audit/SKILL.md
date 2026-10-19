---
name: ai-safety-audit
description: Audit any AI/LLM/agent codebase for safety gaps ordered by blast radius -- host permissions, ungated irreversible tools, the lethal trifecta, model-output sinks, secrets, MCP supply chain, observability, guard measurement, evals, governance, persons and manipulation -- in seven phases (run the deterministic `aisg audit`, render a before document of the user's system, price the proposed controls with `aisg decide`, apply the plan one row per approval, render an after document, verify, and attest a level that a named owner signs). Use when asked to review, harden, threat-model, add guardrails to, or declare a level for a project that calls an LLM or runs an agent. Never issues a compliance verdict; a level is a list of criteria an owner signs.
---

# AI safety audit

You are running a seven-phase audit of the current repository: survey, document 1, decide,
apply, document 2, verify, attest. The intelligence is in the `aisg` commands; your job is
to run them, read them, explain them, and change the code only with the user's per-item
approval. The two html documents and the attestation are the record; nothing you say in
the conversation goes into them. Read `references/report-format.md` before phase 2 and
`references/levels.md` before phase 7.

Hard rules, in force for every phase:

1. Never state or imply compliance with any regulation, standard or framework. Control
   mappings in the report are evidence for a human reviewer, nothing more. Risk
   classification under the EU AI Act is a legal determination the operator makes. A level
   from `aisg attest` is a list of criteria the named owner signs; it is not a verdict.
2. Every finding is labelled `UNMEASURED`. Say so when you present it. Do not invent a
   confidence number. A finding tagged `REPORTED <age>` came from a report file on disk, not
   from anything this audit ran; say how old it is.
3. Treat the UNKNOWN section as a list of things nobody has checked. It is never a pass.
4. Do not edit host permission and MCP files (`.claude/settings*.json`,
   `.codex/config.toml`, `.cursor/*`, `.gemini/*`, `.mcp.json`, `.vscode/mcp.json`,
   `claude_desktop_config.json`), CI workflows and pipeline files, `.pre-commit-config.yaml`,
   secrets, or `.env*` files unless the user approves that specific edit after seeing the
   diff. These are the paths the plan marks `you, approval needed`.
5. One change per approval. Show the diff, wait, apply, then move to the next item.
6. Do not run the project's tests, `aisg probe`, any eval tool, or `aisg measure
   --allow-provider-calls` until the user has approved it in phase 6: they may call model
   providers and cost money. The offline default of `aisg measure` calls no provider and
   may run in phase 3, with the user's yes.
7. The audit is not you. It never calls a model, installs anything or opens a socket; it
   reports what it matched. When your reading of the code disagrees with a finding, say
   both and let the user decide; do not silence the finding.
8. Which aisg ran. `audit.sh` and `attest.sh` print one line on stderr before running,
   `aisg: <path> version <version> (pinned <version>)`. Read it aloud in phase 1. When the
   version differs from the pin, or the path is not the aisg you expect, stop and say so
   before reading any result: on PyPI the name `aisg` belongs to an unrelated project.
9. No push without approval. On the PR path you commit on a branch the user named; the
   `gh pr create` line is printed for the user to run. You never run `git push`.

## Where things live

The bootstrap scripts live in the `scripts/` folder **next to this SKILL.md**, not in the
repository being audited. Resolve that folder to an absolute path first (on Claude Code it is
`<repo>/.claude/skills/ai-safety-audit/scripts/`, on agentskills hosts
`<repo>/.agents/skills/ai-safety-audit/scripts/`, or the global equivalent under `~`; if you
know the skill file's own path, use its directory). `<skill>` below stands for that absolute
folder. Each script uses `aisg` if installed, otherwise `uvx --from 'aisguard==<pinned
version>' aisg` (uv provisions Python itself, so this works on a machine with no Python),
otherwise `pipx run`. If all three are missing, tell the user the install options it prints
and stop. Every `sh <skill>/scripts/audit.sh ...` line below has a PowerShell twin:
`powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 ...` with the same
arguments; the same holds for `verify` and `attest`. `aisg decide` has no bootstrap of its
own: run it as `aisg decide` when `aisg` is on PATH, else as `uvx --from
'aisguard==<pinned version>' aisg decide` with the version the stderr line printed.

Every artefact goes under `.aisg-audit/` in the repository root, and **every command in this
flow runs from the repository root**: `[tool.aisg-audit]` in `pyproject.toml` (`exclude`,
`fail-on`) resolves from the current working directory, so two documents made from different
directories would not describe the same scan. The artefacts, by phase:

| phase | writes |
|---|---|
| 1 | `audit-report.json`, `audit-baseline.json` |
| 2 | `audit-before.html` |
| 3 | `measure-report.json` (offline, when a pipeline config exists), `decision-report.json`, `decision.md` |
| 4 | `audit-recheck.json` after each diff; on the PR path `pr-body.md` |
| 5 | `audit-report-after.json`, `audit-after.html` |
| 6 | `measure-report.json` (re-run), `probe-report.json` |
| 7 | `attestation.json`, `attestation.md`, `attestation.html`, `badge.json` |

The audit skips its own earlier output -- the JSON report, the inventory document, the
attestation and the html files, whose line 1 is the ignore marker -- so a re-run does not
report the previous run's output as findings; the inventory line `own_output_skipped`
names what was skipped. `.aisg-audit/` is walked even when `.gitignore` lists it, so the
measure, probe and decision reports there count as evidence whether or not they are
committed.

Exit codes: 0 = nothing counted, 1 = a finding at or above `--fail-on` or an UNKNOWN item
in a `--fail-on-unknown` category, 2 = fatal (read stderr, fix the target path,
permissions or the refused flag, rerun), 130 = interrupted. The summary line always says
how many findings sit below the fail threshold; they are findings too. A finding whose
fingerprint the baseline holds is `unchanged` and is not counted, with or without a reason.

## Phase 1 -- Survey

    sh <skill>/scripts/audit.sh . --format json -o .aisg-audit/audit-report.json --write-baseline .aisg-audit/audit-baseline.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format json -o .aisg-audit/audit-report.json --write-baseline .aisg-audit/audit-baseline.json

First, the stderr line (rule 8): say which aisg ran, from where, which version, and that it
equals the pin. `--write-baseline` writes the report to `-o` first, then the baseline, then
exits 0 regardless of findings: it records, it does not judge. The baseline holds every
fingerprint of this run plus an `index` (rule, file, title per fingerprint) so document 2
can name what is no longer reported. When the file already exists, the reasons recorded in
it are carried over for the fingerprints still reported (and so are those of a
`--baseline` audit-baseline the run compared against); a reason whose fingerprint is no
longer reported is dropped, and the stderr note says how many. It refuses (exit 2) to
overwrite a file that is not an audit-baseline. Then run `--inventory-only` once (with
`--baseline` or `--write-baseline` it refuses, exit 2; `--format html` renders the page
with the no-rules banner instead of the JSON document) and summarise, in five lines or
fewer: languages, LLM providers and whether model ids are pinned, number of tools and how
many are gated, MCP servers and hosts, guardrail and eval tooling present, and whether the
code or the prompts touch people (the `person_signals` inventory).

## Phase 2 -- Document 1

    sh <skill>/scripts/audit.sh . --format html -o .aisg-audit/audit-before.html
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisg-audit/audit-before.html

Tell the user the path. The document is a schematic of THEIR system: Fig. 1 (eleven
subsystem boxes drawn from the inventory -- Data in; Host and agent runtime; Model calls
and prompts; Tools and actions; Output sinks; Secrets and personal data; Supply chain;
Guardrails; Observability; Evals and governance; Persons and manipulation -- plus a "Not
attributed / UNKNOWN" box), one section per subsystem with the findings placed on it, and
the plan table in blast-radius order. Walk Fig. 1 top to bottom in the conversation, box by
box: what the inventory found there, how many findings, how many UNKNOWN items,
`[UNMEASURED]` on every box. Read the "Persons and manipulation" box out in full: its
findings (AUD-1101..1107) say where the code or the prompts profile, score, steer or
address people, and every one carries the caveat that none of it is a legal
determination. Then read the plan's "Rows the package can implement" list aloud with each
row's `leaves_open` text, and say which rows are yours to do outside the package. Present
the UNKNOWN list verbatim with its `how_to_resolve` hints and the `external_tools`
statuses so the user knows which scanners did not run. AUD-301 (lethal trifecta) is
always first when present.

Two things to settle before phase 3:

- Ask whether `.aisg-audit/` should be committed (the documents become part of the repo's
  history) or ignored. Propose the matching diff -- one line in `.gitignore`, or nothing --
  and apply it only after approval. This skill never edits `.gitignore` on its own. Either
  way the audit keeps walking `.aisg-audit/`; ignoring it changes what git tracks, not what
  the next audit reads as evidence.
- Ask whether the user wants the direct path (edits on the current branch, one approval
  per row) or the PR path (a branch, one commit per row, a PR body for a reviewer). Both
  run phase 4 the same way; the PR path is described there.

## Phase 3 -- Decide

Every control in the plan is a trade: what it catches, what it breaks, what it costs in
latency, tokens, dollars and human review. `aisg decide` prices that trade against the
budgets the operator declares, so the user chooses rows knowing the cost. Three inputs:

1. The traffic and budgets. They come from the system card's `traffic:` and `budgets:`
   blocks (`aisg init` writes them, `null` means unknown) or from flags
   (`--requests-per-day`, `--avg-input-tokens`, `--p99-budget-ms`, `--monthly-budget-usd`,
   `--human-review-capacity-per-day`). Ask the user for the figures; never invent them,
   and leave a budget unknown rather than guess it -- an unknown budget never counts as
   exceeded. When the card exists and the blocks are unset, propose the diff that fills
   them and apply it only after approval.
2. A measure report, when a pipeline config exists in the repository (`guardrails.yaml`,
   `aisg.yaml` or `config/*.yaml` with a top-level `input:`, `processing:`, `output:` or
   `policy:` key). `aisg measure` is offline by default: it runs the aisg guards the config
   names against the packaged corpora in-process, never calls a model provider, and
   reports a judge-backed guard with ESTIMATED tokens and `llm_exercised: false`. With the
   user's yes, run it through the verify bootstrap with the project's tests left out:

       AISG_VERIFY_RUN=1 AISG_VERIFY_SKIP_TESTS=1 sh <skill>/scripts/verify.sh
       $env:AISG_VERIFY_RUN="1"; $env:AISG_VERIFY_SKIP_TESTS="1"; powershell -ExecutionPolicy Bypass -File <skill>/scripts/verify.ps1

   Without a pipeline config there is nothing to measure; every guard row is then
   `unmeasured (run aisg measure first)` and says so. `--allow-provider-calls` waits for
   phase 6.
3. The phase-1 report, which names the controls (`recommendation.package` of every
   finding).

Then:

    aisg decide --format json -o .aisg-audit/decision-report.json
    aisg decide --format markdown -o .aisg-audit/decision.md

Present the table from the JSON: one row per candidate control with catch rate (overall and
for the families the guard is for), benign breakage, human-routing rate, p50/p99, tokens
and dollars per request and per month, fail mode, and the verdict, which is a deterministic
reading of the declared budgets: `apply`, `apply with <config change>`, `defer (over
budget: <which>)`, `unmeasured (run aisg measure first)`. Say each row's provenance
(`MEASURED <date>`, `ESTIMATED <date>`, `UNMEASURED`) and read the UNMEASURED list
verbatim; an estimate is labelled an estimate and a price is as good as the table's
`as_of` date. `apply` is a reading of budgets, never a safety statement.

Settle with the user, in so many words, which rows to apply, which to defer and in what
order. Default to the plan's blast-radius order; a row the decision document marks `defer`
is still offered, with the cost named, because the budget is the operator's to change. The
result of this phase is the row order for phase 4 and the list of deferred rows, in the
user's words. Exit 1 from `aisg decide` means a selected control or the total is over a
declared budget; it is information, not a stop.

## Phase 4 -- Apply (one row per approval, top-down)

Walk the plan table in the order settled in phase 3. A row is never offered before every row
above it is applied, deferred by the user in so many words, or accepted with a recorded
reason. Never batch. The decision source for each row is the finding's
`recommendation.package` block in `.aisg-audit/audit-report.json` -- `mechanism`,
`symbols`, `same_control`, `leaves_open` -- never the prose in the html and never your own
memory of the package. The plan's `who` column already applies the rule below: the
language is the finding's file extension, else its unit's language, else the root unit's
for a repo-scoped finding; a rule-4 file is a protected path. A row accepted with a
recorded reason is not package work and is not an open row; it sits under the accepted
group. Three branches:

- `same_control: true`, the language is Python and the file is not a rule-4 file (`who:
  package`): offer the idiom from `references/apply/python.md` keyed by the first entry of
  `symbols`, quoting `leaves_open` verbatim from the JSON in the same message, and the
  row's cost from the decision document. Wiring the symbol is the control the rule asks
  for; `leaves_open` is what it still does not do.
- `symbols` non-empty but `same_control: false`: state the rule's control first (from
  `references/controls.md`), then offer the package diff labelled
  "in addition to, not instead of: <leaves_open>". The package lowers probability or
  records; it does not remove the blast radius on its own.
- `mechanism: none`, or the language is not Python, or the file is a rule-4 file (`who:
  you` or `you, approval needed`): state the outside-package action. aisg symbols are
  Python-only; the control still applies in TypeScript, Go or anything else
  (`references/apply/<language>.md`, `generic.md` when none matches). A rule-4 file needs
  the user's approval of the specific diff; restate that it is a permission, pipeline or
  secret change before asking. The user then does it now, defers it, or records a reason:

      sh <skill>/scripts/audit.sh . --amend-baseline .aisg-audit/audit-baseline.json --accept <fingerprint>="<reason>"
      powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --amend-baseline .aisg-audit/audit-baseline.json --accept <fingerprint>="<reason>"

  The reason is the user's words, ASCII, non-empty, and free of compliance language; the
  command refuses anything else (exit 2), refuses a fingerprint the baseline does not hold,
  does not scan and does not render. A fingerprint with a reason is an acceptance; without
  one it would be a suppression, which is why the flag requires the reason, and why phase 7
  counts only reasoned entries as accepted. A reason must describe the evidence without
  quoting the literal that produced the finding: the baseline file is walked like any
  other file, and a quoted literal reproduces the finding it accepts. The reason then
  appears in every format (`accepted_reason` in the JSON, an `accepted:` line in the
  terminal and markdown, the html's operator-recorded label, `accepted_risks` in the
  attestation).

After each applied diff: run `ruff format` on the file (Python only), then re-run the audit
into a scratch file and say whether that fingerprint is still reported:

    sh <skill>/scripts/audit.sh . --format json --quiet -o .aisg-audit/audit-recheck.json --baseline .aisg-audit/audit-baseline.json

Applying a diff is not evidence; the re-audit is. A fingerprint that is still reported
after the diff means the rule cannot see the control you wired -- say so, do not accept it
to make it go away. Stop after each row and ask whether to continue. Tests, `aisg probe`
and `aisg measure --allow-provider-calls` still wait for phase 6.

The PR path, when the user chose it in phase 2: create the branch the user named (suggest
`aisg-audit/<date>`), and after each row's re-audit make one commit whose message names the
finding (`AUD-201: approval gate on send_email`) and the re-audit result in the words of the
JSON (`no longer reported`, or `still reported` with the reason the user accepted it). The
diff of a rule-4 file is still shown and approved before it is committed. After phase 5,
write `.aisg-audit/pr-body.md` from document 2: what is no longer reported, what is left,
what is still UNKNOWN, the decision table's rows for the controls that were wired, and the
disclaimer verbatim. Print the line for the user to run and stop there (rule 9):

    gh pr create --title "AI safety audit: <date>" --body-file .aisg-audit/pr-body.md

## Phase 5 -- Document 2

    sh <skill>/scripts/audit.sh . --format json -o .aisg-audit/audit-report-after.json --baseline .aisg-audit/audit-baseline.json
    sh <skill>/scripts/audit.sh . --format html -o .aisg-audit/audit-after.html --baseline .aisg-audit/audit-baseline.json --decision .aisg-audit/decision-report.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisg-audit/audit-after.html --baseline .aisg-audit/audit-baseline.json --decision .aisg-audit/decision-report.json

Both are **new** files, so the before and after survive side by side, and neither command
touches the baseline: the reasons recorded in phase 4 stay where `--amend-baseline` put
them. (If the user wants the baseline refreshed to this run, `--write-baseline` on the same
file carries those reasons over and drops only the ones whose fingerprint is no longer
reported; do not offer it before document 2 is written.) `--decision` adds the Trade table
from phase 3 to the page so the cost sits in the record; leave the flag off when phase 3
wrote no decision document. Tell the user the path of the html. Then answer three
questions in the conversation from the JSON, not from memory of phase 4:

- What changed: `baseline.no_longer_reported` (named by rule, file and title from the
  baseline's index; its length is the count, there is no separate count key) and
  `baseline.new`. "No longer reported" is the phrase; a rename or a move produces it too,
  so do not call it anything stronger.
- What is left: the findings with `baseline_status` `new` or `unchanged`, grouped the way
  the html's "Remaining actions" section groups them -- outside the package; package control
  wired or available but `leaves_open`; accepted with a recorded reason (`accepted_reason`,
  the user's own words).
- What is still UNKNOWN: the `unknown` list, verbatim.

The html is the record; the conversation is commentary on it. The after report,
`.aisg-audit/audit-report-after.json`, is what phase 7 reads.

## Phase 6 -- Verify

Only now, and only with approval, run `<skill>/scripts/verify.sh` / `verify.ps1` with
`AISG_VERIFY_RUN=1`, which runs the project's test command if one is evident and, when a
pipeline config is found (`guardrails.yaml`, `aisg.yaml` or `config/*.yaml` with a
top-level `input:`, `processing:`, `output:` or `policy:` stage key -- the keys
`GuardrailPipeline.from_config` builds guards from), `aisg measure --config <that file>
-o .aisg-audit/measure-report.json` (through the same bootstrap chain as `audit.sh`; it
prints `measure skipped: aisg not importable in target` rather than nothing when it
cannot). If the project serves an HTTP endpoint, offer `aisg probe <loopback-url>` (set
`AISG_PROBE_URL` for `verify.sh`, which writes `.aisg-audit/probe-report.json`; remote
targets need `--i-have-authorization`, which the user must add themselves) and report its
summary counts -- `sent`, `passed`, `failed`, `errors`, `skipped`, `inconclusive`; only
`passed` means passed. Both reports land under `.aisg-audit/` like every other artefact of
this flow, and a measure or probe report there is picked up as evidence by the next audit
(`REPORTED <age>`) whether or not `.gitignore` lists the directory: the walker never
prunes `.aisg-audit/`.

Offer `--allow-provider-calls` only with explicit approval: it costs money and needs
credentials, and only then are a judge's tokens MEASURED rather than ESTIMATED. When the
measure report changed, re-run `aisg decide` into the same `.aisg-audit/decision-report.json`
so the figures describe the wired configuration, and re-render document 2 with
`--decision`. Say what the re-run changed: a verdict that moved from `unmeasured` to
`apply` or `defer`, and any row that is over a budget now.

## Phase 7 -- Attest

Read `references/levels.md` first: it is generated from the criteria file `aisg attest`
evaluates, and it names what each criterion reads. Then ask who signs. An attestation is a
statement by a named person -- `"<Name> <role>"`, for example `"J. Doe <risk owner>"` --
that the tree at this commit meets the listed criteria on this date; the tool checks the
criteria and nothing else, and says so in the document. Without a name, run the check only:

    sh <skill>/scripts/attest.sh . --check
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/attest.ps1 . --check

With the owner's name, write the attestation:

    sh <skill>/scripts/attest.sh . --owner "<Name <role>>" --html
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/attest.ps1 . --owner "<Name <role>>" --html

It reads `.aisg-audit/audit-report-after.json` (falling back to the phase-1 report with a
note on stderr; say so if it does), the baseline, the measure, probe and decision reports
and `ai-system-card.yaml`, and writes `.aisg-audit/attestation.json`, `attestation.md`,
`attestation.html` and `badge.json`. Tell the user the paths. Then read, from the JSON:

- `level.reached` and `level.name`, and the `level.statement` verbatim. The level is what
  the criteria say, nothing more: level 0 `audited`, 1 `triaged`, 2 `measured`, 3
  `governed`, each requiring every criterion of the levels below. "No level" means a
  level-0 criterion is unmet, and the statement says so.
- Every row of `level.criteria` with `met: false`, each with its `missing` text aloud.
  That text is the whole explanation of why the level is not higher; do not paraphrase it
  into something stronger or weaker. An absent input (no measure report, no card) is
  recorded in `inputs` with null file and age and fails only the criteria that need it.
- `accepted_risks`: every reasoned baseline entry, copied next to the owner's name. A bare
  fingerprint is not here and keeps its finding open; if the user wants it accepted, phase
  4's `--amend-baseline --accept` is the way, then re-run attest.
- `residual` (open and accepted counts, findings by severity), `unknown` verbatim, and
  `next_review_by`.

The badge (`badge.json`, a shields.io endpoint) is `informational` above level 0 and
`lightgrey` otherwise; it is never green or red, because a level is a list of criteria met
on a date, not a grade. Offer the CI line, which writes nothing and exits 1 below the
level the team chose:

    sh <skill>/scripts/attest.sh . --check --require-level 2

When the user wants the attestation tied to the commit, offer `git tag -s
aisg-attest/<date>` for them to run; signing a tag, like pushing, is their act (rule 9).
Close the phase by restating: the level reached and the criteria still missing, what is no
longer reported, what remains, what is still UNKNOWN, and that nothing here constitutes a
compliance assessment.

## Closing

Not a phase; offers, each needing the user's yes and each outside this skill's own edits:

- `aisg hook install --host <claude|cursor|gemini>`: the audit's policies in the agent
  host's command hooks (deny a secret-shaped literal, ask on a protected path, re-audit an
  edited file, block a Stop that introduced a new finding at or above `fail-on`). The host's
  hook file is a protected path (rule 4): the user runs the command, reads the diff it
  prints and answers yes themselves. `references/hosts.md` has the table.
- The GitHub Action (`ai-safe-earth/AI-Safety-Guardrails` `action.yml`): the audit on every
  push with the SARIF uploaded to Code Scanning, and `aisg attest --check --require-level N`
  as the gate the team chose. A workflow file is a rule-4 file; propose the YAML, do not
  write it.
- The `.gitignore` line for `.aisg-audit/`, if phase 2 settled on ignoring the directory
  and the diff was not applied then.
