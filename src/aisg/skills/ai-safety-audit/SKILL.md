---
name: ai-safety-audit
description: Audit any AI/LLM/agent codebase for safety gaps ordered by blast radius -- host permissions, ungated irreversible tools, the lethal trifecta, model-output sinks, secrets, MCP supply chain, observability, guard measurement, evals, governance -- by running the deterministic `aisg audit`, rendering a before document of the user's system, applying the plan one row per approval, rendering an after document, and verifying. Use when asked to review, harden, threat-model, or add guardrails to a project that calls an LLM or runs an agent. Never issues a compliance verdict.
---

# AI safety audit

You are running a five-phase audit of the current repository: survey, document 1, apply,
document 2, verify. The intelligence is in the `aisg audit` command; your job is to run it,
read it, explain it, and change the code only with the user's per-item approval. The two
html documents are the record; nothing you say in the conversation goes into them. Read
`references/report-format.md` before phase 2.

Hard rules, in force for every phase:

1. Never state or imply compliance with any regulation, standard or framework. Control
   mappings in the report are evidence for a human reviewer, nothing more. Risk
   classification under the EU AI Act is a legal determination the operator makes.
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
6. Do not run the project's tests, `aisg measure`, `aisg probe`, or any eval tool until the
   user has approved it in phase 5 -- they may call model providers and cost money.
7. The audit is not you. It never calls a model, installs anything or opens a socket; it
   reports what it matched. When your reading of the code disagrees with a finding, say
   both and let the user decide; do not silence the finding.

## Where things live

The bootstrap scripts live in the `scripts/` folder **next to this SKILL.md**, not in the
repository being audited. Resolve that folder to an absolute path first (on Claude Code it is
`<repo>/.claude/skills/ai-safety-audit/scripts/`, on agentskills hosts
`<repo>/.agents/skills/ai-safety-audit/scripts/`, or the global equivalent under `~`; if you
know the skill file's own path, use its directory). `<skill>` below stands for that absolute
folder. The script uses `aisg` if installed, otherwise `uvx --from 'aisguard==<pinned
version>' aisg` (uv provisions Python itself, so this works on a machine with no Python),
otherwise `pipx run`. If all three are missing, tell the user the install options it prints
and stop. Every `sh <skill>/scripts/audit.sh ...` line below has a PowerShell twin:
`powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 ...` with the same
arguments.

Every artefact goes under `.aisg-audit/` in the repository root, and **every command in this
flow runs from the repository root**: `[tool.aisg-audit]` in `pyproject.toml` (`exclude`,
`fail-on`) resolves from the current working directory, so two documents made from different
directories would not describe the same scan. The audit skips its own earlier output -- the
JSON report, the inventory document and the html, whose line 1 is the ignore marker -- so a
re-run does not report the previous run's output as findings; the inventory line
`own_output_skipped` names what was skipped. `.aisg-audit/` is walked even when
`.gitignore` lists it, so the reports there count as evidence whether or not they are
committed.

Exit codes: 0 = nothing counted, 1 = a finding at or above `--fail-on` or an UNKNOWN item
in a `--fail-on-unknown` category, 2 = fatal (read stderr, fix the target path,
permissions or the refused flag, rerun), 130 = interrupted. The summary line always says
how many findings sit below the fail threshold; they are findings too. A finding whose
fingerprint the baseline holds is `unchanged` and is not counted, with or without a reason.

## Phase 1 -- Survey

    sh <skill>/scripts/audit.sh . --format json -o .aisg-audit/audit-report.json --write-baseline .aisg-audit/audit-baseline.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format json -o .aisg-audit/audit-report.json --write-baseline .aisg-audit/audit-baseline.json

`--write-baseline` writes the report to `-o` first, then the baseline, then exits 0
regardless of findings: it records, it does not judge. The baseline holds every fingerprint
of this run plus an `index` (rule, file, title per fingerprint) so document 2 can name what
is no longer reported. When the file already exists, the reasons recorded in it are
carried over for the fingerprints still reported (and so are those of a `--baseline`
audit-baseline the run compared against); a reason whose fingerprint is no longer reported
is dropped, and the stderr note says how many. It refuses (exit 2) to overwrite a file
that is not an audit-baseline. Then run `--inventory-only` once (with `--baseline` or
`--write-baseline` it refuses, exit 2; `--format html` renders the page with the no-rules
banner instead of the JSON document) and summarise, in five lines or fewer: languages, LLM
providers and whether model ids are pinned, number of tools and how many are gated, MCP
servers and hosts, guardrail and eval tooling present.

## Phase 2 -- Document 1

    sh <skill>/scripts/audit.sh . --format html -o .aisg-audit/audit-before.html
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisg-audit/audit-before.html

Tell the user the path. The document is a schematic of THEIR system: Fig. 1 (ten
subsystem boxes drawn from the inventory, plus a "Not attributed / UNKNOWN" box), one
section per subsystem with the findings placed on it, and the plan table in blast-radius
order. Walk Fig. 1 top to bottom in the conversation, box by box: what the inventory found
there, how many findings, how many UNKNOWN items, `[UNMEASURED]` on every box. Then read the
plan's "Rows the package can implement" list aloud with each row's `leaves_open` text, and
say which rows are yours to do outside the package. Present the UNKNOWN list verbatim with
its `how_to_resolve` hints and the `external_tools` statuses so the user knows which scanners
did not run. AUD-301 (lethal trifecta) is always first when present.

Two things to settle before phase 3:

- Ask whether `.aisg-audit/` should be committed (the documents become part of the repo's
  history) or ignored. Propose the matching diff -- one line in `.gitignore`, or nothing --
  and apply it only after approval. This skill never edits `.gitignore` on its own. Either
  way the audit keeps walking `.aisg-audit/`; ignoring it changes what git tracks, not what
  the next audit reads as evidence.
- Ask which rows to defer, in so many words. Default to top-down order.

## Phase 3 -- Apply (one row per approval, top-down)

Walk the plan table top-down. A row is never offered before every row above it is
applied, deferred by the user in so many words, or accepted with a recorded reason. Never
batch. The decision source for each row is the finding's `recommendation.package` block in
`.aisg-audit/audit-report.json` -- `mechanism`, `symbols`, `same_control`, `leaves_open` --
never the prose in the html and never your own memory of the package. The plan's `who`
column already applies the rule below: the language is the finding's file extension, else
its unit's language, else the root unit's for a repo-scoped finding; a rule-4 file is a
protected path. A row accepted with a recorded reason is not package work and is not an
open row; it sits under the accepted group. Three branches:

- `same_control: true`, the language is Python and the file is not a rule-4 file (`who:
  package`): offer the idiom from `references/apply/python.md` keyed by the first entry of
  `symbols`, quoting `leaves_open` verbatim from the JSON in the same message. Wiring the
  symbol is the control the rule asks for; `leaves_open` is what it still does not do.
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
  one it would be a suppression, which is why the flag requires the reason. A reason must
  describe the evidence without quoting the literal that produced the finding: the
  baseline file is walked like any other file, and a quoted literal reproduces the finding
  it accepts. The reason then appears in every format (`accepted_reason` in the JSON, an
  `accepted:` line in the terminal and markdown, the html's operator-recorded label).

After each applied diff: run `ruff format` on the file (Python only), then re-run the audit
into a scratch file and say whether that fingerprint is still reported:

    sh <skill>/scripts/audit.sh . --format json --quiet -o .aisg-audit/audit-recheck.json --baseline .aisg-audit/audit-baseline.json

Applying a diff is not evidence; the re-audit is. A fingerprint that is still reported
after the diff means the rule cannot see the control you wired -- say so, do not accept it
to make it go away. Stop after each row and ask whether to continue. Tests, `aisg measure`
and `aisg probe` still wait for phase 5.

## Phase 4 -- Document 2

    sh <skill>/scripts/audit.sh . --format json -o .aisg-audit/audit-report-after.json --baseline .aisg-audit/audit-baseline.json
    sh <skill>/scripts/audit.sh . --format html -o .aisg-audit/audit-after.html --baseline .aisg-audit/audit-baseline.json
    powershell -ExecutionPolicy Bypass -File <skill>/scripts/audit.ps1 . --format html -o .aisg-audit/audit-after.html --baseline .aisg-audit/audit-baseline.json

Both are **new** files, so the before and after survive side by side, and neither command
touches the baseline: the reasons recorded in phase 3 stay where `--amend-baseline` put
them. (If the user wants the baseline refreshed to this run, `--write-baseline` on the same
file carries those reasons over and drops only the ones whose fingerprint is no longer
reported; do not offer it before document 2 is written.) Tell the user the path of the
html. Then answer three questions in the conversation from the JSON, not from memory of
phase 3:

- What changed: `baseline.no_longer_reported` (named by rule, file and title from the
  baseline's index; its length is the count, there is no separate count key) and
  `baseline.new`. "No longer reported" is the phrase; a rename or a move produces it too,
  so do not call it anything stronger.
- What is left: the findings with `baseline_status` `new` or `unchanged`, grouped the way
  the html's "Remaining actions" section groups them -- outside the package; package control
  wired or available but `leaves_open`; accepted with a recorded reason (`accepted_reason`,
  the user's own words).
- What is still UNKNOWN: the `unknown` list, verbatim.

The html is the record; the conversation is commentary on it.

## Phase 5 -- Verify

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
Close by restating: what is no longer reported, what remains, what is still UNKNOWN, and
that nothing here constitutes a compliance assessment.
