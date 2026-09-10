# Reading an `aisg audit` report

Read this before phase 2. It condenses the finding and report schema so you can present
`.aisg-audit/audit-report.json` without guessing what a field means. The JSON is
authoritative in every phase; the html documents are rendered from the same `Report` and
carry no information the JSON lacks.

## The three buckets

Every finding sits in exactly one bucket. The bucket says where the evidence came from, not
how bad the finding is.

| bucket | meaning | how it renders |
|---|---|---|
| `measured` | an external scanner ran during THIS audit and produced the finding (gitleaks, detect-secrets, pip-audit, npm audit, osv-scanner, semgrep, mcp-scan) | `MEASURED` |
| `asserted` | this audit's own rules matched code or config, OR a report file on disk was read | `[UNMEASURED]`, plus `[REPORTED <age>d, <source>]` when it came from a file |
| `unknown` | nobody checked: a scanner was not on PATH, deep analysis is not available for a language, a report was unreadable or undated, something could not be established statically | listed under UNKNOWN with `how_to_resolve` |

Rules that hold:

- `MEASURED` means a tool ran now. A `measure-report.json` or `probe-report.json` read from
  disk is never `MEASURED`; it is `REPORTED <age>` under `asserted`, and the age comes from
  the report's `generated_at`, else the file mtime, else `git log`. If none of those is
  available the report yields an UNKNOWN item ("report age unknown") and no finding.
- `UNKNOWN` is never a pass. A run with zero findings still prints the UNKNOWN block and the
  disclaimer. Present the list verbatim with its `how_to_resolve` hints.
- Absence of a finding is not evidence of safety.

## `[UNMEASURED]`

Every rule carries `measured_precision: null`. `null` means nobody has labelled a corpus for
that rule yet; it does not mean the rule is perfect and it does not mean it is noisy. An
unmeasured rule still fires by default. When you present a finding, say `[UNMEASURED]` out
loud and never invent a confidence number. `confidence.label` is always `"UNMEASURED"` in this
version; `confidence.evidence_kind` (`code`, `config`, `absence`, `tool_output`, `report`)
and `confidence.match_kind` (`grep`, `structured`, `ast`, `external`) tell you how the match
was made. A `grep` match on a non-Python sink (AUD-401..406) is rendered "co-located,
unverified": the sink and a model call share a file and an identifier, nothing more.

## `[REPORTED <age>]`

AUD-803, AUD-902 and AUD-903 read `measure-report.json` / `probe-report.json` from the target.
Their findings carry `evidence_kind: "report"` and a `report` block:

    "report": {"file": "measure-report.json", "schema": "aisg/1",
               "generated_at": null, "age_source": "mtime", "age_days": 41}

Say how old the report is and where the age came from. A 41-day-old measurement of a guard
that has since been reconfigured measures the old configuration. `aisg measure` never emits a
precision figure, so no audit rule compares one; AUD-803 reads `threshold_failures` and
`false_positive_rate` only.

## One finding

    {
      "id": "AUD-301",
      "fingerprint": "3f9a1c0b2d4e5f67",
      "title": "LETHAL TRIFECTA: private data + untrusted content + external action in one scope",
      "severity": "critical",
      "priority": 3,
      "bucket": "asserted",
      "basis": "presence",
      "confidence": {"evidence_kind": "code", "match_kind": "ast", "precision": null, "label": "UNMEASURED"},
      "scope": {"kind": "function", "unit": "u1", "name": "services/agent/app.py::handle_ticket"},
      "evidence": [{"role": "private", "file": "...", "line": 52, "snippet": "..."}, ...],
      "controls": ["ASI01", "ASI02", "ASI06", "LLM01", "LLM02", "LLM06", "EU:Art.9", "EU:Art.15", "NIST:MAP-5.1", "NIST:MANAGE-2.2"],
      "recommendation": {"tier": "T3", "summary": "...", "alternatives": ["aisg ToolPolicyGuard + PIIDetector", "NeMo Guardrails flows", "Guardrails AI validators", "LLM Guard scanners"],
                         "package": {"mechanism": "gate", "symbols": ["ToolPolicyGuard", "PIIDetector"], "same_control": false,
                                     "leaves_open": "the control is the structural split of trusted and untrusted scopes; a gate plus a detector never closes this"}},
      "related_lint_rules": ["EU-AIA-012a", "ALIGN-003"],
      "known_failure_modes": ["unit-level scope over-approximates in monorepos"],
      "suppressed": false,
      "gitignored": false,
      "baseline_status": "unchanged",
      "accepted_reason": "reader and writer split tracked in ticket 412; scope of the writer reviewed 2026-09"
    }

- `severity` is blast radius (what the gap lets an attacker do), never detector confidence.
  It is not adjusted downward because a match is a grep.
- `priority` is the threat-model group (1 = blast radius, 2 = irreversible gates, 3 = trust
  boundaries, 4 = output sinks, 5 = secrets and PII, 6 = supply chain, 7 = observability,
  8 = detection guards, 9 = evaluation loop, 10 = governance). Findings sort by
  `(priority, severity, file, line)` and AUD-301 is pinned first whenever present.
- `fingerprint` is stable across renumbered lines and renamed locals; it is what
  `--baseline` compares and what `--accept` names in phase 3.
- `controls` are evidence for a human reviewer: OWASP Agentic (ASI), OWASP LLM (LLM), EU AI
  Act articles and NIST AI RMF functions the finding is relevant to. The terminal and
  markdown renderers print them as one line, `controls: <items>` (comma-separated); a
  later finding of the same rule with the same list gets `controls: see the first
  <id> above` instead of a repeat. The html does not print the list: its plan table's
  `control` column is `recommendation.summary`, the control the rule asks for, not these
  ids. Read them from the JSON. Never state or imply compliance with any of them.
- `baseline_status` is present only when `--baseline` was given: `new` (not in the
  baseline) or `unchanged` (in it). Findings whose fingerprint is in the baseline but not in
  this run do not appear as findings at all; they are listed under
  `baseline.no_longer_reported`.
- `accepted_reason` is present only when the baseline carries a reason for this fingerprint
  (recorded with `--amend-baseline ... --accept`). It is the operator's own words, ASCII,
  html-escaped when rendered. An accepted finding is still a finding: it stays in
  `findings` with its severity and its `unchanged` status, and a reason does not change
  what the exit code counts (see "Exit codes and the fail threshold"). The reason
  travels into every format: this JSON key, a SARIF result property, the html's
  "Operator-recorded reason" label, and an `accepted: <reason>` line under the finding in
  the terminal and markdown output. In the html plan an accepted finding is not counted
  as package work and is not an open row; it sits under the accepted group.

## `recommendation.package`

What this package offers for the finding, and what that leaves open. Four keys, always
present, in this order:

| key | values | meaning |
|---|---|---|
| `mechanism` | `gate`, `budget`, `detector`, `record`, `measurement`, `document`, `none` | the kind of thing the package can add. `gate` lowers impact; `detector` lowers probability; `record` writes evidence; `measurement` and `document` produce reports and cards, not runtime behaviour |
| `symbols` | list of aisg class names (`ToolPolicyGuard`) or verbs (`aisg measure`); empty when `mechanism` is `none` | what to wire, in preference order; the first entry keys `apply/python.md` |
| `same_control` | `true` / `false` | `true` only when wiring `symbols` IS the control the rule asks for. `false` means the package offers a different, additional mechanism |
| `leaves_open` | text; non-empty whenever `mechanism` is not `none` | what wiring the symbols still does not do, in the rule author's words. Quote it every time you offer the symbol |

`same_control: true` does not mean the finding disappears once the symbol is wired: the
symbol must sit on the path the finding is about (a `ToolPolicyGuard` only sees calls
dispatched through `run_processing`; a `TelemetryProvider` only traces calls through
`run_full`), and `leaves_open` says what is outside it even then. It also does not mean the
rule will stop firing: only the re-audit in phase 3 shows that. `same_control: false` with
symbols means "in addition to, not instead of" the control in `controls.md`; a detector is
never the control for a P1-P4 finding. aisg symbols are Python-only; on a non-Python unit
the mechanism is still named, the control still applies, and the symbol does not.

Every row's `who` in the html plan table derives from this block and nothing else:
`package` when `same_control` is true, the finding's language is Python and the file is
not a protected path; `you, approval needed` when the file is protected; `you` otherwise.
The language comes from the finding's file extension; a finding without a file takes its
unit's language, and a repo-scoped finding the root unit's. Protected paths are the host
permission and MCP files (`.claude/settings*.json`, `.codex/config.toml`, `.cursor/*`,
`.gemini/*`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`), CI workflows
and pipeline files (`.github/workflows/*`, `.gitlab-ci*.yml`, `.circleci/config.yml`,
`Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.travis.yml`), `.env*`,
`.secrets*` and `.pre-commit-config.yaml`. An accepted finding is neither package work
nor an open row; it sits under the accepted group.
- `sub` names a sub-finding (`AUD-101/interpreter`, `AUD-107/inert`, `AUD-701/apm-only`);
  the display id is `AUD-101/interpreter`.
- `gitignored: true` means the evidence file is excluded by `.gitignore` but was walked
  anyway. `.env*` always is, and so is `.aisg-audit/`, so the reports there count as
  evidence whether or not they are committed. Say so for a credential: it is a
  developer-machine one, not a committed one.
- Snippets are masked before they enter a finding, by two different mechanisms with two
  different shapes. Secret-shaped tokens become `<redacted:PREFIX...LAST4>` (`sk-ant-`,
  `sk-`, `ghp_`, `AKIA`, `xoxb-`, `AIza`, bearer tokens, `key=`/`token=` assignments and
  long hex or base64 values next to such a name); this runs on every snippet in every
  format. PII hits become `<pii:ENTITY>` with the entity name in upper case -- `<pii:EMAIL>`,
  `<pii:PHONE_US>`, `<pii:PHONE_INTL>`, `<pii:SSN>`, `<pii:CREDIT_CARD>`,
  `<pii:IP_ADDRESS>`, `<pii:IBAN>`, `<pii:DATE_OF_BIRTH>`, the shipped PII detector's
  default entities -- and are masked when discovery records the hit, so the AUD-505
  snippet never holds the value. There is no flag to turn either off: `--no-redact` is
  refused with exit 2.

## The report envelope

Key order is fixed; `schema` is first.

    schema, kind, tool, target, generated_at, disclaimer, summary, findings, measured,
    reports, unknown, external_tools, baseline, inventory, rules

- `disclaimer` opens every format: "Not an assessment of compliance with any regulation.
  Risk classification under the EU AI Act is a legal determination made by the operator, not
  a tool output. Every rule in this report is UNMEASURED ... Absence of a finding is not
  evidence of safety." Repeat its substance when you close.
- `summary`: `findings`, `by_severity`, `by_bucket`, `reported` (findings read from disk),
  `below_threshold`, `fail_on`, `unknown_items`, `unknown_by_category`
  (`tools` / `deep` / `reports` / `runtime`), `exit_code`, `top` (first finding id),
  `suppressed`, `baseline_new` (null without `--baseline`).
- `measured`: one row per scanner that ran, with `version`, `duration_ms`, `findings` and
  `network` (whether that scanner uses the network the way it normally does).
- `reports`: every on-disk aisg report that was read, with its age and the fields the rules
  consumed (`guards` for measure, `summary` for probe).
- `external_tools`: every adapter and its status: `ran`, `not_on_path`, `not_applicable`,
  `failed`, `timeout`, `skipped_by_flag` (`--no-external`), `skipped_needs_flag`
  (promptfoo needs `--run-evals` because it may call providers). Read this list to the user
  so they know which scanners did not run.
- `baseline`: present when `--baseline` was given, keys in this order:
  `file`, `kind`, `new`, `unchanged` (counts), `accepted`, `generated_at`,
  `no_longer_reported`. There is no count key for the fingerprints that are gone: the
  length of `no_longer_reported` is the count. Every renderer's baseline line reads
  `baseline: N new, N unchanged, N no longer reported (file)`. Only `new` findings count
  toward the exit code; `unchanged` ones do not, reason or no reason.
  - `kind`: `audit-baseline` for a baseline file, `audit` when a full report was used as
    the baseline. A report carries no reasons, so `accepted` is always empty then; say
    "the baseline was a report", not "no reasons recorded".
  - `accepted`: `[{"fingerprint", "rule", "file", "reason"}]`, one entry per reason in
    the baseline file that matched a finding reported this run. A reason whose finding
    is gone shows up under `no_longer_reported` instead, not here.
  - `generated_at`: the compared document's own timestamp (a baseline file's, or the
    report's), so document 2 can say how old the comparison point is; `null` when the
    document has none.
  - `no_longer_reported`: `[{"fingerprint", "rule", "file", "title"}]`, one entry per
    fingerprint the baseline holds that this run did not produce. The names come from the
    baseline file's `index`; a baseline written without one yields `{"fingerprint"}` only.
    Say "no longer reported": a rename, a move or a changed snippet produces the same
    entry as a removed gap, and the audit cannot tell them apart.
- `rules`: the catalogue that ran, each with `measured_precision: null`.

## Inventory keys worth reading out

`inventory.own_output_skipped`: the paths of the audit's own earlier output the walk
skipped: a JSON whose head carries `"schema": "aisg/1"` and `"kind": "audit"` (the
report) or `"kind": "inventory"` (the `--inventory-only` document), and an html whose
first line is exactly `<!-- # aisg-audit: ignore-file -->`. Without this the phase-1
documents would be scanned as source and their evidence snippets reported as new findings.
Baseline files are not skipped (they hold no snippets; the reasons are read as text, which
is why a reason must not quote the literal it accepts), and measure and probe reports are
not skipped (they are evidence for AUD-803, AUD-902 and AUD-903). `.aisg-audit/` is
deliberately not a skipped directory, for the same reason, and `.gitignore` never prunes
it. The list is one inventory line in every format; SARIF carries it at
`runs[0].properties.own_output_skipped`.

## The baseline file

`--write-baseline FILE` writes, keys in this order: `schema`, `kind: "audit-baseline"`,
`generated_at`, `tool`, `fingerprints`, then `accepted` when any reason has been recorded,
then `index` (`{fingerprint: {rule, file, title}}`). With `-o` the report is rendered and
written first, then the baseline, and the exit code is 0 regardless of findings: the
command records, it does not judge. Read the report it wrote; the baseline alone tells you
nothing about severity.

Operator reasons are carried over, not retyped: from the `--baseline` document the run
was compared against (when that document is an audit-baseline; a report holds none) and
from the file `--write-baseline` refreshes. A reason whose fingerprint is no longer
reported is dropped, and the note on stderr says how many. `--write-baseline` refuses
(exit 2) to overwrite a file that exists and is not `kind: audit-baseline`, so a report or
a source file cannot be replaced by mistake. Reading a baseline applies the same check as
`--accept`: a reason carrying verdict language or a secret shape is rejected.

`--amend-baseline FILE --accept FINGERPRINT=REASON` (repeatable) adds reasons to an
existing baseline without scanning or rendering. It refuses (exit 2) a file that is not
`kind: audit-baseline`, a fingerprint not in `fingerprints`, an empty reason, a reason that
is not ASCII, one that contains compliance language, and one that looks like a secret. A
second `--accept` for the same fingerprint replaces the reason. `--accept` without
`--amend-baseline` is exit 2.

## `--format html`

One renderer, two documents: without `--baseline` it is document 1 (the survey), with it
document 2 (the comparison). Every sentence in it is a fixed template; there is no agent
prose. `--quiet` has no effect on html. `--inventory-only` renders the header, Fig. 1 and
the inventory with a banner saying the rules did not run, and no plan. ASCII throughout, no
severity colour, no ticks, grades, scores or percentages. Sections, in order:

1. Line 1 is `<!-- # aisg-audit: ignore-file -->`, so a re-audit of a tree that contains the
   document skips it instead of reporting its own snippets.
2. Header: target, commit, `generated_at`, tool version; "Compared against: none -- this
   is the first survey" or "Compared against <path>, written <age> ago" plus the number of
   operator-recorded reasons; the resolved `fail-on` and `exclude` so two documents made
   from different working directories show the mismatch.
3. The disclaimer verbatim, "Absence of a finding is not evidence of safety.", and the
   UNKNOWN count, all above the figure. No severity totals strip.
4. Document 2 only -- "Since the baseline": What changed (`no_longer_reported`, named,
   and `new`), What is left, What we still do not know.
5. Fig. 1 -- System map: ten subsystem boxes drawn from the inventory (Data in; Host and
   agent runtime; Model calls and prompts; Tools and actions; Output sinks; Secrets and
   personal data; Supply chain; Guardrails; Observability; Evals and governance) plus a
   dashed "Not attributed / UNKNOWN" box. Each box: up to two inventory facts,
   "reported n | UNKNOWN m | rules ran k/K", and `[UNMEASURED]`. "No surface found" is
   different from "reported 0". The caption says what the figure deliberately omits.
6. One section per subsystem: inventory facts with file:line, then the findings placed
   there in report order, each with its bucket tag, baseline status, redacted evidence,
   recommendation and the package line (`aisg: <symbols> -- implements the control this
   rule asks for. Leaves open: ...`, or `... a different control (<mechanism>), in
   addition to, not instead of: ...`, or `outside the package: ...`), the Python-only note
   on non-Python units, the approval note on protected paths, and the operator's recorded
   reason when there is one.
7. Plan: one table in report order -- #, id, severity, subsystem, control, tier, aisg,
   who, status -- then "Rows the package can implement (walk the table top-down; do not
   skip a row above)" and the sentence "Wiring a control is not evidence the finding is
   gone: re-run the audit and read document 2."
8. Document 2 only -- "Remaining actions": open findings grouped as Outside the package /
   Package control wired or available, but leaves open / Accepted with a recorded reason /
   Still UNKNOWN.
9. UNKNOWN, every item with `how_to_resolve` and the install hint as text.
10. External tools that ran, with version and network flag, and the reports read.
11. Footer: the terminal's summary sentence, the absence sentence again, "generated by
    aisguard <version>; the JSON report is authoritative".

Read the JSON to answer questions; point the user at the html to keep.

## Exit codes and the fail threshold

| exit | meaning |
|---|---|
| 0 | nothing counted: no finding at or above `--fail-on` (default `low`), and no UNKNOWN item in a selected category when `--fail-on-unknown` is set |
| 1 | a finding at or above `--fail-on`, or an UNKNOWN item in a `--fail-on-unknown` category |
| 2 | fatal: path missing, unreadable target, walker error, report unwritable, a refused flag; read stderr, fix, rerun |
| 130 | interrupted |

Severity is what counts, not novelty: a finding below `--fail-on` is not counted however
new it is. With `--baseline`, a finding whose fingerprint the baseline holds is
`unchanged` and is not counted either, with or without a reason; only `new` ones at or
above the threshold are. `--write-baseline` always exits 0.

Findings below `--fail-on` are still findings. The summary line is always

    N findings (M below --fail-on <level>, not counted in exit code); K unknown items

and JSON carries `summary.below_threshold` and `summary.fail_on`. An exit code of 0 with
`M > 0` means the user chose not to fail the build on those; it does not mean they are
resolved. Present them.

`--fail-on-unknown` without a category list fails on any UNKNOWN item, which is unusable on a
runner missing any optional scanner or on a non-Python repo (deep analysis is Python-only).
The CI recipe is `--fail-on-unknown tools,reports` after installing the scanners the team
cares about.

## Inventory (`--inventory-only`)

A separate document, also `schema: "aisg/1"` first: languages, units, LLM providers and
model ids with `pinned: true|false|null` (`null` = unknown provider, no finding), tool
definitions and how many carry an approval symbol, MCP servers with transport and pinning,
host configs found, guardrail libraries, eval tooling, on-disk reports. Summarise it in five
lines or fewer in phase 1. The document's `kind` is `inventory`, so a later walk skips it
as own output. With `--format html` the page is rendered instead, with the no-rules
banner and the inventory; every other format writes the JSON document. `--inventory-only`
refuses (exit 2) `--baseline` and `--write-baseline`: no rule runs, so neither flag can
do what it says.
