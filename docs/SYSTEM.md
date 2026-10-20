# The system, on one page

How the pieces of AnyAISafe fit together: what each step reads, what it
writes, and what it never does. Every path is relative to the root of the repository
being audited, and every artefact of the flow lives under `.aisafe-audit/`. The skill
(`src/aisafe/skills/ai-safety-audit/SKILL.md`) runs the steps in this order with a person
approving each change; the commands also run on their own, in CI, or over a fleet.

## The flow

| step | command | reads | writes | never |
|---|---|---|---|---|
| 1 survey | `aisafe audit . --format json -o .aisafe-audit/audit-report.json --write-baseline .aisafe-audit/audit-baseline.json` | the tree; `ai-system-card.yaml`; measure, probe and decision reports already under `.aisafe-audit/` (`REPORTED <age>`) | `audit-report.json` (`kind: audit`), `audit-baseline.json` (`kind: audit-baseline`) | calls a model, installs anything, opens a socket |
| 2 document 1 | `aisafe audit . --format html -o .aisafe-audit/audit-before.html` | the same | `audit-before.html` (line 1 is the own-output marker) | a verdict, a colour, a score |
| 3 decide | offline `aisafe measure --config <pipeline.yaml> -o .aisafe-audit/measure-report.json` when a pipeline config exists; then `aisafe decide --format json -o .aisafe-audit/decision-report.json` | the audit report; the measure report; `prices.yaml` (dated); the card's `traffic:` and `budgets:` blocks or flags | `measure-report.json`, `decision-report.json` (`kind: decision`), `decision.md` | a provider call without `--allow-provider-calls`; a fetched price; a guessed budget |
| 4 apply | the agent, one row per approval, top-down | `recommendation.package` of each finding; `references/apply/<language>.md` | code diffs; `audit-recheck.json` after each; `--amend-baseline --accept` reasons; on the PR path, commits on a branch and `pr-body.md` | an edit to a protected path without the diff shown; a push |
| 5 document 2 | `aisafe audit . --format json -o .aisafe-audit/audit-report-after.json --baseline .aisafe-audit/audit-baseline.json`; `--format html --decision .aisafe-audit/decision-report.json` | the tree; the baseline; the decision document | `audit-report-after.json`, `audit-after.html` | a count stronger than "no longer reported" |
| 6 verify | the project's tests; `aisafe measure` (with provider calls only on approval); `aisafe probe <loopback-url> -o .aisafe-audit/probe-report.json` | the pipeline config; the served endpoint | `measure-report.json`, `probe-report.json` | `--i-have-authorization` added by a script; a probe case counted as passed when it was `inconclusive`, `skipped` or `error` |
| 7 attest | `aisafe attest . --owner "<Name <role>>" --html` | every document above and the card; `attest-levels.yaml` | `attestation.json` (`kind: attestation`), `attestation.md`, `attestation.html`, `badge.json` | a verdict; a green or red badge; an owner from `pyproject.toml` |
| hooks | `aisafe hook run` from the agent host's hook configuration (Claude Code, Cursor, Gemini CLI; the Claude Code plugin ships the same) | the host's event payload; the baseline | `hook-state.json`, `hook-recheck.json`, `hook-stop.json` | failing closed on its own error; a model call; a socket |
| CI | `action.yml`, `.pre-commit-hooks.yaml`, the GitLab job; `aisafe attest . --check --require-level N` | the tree | the documents as build artefacts; SARIF to Code Scanning | |
| fleet | `aisafe fleet LIST [--jobs N] [--proposal]` | the YAML or CSV list the operator wrote; each repository cloned at its pin (or used in place) and audited with `--no-external` in its own subprocess | `fleet-report.{json,csv,md}` (`kind: fleet`), one audit report per repository, `proposal.md` with `--proposal` | network use beyond `git clone` of the listed URLs; a push or a PR; a snippet in the fleet documents |

## Who reads what back

- The audit reads the measure, probe and decision reports as evidence labelled
  `REPORTED <age>` (AUD-803, AUD-806, AUD-902, AUD-903), never as if it had just measured
  them. It skips its own report, inventory and html, and the attestation, as own output
  and lists them under `own_output_skipped`. A baseline is walked like any file, which is
  why an accepted reason must not quote the literal it accepts.
- `aisafe decide` reads the audit report for the controls (`recommendation.package`
  symbols), the measure report for their figures, the price table for dollars and the
  card for traffic and budgets. An unknown budget never counts as exceeded; an unknown
  figure never counts as zero; a judge the measure report never exercised is UNMEASURED,
  never 0%.
- `aisafe attest` reads everything and judges nothing beyond the listed criteria. Only
  baseline entries that carry a reason count as accepted; an absent document fails the
  criteria that need it, not the run.
- The hooks read the baseline the skill wrote in phase 1, so a new finding on an edited
  file, or at Stop, is "new" against the same comparison point as document 2.

## Runtime and measurement

`GuardrailPipeline` runs guards in four stages (input, processing, output, policy) from a
YAML preset (`default.yaml`, `eu_high_risk.yaml`). A guard is a trade: `aisafe measure` runs
the attack corpus (55 cases, seven families), the adversarially benign corpus (48 cases)
and the output corpus (20 responses) through each guard in isolation and reports catch
rate, benign breakage, latency and tokens; a `Profile` is populated from that output and
never typed by hand. `GuardrailPipeline(thresholds=...)` demotes a guard whose MEASURED
profile fails the operator's bar; an unmeasured guard always runs.

## What is fixed, and what is data

- `attest-levels.yaml` (the criteria) and `prices.yaml` (the price table, dated) are data,
  shipped in the wheel and mirrored at `config/`; tests pin the pairs identical.
- The 54 audit rules carry `measured_precision: None`: UNMEASURED, never good, and an
  unmeasured rule still fires. `bench/` is where a number would come from.
- The skill's `references/controls.md` and `references/levels.md` are generated from the
  rule registry and the criteria file; the three skill mirrors are written by
  `scripts/sync_skill.py` and nothing else.

## Stance

Nothing here is a compliance verdict, and no renderer calls it one (`report.BANNED_PHRASES`
is checked against every template). Every finding is UNMEASURED until a labelled corpus
says otherwise. Absence of a finding is not evidence of safety. A level is a list of
criteria met on a date, signed by a named owner.
