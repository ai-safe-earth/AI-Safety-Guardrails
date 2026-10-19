# The attestation levels

Generated from the packaged `attest-levels.yaml` by `scripts/levels_md.py`; do not edit by
hand (`python scripts/levels_md.py --check` fails on drift). Read this in phase 7, before
running `aisg attest`.

A level is a list of criteria met on a date, signed by the named owner. It is not a
verdict, a grade or a statement about any regulation: the tool checked the listed
criteria and nothing else, and `attestation.json` says so in its disclaimer. The level
reached is the highest N such that every criterion of levels 0..N is met. One unmet
criterion at level 1 caps the result at level 0 whatever level 3 says; when a level-0
criterion is unmet, no level is reached and the statement says so.

Every criterion row in `attestation.json` (`level.criteria[]`) carries `id`, `level`,
`met`, `evidence` (what was read) and `missing` (what would have to change). Read the
`missing` text aloud for every unmet row; it is the whole explanation.

The criteria are evaluated against the documents under `.aisg-audit/` (the audit report,
the baseline, the measure, probe and decision reports) and `ai-system-card.yaml`. A
document that is absent is recorded as absent and fails the criteria that need it; it
never fails the run. A document of the wrong kind, or one that cannot be parsed, is fatal
(exit 2), because ignoring it silently would read as "met".

## Level 0: audited

| id | kind | parameters | reads |
|---|---|---|---|
| `L0.report` | `report_present` | max_age_days: 30 | audit report: `generated_at` |
| `L0.commit` | `report_names_head` | - | audit report: `target.git_sha`; git HEAD |
| `L0.unknown` | `unknown_listed` | - | audit report: `unknown` |

## Level 1: triaged

| id | kind | parameters | reads |
|---|---|---|---|
| `L1.no_open_high` | `no_open_findings_at_or_above` | severity: high | audit report: `findings[].severity`, `fingerprint`; baseline: `accepted` |
| `L1.scanners` | `external_tools_attempted` | - | audit report: `external_tools[].status` |
| `L1.reasons` | `accepted_reasons_present` | - | baseline: `fingerprints`, `accepted` |

## Level 2: measured

| id | kind | parameters | reads |
|---|---|---|---|
| `L2.measure` | `document_present` | document: measure; max_age_days: 30 | the named document: `generated_at` |
| `L2.thresholds` | `measure_thresholds` | - | measure report: `guards[].threshold_failures`, `guards[].unavailable` |
| `L2.probe` | `probe_passing_if_present` | - | probe report: `summary.failed`, `summary.errors` |
| `L2.decision` | `document_present` | document: decision; max_age_days: 30 | the named document: `generated_at` |
| `L2.evals_ci` | `rules_closed` | rules: AUD-901, AUD-903 | audit report: `findings[].id`; baseline: `accepted` |

## Level 3: governed

| id | kind | parameters | reads |
|---|---|---|---|
| `L3.card` | `card_fields_set` | fields: system.purpose, affected_persons, incident_contact, risk_tier, deployment | ai-system-card.yaml: the listed fields |
| `L3.prompt_audit` | `card_section_fresh` | section: prompt_audit; fields: reviewed_at, reviewer; date_field: reviewed_at; max_age_days: 180 | ai-system-card.yaml: the section's fields and its `date_field` |
| `L3.controls` | `rules_closed` | rules: AUD-107, AUD-701, AUD-702, AUD-703, AUD-1107 | audit report: `findings[].id`; baseline: `accepted` |
| `L3.owner` | `accepted_risks_owned` | - | baseline: `accepted`; `--owner` |
| `L3.tree` | `tree_clean` | - | git: `status --porcelain` |

## Rules that hold

- **A bare fingerprint is a suppression, not an acceptance.** Only baseline entries that
  carry a reason count as accepted. A finding whose fingerprint the baseline holds without
  a reason stays open for `no_open_findings_at_or_above` and `rules_closed`, and
  `accepted_reasons_present` names how many fingerprints have no reason. The only way to
  record a reason is `aisg audit --amend-baseline <baseline> --accept <fingerprint>="<reason>"`.
- **Freshness is relative to the run.** `max_age_days` is read against the clock of the
  `aisg attest` run; `report_names_head` compares the report's `target.git_sha` with HEAD,
  so a report from another commit fails level 0 until the audit is re-run.
- **The dirty-tree rule.** `tree_clean` (level 3) fails when `git status
  --porcelain` lists anything, and no other criterion reads the working tree, so uncommitted
  changes cap the result at level 2 and never lower.
- **The owner signs.** `--owner "<Name <role>>"` is required to write an attestation and is
  never a `pyproject.toml` default; `accepted_risks_owned` is met only when every accepted
  risk is written next to that owner. `--check` runs unsigned and writes nothing;
  `--check --require-level N` exits 1 when level N is not reached (the CI line).
- **Review.** `next_review_by` is `generated_at` plus 90 days.
- **Your own criteria.** `--level-criteria PATH` evaluates another file of the same shape;
  it is validated against the rule registry (every id in `rules:` must exist) and the
  default system card (every `fields:` path must exist) before anything is read.
