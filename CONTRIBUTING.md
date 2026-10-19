# Contributing

Thank you for looking. This page is the short version; `CLAUDE.md` is the long one (it is
written for coding agents, and everything in it holds for people too), and
`docs/SYSTEM.md` is the system on one page.

## Setup

```bash
git clone https://github.com/ai-safe-earth/AnyAISafe.git
cd AnyAISafe
python -m venv .venv && . .venv/bin/activate      # .venv\Scripts\activate on Windows
pip install -e ".[devtools,dev]"
pytest -q                                          # no API keys, no network
```

The distribution is `anyaisafe`; the import name and the console script are `aisg`. On
Windows set `PYTHONIOENCODING=utf-8` before running the examples or the CLIs.

## The gate

Run from the repository root; everything green before a commit:

```bash
pytest -q
ruff check . && ruff format --check .
aisg lint src examples --errors-only
aisg misalign src
aisg audit . --no-external --fail-on high --baseline audit-baseline.json   # must exit 0
aisg measure --max-p99-ms 25
python scripts/controls_md.py --check
python scripts/levels_md.py --check
python scripts/sync_skill.py --check
python scripts/bump_version.py --check
```

A non-zero self-audit means a new finding at `high` or above that is not in
`audit-baseline.json`: fix it, or accept it with a reason that describes the evidence
without quoting the literal (`aisg audit --amend-baseline audit-baseline.json --accept
<fingerprint>="<reason>"`). A fingerprint without a reason is a suppression, not an
acceptance.

## Conventions

- `ruff format` is the formatter (line length 100, Python 3.10 target); `ruff check`
  selects `E, F, W, I`. Every module starts with `from __future__ import annotations`
  and a `"""path/to/module.py\n---------\n"""` header. PEP 604 unions, double quotes.
- Every JSON document the tools write starts with `"schema": "aisg/1"` and carries a
  `kind` (`audit`, `audit-baseline`, `inventory`, `prices`, `decision`, `attestation`,
  `attest-levels`, `hook-state`). SARIF is the one exception; its marker is in the run's
  property bag.
- Nothing under `aisg.devtools` calls a model, installs anything or opens a socket; the
  tests wrap `socket.socket` to prove it. External scanners run only if already on PATH.
- Never a verdict. `report.BANNED_PHRASES` lists the phrases no renderer may emit and a
  self-check runs against every template; do not spell them out in prose, point at the
  constant. `measured_precision` is `None` on every rule and renders `[UNMEASURED]`;
  never type a number in.
- Generated files are regenerated, not edited: `references/controls.md` (severity,
  mapping and leaves-open text, `scripts/controls_md.py`), `references/levels.md` (the
  whole file, `scripts/levels_md.py`), and the three skill mirrors (`.claude/skills/`,
  `.agents/skills/`, `plugins/ai-safety-audit/skills/`, `scripts/sync_skill.py`).
- `# aisg-audit: ignore-file` sits only on the files that are the audit's vocabulary; a
  real finding anywhere else goes in the baseline with a reason. The same holds for the
  `euaiact-lint` and `misalignment-check` markers.
- YAML presets and data files exist twice on purpose (`src/aisg/config/` ships in the
  wheel, `config/` is the local-dev copy); edit both, a test pins them identical.

## Adding things

- **A guard**: `.claude/skills/add-guard/SKILL.md` is the checklist (subclass, register,
  all four presets, export, probe cases with `seed_pattern`, the audit's name tables, an
  AUD-801 acceptance in the baseline, `CLASS_SYMBOLS` and an `apply/python.md` heading when
  a rule names it).
- **An audit rule**: a class under `src/aisg/devtools/audit/rules/`, a row in
  `SUBSYSTEM_OF_RULE`, a `recommendation.package` with `leaves_open` text whenever the
  mechanism is not `none`, a hand-written section in `references/controls.md` followed by
  `python scripts/controls_md.py`, a positive and a negative fixture under
  `tests/fixtures/audit/`, and `measured_precision = None`.
- **An attestation criterion kind**: the name in `attest.CRITERION_KINDS`, an evaluator in
  `_EVALUATORS`, a line in `attest.CRITERION_READS`, its use in both copies of
  `attest-levels.yaml`, then `python scripts/levels_md.py` and `python scripts/sync_skill.py`.
- **A price**: both copies of `prices.yaml`, with the date and the source URL. An
  unverifiable figure stays out; the model then renders `unavailable` and names itself.
- **A probe or benign case**: the family's YAML under `src/aisg/probes/`, with its
  `seed_pattern`; a benign case that a naive guard would flag is worth more than one that
  nothing would.

## Releases

A release is the maintainer's act. `python scripts/bump_version.py X.Y.Z` rewrites every
version site and runs the sync; a `vX.Y.Z` tag pushed to `origin` runs the release
workflow, which publishes to PyPI through trusted publishing behind a GitHub environment
with a required reviewer. No token exists anywhere.

## Reporting

Vulnerabilities: `SECURITY.md`. A guard that misses an attack is a detection gap, not a
vulnerability: open an issue with the payload, or add a case to the probe corpus.
