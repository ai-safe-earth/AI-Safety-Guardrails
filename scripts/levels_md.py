"""scripts/levels_md.py
--------------------
Generate the skill's `references/levels.md` from the packaged `attest-levels.yaml`.

The skill reads the attestation levels aloud in phase 7, so the document must say exactly
what `aisafe attest` checks. Rather than copy the criteria by hand, this tool renders the
whole file from `aisafe.devtools.attest.load_levels()` (the same loader the command uses) and
`attest.CRITERION_READS` (what each criterion kind reads). The prose around the tables is
fixed here; the tables are data.

    python scripts/levels_md.py          # rewrite the canonical levels.md
    python scripts/levels_md.py --check  # exit 1 when the file differs, write nothing

Run from the repo root, then `python scripts/sync_skill.py` so the mirrors follow.
Not shipped.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LEVELS_MD = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "references" / "levels.md"

_HEAD = """# The attestation levels

Generated from the packaged `attest-levels.yaml` by `scripts/levels_md.py`; do not edit by
hand (`python scripts/levels_md.py --check` fails on drift). Read this in phase 7, before
running `aisafe attest`.

A level is a list of criteria met on a date, signed by the named owner. It is not a
verdict, a grade or a statement about any regulation: the tool checked the listed
criteria and nothing else, and `attestation.json` says so in its disclaimer. The level
reached is the highest N such that every criterion of levels 0..N is met. One unmet
criterion at level 1 caps the result at level 0 whatever level 3 says; when a level-0
criterion is unmet, no level is reached and the statement says so.

Every criterion row in `attestation.json` (`level.criteria[]`) carries `id`, `level`,
`met`, `evidence` (what was read) and `missing` (what would have to change). Read the
`missing` text aloud for every unmet row; it is the whole explanation.

The criteria are evaluated against the documents under `.aisafe-audit/` (the audit report,
the baseline, the measure, probe and decision reports) and `ai-system-card.yaml`. A
document that is absent is recorded as absent and fails the criteria that need it; it
never fails the run. A document of the wrong kind, or one that cannot be parsed, is fatal
(exit 2), because ignoring it silently would read as "met".
"""

_RULES = """## Rules that hold

- **A bare fingerprint is a suppression, not an acceptance.** Only baseline entries that
  carry a reason count as accepted. A finding whose fingerprint the baseline holds without
  a reason stays open for `no_open_findings_at_or_above` and `rules_closed`, and
  `accepted_reasons_present` names how many fingerprints have no reason. The only way to
  record a reason is `aisafe audit --amend-baseline <baseline> --accept <fingerprint>="<reason>"`.
- **Freshness is relative to the run.** `max_age_days` is read against the clock of the
  `aisafe attest` run; `report_names_head` compares the report's `target.git_sha` with HEAD,
  so a report from another commit fails level 0 until the audit is re-run.
- **The dirty-tree rule.** `tree_clean` (level {tree_level}) fails when `git status
  --porcelain` lists anything, and no other criterion reads the working tree, so uncommitted
  changes cap the result at level {tree_cap} and never lower.
- **The owner signs.** `--owner "<Name <role>>"` is required to write an attestation and is
  never a `pyproject.toml` default; `accepted_risks_owned` is met only when every accepted
  risk is written next to that owner. `--check` runs unsigned and writes nothing;
  `--check --require-level N` exits 1 when level N is not reached (the CI line).
- **Review.** `next_review_by` is `generated_at` plus {interval} days.
- **Your own criteria.** `--level-criteria PATH` evaluates another file of the same shape;
  it is validated against the rule registry (every id in `rules:` must exist) and the
  default system card (every `fields:` path must exist) before anything is read.
"""


def _params(params: dict) -> str:
    if not params:
        return "-"
    parts = []
    for key, value in params.items():
        if isinstance(value, (list, tuple)):
            rendered = ", ".join(str(v) for v in value)
        else:
            rendered = str(value)
        parts.append(f"{key}: {rendered}")
    return "; ".join(parts)


def render(levels, reads: dict[str, str]) -> str:
    """The whole levels.md for `levels` (an `attest.Levels`)."""
    out = [_HEAD]
    for level in levels.levels:
        out.append(f"## Level {level.level}: {level.name}\n")
        out.append("| id | kind | parameters | reads |")
        out.append("|---|---|---|---|")
        for criterion in level.criteria:
            out.append(
                f"| `{criterion.id}` | `{criterion.kind}` | {_params(criterion.params)} | "
                f"{reads[criterion.kind]} |"
            )
        out.append("")
    tree = next((c for c in levels.criteria() if c.kind == "tree_clean"), None)
    tree_level = tree.level if tree is not None else "-"
    tree_cap = max(tree.level - 1, 0) if tree is not None else "-"
    out.append(
        _RULES.format(
            tree_level=tree_level, tree_cap=tree_cap, interval=levels.review_interval_days
        )
    )
    text = "\n".join(out)
    return text.rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="levels_md.py",
        description="Generate the skill's references/levels.md from attest-levels.yaml.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when the file differs from the generated text; write nothing.",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=LEVELS_MD,
        help="The levels.md to write or check (default: the canonical skill copy).",
    )
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO / "src"))
    from aisafe.devtools.attest import CRITERION_READS, load_levels

    levels = load_levels()
    generated = render(levels, CRITERION_READS)
    target: Path = args.path
    current = target.read_text(encoding="ascii") if target.is_file() else None
    if args.check:
        if current == generated:
            print(f"in sync: {len(levels.criteria())} criteria in {len(levels.levels)} levels")
            return 0
        what = "missing" if current is None else "differs"
        print(f"{target.relative_to(REPO) if target.is_relative_to(REPO) else target}: {what}")
        print("run `python scripts/levels_md.py` to regenerate", file=sys.stderr)
        return 1
    if current != generated:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(generated.encode("ascii"))  # bytes: keep LF on Windows
        print(f"levels.md: rewritten from {len(levels.criteria())} criteria")
    else:
        print("levels.md: unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
