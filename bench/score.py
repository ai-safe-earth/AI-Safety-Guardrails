"""
bench/score.py
--------------
Read the hand-labelled verdicts in bench/findings.csv and write
bench/precision.md.

This script measures. It never invents. If a single finding is unlabelled or
carries a verdict outside {tp, fp, unclear}, it refuses to produce a report and
exits non-zero -- a precision number computed over a partly-labelled sample is
worse than no number at all.

Precision is tp / (tp + fp). `unclear` rows are excluded from the denominator
and reported separately, so a rule whose sample is mostly unclear is visible as
a thin sample rather than hidden inside a confident-looking ratio.

Usage:
    python bench/score.py
    python bench/score.py --min-precision 0.80
    python bench/score.py --allow-partial     # score only the labelled subset
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

BENCH = Path(__file__).resolve().parent
CSV_PATH = BENCH / "findings.csv"
RESULTS = BENCH / "results"
OUT = BENCH / "precision.md"

VALID = {"tp", "fp", "unclear"}
DEFAULT_MIN_PRECISION = 0.80
WORST_N = 3


def die(msg: str) -> None:
    print(f"\nERROR: {msg}\n", file=sys.stderr)
    sys.exit(1)


def load_rows() -> list[dict]:
    if not CSV_PATH.is_file():
        die(f"{CSV_PATH} not found. Run `python bench/run.py` first.")
    with CSV_PATH.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        die(f"{CSV_PATH} has no findings. Nothing to score.")
    return rows


def validate(rows: list[dict], allow_partial: bool) -> list[dict]:
    """Refuse to score an incompletely or invalidly labelled sample."""
    blank, bad = [], []
    for i, row in enumerate(rows, start=2):  # +2: header is line 1
        v = (row.get("verdict") or "").strip().lower()
        if not v:
            blank.append((i, row))
        elif v not in VALID:
            bad.append((i, row, v))

    if bad:
        print(
            f"\nERROR: {len(bad)} row(s) have a verdict outside {{tp, fp, unclear}}:",
            file=sys.stderr,
        )
        for line, row, v in bad[:10]:
            print(
                f"  line {line}: {row['rule_id']} {row['repo']}/{row['file']}:{row['line']} -> {v!r}",
                file=sys.stderr,
            )
        if len(bad) > 10:
            print(f"  ... and {len(bad) - 10} more", file=sys.stderr)
        sys.exit(1)

    if blank and not allow_partial:
        total = len(rows)
        done = total - len(blank)
        print(
            f"\nERROR: {len(blank)} of {total} findings are unlabelled "
            f"({done}/{total} done, {100 * done / total:.1f}%).",
            file=sys.stderr,
        )
        print(
            "\nPrecision over a partly-labelled sample is not a measurement. Label every row, or",
            file=sys.stderr,
        )
        print(
            "re-run with --allow-partial to score only the labelled subset "
            "(the report will say so).",
            file=sys.stderr,
        )
        by_rule: dict[str, int] = defaultdict(int)
        for _, row in blank:
            by_rule[row["rule_id"]] += 1
        print("\nUnlabelled by rule:", file=sys.stderr)
        for rid, n in sorted(by_rule.items(), key=lambda kv: -kv[1]):
            print(f"  {rid:<16} {n}", file=sys.stderr)
        print(f"\nFirst unlabelled row: line {blank[0][0]} in {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    for row in rows:
        row["verdict"] = (row.get("verdict") or "").strip().lower()
    return [r for r in rows if r["verdict"] in VALID]


def load_snippets() -> dict[tuple, dict]:
    """
    Pull the source line and description out of the raw JSON reports so the
    report can quote a false positive verbatim rather than paraphrasing it.
    """
    out: dict[tuple, dict] = {}
    if not RESULTS.is_dir():
        return out
    for jf in sorted(RESULTS.glob("*.json")):
        repo = jf.stem
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for f in data.get("findings", []):
            fname = str(f.get("file", "")).replace("\\", "/")
            key = (repo, fname.rsplit("/", 1)[-1], str(f.get("line", "")), f.get("rule_id", ""))
            out[key] = {
                "snippet": f.get("snippet", ""),
                "description": f.get("description", ""),
                "severity": f.get("severity", ""),
                "article": f.get("article", ""),
                "title": f.get("title", ""),
            }
    return out


def enrich(row: dict, snippets: dict[tuple, dict]) -> dict:
    key = (row["repo"], row["file"].rsplit("/", 1)[-1], str(row["line"]), row["rule_id"])
    return snippets.get(key, {})


def rule_metadata() -> dict[str, dict]:
    """Severity/article straight from the rule registry, when importable."""
    meta: dict[str, dict] = {}
    sys.path.insert(0, str(BENCH.parent / "src"))
    try:
        from aisg.modules.policy.code_analyzer.rules import ALL_RULES
    except Exception:
        return meta
    for r in ALL_RULES:
        meta[r.rule_id] = {
            "severity": getattr(r.severity, "value", str(r.severity)),
            "article": r.article,
            "title": r.title,
            "declared_precision": getattr(r, "measured_precision", None),
        }
    return meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bench/score.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--min-precision",
        type=float,
        default=DEFAULT_MIN_PRECISION,
        help=f"Default-on threshold (default: {DEFAULT_MIN_PRECISION})",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="Score only the labelled subset instead of failing",
    )
    args = p.parse_args(argv)

    raw = load_rows()
    rows = validate(raw, args.allow_partial)
    partial = len(rows) != len(raw)
    snippets = load_snippets()
    meta = rule_metadata()

    by_rule: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_rule[row["rule_id"]].append(row)

    stats = {}
    for rid, rrows in by_rule.items():
        tp = sum(1 for r in rrows if r["verdict"] == "tp")
        fp = sum(1 for r in rrows if r["verdict"] == "fp")
        unclear = sum(1 for r in rrows if r["verdict"] == "unclear")
        judged = tp + fp
        stats[rid] = {
            "tp": tp,
            "fp": fp,
            "unclear": unclear,
            "judged": judged,
            "total": len(rrows),
            "precision": (tp / judged) if judged else None,
            "repos": len({r["repo"] for r in rrows}),
        }

    # "Worst" = from the least precise rule first; then the rule contributing the
    # most false positives; then deterministic by location.
    def fp_sort_key(row: dict):
        s = stats[row["rule_id"]]
        prec = s["precision"] if s["precision"] is not None else 1.0
        sev = (
            meta.get(row["rule_id"], {}).get("severity")
            or enrich(row, snippets).get("severity")
            or "warning"
        )
        return (
            prec,
            0 if sev == "error" else 1,
            -s["fp"],
            row["repo"],
            row["file"],
            int(row["line"] or 0),
        )

    worst = sorted((r for r in rows if r["verdict"] == "fp"), key=fp_sort_key)[:WORST_N]

    ordered = sorted(
        stats.items(),
        key=lambda kv: (kv[1]["precision"] if kv[1]["precision"] is not None else 2.0, kv[0]),
    )

    L: list[str] = []
    L.append("# euaiact-lint rule precision")
    L.append("")
    L.append(
        f"Measured over `bench/findings.csv` -- {len(rows)} hand-labelled findings "
        f"from {len({r['repo'] for r in rows})} repositories, "
        f"{len(by_rule)} rules fired."
    )
    L.append("")
    if partial:
        L.append(
            f"> **Partial sample.** {len(raw) - len(rows)} of {len(raw)} findings were "
            f"unlabelled and are excluded. These numbers describe the labelled subset only."
        )
        L.append("")
    L.append(
        "`precision = tp / (tp + fp)`. `unclear` rows are excluded from the denominator "
        "and counted separately, so a rule resting on a thin sample is visible rather than "
        "hidden behind a confident ratio."
    )
    L.append("")
    L.append(
        f"Default-on threshold: **{args.min_precision:.2f}**. "
        "Rules below it should be gated behind `aisg lint --experimental`."
    )
    L.append("")
    L.append("## Per-rule precision")
    L.append("")
    L.append(
        "| Rule | Severity | Precision | tp | fp | unclear | n (judged/total) | Repos | Default-on |"
    )
    L.append("|---|---|---:|---:|---:|---:|---:|---:|---|")
    for rid, s in ordered:
        m = meta.get(rid, {})
        sev = m.get("severity", "?")
        prec = "n/a" if s["precision"] is None else f"{s['precision']:.3f}"
        if s["precision"] is None:
            gate = "no judgeable sample"
        elif s["precision"] >= args.min_precision:
            gate = "yes"
        else:
            gate = "**NO -- experimental**"
        L.append(
            f"| `{rid}` | {sev} | {prec} | {s['tp']} | {s['fp']} | {s['unclear']} "
            f"| {s['judged']}/{s['total']} | {s['repos']} | {gate} |"
        )
    L.append("")

    below = [
        (rid, s)
        for rid, s in ordered
        if s["precision"] is not None and s["precision"] < args.min_precision
    ]
    nosample = [rid for rid, s in ordered if s["precision"] is None]

    L.append("## Rules below threshold")
    L.append("")
    if below:
        L.append(
            f"{len(below)} rule(s) measured below {args.min_precision:.2f}. "
            "Set `measured_precision` on each and they stop firing by default:"
        )
        L.append("")
        L.append("```python")
        for rid, s in below:
            L.append(f"# {rid}: {s['tp']}/{s['judged']} judged findings were true positives")
            L.append(f"measured_precision = {s['precision']:.3f}")
        L.append("```")
    else:
        L.append(f"None. Every rule with a judgeable sample met {args.min_precision:.2f}.")
    L.append("")
    if nosample:
        L.append(
            f"{len(nosample)} rule(s) produced findings but no tp/fp judgement "
            f"(all `unclear`): {', '.join('`' + r + '`' for r in nosample)}. "
            "Precision is unmeasured for these -- leave `measured_precision = None`."
        )
        L.append("")

    fired = set(by_rule)
    silent = sorted(set(meta) - fired)
    if silent:
        L.append("## Rules that never fired")
        L.append("")
        L.append(
            f"{len(silent)} rule(s) produced no findings anywhere in the corpus, so their "
            "precision is unmeasured -- not perfect. Leave `measured_precision = None`:"
        )
        L.append("")
        L.append(", ".join(f"`{r}`" for r in silent))
        L.append("")

    L.append(f"## {WORST_N} worst false positives")
    L.append("")
    if not worst:
        L.append("No findings were labelled `fp`.")
    else:
        L.append(
            "Ordered by the firing rule's precision (lowest first), then severity, then "
            "how many false positives that rule contributed. Quoted verbatim from the "
            "scanned source."
        )
        L.append("")
        for i, row in enumerate(worst, 1):
            info = enrich(row, snippets)
            m = meta.get(row["rule_id"], {})
            s = stats[row["rule_id"]]
            prec = "n/a" if s["precision"] is None else f"{s['precision']:.3f}"
            L.append(f"### {i}. `{row['rule_id']}` -- {row['message']}")
            L.append("")
            L.append(f"- **Location:** `{row['repo']}` -> `{row['file']}:{row['line']}`")
            L.append(f"- **Article:** {m.get('article') or info.get('article') or '?'}")
            L.append(f"- **Severity:** {m.get('severity') or info.get('severity') or '?'}")
            L.append(f"- **Rule precision:** {prec} ({s['fp']} fp / {s['judged']} judged)")
            L.append("")
            snippet = (info.get("snippet") or "").rstrip()
            if snippet:
                L.append("```python")
                L.append(snippet)
                L.append("```")
            else:
                L.append("> No snippet recorded in `bench/results/` for this finding.")
            L.append("")
            if info.get("description"):
                L.append(f"> **Rule says:** {info['description']}")
                L.append("")

    L.append("---")
    L.append("")
    L.append(
        "Regenerate with `python bench/score.py` after editing "
        "`bench/findings.csv`. Every number above is derived from that file; "
        "none is hand-written."
    )
    L.append("")

    OUT.write_text("\n".join(L), encoding="utf-8")

    print(f"Scored {len(rows)} labelled findings across {len(by_rule)} rules -> {OUT}")
    if below:
        print(
            f"\n{len(below)} rule(s) below {args.min_precision:.2f} "
            f"-- should be --experimental only:"
        )
        for rid, s in below:
            print(f"  {rid:<16} precision={s['precision']:.3f}  (tp={s['tp']} fp={s['fp']})")
    if nosample:
        print(f"\n{len(nosample)} rule(s) had no judgeable sample (all unclear).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
