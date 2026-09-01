"""
bench/run.py
------------
Clone every repo in corpus.yaml at its pinned SHA, run `aisg lint` over it, and
collect the findings.

Outputs:
    bench/results/<name>.sarif   raw SARIF per repo
    bench/results/<name>.json    raw JSON per repo (carries the summary block)
    bench/findings.csv           one row per finding, `verdict` left EMPTY

The verdict column is deliberately blank. It is filled in by hand -- tp / fp /
unclear -- and bench/score.py refuses to run until it is complete. Nothing in
this harness infers, guesses or defaults a verdict.

Usage:
    python bench/run.py                    # full corpus
    python bench/run.py --only langchain crewAI
    python bench/run.py --keep-clones      # leave checkouts in bench/.cache
    python bench/run.py --experimental     # include sub-threshold rules
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
CORPUS = BENCH / "corpus.yaml"
RESULTS = BENCH / "results"
CACHE = BENCH / ".cache"
CSV_PATH = BENCH / "findings.csv"
CSV_ALL_PATH = BENCH / "findings-all.csv"

# Findings kept per rule for hand-labelling. The full corpus produces
# ~25k findings, which nobody labels; precision needs roughly 30-50 judged
# findings per rule, not thousands. 0 disables sampling.
DEFAULT_SAMPLE_PER_RULE = 40

CSV_COLUMNS = ["repo", "file", "line", "rule_id", "message", "verdict"]


def load_corpus() -> list[dict]:
    try:
        import yaml
    except ModuleNotFoundError:
        sys.exit("pyyaml is required: pip install pyyaml")
    data = yaml.safe_load(CORPUS.read_text(encoding="utf-8"))
    repos = data.get("repos") or []
    if not repos:
        sys.exit(f"No repos listed in {CORPUS}")
    for r in repos:
        missing = {"name", "url", "sha"} - set(r)
        if missing:
            sys.exit(f"corpus entry {r.get('name', '?')} missing keys: {sorted(missing)}")
        if len(str(r["sha"])) != 40:
            sys.exit(f"corpus entry {r['name']}: sha is not a full 40-char commit id")
    return repos


def fetch(repo: dict) -> Path:
    """
    Shallow-fetch exactly the pinned commit. `clone --depth 1` only reaches
    branch tips, so this inits an empty repo and fetches the SHA directly --
    that pins the scan to the corpus commit even after upstream moves on.
    """
    dest = CACHE / repo["name"]
    stamp = dest / ".aisg-bench-sha"
    if stamp.is_file() and stamp.read_text(encoding="utf-8").strip() == repo["sha"]:
        print(f"    cached at {repo['sha'][:12]}")
        return dest
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)

    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        # core.longpaths: several corpus repos have paths over the Windows
        # 260-char limit (deeply nested Next.js route directories, for one),
        # and checkout fails outright without it. No-op elsewhere.
        return subprocess.run(
            ["git", "-c", "core.longpaths=true", "-C", str(dest), *args],
            capture_output=True,
            text=True,
            check=check,
            timeout=1800,
        )

    git("init", "-q")
    git("remote", "add", "origin", repo["url"])
    try:
        git("fetch", "--depth", "1", "--quiet", "origin", repo["sha"])
    except subprocess.CalledProcessError as exc:
        # Some servers refuse fetch-by-sha; fall back to the recorded branch.
        detail = (exc.stderr or "").strip()[:120]
        print(f"    fetch-by-sha refused, falling back to branch: {detail}")
        git("fetch", "--depth", "50", "--quiet", "origin", repo.get("branch", "HEAD"))
    git("checkout", "-q", repo["sha"])
    stamp.write_text(repo["sha"], encoding="utf-8")
    return dest


def lint(path: Path, out_stem: Path, experimental: bool) -> tuple[int, dict | None]:
    """Run `aisg lint` twice: once for SARIF, once for JSON (JSON has the summary)."""
    base = [sys.executable, "-m", "aisg.cli", "lint", str(path.resolve())]
    if experimental:
        base.append("--experimental")

    # Run with the CLONE as cwd, not this repo. apply_tool_config() walks up
    # from cwd for a pyproject.toml, and scanning third-party code under this
    # project's [tool.euaiact-lint] defaults would make results depend on where
    # the harness happens to live. PYTHONPATH keeps aisg importable without
    # requiring an install.
    env = dict(os.environ)
    src = str(ROOT / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

    codes = []
    for fmt, suffix in (("sarif", ".sarif"), ("json", ".json")):
        proc = subprocess.run(
            base + ["--format", fmt, "--output", str(out_stem.with_suffix(suffix).resolve())],
            capture_output=True,
            text=True,
            cwd=str(path),
            env=env,
            timeout=3600,
        )
        codes.append(proc.returncode)
        if proc.returncode == 2:
            print(f"    !! lint fatal ({fmt}): {proc.stderr.strip()[:300]}")

    summary = None
    jf = out_stem.with_suffix(".json")
    if jf.is_file():
        try:
            summary = json.loads(jf.read_text(encoding="utf-8")).get("summary")
        except json.JSONDecodeError as exc:
            print(f"    !! unreadable JSON report: {exc}")
    return max(codes), summary


def rows_from_json(name: str, jf: Path) -> list[dict]:
    """
    One row per finding. `verdict` stays empty by design.

    Paths are made repo-relative by stripping the cache prefix as a string, not
    via Path.relative_to -- the checkout is deleted after each scan, and rows
    must still be readable for a repo that is no longer on disk.
    """
    if not jf.is_file():
        return []
    try:
        data = json.loads(jf.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    prefix = str((CACHE / name).resolve()).replace("\\", "/").rstrip("/") + "/"
    rows = []
    for f in data.get("findings", []):
        rel = str(f.get("file", "")).replace("\\", "/")
        if rel.lower().startswith(prefix.lower()):
            rel = rel[len(prefix) :]
        rows.append(
            {
                "repo": name,
                "file": rel,
                "line": f.get("line", ""),
                "rule_id": f.get("rule_id", ""),
                # The title is the reviewable claim; description is boilerplate.
                "message": f.get("title", ""),
                "verdict": "",
            }
        )
    return rows


def sample_per_rule(rows: list[dict], per_rule: int) -> list[dict]:
    """
    Keep at most `per_rule` findings for each rule, spread across repos.

    Round-robin over repos rather than taking the first N, so a rule is not
    measured entirely against whichever repo happens to sort first -- one
    codebase's idiosyncrasies would masquerade as the rule's precision.

    Deterministic: the same findings.csv yields the same sample every run, so
    labelling work is never invalidated by a re-run.
    """
    if per_rule <= 0:
        return rows

    by_rule: dict[str, dict[str, list[dict]]] = {}
    for row in rows:
        by_rule.setdefault(row["rule_id"], {}).setdefault(row["repo"], []).append(row)

    kept: list[dict] = []
    for rule in sorted(by_rule):
        per_repo = by_rule[rule]
        for repo in per_repo:
            per_repo[repo].sort(key=lambda r: (r["file"], int(r["line"] or 0)))
        repos = sorted(per_repo)
        taken, idx = 0, 0
        while taken < per_rule and any(per_repo[r] for r in repos):
            repo = repos[idx % len(repos)]
            if per_repo[repo]:
                kept.append(per_repo[repo].pop(0))
                taken += 1
            idx += 1
    return kept


def merge_preserving_verdicts(new_rows: list[dict]) -> list[dict]:
    """
    Re-running the harness must never destroy labelling work already done.
    Verdicts are carried over by (repo, file, line, rule_id).
    """
    if not CSV_PATH.is_file():
        return new_rows
    existing: dict[tuple, str] = {}
    with CSV_PATH.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key = (row.get("repo"), row.get("file"), str(row.get("line")), row.get("rule_id"))
            if (row.get("verdict") or "").strip():
                existing[key] = row["verdict"].strip()
    carried = 0
    for row in new_rows:
        key = (row["repo"], row["file"], str(row["line"]), row["rule_id"])
        if key in existing:
            row["verdict"] = existing[key]
            carried += 1
    if carried:
        print(f"\nCarried over {carried} existing verdict(s) from the previous findings.csv")
    return new_rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="bench/run.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--only", nargs="*", default=None, help="Limit to these corpus names")
    p.add_argument("--keep-clones", action="store_true", help="Leave checkouts in bench/.cache")
    p.add_argument("--experimental", action="store_true", help="Include sub-threshold rules")
    p.add_argument(
        "--sample-per-rule",
        type=int,
        default=DEFAULT_SAMPLE_PER_RULE,
        metavar="N",
        help=(
            f"Findings kept per rule in findings.csv, spread across repos "
            f"(default: {DEFAULT_SAMPLE_PER_RULE}; 0 = keep everything). "
            "The complete set is always written to findings-all.csv."
        ),
    )
    args = p.parse_args(argv)

    repos = load_corpus()
    if args.only:
        wanted = {n.lower() for n in args.only}
        repos = [r for r in repos if r["name"].lower() in wanted]
        if not repos:
            available = ", ".join(r["name"] for r in load_corpus())
            sys.exit(f"--only matched nothing. Available: {available}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict] = []
    failures: list[str] = []
    started = time.time()

    for i, repo in enumerate(repos, 1):
        name = repo["name"]
        print(f"[{i}/{len(repos)}] {repo['repo']} @ {repo['sha'][:12]}")
        t0 = time.time()
        try:
            clone = fetch(repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            print(f"    !! clone failed: {str(detail).strip()[:300]}")
            failures.append(f"{name}: clone failed")
            continue

        stem = RESULTS / name
        try:
            code, summary = lint(clone, stem, args.experimental)
        except subprocess.TimeoutExpired:
            print("    !! lint timed out after 3600s")
            failures.append(f"{name}: lint timeout")
            continue

        rows = rows_from_json(name, stem.with_suffix(".json"))
        if summary:
            print(
                f"    {summary.get('scanned_files', '?')} files, "
                f"{len(rows)} findings "
                f"({summary.get('error_count', 0)}E/{summary.get('warning_count', 0)}W) "
                f"exit={code} in {time.time() - t0:.1f}s"
            )
        else:
            print(f"    no summary produced (exit={code})")
            failures.append(f"{name}: no summary")

        if not args.keep_clones:
            shutil.rmtree(clone, ignore_errors=True)

    # Rebuild from every report in results/, not just the repos scanned now.
    # Otherwise `--only <repo>` would silently drop every other repo's rows.
    all_rows = []
    for jf in sorted(RESULTS.glob("*.json")):
        all_rows.extend(rows_from_json(jf.stem, jf))

    all_rows = merge_preserving_verdicts(all_rows)
    order = lambda r: (r["rule_id"], r["repo"], r["file"], int(r["line"] or 0))  # noqa: E731
    all_rows.sort(key=order)

    def write(path: Path, rows: list[dict]) -> None:
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
            w.writeheader()
            w.writerows(rows)

    # The complete set is always kept, so sampling never loses evidence.
    write(CSV_ALL_PATH, all_rows)

    sampled = sample_per_rule(all_rows, args.sample_per_rule)
    sampled.sort(key=order)
    write(CSV_PATH, sampled)

    unlabelled = sum(1 for r in sampled if not r["verdict"])
    distinct = len({r["rule_id"] for r in sampled})
    print("\n" + "=" * 70)
    print(
        f"{len(all_rows)} findings across {len(repos) - len(failures)} repos "
        f"in {time.time() - started:.0f}s"
    )
    print(f"{distinct} distinct rules fired")
    print(f"\nfull set  -> {CSV_ALL_PATH}  ({len(all_rows)} rows)")
    if args.sample_per_rule > 0:
        print(
            f"to label  -> {CSV_PATH}  ({len(sampled)} rows, "
            f"<={args.sample_per_rule} per rule spread across repos)"
        )
        print("            --sample-per-rule 0 keeps everything")
    else:
        print(f"to label  -> {CSV_PATH}  ({len(sampled)} rows, sampling disabled)")
    if failures:
        print(f"\n{len(failures)} repo(s) did not complete:")
        for f in failures:
            print(f"  - {f}")
    print(f"\nNEXT: label the `verdict` column ({unlabelled} blank) with tp / fp / unclear,")
    print("      then run:  python bench/score.py")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
