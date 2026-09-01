"""
tests/unit/test_bench_sampling.py
---------------------------------
Tests for bench/run.py's stratified sampling.

The full corpus produces ~25k findings, which nobody hand-labels. Sampling makes
the benchmark usable, but only if it holds three properties:

  1. Deterministic -- a re-run must not invalidate labelling already done.
  2. Nested -- a smaller cap must be a subset of a larger one, so changing the
     cap never orphans a row someone already labelled.
  3. Spread across repos -- otherwise a rule's "precision" is really one
     codebase's idiosyncrasies.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parent.parent.parent / "bench"


def _load_run_module():
    """bench/ is a script directory, not a package."""
    spec = importlib.util.spec_from_file_location("bench_run", BENCH / "run.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["bench_run"] = module
    spec.loader.exec_module(module)
    return module


run = _load_run_module()


def make_rows(spec: dict[str, dict[str, int]]) -> list[dict]:
    """spec: {rule_id: {repo: how_many}}"""
    rows = []
    for rule, repos in spec.items():
        for repo, n in repos.items():
            for i in range(n):
                rows.append(
                    {
                        "repo": repo,
                        "file": f"src/mod{i // 10}.py",
                        "line": str(i),
                        "rule_id": rule,
                        "message": "x",
                        "verdict": "",
                    }
                )
    return rows


def key(row: dict) -> tuple:
    return (row["repo"], row["file"], row["line"], row["rule_id"])


class TestSamplePerRule:
    def test_zero_disables_sampling(self):
        rows = make_rows({"R1": {"a": 50}})
        assert len(run.sample_per_rule(rows, 0)) == 50

    def test_negative_disables_sampling(self):
        rows = make_rows({"R1": {"a": 50}})
        assert len(run.sample_per_rule(rows, -1)) == 50

    def test_caps_each_rule_independently(self):
        rows = make_rows({"R1": {"a": 100}, "R2": {"a": 5}})
        out = run.sample_per_rule(rows, 10)
        counts = {r: sum(1 for x in out if x["rule_id"] == r) for r in ("R1", "R2")}
        assert counts == {"R1": 10, "R2": 5}, "a thin rule must keep everything it has"

    def test_deterministic(self):
        rows = make_rows({"R1": {"a": 60, "b": 40, "c": 20}})
        first = [key(r) for r in run.sample_per_rule(list(rows), 30)]
        for _ in range(4):
            assert [key(r) for r in run.sample_per_rule(list(rows), 30)] == first

    def test_smaller_cap_is_a_subset_of_larger(self):
        """Tightening the cap must not orphan an already-labelled row."""
        rows = make_rows({"R1": {"a": 60, "b": 40}, "R2": {"a": 30}})
        small = {key(r) for r in run.sample_per_rule(list(rows), 10)}
        large = {key(r) for r in run.sample_per_rule(list(rows), 25)}
        assert small <= large

    def test_spreads_across_repos(self):
        """
        Taking the first N would draw every finding from whichever repo sorts
        first, and call one codebase's quirks the rule's precision.
        """
        rows = make_rows({"R1": {"aaa": 100, "bbb": 100, "ccc": 100}})
        out = run.sample_per_rule(rows, 30)
        per_repo = {r: sum(1 for x in out if x["repo"] == r) for r in ("aaa", "bbb", "ccc")}
        assert per_repo == {"aaa": 10, "bbb": 10, "ccc": 10}

    def test_uneven_repos_still_fill_the_quota(self):
        """One repo running dry must not leave the quota short."""
        rows = make_rows({"R1": {"aaa": 2, "bbb": 100}})
        out = run.sample_per_rule(rows, 20)
        assert len(out) == 20
        assert sum(1 for x in out if x["repo"] == "aaa") == 2

    def test_quota_larger_than_available(self):
        rows = make_rows({"R1": {"a": 3, "b": 4}})
        assert len(run.sample_per_rule(rows, 100)) == 7

    def test_empty_input(self):
        assert run.sample_per_rule([], 10) == []

    def test_preserves_row_contents(self):
        rows = make_rows({"R1": {"a": 5}})
        out = run.sample_per_rule(rows, 3)
        for r in out:
            assert set(r) == set(run.CSV_COLUMNS)

    def test_verdicts_survive_sampling(self):
        rows = make_rows({"R1": {"a": 10}})
        rows[0]["verdict"] = "tp"
        out = run.sample_per_rule(rows, 10)
        assert any(r["verdict"] == "tp" for r in out)


class TestShippedCorpusIsLabellable:
    """The committed findings.csv must actually be hand-labellable."""

    @pytest.mark.skipif(not (BENCH / "findings.csv").is_file(), reason="benchmark has not been run")
    def test_sample_is_a_realistic_size(self):
        import csv

        with (BENCH / "findings.csv").open(newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert 0 < len(rows) <= 2000, (
            f"{len(rows)} rows is too many to hand-label; "
            "lower --sample-per-rule or re-run the harness"
        )

    @pytest.mark.skipif(
        not (BENCH / "findings-all.csv").is_file(), reason="benchmark has not been run"
    )
    def test_full_set_is_retained_alongside_the_sample(self):
        import csv

        with (BENCH / "findings-all.csv").open(newline="", encoding="utf-8") as fh:
            full = list(csv.DictReader(fh))
        with (BENCH / "findings.csv").open(newline="", encoding="utf-8") as fh:
            sample = list(csv.DictReader(fh))
        assert len(full) >= len(sample), "sampling must never lose evidence"
        assert {key(r) for r in sample} <= {key(r) for r in full}
