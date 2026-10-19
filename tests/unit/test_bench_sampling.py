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


def make_rows(spec: dict[str, dict[str, int]], audit: bool = False) -> list[dict]:
    """spec: {rule_id: {repo: how_many}}; `audit` adds the audit CSV's extra columns."""
    rows = []
    for rule, repos in spec.items():
        for repo, n in repos.items():
            for i in range(n):
                row = {
                    "repo": repo,
                    "file": f"src/mod{i // 10}.py",
                    "line": str(i),
                    "rule_id": rule,
                    "message": "x",
                    "verdict": "",
                }
                if audit:
                    row.update({"sub": "", "snippet": f"x = {i}"})
                rows.append(row)
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


REPO = BENCH.parent
DECIDE_AUDIT = REPO / "tests" / "fixtures" / "decide" / "audit-report.json"


class TestAuditTool:
    """`--tool audit` reuses the sampling and the label loop over audit findings."""

    def test_audit_columns_extend_the_lint_columns(self):
        assert set(run.AUDIT_CSV_COLUMNS) == set(run.CSV_COLUMNS) | {"sub", "snippet"}
        assert run.AUDIT_CSV_COLUMNS[-1] == "verdict"
        assert run.paths_for("audit")[3] is run.AUDIT_CSV_COLUMNS
        assert run.paths_for("lint")[3] is run.CSV_COLUMNS

    def test_rows_from_audit_json_flatten_the_first_evidence_leg(self, tmp_path: Path):
        import json
        import shutil

        jf = tmp_path / "py_agent.json"
        shutil.copy(DECIDE_AUDIT, jf)
        rows = run.rows_from_audit_json("py_agent", jf)
        report = json.loads(jf.read_text(encoding="utf-8"))
        assert len(rows) == len(report["findings"])
        for row, finding in zip(rows, report["findings"]):
            assert set(row) == set(run.AUDIT_CSV_COLUMNS)
            assert row["rule_id"] == finding["rule_id"]  # the parent, never `AUD-101/docs`
            assert "/" not in row["rule_id"]
            assert row["sub"] == (finding["sub"] or "")
            assert row["message"] == finding["title"] and row["verdict"] == ""
            evidence = finding.get("evidence") or []
            if evidence:
                assert row["file"] == evidence[0]["file"]
                assert str(row["line"]) == str(evidence[0]["line"])
                assert row["snippet"] == " ".join(str(evidence[0]["snippet"]).split())
            else:
                assert row["file"] == "" and row["line"] == ""

    def test_sampling_over_audit_rows_is_deterministic_and_nested(self):
        rows = make_rows({"AUD-501": {"a": 60, "b": 40}, "AUD-602": {"a": 30}}, audit=True)
        first = [key(r) for r in run.sample_per_rule(list(rows), 30)]
        assert [key(r) for r in run.sample_per_rule(list(rows), 30)] == first
        small = {key(r) for r in run.sample_per_rule(list(rows), 10)}
        large = {key(r) for r in run.sample_per_rule(list(rows), 25)}
        assert small <= large
        for r in run.sample_per_rule(rows, 5):
            assert set(r) == set(run.AUDIT_CSV_COLUMNS)

    def test_merge_preserving_verdicts_takes_a_path(self, tmp_path: Path):
        import csv

        rows = make_rows({"AUD-501": {"a": 2}}, audit=True)
        rows[0]["verdict"] = "fp"
        path = tmp_path / "findings-audit.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=run.AUDIT_CSV_COLUMNS)
            w.writeheader()
            w.writerows(rows)
        fresh = make_rows({"AUD-501": {"a": 2}}, audit=True)
        merged = run.merge_preserving_verdicts(fresh, path)
        assert [r["verdict"] for r in merged] == ["fp", ""]

    def test_score_tool_audit_refuses_a_partly_labelled_csv(self, tmp_path: Path):
        import csv
        import subprocess

        rows = make_rows({"AUD-501": {"a": 3}}, audit=True)
        rows[0]["verdict"] = "tp"
        path = tmp_path / "findings-audit.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=run.AUDIT_CSV_COLUMNS)
            w.writeheader()
            w.writerows(rows)
        argv = [
            sys.executable,
            str(BENCH / "score.py"),
            "--tool",
            "audit",
            "--csv",
            str(path),
            "--results",
            str(tmp_path / "none"),
            "--out",
            str(tmp_path / "precision-audit.md"),
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 1
        assert "2 of 3 findings are unlabelled" in proc.stderr
        assert not (tmp_path / "precision-audit.md").exists()
        # fully labelled: the report is written and the paste block names the class
        for r in rows:
            r["verdict"] = r["verdict"] or "fp"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=run.AUDIT_CSV_COLUMNS)
            w.writeheader()
            w.writerows(rows)
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr
        text = (tmp_path / "precision-audit.md").read_text(encoding="utf-8")
        assert text.startswith("# aisg audit rule precision")
        assert "measured_precision = 0.333" in text
        assert "# AUD-501 SecretLiteral: 1/3 judged" in text or "# AUD-501 " in text
        assert "`aisg audit --experimental`" in text


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
