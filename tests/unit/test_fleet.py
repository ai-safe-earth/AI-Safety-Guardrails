"""tests/unit/test_fleet.py
------------------------
`aisg fleet` audits many repositories, one subprocess each, and aggregates counts, names and
paths; never a snippet. These tests pin the list formats and their validation, the three
documents (key order, CSV header, markdown with the disclaimer), the exit-code rule (a
repository that could not be audited is the fleet's failure, a finding in one is not),
`--resume`, `--proposal`, that local paths open no socket and are never written into, and
that the only program the fleet spawns is this interpreter.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from aisg.devtools import fleet
from aisg.devtools.audit.adapters import FORBIDDEN_LAUNCHERS
from aisg.devtools.audit.report import BANNED_PHRASES
from aisg.devtools.fleet import (
    CSV_COLUMNS,
    EXIT_FATAL,
    EXIT_INCOMPLETE,
    EXIT_OK,
    FleetError,
    FleetOptions,
    Target,
    audit_argv,
    build_parser,
    check_templates,
    main,
    read_list,
    render_markdown,
    render_proposal,
    run_fleet,
    summarise,
)

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "audit"
DECIDE_AUDIT = REPO / "tests" / "fixtures" / "decide" / "audit-report.json"


def _tree(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("aisg fleet opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    return cwd


@pytest.fixture
def two_repos(tmp_path: Path) -> tuple[Path, Path]:
    """Copies of two fixtures (so the repo's own pyproject is not above them)."""
    a = tmp_path / "repos" / "clean_py"
    b = tmp_path / "repos" / "py_agent"
    shutil.copytree(FIXTURES / "clean_py", a)
    shutil.copytree(FIXTURES / "py_agent", b)
    return a, b


def _yaml_list(path: Path, entries: list[dict]) -> Path:
    import yaml

    path.write_text(yaml.safe_dump({"repos": entries}, sort_keys=False), encoding="utf-8")
    return path


def _options(list_path: Path, out: Path, **over) -> FleetOptions:
    base = dict(list_path=str(list_path), out=str(out), fail_on="never")
    base.update(over)
    return FleetOptions(**base)


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------


class TestList:
    def test_yaml_and_csv_parse_to_the_same_targets(self, tmp_path: Path):
        yaml_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [
                {
                    "name": "one",
                    "url": "https://example.test/one.git",
                    "sha": "a" * 40,
                    "branch": "main",
                },
                {"name": "two", "path": "/tmp/two"},
            ],
        )
        csv_path = tmp_path / "fleet.csv"
        csv_path.write_text(
            "name,url,path,sha,branch\none,https://example.test/one.git,,"
            + "a" * 40
            + ",main\ntwo,,/tmp/two,,\n",
            encoding="utf-8",
        )
        assert read_list(yaml_path) == read_list(csv_path)
        assert read_list(yaml_path)[0] == Target(
            "one", "https://example.test/one.git", None, "a" * 40, "main"
        )
        assert read_list(yaml_path)[1].location == "/tmp/two"

    def test_bench_corpus_is_a_valid_fleet_list(self):
        targets = read_list(REPO / "bench" / "corpus.yaml")
        assert len(targets) >= 10
        assert all(t.url and t.sha and len(t.sha) == 40 for t in targets)

    @pytest.mark.parametrize(
        "entries, fragment",
        [
            ([{"name": "x"}], "exactly one of"),
            ([{"name": "x", "url": "u", "path": "p"}], "exactly one of"),
            ([{"name": "../x", "path": "p"}], "file-system safe"),
            ([{"name": "x", "path": "p", "sha": "zz"}], "not a commit id"),
            ([{"name": "x", "path": "p"}, {"name": "x", "path": "q"}], "duplicate names"),
            ([], "non-empty list"),
        ],
    )
    def test_bad_entries_are_refused(self, tmp_path: Path, entries, fragment: str):
        path = _yaml_list(tmp_path / "fleet.yaml", entries)
        with pytest.raises(FleetError, match=fragment):
            read_list(path)

    def test_unknown_suffix_and_missing_file(self, tmp_path: Path):
        (tmp_path / "list.txt").write_text("x", encoding="utf-8")
        with pytest.raises(FleetError, match="expected a .yaml"):
            read_list(tmp_path / "list.txt")
        with pytest.raises(FleetError):
            read_list(tmp_path / "none.yaml")


# ---------------------------------------------------------------------------
# The run over local paths
# ---------------------------------------------------------------------------


class TestRun:
    def test_two_local_repos_produce_the_three_documents(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        a, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [{"name": "clean_py", "path": str(a)}, {"name": "py_agent", "path": str(b)}],
        )
        before = (_tree(a), _tree(b))
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert code == EXIT_OK
        assert list(doc) == [
            "schema",
            "kind",
            "tool",
            "generated_at",
            "options",
            "totals",
            "disclaimer",
            "repos",
        ]
        assert (
            doc["schema"] == "aisg/1"
            and doc["kind"] == "fleet"
            and doc["tool"]["name"] == "aisg-fleet"
        )
        assert (
            doc["totals"]["repos"] == 2
            and doc["totals"]["completed"] == 2
            and doc["totals"]["failed"] == 0
        )
        rows = {r["name"]: r for r in doc["repos"]}
        assert rows["py_agent"]["status"] == "ok" and rows["py_agent"]["summary"]["findings"] > 0
        assert rows["py_agent"]["exit_code"] in (0, 1)
        assert rows["clean_py"]["status"] == "ok"
        assert set(rows["py_agent"]["highlights"]) == {
            "languages",
            "providers",
            "frameworks",
            "tools",
            "mcp_servers",
            "hosts",
            "guardrails",
            "evals",
        }
        assert "python" in rows["py_agent"]["highlights"]["languages"]
        out = neutral_cwd / "out"
        assert (out / "fleet-report.json").is_file()
        assert (out / "py_agent" / "audit-report.json").is_file()
        csv_text = (out / "fleet-report.csv").read_text(encoding="utf-8")
        assert csv_text.splitlines()[0] == ",".join(CSV_COLUMNS)
        md = (out / "fleet-report.md").read_text(encoding="utf-8")
        assert md.startswith("# aisg fleet\n\n> This report lists observations")
        assert "| py_agent | ok |" in md
        # the fleet never writes into the audited trees
        assert (_tree(a), _tree(b)) == before
        # and copies no snippet: the JSON carries counts, names and paths only
        report = json.loads((out / "py_agent" / "audit-report.json").read_text(encoding="utf-8"))
        snippets = [
            e["snippet"]
            for f in report["findings"]
            for e in f.get("evidence", [])
            if e.get("snippet")
        ]
        text = json.dumps(doc)
        assert snippets and not any(s in text for s in snippets)
        assert not any("evidence" in r or "snippet" in r for r in doc["repos"])

    def test_findings_do_not_fail_the_fleet_but_fail_on_findings_does(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        _, b = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "py_agent", "path": str(b)}])
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out", fail_on="high"), echo=False)
        assert code == EXIT_OK
        assert doc["repos"][0]["exit_code"] == 1 and doc["totals"]["repos_with_exit_1"] == 1
        doc, code = run_fleet(
            _options(list_path, neutral_cwd / "out2", fail_on="high", fail_on_findings=True),
            echo=False,
        )
        assert code == EXIT_INCOMPLETE

    def test_missing_path_is_clone_failed_and_exit_one(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        a, _ = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [
                {"name": "clean_py", "path": str(a)},
                {"name": "gone", "path": str(tmp_path / "nope")},
            ],
        )
        doc, code = run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert code == EXIT_INCOMPLETE
        rows = {r["name"]: r for r in doc["repos"]}
        assert (
            rows["gone"]["status"] == "clone_failed" and "does not exist" in rows["gone"]["error"]
        )
        assert rows["gone"]["report"] is None and rows["gone"]["exit_code"] is None
        assert doc["totals"]["failed"] == 1
        md = (neutral_cwd / "out" / "fleet-report.md").read_text(encoding="utf-8")
        assert "## Not audited" in md and "- gone: clone_failed:" in md

    def test_resume_skips_a_repository_whose_report_parses(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, monkeypatch
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        out = neutral_cwd / "out"
        first, _ = run_fleet(_options(list_path, out), echo=False)
        calls: list[list[str]] = []
        real_run = subprocess.run

        def spy(argv, *args, **kwargs):
            calls.append(list(argv))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(fleet.subprocess, "run", spy)
        second, code = run_fleet(_options(list_path, out, resume=True), echo=False)
        assert code == EXIT_OK and calls == []
        assert second["repos"][0]["resumed"] is True
        assert second["repos"][0]["summary"] == first["repos"][0]["summary"]

    def test_proposal_has_plan_and_decide_tables_and_no_snippet(
        self, tmp_path: Path, two_repos, neutral_cwd: Path
    ):
        _, b = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "py_agent", "path": str(b)}])
        run_fleet(_options(list_path, neutral_cwd / "out", proposal=True), echo=False)
        text = (neutral_cwd / "out" / "py_agent" / "proposal.md").read_text(encoding="utf-8")
        assert text.startswith("# AI safety audit: py_agent\n\n> This report lists observations")
        for heading in (
            "## Findings by severity",
            "## Plan (blast-radius order)",
            "## Decide",
            "## UNKNOWN",
            "## How this was produced",
            "## How to apply",
        ):
            assert heading in text, heading
        assert (
            "| # | rule | title | file:line | who | mechanism | same_control | leaves_open |"
            in text
        )
        assert "| 1 | AUD-" in text
        assert "| # | decision (apply / defer / accept) | reason |" in text
        assert "| 1 | | |" in text
        assert "-m aisg.cli audit . --format json --no-external" in text
        assert "never pushes" in text
        report = json.loads(
            (neutral_cwd / "out" / "py_agent" / "audit-report.json").read_text(encoding="utf-8")
        )
        snippets = [
            e["snippet"]
            for f in report["findings"]
            for e in f.get("evidence", [])
            if e.get("snippet")
        ]
        assert snippets and not any(s in text for s in snippets)
        assert text.isascii()

    def test_jobs_two_yields_the_same_document(self, tmp_path: Path, two_repos, neutral_cwd: Path):
        a, b = two_repos
        list_path = _yaml_list(
            tmp_path / "fleet.yaml",
            [{"name": "clean_py", "path": str(a)}, {"name": "py_agent", "path": str(b)}],
        )
        one, _ = run_fleet(_options(list_path, neutral_cwd / "o1"), echo=False)
        two, _ = run_fleet(_options(list_path, neutral_cwd / "o2", jobs=2), echo=False)

        def stable(doc: dict) -> dict:
            repos = []
            for r in doc["repos"]:
                r = dict(r)
                r.pop("duration_s")
                r["report"] = Path(r["report"]).name if r["report"] else None
                repos.append(r)
            return {"totals": doc["totals"], "repos": repos}

        assert stable(one) == stable(two)

    def test_only_this_interpreter_is_spawned(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, monkeypatch
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        seen: list[list[str]] = []
        real_run = subprocess.run

        def spy(argv, *args, **kwargs):
            seen.append(list(argv))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(fleet.subprocess, "run", spy)
        run_fleet(_options(list_path, neutral_cwd / "out"), echo=False)
        assert seen and all(argv[0] == sys.executable for argv in seen)
        assert all(
            Path(argv[0]).name.lower().split(".")[0] not in FORBIDDEN_LAUNCHERS for argv in seen
        )
        assert all("install" not in token for argv in seen for token in argv)

    def test_extra_args_reach_every_audit(self):
        argv = audit_argv("high", Path("r.json"), ("--rules", "AUD-501"))
        assert argv[:4] == [sys.executable, "-m", "aisg.cli", "audit"]
        assert argv[-2:] == ["--rules", "AUD-501"]
        assert "--no-external" in argv


# ---------------------------------------------------------------------------
# Documents without a run
# ---------------------------------------------------------------------------


class TestDocuments:
    def test_summarise_reads_counts_names_and_sha(self):
        report = json.loads(DECIDE_AUDIT.read_text(encoding="utf-8"))
        summary, frequency, highlights, sha = summarise(report)
        assert summary["findings"] == report["summary"]["findings"]
        assert set(summary["by_severity"]) == {"critical", "high", "medium", "low", "info"}
        assert sum(frequency.values()) == len(report["findings"])
        assert highlights["providers"] == ["anthropic"] and highlights["mcp_servers"] == 2
        assert highlights["hosts"] == ["claude"] and highlights["tools"] == 3
        assert sha is None  # that fixture names no git_sha

    def test_templates_are_free_of_banned_phrases(self):
        assert check_templates() == []

    def test_markdown_sorts_by_critical_then_high_then_name(self):
        def repo(name, critical, high):
            return {
                "name": name,
                "url": name,
                "sha": None,
                "status": "ok",
                "duration_s": 1.0,
                "exit_code": 0,
                "report": f"{name}/audit-report.json",
                "summary": {
                    "findings": critical + high,
                    "by_severity": {
                        "critical": critical,
                        "high": high,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                    "unknown_items": 0,
                },
                "rule_frequency": {"AUD-301": critical} if critical else {},
                "highlights": {},
                "error": None,
                "resumed": False,
            }

        options = FleetOptions(list_path="l.yaml")
        doc = fleet.build_report([], options, "2026-10-19T00:00:00Z")
        doc["repos"] = [repo("b", 1, 0), repo("a", 1, 0), repo("c", 0, 5)]
        doc["totals"]["rule_frequency"] = {"AUD-301": 2}
        md = render_markdown(doc)
        order = [
            line.split("|")[1].strip()
            for line in md.splitlines()
            if line.startswith("| ") and " | ok | " in line
        ]
        assert order == ["a", "b", "c"]
        assert "| AUD-301 | 2 | 2 |" in md
        lowered = md.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered

    def test_proposal_who_column_follows_the_plan_rule(self):
        report = json.loads(DECIDE_AUDIT.read_text(encoding="utf-8"))
        text = render_proposal(
            Target("py_agent", path="x"), report, ["python", "-m", "aisg.cli", "audit", "."]
        )
        rows = [line for line in text.splitlines() if line.startswith("| ") and "| AUD-" in line]
        assert rows
        whos = {line.split("|")[5].strip() for line in rows}
        assert whos <= {"package", "you", "you, approval needed"}
        protected = [
            line for line in rows if ".claude/settings.json" in line or ".mcp.json" in line
        ]
        assert protected and all("you, approval needed" in line for line in protected)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_help_starts_with_the_prog_name(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.startswith("usage: aisg fleet")

    def test_bad_list_exits_two(self, tmp_path: Path, neutral_cwd: Path, capsys):
        path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "x"}])
        assert main([str(path)]) == EXIT_FATAL
        assert "exactly one of" in capsys.readouterr().err

    def test_main_runs_and_prints_the_summary_line(
        self, tmp_path: Path, two_repos, neutral_cwd: Path, capsys
    ):
        a, _ = two_repos
        list_path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "clean_py", "path": str(a)}])
        assert main([str(list_path), "--out", "out", "--fail-on", "never", "--quiet"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "aisg fleet: 1/1 audited, 0 not audited" in out
        assert (neutral_cwd / "out" / "fleet-report.json").is_file()

    def test_jobs_zero_is_fatal(self, tmp_path: Path, neutral_cwd: Path):
        path = _yaml_list(tmp_path / "fleet.yaml", [{"name": "x", "path": str(tmp_path)}])
        assert main([str(path), "--jobs", "0"]) == EXIT_FATAL

    def test_console_script_routes_fleet(self):
        from aisg import cli

        assert "fleet" in cli.COMMANDS
        assert "aisg fleet" in cli._EPILOG
