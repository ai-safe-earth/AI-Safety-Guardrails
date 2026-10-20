"""tests/unit/test_audit_only.py
------------------------------
`aisafe audit --only PATH`: the file-scoped run the agent hook uses after an edit. The
tree is walked as usual (excludes, gitignore, marker, size limit), only the records are
filtered, and the rule set is `FILE_LOCAL_RULES` unless `--rules` is given. The one
invariant that matters: a finding a partial run reports carries the fingerprint the full
run gives it, so a baseline written by the full run applies unchanged.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisafe.devtools._config import find_pyproject
from aisafe.devtools.audit import discover, report, walk
from aisafe.devtools.audit.main import FILE_LOCAL_RULES, NOT_CONFIGURABLE, AuditOptions, main

REPO = Path(__file__).resolve().parents[2]
PY_AGENT = REPO / "tests" / "fixtures" / "audit" / "py_agent"
FIXTURE_FILES = (".claude/settings.json", ".mcp.json", "app.py", "tools.py", "pyproject.toml")


@pytest.fixture(autouse=True)
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert find_pyproject() is None
    return cwd


def _run(tmp_path: Path, *args: str) -> tuple[int, dict]:
    out = tmp_path / f"report-{len(list(tmp_path.iterdir()))}.json"
    rc = main([str(PY_AGENT), "--no-external", "--format", "json", "-o", str(out), *args])
    return rc, json.loads(out.read_text(encoding="utf-8"))


def _keyed(doc: dict) -> dict[tuple[str, str], str]:
    """{(rule id, fingerprint): first evidence file} for every finding."""
    out: dict[tuple[str, str], str] = {}
    for finding in doc["findings"]:
        first = finding["evidence"][0]["file"] if finding["evidence"] else ""
        out[(finding["id"], finding["fingerprint"])] = first
    return out


@pytest.fixture(scope="module")
def full_run(tmp_path_factory: pytest.TempPathFactory) -> dict:
    cwd = tmp_path_factory.mktemp("full")
    out = cwd / "full.json"
    import os

    previous = os.getcwd()
    os.chdir(cwd)
    try:
        rc = main([str(PY_AGENT), "--no-external", "--format", "json", "-o", str(out)])
    finally:
        os.chdir(previous)
    assert rc == 1
    return json.loads(out.read_text(encoding="utf-8"))


class TestFingerprintsMatchTheFullRun:
    @pytest.mark.parametrize("rel", FIXTURE_FILES)
    def test_only_reports_exactly_the_full_runs_file_local_findings(self, tmp_path, full_run, rel):
        _rc, partial = _run(tmp_path, "--only", rel)
        expected = {
            key: file
            for key, file in _keyed(full_run).items()
            if key[0].split("/")[0] in FILE_LOCAL_RULES and file == rel
        }
        assert _keyed(partial) == expected

    def test_the_fixture_exercises_the_invariant(self, full_run):
        local = [f for f in full_run["findings"] if f["id"].split("/")[0] in FILE_LOCAL_RULES]
        assert {f["id"].split("/")[0] for f in local} >= {"AUD-101", "AUD-602"}

    def test_only_with_two_files_is_the_union(self, tmp_path, full_run):
        _rc, partial = _run(tmp_path, "--only", ".claude/settings.json,.mcp.json")
        expected = {
            key: file
            for key, file in _keyed(full_run).items()
            if key[0].split("/")[0] in FILE_LOCAL_RULES
            and file in (".claude/settings.json", ".mcp.json")
        }
        assert _keyed(partial) == expected


class TestTheDocumentSaysItIsPartial:
    def test_target_only_lists_the_files_and_a_full_run_lists_none(self, tmp_path, full_run):
        _rc, partial = _run(tmp_path, "--only", "app.py", "--only", ".mcp.json")
        assert partial["target"]["only"] == ["app.py", ".mcp.json"]
        assert full_run["target"]["only"] == []

    def test_terminal_and_markdown_print_the_partial_line(self, tmp_path, capsys):
        rc = main([str(PY_AGENT), "--no-external", "--only", ".mcp.json"])
        assert rc == 1
        text = capsys.readouterr().out
        assert "partial run: 1 file(s) via --only" in text
        out = tmp_path / "r.md"
        main(
            [
                str(PY_AGENT),
                "--no-external",
                "--only",
                ".mcp.json",
                "--format",
                "markdown",
                "-o",
                str(out),
            ]
        )
        assert "partial run: 1 file(s) via --only" in out.read_text(encoding="utf-8")

    def test_the_line_is_a_checked_template(self):
        assert report._T_ONLY in report._TEMPLATES
        assert not report.check_templates()

    def test_a_full_run_prints_no_partial_line(self, capsys):
        main([str(PY_AGENT), "--no-external", "-q"])
        assert "partial run" not in capsys.readouterr().out


class TestUnseenPaths:
    def test_an_unseen_path_is_an_unknown_row(self, tmp_path):
        rc, doc = _run(tmp_path, "--only", "does/not/exist.py")
        assert rc == 0, "nothing audited, nothing found; the UNKNOWN row carries the fact"
        rows = [u for u in doc["unknown"] if u["what"] == "--only path not walked"]
        assert len(rows) == 1
        assert rows[0]["file"] == "does/not/exist.py"
        assert rows[0]["category"] == "runtime"

    def test_fail_on_unknown_turns_it_into_exit_1(self, tmp_path):
        rc, _doc = _run(tmp_path, "--only", "nope.py", "--fail-on-unknown", "runtime")
        assert rc == 1

    def test_an_excluded_path_is_unseen_too(self, tmp_path):
        rc, doc = _run(tmp_path, "--only", "tools.py", "--exclude", "tools.py")
        rows = [u for u in doc["unknown"] if u["what"] == "--only path not walked"]
        assert [r["file"] for r in rows] == ["tools.py"]
        assert not doc["findings"]

    def test_walk_options_filter_records_but_keep_units(self):
        full_files, full_units, _ = walk.walk(PY_AGENT, walk.WalkOptions())
        files, units, unknown = walk.walk(PY_AGENT, walk.WalkOptions(only=("app.py", "ghost.py")))
        assert [f.relpath for f in files] == ["app.py"]
        assert [u.id for u in units] == [u.id for u in full_units]
        assert len(full_files) > 1
        assert [u.file for u in unknown if u.what == "--only path not walked"] == ["ghost.py"]


class TestRuleSelection:
    def test_only_without_rules_runs_the_file_local_set(self, tmp_path):
        _rc, doc = _run(tmp_path, "--only", "app.py")
        ran = {r["id"] for r in doc["rules"] if r["ran"]}
        assert ran == set(FILE_LOCAL_RULES)

    def test_explicit_rules_win_over_the_file_local_set(self, tmp_path):
        _rc, doc = _run(tmp_path, "--only", "app.py", "--rules", "AUD-601")
        assert {r["id"] for r in doc["rules"] if r["ran"]} == {"AUD-601"}

    def test_file_local_rules_exclude_the_grouped_and_absence_rules(self):
        for excluded in ("AUD-601", "AUD-504", "AUD-503", "AUD-701", "AUD-901", "AUD-1001"):
            assert excluded not in FILE_LOCAL_RULES

    def test_only_is_never_a_pyproject_default(self, tmp_path, neutral_cwd):
        assert "only" in NOT_CONFIGURABLE
        (neutral_cwd / "pyproject.toml").write_text(
            '[tool.aisafe-audit]\nonly = ["app.py"]\n', encoding="utf-8"
        )
        _rc, doc = _run(tmp_path)
        assert doc["target"]["only"] == []
        assert len([r for r in doc["rules"] if r["ran"]]) > len(FILE_LOCAL_RULES)

    def test_options_default_is_empty(self):
        assert AuditOptions().only == ()


def test_secret_file_exclusion_is_public_and_aliased():
    assert discover.is_excluded_secret_file("config/.env.example")
    assert discover.is_excluded_secret_file("tests/fixtures/audit/py_agent/app.py")
    assert not discover.is_excluded_secret_file("app.py")
    assert discover._excluded_secret_file is discover.is_excluded_secret_file
