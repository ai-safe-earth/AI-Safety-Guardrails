"""
tests/unit/test_euaiact_lint.py
--------------------------------
The EU AI Act linter: suppression (file marker and line directive), the
exclude semantics the CI gate depends on, the JSON summary the workflow's
check step reads, and the self-lint the compliance gate enforces.

Every suppression must stay observable: a skipped file lands in
`skipped_files`, a silenced finding bumps `suppressed_count`, and both are
rendered by every reporter that has a summary line.
"""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

import pytest

from aisg.devtools.euaiact_lint import main
from aisg.devtools.misalignment_check import TOOL as MISALIGN_TOOL
from aisg.devtools.misalignment_check import main as misalign_main
from aisg.modules.policy.code_analyzer.analyzer import (
    DEFAULT_TOOL,
    IGNORE_MARKER,
    MARKER_LINES,
    CodeFinding,
    EUAIActCodeAnalyzer,
    ScanReport,
    Severity,
    has_ignore_marker,
    ignore_marker,
    ignored_rules,
    is_excluded,
)
from aisg.modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)
from aisg.modules.policy.code_analyzer.rules import ALL_RULES

REPO_ROOT = Path(__file__).resolve().parents[2]

# The phrase is assembled so this file does not trip the rule it tests.
TRIPWIRE = "social" + "_" + "scoring"
RULE = "EU-AIA-005a"


def _rule(rule_id: str):
    return [r for r in ALL_RULES if r.rule_id == rule_id]


def _write(tmp_path: Path, name: str, body: str) -> Path:
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent(body), encoding="utf-8")
    return target


# ---------------------------------------------------------------------------
# File marker
# ---------------------------------------------------------------------------


class TestIgnoreMarker:
    def test_marker_on_first_line(self):
        assert has_ignore_marker(f"{IGNORE_MARKER}\nx = 1\n")

    def test_marker_on_last_permitted_line(self):
        head = "\n".join("#" for _ in range(MARKER_LINES - 1))
        assert has_ignore_marker(f"{head}\n{IGNORE_MARKER}\n")

    def test_marker_past_the_window_is_not_honoured(self):
        head = "\n".join("#" for _ in range(MARKER_LINES))
        assert not has_ignore_marker(f"{head}\n{IGNORE_MARKER}\n")

    def test_no_marker(self):
        assert not has_ignore_marker("x = 1\n")
        assert not has_ignore_marker("")

    def test_marked_file_is_skipped_not_scanned(self, tmp_path):
        path = _write(tmp_path, "vocab.py", f"{IGNORE_MARKER}\n{TRIPWIRE} = 1\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert report.skipped_files == [str(path)]
        assert report.scanned_files == []
        assert report.findings == []
        assert report.suppressed_count == 0

    def test_unmarked_file_with_the_same_content_is_reported(self, tmp_path):
        path = _write(tmp_path, "app.py", f"{TRIPWIRE} = 1\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert report.scanned_files == [str(path)]
        assert [f.rule_id for f in report.findings] == [RULE]


# ---------------------------------------------------------------------------
# Line directive
# ---------------------------------------------------------------------------


class TestIgnoredRules:
    def test_single_rule(self):
        assert ignored_rules("x = 1  # euaiact-lint: ignore EU-AIA-005a") == {"EU-AIA-005A"}

    def test_comma_list(self):
        got = ignored_rules("x = 1  # euaiact-lint: ignore EU-AIA-005a, EU-AIA-012b")
        assert got == {"EU-AIA-005A", "EU-AIA-012B"}

    def test_case_insensitive(self):
        assert ignored_rules("x = 1  # euaiact-lint: ignore eu-aia-005a") == {"EU-AIA-005A"}

    def test_bare_ignore_names_nothing(self):
        assert ignored_rules("x = 1  # euaiact-lint: ignore") == set()
        assert ignored_rules("x = 1  # euaiact-lint: ignore   ") == set()

    def test_file_marker_is_not_a_line_directive(self):
        assert ignored_rules(f"x = 1  {IGNORE_MARKER}") == set()

    def test_no_directive(self):
        assert ignored_rules("x = 1  # plain comment") == set()
        assert ignored_rules("") == set()


class TestLineSuppression:
    def test_directive_naming_the_rule_suppresses_and_counts(self, tmp_path):
        path = _write(tmp_path, "app.py", f"x = '{TRIPWIRE}'  # euaiact-lint: ignore {RULE}\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert report.findings == []
        assert report.suppressed_count == 1
        assert report.scanned_files == [str(path)]
        assert report.passed

    def test_directive_naming_another_rule_keeps_the_finding(self, tmp_path):
        path = _write(tmp_path, "app.py", f"x = '{TRIPWIRE}'  # euaiact-lint: ignore EU-AIA-012b\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert [f.rule_id for f in report.findings] == [RULE]
        assert report.suppressed_count == 0

    def test_directive_on_another_line_keeps_the_finding(self, tmp_path):
        path = _write(
            tmp_path,
            "app.py",
            f"# euaiact-lint: ignore {RULE}\nx = '{TRIPWIRE}'\n",
        )
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert [f.rule_id for f in report.findings] == [RULE]
        assert report.suppressed_count == 0

    def test_bare_directive_keeps_the_finding(self, tmp_path):
        path = _write(tmp_path, "app.py", f"x = '{TRIPWIRE}'  # euaiact-lint: ignore\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert [f.rule_id for f in report.findings] == [RULE]
        assert report.suppressed_count == 0

    # Characters str.splitlines() treats as line breaks and ast.parse does not:
    # form feed, vertical tab, NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR.
    @pytest.mark.parametrize("sep", ["\x0c", "\x0b", "\x85", "\u2028", "\u2029"])
    def test_ast_finding_lines_are_physical_lines(self, sep, tmp_path):
        """A separator inside a string on line 1 must not shift every later
        finding: the directive on the finding's own line still suppresses it,
        and a directive on the line above does not silence the next one."""
        path = tmp_path / "app.py"
        path.write_text(
            f's = "a{sep}b"\n'
            "class FooModel: pass  # euaiact-lint: ignore EU-AIA-011a\n"
            "class BarModel: pass\n",
            encoding="utf-8",
        )
        report = EUAIActCodeAnalyzer(rules=_rule("EU-AIA-011a")).scan_file(path)
        assert report.suppressed_count == 1
        assert [(f.line, f.snippet) for f in report.findings] == [(3, "class BarModel: pass")]

    def test_a_page_break_line_does_not_shift_later_findings(self, tmp_path):
        """An Emacs-style form feed alone on a line is a valid, blank line to
        the tokenizer. It used to be two entries to the directive lookup."""
        path = tmp_path / "app.py"
        path.write_text(
            "x = 1\n\x0c\nclass FooModel: pass  # euaiact-lint: ignore EU-AIA-011a\n",
            encoding="utf-8",
        )
        report = EUAIActCodeAnalyzer(rules=_rule("EU-AIA-011a")).scan_file(path)
        assert report.findings == []
        assert report.suppressed_count == 1

    @pytest.mark.parametrize("sep", ["\x0c", "\u2028"])
    def test_text_rule_lines_are_physical_lines(self, sep, tmp_path):
        """Text rules count lines the same way, so a directive written against
        the line the AST rules report also lands for a text-rule finding."""
        path = tmp_path / "app.py"
        path.write_text(
            f's = "a{sep}b"\nx = "{TRIPWIRE}"  # euaiact-lint: ignore {RULE}\ny = "{TRIPWIRE}"\n',
            encoding="utf-8",
        )
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert report.suppressed_count == 1
        assert [f.line for f in report.findings] == [3]

    @pytest.mark.parametrize(
        "rel",
        [
            "src/aisg/modules/policy/code_analyzer/rules/__init__.py",
            "src/aisg/devtools/misalignment/rules/__init__.py",
        ],
    )
    def test_rule_tables_count_physical_lines(self, rel):
        """A text rule that enumerates `splitlines()` reports line numbers the
        directive lookup cannot find. `physical_lines()` is the only splitter."""
        assert "splitlines" not in (REPO_ROOT / rel).read_text(encoding="utf-8"), rel

    def test_suppression_survives_the_cli_merge(self, tmp_path):
        _write(tmp_path, "a.py", f"x = '{TRIPWIRE}'  # euaiact-lint: ignore {RULE}\n")
        _write(tmp_path, "b.py", f"{IGNORE_MARKER}\ny = '{TRIPWIRE}'\n")
        _write(tmp_path, "c.py", "z = 1\n")
        out = tmp_path / "report.json"
        code = main([str(tmp_path), "--rules", RULE, "--format", "json", "-o", str(out)])
        summary = json.loads(out.read_text(encoding="utf-8"))["summary"]
        assert code == 0
        assert summary["scanned_files"] == 2
        assert summary["skipped_files"] == 1
        assert summary["suppressed_count"] == 1
        assert summary["error_count"] == 0


# ---------------------------------------------------------------------------
# Tool scoping: the analyzer is shared with `aisg misalign`
# ---------------------------------------------------------------------------

ALIGN_TRIPWIRE = "skip" + "_" + "guardrail"  # trips ALIGN-001, assembled so this file does not
ALIGN_RULE = "ALIGN-001"


def _align_rule():
    from aisg.devtools.misalignment.rules import MISALIGNMENT_RULES

    return [r for r in MISALIGNMENT_RULES if r.rule_id == ALIGN_RULE]


class TestToolScoping:
    def test_marker_names_the_tool(self):
        assert ignore_marker() == IGNORE_MARKER == f"# {DEFAULT_TOOL}: ignore-file"
        assert ignore_marker(MISALIGN_TOOL) == "# misalignment-check: ignore-file"

    def test_lint_marker_is_ignored_by_misalign(self, tmp_path):
        path = _write(tmp_path, "app.py", f"{IGNORE_MARKER}\n{ALIGN_TRIPWIRE} = True\n")
        report = EUAIActCodeAnalyzer(rules=_align_rule(), tool=MISALIGN_TOOL).scan_file(path)
        assert report.scanned_files == [str(path)]
        assert report.skipped_files == []
        assert [f.rule_id for f in report.findings] == [ALIGN_RULE]

    def test_misalign_marker_is_ignored_by_lint(self, tmp_path):
        path = _write(tmp_path, "app.py", f"{ignore_marker(MISALIGN_TOOL)}\n{TRIPWIRE} = 1\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_file(path)
        assert report.scanned_files == [str(path)]
        assert [f.rule_id for f in report.findings] == [RULE]

    def test_misalign_marker_is_honoured_by_misalign(self, tmp_path):
        path = _write(
            tmp_path, "app.py", f"{ignore_marker(MISALIGN_TOOL)}\n{ALIGN_TRIPWIRE} = True\n"
        )
        report = EUAIActCodeAnalyzer(rules=_align_rule(), tool=MISALIGN_TOOL).scan_file(path)
        assert report.skipped_files == [str(path)]
        assert report.findings == []
        assert report.tool == MISALIGN_TOOL

    def test_line_directive_is_tool_scoped(self):
        line = f"x = 1  # {MISALIGN_TOOL}: ignore {ALIGN_RULE}"
        assert ignored_rules(line, MISALIGN_TOOL) == {ALIGN_RULE}
        assert ignored_rules(line) == set()
        assert ignored_rules(f"x = 1  # euaiact-lint: ignore {RULE}", MISALIGN_TOOL) == set()

    def test_misalign_cli_carries_its_own_suppressions(self, tmp_path):
        _write(
            tmp_path, "a.py", f"{ALIGN_TRIPWIRE} = True  # {MISALIGN_TOOL}: ignore {ALIGN_RULE}\n"
        )
        _write(tmp_path, "b.py", f"{ignore_marker(MISALIGN_TOOL)}\n{ALIGN_TRIPWIRE} = True\n")
        _write(
            tmp_path, "c.py", f"{IGNORE_MARKER}\n{ALIGN_TRIPWIRE} = True\n"
        )  # lint marker: no effect
        out = tmp_path / "report.json"
        code = misalign_main(
            [str(tmp_path), "--rules", ALIGN_RULE, "--format", "json", "-o", str(out)]
        )
        summary = json.loads(out.read_text(encoding="utf-8"))["summary"]
        assert code == 1
        assert summary["scanned_files"] == 2
        assert summary["skipped_files"] == 1
        assert summary["suppressed_count"] == 1
        assert summary["error_count"] == 1

    def test_reporter_note_names_the_tool(self):
        buf = io.StringIO()
        report = ScanReport(scanned_files=["a.py"], skipped_files=["b.py"], tool=MISALIGN_TOOL)
        TerminalReporter(out=buf, color=False).write(report)
        assert "skipped by `# misalignment-check: ignore-file`" in buf.getvalue()


# ---------------------------------------------------------------------------
# Missing paths are fatal
# ---------------------------------------------------------------------------


class TestMissingPaths:
    @pytest.mark.parametrize("entry", [main, misalign_main])
    def test_nonexistent_path_exits_2(self, entry, tmp_path, capsys):
        _write(tmp_path, "ok.py", "x = 1\n")
        code = entry([str(tmp_path / "ok.py"), str(tmp_path / "nope"), "--format", "json"])
        assert code == 2
        assert "nope" in capsys.readouterr().err

    def test_existing_paths_still_scan(self, tmp_path):
        _write(tmp_path, "ok.py", "x = 1\n")
        out = tmp_path / "report.json"
        assert main([str(tmp_path / "ok.py"), "--format", "json", "-o", str(out)]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["scanned_files"] == 1


class TestConfigSourcedPaths:
    """`paths` from pyproject resolve against the CWD. From a subdirectory
    they do not exist; exit 2 is right, and the message must say where the
    paths came from, or the user sees `src is not a file` having typed nothing."""

    @pytest.mark.parametrize(
        ("entry", "section"),
        [(main, "euaiact-lint"), (misalign_main, MISALIGN_TOOL)],
        ids=["lint", "misalign"],
    )
    def test_from_a_subdirectory_the_note_names_the_section(
        self, entry, section, tmp_path, monkeypatch, capsys
    ):
        _write(tmp_path, "src/app.py", "x = 1\n")
        (tmp_path / "pyproject.toml").write_text(
            f'[tool.{section}]\npaths = ["src"]\n', encoding="utf-8"
        )
        sub = tmp_path / "docs"
        sub.mkdir()
        monkeypatch.chdir(sub)
        assert entry(["--format", "json", "-o", str(tmp_path / "r.json")]) == 2
        err = capsys.readouterr().err
        assert "src is not a file or directory" in err
        assert f"[tool.{section}]" in err
        assert "pyproject.toml" in err

    def test_an_explicit_missing_path_gets_no_note(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.euaiact-lint]\npaths = ["src"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        assert main(["nope", "--format", "json"]) == 2
        err = capsys.readouterr().err
        assert "nope is not a file or directory" in err
        assert "pyproject.toml" not in err

    def test_from_the_root_the_config_paths_scan(self, tmp_path, monkeypatch):
        _write(tmp_path, "src/app.py", "x = 1\n")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.euaiact-lint]\npaths = ["src"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "r.json"
        assert main(["--format", "json", "-o", str(out)]) == 0
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["scanned_files"] == 1


# ---------------------------------------------------------------------------
# --staged / --diff: the pre-commit path
# ---------------------------------------------------------------------------


class _Completed:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestDiffBranch:
    def test_scan_diff_honours_exclude_dirs(self, tmp_path):
        kept = _write(tmp_path, "src/app.py", f"x = '{TRIPWIRE}'\n")
        _write(tmp_path, "tests/fixtures/bad.py", f"x = '{TRIPWIRE}'\n")
        diff = "+++ b/src/app.py\n+++ b/tests/fixtures/bad.py\n"
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_diff(
            diff, base_dir=str(tmp_path), exclude_dirs=["tests/fixtures"]
        )
        assert report.scanned_files == [str(tmp_path / "src" / "app.py")]
        assert [f.file for f in report.findings] == [str(kept)]

    def test_staged_run_honours_the_pyproject_exclude(self, tmp_path, monkeypatch):
        """The shipped pre-commit hook is `aisg lint --staged --errors-only`.
        A staged fixture must not block the commit when the full scan excludes it."""
        _write(tmp_path, "src/app.py", "x = 1\n")
        _write(tmp_path, "tests/fixtures/bad.py", f"x = '{TRIPWIRE}'\n")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.euaiact-lint]\nexclude = ["tests/fixtures"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "aisg.devtools.euaiact_lint.subprocess.run",
            lambda *a, **k: _Completed(0, "src/app.py\ntests/fixtures/bad.py\n"),
        )
        out = tmp_path / "r.json"
        code = main(["--staged", "--rules", RULE, "--format", "json", "-o", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert code == 0, data["findings"]
        assert data["summary"]["scanned_files"] == 1
        assert data["summary"]["error_count"] == 0

    @pytest.mark.parametrize(
        ("entry", "module"),
        [(main, "aisg.devtools.euaiact_lint"), (misalign_main, "aisg.devtools.misalignment_check")],
        ids=["lint", "misalign"],
    )
    def test_a_failing_git_diff_is_fatal(self, entry, module, monkeypatch, capsys):
        """`fatal: not a git repository` used to print "No Python files changed"
        and exit 0 -- a clean result from a scan that never happened."""
        monkeypatch.setattr(
            f"{module}.subprocess.run",
            lambda *a, **k: _Completed(128, "", "fatal: not a git repository"),
        )
        assert entry(["--staged", "--format", "json"]) == 2
        captured = capsys.readouterr()
        assert "git diff failed" in captured.err
        assert "not a git repository" in captured.err
        assert "No Python files changed" not in captured.out

    def test_git_not_installed_is_fatal(self, monkeypatch, capsys):
        def _missing(*a, **k):
            raise FileNotFoundError("git")

        monkeypatch.setattr("aisg.devtools.euaiact_lint.subprocess.run", _missing)
        assert main(["--diff", "--format", "json"]) == 2
        assert "cannot run git" in capsys.readouterr().err

    def test_no_changed_python_files_is_a_clean_zero(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "aisg.devtools.euaiact_lint.subprocess.run",
            lambda *a, **k: _Completed(0, "README.md\n"),
        )
        assert main(["--staged"]) == 0
        assert "No Python files changed" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Exclude semantics
# ---------------------------------------------------------------------------


class TestIsExcluded:
    @pytest.mark.parametrize(
        "entry",
        ["tests/fixtures", "fixtures", "tests\\fixtures", "tests/fixtures/", "/tests/fixtures"],
    )
    def test_matching_entries(self, entry):
        assert is_excluded(Path("tests/fixtures/noncompliant_sample.py"), {entry})

    def test_windows_path_matches_posix_entry(self):
        assert is_excluded(Path("tests") / "fixtures" / "sample.py", {"tests/fixtures"})

    @pytest.mark.parametrize("entry", ["fixtures/other", "tests/fixture", "ixtures", "src/tests"])
    def test_non_matching_entries(self, entry):
        assert not is_excluded(Path("tests/fixtures/noncompliant_sample.py"), {entry})

    def test_empty_entry_matches_nothing(self):
        assert not is_excluded(Path("src/app.py"), {""})
        assert not is_excluded(Path("src/app.py"), set())

    def test_directory_name_matches_anywhere(self):
        assert is_excluded(Path("a/b/__pycache__/x.py"), {"__pycache__"})

    def test_scan_directory_honours_a_multi_segment_entry(self, tmp_path):
        kept = _write(tmp_path, "src/app.py", f"x = '{TRIPWIRE}'\n")
        _write(tmp_path, "tests/fixtures/bad.py", f"x = '{TRIPWIRE}'\n")
        report = EUAIActCodeAnalyzer(rules=_rule(RULE)).scan_directory(
            tmp_path, exclude_dirs=["tests/fixtures"]
        )
        assert report.scanned_files == [str(kept)]
        assert [f.file for f in report.findings] == [str(kept)]


class TestPyprojectExclude:
    def test_exclude_list_in_pyproject_is_applied(self, tmp_path, monkeypatch):
        _write(tmp_path, "src/app.py", "x = 1\n")
        _write(tmp_path, "tests/fixtures/bad.py", f"x = '{TRIPWIRE}'\n")
        (tmp_path / "pyproject.toml").write_text(
            '[tool.euaiact-lint]\nexclude = ["tests/fixtures"]\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "report.json"
        code = main([".", "--rules", RULE, "--format", "json", "-o", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert code == 0
        assert data["summary"]["error_count"] == 0
        assert data["summary"]["scanned_files"] == 1

    def test_without_the_exclude_the_fixture_is_scanned(self, tmp_path, monkeypatch):
        _write(tmp_path, "src/app.py", "x = 1\n")
        _write(tmp_path, "tests/fixtures/bad.py", f"x = '{TRIPWIRE}'\n")
        (tmp_path / "pyproject.toml").write_text("[tool.euaiact-lint]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "report.json"
        code = main([".", "--rules", RULE, "--format", "json", "-o", str(out)])
        data = json.loads(out.read_text(encoding="utf-8"))
        assert code == 1
        assert data["summary"]["error_count"] == 1
        assert data["summary"]["scanned_files"] == 2


# ---------------------------------------------------------------------------
# Reporters
# ---------------------------------------------------------------------------


def _report_with_suppressions() -> ScanReport:
    report = ScanReport(scanned_files=["a.py"], skipped_files=["b.py", "c.py"], suppressed_count=1)
    return report


class TestReporters:
    # These are the keys .github/workflows/eu-ai-act-compliance.yml reads.
    WORKFLOW_KEYS = {"error_count", "warning_count", "info_count", "scanned_files"}

    def test_json_summary_keys(self):
        buf = io.StringIO()
        JSONReporter(out=buf).write(_report_with_suppressions())
        data = json.loads(buf.getvalue())
        assert list(data)[0] == "schema"
        assert data["schema"] == "aisg/1"
        summary = data["summary"]
        assert self.WORKFLOW_KEYS <= set(summary)
        assert summary["scanned_files"] == 1
        assert summary["skipped_files"] == 2
        assert summary["suppressed_count"] == 1
        assert summary["passed"] is True

    def test_terminal_prints_the_suppression_note(self):
        buf = io.StringIO()
        TerminalReporter(out=buf, color=False).write(_report_with_suppressions())
        text = buf.getvalue()
        assert "2 files skipped by `# euaiact-lint: ignore-file`" in text
        assert "1 finding suppressed by `# euaiact-lint: ignore <rule>`" in text

    def test_markdown_prints_the_suppression_note(self):
        buf = io.StringIO()
        MarkdownReporter(out=buf).write(_report_with_suppressions())
        text = buf.getvalue()
        assert "2 files skipped by `# euaiact-lint: ignore-file`" in text
        assert "1 finding suppressed by `# euaiact-lint: ignore <rule>`" in text

    def test_no_note_when_nothing_was_suppressed(self):
        buf = io.StringIO()
        TerminalReporter(out=buf, color=False).write(ScanReport(scanned_files=["a.py"]))
        assert "skipped by" not in buf.getvalue()
        assert "suppressed by" not in buf.getvalue()


# ---------------------------------------------------------------------------
# SARIF as Code Scanning validates it
# ---------------------------------------------------------------------------

# Root keys the SARIF 2.1.0 schema defines. `additionalProperties` is false at
# the root, and GitHub's upload step rejects the whole file on one extra key.
SARIF_ROOT_KEYS = {"$schema", "version", "runs", "inlineExternalProperties", "properties"}


def assert_uploadable_sarif(doc: dict) -> None:
    """
    The subset of the 2.1.0 schema that `codeql-action/upload-sarif` has
    rejected our output on, plus the neighbouring fields that would fail the
    same way. `None` is never valid where the schema wants an object or a
    string: an optional field is omitted, not nulled.
    """
    assert set(doc) <= SARIF_ROOT_KEYS, sorted(set(doc) - SARIF_ROOT_KEYS)
    assert doc["version"] == "2.1.0"
    for run in doc["runs"]:
        for rule in run["tool"]["driver"]["rules"]:
            assert isinstance(rule["id"], str) and isinstance(rule["shortDescription"]["text"], str)
            if "helpUri" in rule:
                assert isinstance(rule["helpUri"], str) and rule["helpUri"]
            if "help" in rule:
                assert isinstance(rule["help"]["text"], str)
                if "markdown" in rule["help"]:
                    assert isinstance(rule["help"]["markdown"], str)
            for tag in rule.get("properties", {}).get("tags", []):
                assert isinstance(tag, str)
        for result in run["results"]:
            assert isinstance(result["message"]["text"], str)
            for loc in result.get("locations", []) + result.get("relatedLocations", []):
                region = loc["physicalLocation"].get("region", {})
                assert region.get("startLine", 1) >= 1
                if "snippet" in region:
                    assert isinstance(region["snippet"], dict)
                    assert isinstance(region["snippet"]["text"], str)


def _finding(**overrides) -> CodeFinding:
    base = dict(
        rule_id="EU-AIA-011a",
        article="Art. 13",
        severity=Severity.WARNING,
        title="Model without documentation",
        description="",
        file="src\\app.py",
        line=3,
    )
    base.update(overrides)
    return CodeFinding(**base)


class TestSARIF:
    def _doc(self, *findings: CodeFinding, tool: str = DEFAULT_TOOL) -> dict:
        report = ScanReport(findings=list(findings), scanned_files=["src/app.py"], tool=tool)
        buf = io.StringIO()
        SARIFReporter(out=buf).write(report)
        return json.loads(buf.getvalue())

    def test_no_marker_at_the_root(self):
        """The `aisg/1` marker is a root key everywhere else; SARIF forbids it there."""
        doc = self._doc(_finding())
        assert "schema" not in doc
        assert doc["runs"][0]["properties"]["aisg_schema"] == "aisg/1"
        assert_uploadable_sarif(doc)

    def test_an_empty_snippet_is_omitted_not_null(self):
        """Code Scanning rejected `region.snippet: null` on every snippet-less finding."""
        doc = self._doc(_finding(snippet=""), _finding(snippet="class UserModel:", line=9))
        regions = [
            r["locations"][0]["physicalLocation"]["region"] for r in doc["runs"][0]["results"]
        ]
        assert "snippet" not in regions[0]
        assert regions[1]["snippet"] == {"text": "class UserModel:"}
        assert_uploadable_sarif(doc)

    def test_optional_rule_fields_are_omitted_when_empty(self):
        doc = self._doc(_finding(reference="", suggestion="", description=""))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule
        assert "markdown" not in rule["help"]
        assert rule["help"]["text"]
        assert_uploadable_sarif(doc)

    def test_paths_are_posix_and_the_driver_is_the_tool_that_ran(self):
        doc = self._doc(_finding(), tool=MISALIGN_TOOL)
        run = doc["runs"][0]
        assert run["tool"]["driver"]["name"] == MISALIGN_TOOL
        uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "src/app.py"

    def test_a_real_scan_is_uploadable(self, tmp_path):
        """The shape CI uploads: `aisg lint src examples --format sarif` on our own tree."""
        out = tmp_path / "results.sarif"
        main([str(REPO_ROOT / "src"), str(REPO_ROOT / "examples"), "-f", "sarif", "-o", str(out)])
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["runs"][0]["results"], "the self-scan has warnings; the shape check needs rows"
        assert_uploadable_sarif(doc)


# ---------------------------------------------------------------------------
# The compliance gate as CI runs it
# ---------------------------------------------------------------------------


class TestComplianceGate:
    def test_fixture_still_trips_the_linter(self, tmp_path):
        out = tmp_path / "report.json"
        code = main(
            [
                str(REPO_ROOT / "tests" / "fixtures" / "noncompliant_sample.py"),
                "-f",
                "json",
                "-o",
                str(out),
            ]
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        assert code == 1
        assert data["summary"]["error_count"] >= 1

    def test_src_and_examples_have_no_errors(self, tmp_path):
        """What `eu-ai-act-compliance.yml` gates on. A new error here fails CI."""
        out = tmp_path / "report.json"
        code = main(
            [str(REPO_ROOT / "src"), str(REPO_ROOT / "examples"), "-f", "json", "-o", str(out)]
        )
        data = json.loads(out.read_text(encoding="utf-8"))
        errors = [f for f in data["findings"] if f["severity"] == "error"]
        assert data["summary"]["error_count"] == 0, errors
        assert code == 0
        # The vocabulary files are skipped, and say so.
        assert data["summary"]["skipped_files"] >= 2
        assert data["summary"]["scanned_files"] > 50

    @staticmethod
    def _marked(tool: str) -> list[str]:
        """The files under src/ the analyzer would skip for `tool` -- read the
        way `_scan_single` reads them, so this pins what a scan honours."""
        marked = []
        for py in (REPO_ROOT / "src").rglob("*.py"):
            if has_ignore_marker(py.read_text(encoding="utf-8", errors="ignore"), tool):
                marked.append(py.relative_to(REPO_ROOT).as_posix())
        return sorted(marked)

    def test_only_the_vocabulary_files_carry_the_marker(self):
        """The marker is for files that ARE the rule tables. Nothing else earns it,
        and each tool's marker sits only on that tool's own tables."""
        assert self._marked(DEFAULT_TOOL) == [
            "src/aisg/modules/policy/code_analyzer/rules/__init__.py",
            "src/aisg/modules/policy/eu_ai_act.py",
        ]
        assert self._marked(MISALIGN_TOOL) == [
            "src/aisg/devtools/misalignment/rules/__init__.py",
        ]


class TestCITemplates:
    """The two CI files that call `aisg lint`. Both are checked into the repo,
    so both must parse, pin what they install, and never call the linter in a
    way that hides a broken run behind a findings exit."""

    GITHUB = REPO_ROOT / ".github" / "workflows" / "eu-ai-act-compliance.yml"
    GITLAB = REPO_ROOT / ".gitlab-ci-euaiact.yml"

    @staticmethod
    def _load(path: Path) -> dict:
        import yaml

        class _Loader(yaml.SafeLoader):
            pass

        # GitLab's `!reference [job, key]` is a custom tag; the value is opaque here.
        _Loader.add_constructor("!reference", lambda loader, node: loader.construct_sequence(node))
        return yaml.load(path.read_text(encoding="utf-8"), Loader=_Loader)

    def test_github_workflow_parses(self):
        doc = self._load(self.GITHUB)
        assert "eu-ai-act-lint" in doc["jobs"]

    def test_gitlab_template_parses(self):
        doc = self._load(self.GITLAB)
        assert {"eu-ai-act-full-scan", "eu-ai-act-mr-scan", "eu-ai-act-weekly-audit"} <= set(doc)

    def test_gitlab_script_entries_are_strings(self):
        """A plain `- echo "x: $Y"` is a YAML mapping, which GitLab rejects and
        which takes the whole including pipeline down with it."""
        doc = self._load(self.GITLAB)

        def flat(items):
            for item in items:
                if isinstance(item, list):
                    yield from flat(item)
                else:
                    yield item

        for job, body in doc.items():
            if not isinstance(body, dict):
                continue
            for key in ("before_script", "script", "after_script"):
                for entry in flat(body.get(key) or []):
                    assert isinstance(entry, str), (job, key, entry)

    def test_gitlab_template_pins_the_package_to_pyproject(self):
        """The template installs from this project's own repository at a tag
        that tracks pyproject.toml, never from PyPI by name: that name belongs
        to an unrelated package, so a PyPI spec would install someone else's
        code."""
        import re

        doc = self._load(self.GITLAB)
        pin = doc["variables"]["AISG_VERSION"]
        m = re.search(r'^version\s*=\s*"([^"]+)"', (REPO_ROOT / "pyproject.toml").read_text(), re.M)
        assert m and pin == m.group(1), (pin, m and m.group(1))
        assert doc["variables"]["AISG_SOURCE"].startswith("git+https://github.com/ai-safe-earth/")
        install = " ".join(doc[".eu-ai-act-base"]["before_script"])
        assert "ai-safety-guardrails[devtools] @ ${AISG_SOURCE}@v${AISG_VERSION}" in install, (
            install
        )
        text = self.GITLAB.read_text(encoding="utf-8")
        assert not re.search(r"ai-safety-guardrails(\[[^\]]*\])?==", text), "PyPI spec by name"
        assert "pip install pyyaml" not in text

    @pytest.mark.parametrize("path", [GITHUB, GITLAB], ids=["github", "gitlab"])
    def test_every_gated_lint_call_tolerates_only_exit_1(self, path: Path):
        """`aisg lint ... || [ $? -eq 1 ]` lets findings through to the verdict
        step; a bare `|| true` or `|| EXIT_CODE=1` would also swallow exit 2 --
        or, after a `git diff`, turn a bad revision into "nothing to scan"."""
        text = path.read_text(encoding="utf-8")
        assert "|| true" not in text
        assert "EXIT_CODE=1" not in text
        assert "[ $? -eq 1 ]" in text
