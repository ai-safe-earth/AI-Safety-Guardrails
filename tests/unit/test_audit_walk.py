"""tests/unit/test_audit_walk.py
----------------------------
Walker for `aisg audit`: skip dirs, gitignore-lite semantics, binary/size/marker skips,
symlink -> UnknownItem, unit assignment, the `.env*` hard exception, `--include-ignored`,
and the `git_meta` / `file_age` read-only git helpers.

Every relpath compared here is POSIX so the tests behave the same on Windows and Linux.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aisg.devtools.audit.model import SCHEMA_VERSION, UnknownCategory
from aisg.devtools.audit.patterns import AUDIT_DIR, IGNORE_MARKER, OWN_HTML_MARKER_LINE
from aisg.devtools.audit.walk import (
    FileRecord,
    GitIgnore,
    WalkOptions,
    file_age,
    git_meta,
    has_ignore_marker,
    is_own_html,
    is_own_report,
    read_text,
    unit_of,
    walk,
)

GIT = shutil.which("git")
needs_git = pytest.mark.skipif(GIT is None, reason="git not on PATH")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _touch(root: Path, relpath: str, text: str = "x\n") -> Path:
    path = root / Path(*relpath.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def _rels(records: list[FileRecord]) -> list[str]:
    return [r.relpath for r in records]


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        [
            "git",
            "-c",
            "user.email=audit@example.com",
            "-c",
            "user.name=audit",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout


def _init_repo(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "init")


# ---------------------------------------------------------------------------
# skip dirs and dotdirs
# ---------------------------------------------------------------------------


class TestSkipDirs:
    def test_skip_dirs_pruned_but_dotdirs_walked(self, tmp_path: Path) -> None:
        _touch(tmp_path, "node_modules/pkg/index.js")
        _touch(tmp_path, ".venv/lib/site.py")
        _touch(tmp_path, "src/__pycache__/x.pyc")
        _touch(tmp_path, ".claude/settings.json", "{}\n")
        _touch(tmp_path, ".cursor/mcp.json", "{}\n")
        _touch(tmp_path, "src/app.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == [
            ".claude/settings.json",
            ".cursor/mcp.json",
            "src/app.py",
        ]

    def test_slash_entry_prunes_by_relpath_only(self, tmp_path: Path) -> None:
        _touch(tmp_path, ".vscode/extensions/foo/package.json", "{}\n")
        _touch(tmp_path, ".vscode/settings.json", "{}\n")
        _touch(tmp_path, "extensions/keep.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == [".vscode/settings.json", "extensions/keep.py"]

    def test_records_are_sorted_and_absolute(self, tmp_path: Path) -> None:
        _touch(tmp_path, "z.py")
        _touch(tmp_path, "a/b.py")
        _touch(tmp_path, "m.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == sorted(_rels(records))
        assert all(r.path.is_absolute() for r in records)
        assert all("\\" not in r.relpath for r in records)
        assert {r.lang for r in records} == {"python"}
        assert all(r.size == 2 for r in records)


# ---------------------------------------------------------------------------
# gitignore-lite
# ---------------------------------------------------------------------------


class TestGitIgnore:
    def test_load_without_file_is_empty(self, tmp_path: Path) -> None:
        matcher = GitIgnore.load(tmp_path)
        assert len(matcher) == 0
        assert matcher.match("anything.py") is False

    def test_blank_and_comment_lines_ignored(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "\n# comment\n   \n")
        assert len(matcher) == 0

    def test_basename_pattern_matches_at_any_depth(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "*.log\n")
        assert matcher.match("a.log") is True
        assert matcher.match("deep/er/b.log") is True
        assert matcher.match("deep/er/b.txt") is False

    def test_star_does_not_cross_slash(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "/src/*.py\n")
        assert matcher.match("src/a.py") is True
        assert matcher.match("src/pkg/a.py") is False

    def test_double_star_crosses_slash(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "docs/**/*.md\n**/temp\n")
        assert matcher.match("docs/a/b/x.md") is True
        assert matcher.match("docs/x.md") is True
        assert matcher.match("other/x.md") is False
        assert matcher.match("temp", is_dir=True) is True
        assert matcher.match("a/b/temp", is_dir=True) is True

    def test_leading_slash_anchors_to_ignore_file_dir(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "/build/\n")
        assert matcher.match("build", is_dir=True) is True
        assert matcher.match("build/x.o") is True
        assert matcher.match("src/build", is_dir=True) is False
        assert matcher.match("src/build/x", is_dir=False) is False

    def test_root_anchored_audit_does_not_swallow_nested_audit(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "/audit/\n")
        assert matcher.match("audit", is_dir=True) is True
        assert matcher.match("src/aisg/devtools/audit", is_dir=True) is False
        assert matcher.match("src/aisg/devtools/audit/walk.py") is False

    def test_trailing_slash_is_directory_only(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "logs/\n")
        assert matcher.match("logs", is_dir=True) is True
        assert matcher.match("logs", is_dir=False) is False
        assert matcher.match("logs/today.log") is True
        assert matcher.match("srv/logs", is_dir=True) is True

    def test_negation_last_match_wins(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "*.log\n!keep.log\n")
        assert matcher.match("a/drop.log") is True
        assert matcher.match("a/keep.log") is False
        matcher.add("", "keep.log\n")
        assert matcher.match("a/keep.log") is True

    def test_cannot_reinclude_under_ignored_directory(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "out/\n!out/keep.txt\n")
        assert matcher.match("out/keep.txt") is True

    def test_nested_ignore_file_scopes_to_its_directory(self) -> None:
        matcher = GitIgnore()
        matcher.add("sub", "/secret.txt\nlocal.*\n")
        assert matcher.match("sub/secret.txt") is True
        assert matcher.match("sub/deep/secret.txt") is False
        assert matcher.match("secret.txt") is False
        assert matcher.match("other/secret.txt") is False
        assert matcher.match("sub/deep/local.cfg") is True
        assert matcher.match("local.cfg") is False

    def test_env_files_never_ignored_by_match_but_would_ignore_is_raw(self) -> None:
        matcher = GitIgnore()
        matcher.add("", ".env\n.env.*\n*.txt\n")
        assert matcher.would_ignore(".env") is True
        assert matcher.would_ignore("cfg/.env.local") is True
        assert matcher.match(".env") is False
        assert matcher.match("cfg/.env.local") is False
        assert matcher.match("notes.txt") is True
        assert matcher.would_ignore("notes.txt") is True

    def test_audit_dir_never_ignored_by_match_but_would_ignore_is_raw(self) -> None:
        # The skill proposes `.aisg-audit/` for .gitignore; the reports it writes there
        # must stay evidence after the line lands. Both the directory and its files.
        matcher = GitIgnore()
        matcher.add("", f"{AUDIT_DIR}/\n*.json\n")
        assert matcher.would_ignore(AUDIT_DIR, is_dir=True) is True
        assert matcher.would_ignore(f"{AUDIT_DIR}/measure.json") is True
        assert matcher.match(AUDIT_DIR, is_dir=True) is False
        assert matcher.match(f"{AUDIT_DIR}/measure.json") is False
        assert matcher.match(f"{AUDIT_DIR}/deep/probe.json") is False
        # Only the exact directory: a sibling with the same prefix is not exempt.
        assert matcher.match(f"{AUDIT_DIR}-old/x.json") is True
        assert matcher.match("other.json") is True

    def test_windows_separators_normalised(self) -> None:
        matcher = GitIgnore()
        matcher.add("", "/build/\n")
        assert matcher.match("build\\x.o") is True


# ---------------------------------------------------------------------------
# gitignore in walk(): .env hard exception and --include-ignored
# ---------------------------------------------------------------------------


class TestWalkGitIgnore:
    def _tree(self, root: Path) -> None:
        _touch(root, ".gitignore", ".env\n.env.*\nnotes.txt\n.envrc\nbuild_out/\n")
        _touch(root, ".env", "SECRET=1\n")
        _touch(root, ".env.local", "SECRET=2\n")
        _touch(root, ".envrc", "export X=1\n")
        _touch(root, "notes.txt", "private\n")
        _touch(root, "app.py", "print(1)\n")
        _touch(root, "build_out/gen.py", "x = 1\n")

    def test_gitignored_env_is_still_walked_and_flagged(self, tmp_path: Path) -> None:
        self._tree(tmp_path)

        records, _, _ = walk(tmp_path)
        by_rel = {r.relpath: r for r in records}

        assert set(by_rel) == {".env", ".env.local", ".gitignore", "app.py"}
        assert by_rel[".env"].gitignored is True
        assert by_rel[".env.local"].gitignored is True
        assert by_rel[".env"].lang == "config"
        assert by_rel["app.py"].gitignored is False

    def test_include_ignored_returns_everything_with_flags(self, tmp_path: Path) -> None:
        self._tree(tmp_path)

        records, _, _ = walk(tmp_path, WalkOptions(include_ignored=True))
        by_rel = {r.relpath: r for r in records}

        assert set(by_rel) == {
            ".env",
            ".env.local",
            ".envrc",
            ".gitignore",
            "app.py",
            "build_out/gen.py",
            "notes.txt",
        }
        assert by_rel["notes.txt"].gitignored is True
        assert by_rel[".envrc"].gitignored is True
        assert by_rel["build_out/gen.py"].gitignored is True
        assert by_rel[".env"].gitignored is True
        assert by_rel["app.py"].gitignored is False

    def test_nested_gitignore_honoured_during_walk(self, tmp_path: Path) -> None:
        _touch(tmp_path, "sub/.gitignore", "/local_only.py\n")
        _touch(tmp_path, "sub/local_only.py")
        _touch(tmp_path, "sub/keep.py")
        _touch(tmp_path, "local_only.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == ["local_only.py", "sub/.gitignore", "sub/keep.py"]

    def test_pruned_gitignored_directories_are_reported_as_unknown(self, tmp_path: Path) -> None:
        """A gitignored logs/ or evals/ directory is where PII and eval corpora
        accumulate; pruning it silently would read as coverage."""
        _touch(tmp_path, ".gitignore", "logs/\nevals/\nout/\n")
        _touch(tmp_path, "app.py", "print(1)\n")
        _touch(tmp_path, "logs/agent.log", "user said hi\n")
        _touch(tmp_path, "evals/cases.jsonl", "{}\n")
        _touch(tmp_path, "svc/out/report.txt", "x\n")
        _touch(tmp_path, "svc/keep.py", "y = 1\n")

        records, _, unknown = walk(tmp_path)

        assert _rels(records) == [".gitignore", "app.py", "svc/keep.py"]
        items = [u for u in unknown if u.what == "gitignored directories skipped"]
        assert len(items) == 1
        item = items[0]
        assert item.category is UnknownCategory.RUNTIME
        assert item.why == "3 gitignored director(ies) not walked: evals, logs, svc/out"
        assert item.how_to_resolve is not None
        assert "--include-ignored" in item.how_to_resolve

    def test_include_ignored_reports_no_pruned_directories(self, tmp_path: Path) -> None:
        _touch(tmp_path, ".gitignore", "logs/\n")
        _touch(tmp_path, "logs/agent.log", "user said hi\n")
        _touch(tmp_path, "app.py", "print(1)\n")

        records, _, unknown = walk(tmp_path, WalkOptions(include_ignored=True))

        assert "logs/agent.log" in _rels(records)
        assert not [u for u in unknown if u.what == "gitignored directories skipped"]

    def test_gitignored_audit_dir_is_still_walked_and_flagged(self, tmp_path: Path) -> None:
        # A measure report the skill wrote under `.aisg-audit/` is evidence; the
        # `.gitignore` line the skill itself proposes must not make it vanish.
        _touch(tmp_path, ".gitignore", f"{AUDIT_DIR}/\n")
        _touch(tmp_path, "app.py", "print(1)\n")
        _touch(
            tmp_path,
            f"{AUDIT_DIR}/measure-report.json",
            '{"schema": "aisg/1", "kind": "measure", "guards": []}\n',
        )

        records, _, unknown = walk(tmp_path)
        by_rel = {r.relpath: r for r in records}

        assert set(by_rel) == {".gitignore", "app.py", f"{AUDIT_DIR}/measure-report.json"}
        assert by_rel[f"{AUDIT_DIR}/measure-report.json"].gitignored is True
        assert not [u for u in unknown if u.what == "gitignored directories skipped"]

    def test_long_pruned_directory_list_is_truncated(self, tmp_path: Path) -> None:
        names = [f"d{i}" for i in range(8)]
        _touch(tmp_path, ".gitignore", "".join(f"{n}/\n" for n in names))
        for n in names:
            _touch(tmp_path, f"{n}/f.txt")

        _, _, unknown = walk(tmp_path)

        item = next(u for u in unknown if u.what == "gitignored directories skipped")
        assert item.why == "8 gitignored director(ies) not walked: d0, d1, d2, d3, d4, d5, +2 more"


# ---------------------------------------------------------------------------
# file guards: binary, size, marker, unreadable
# ---------------------------------------------------------------------------


class TestFileGuards:
    def test_binary_with_nul_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "blob.bin").write_bytes(b"abc\x00def")
        _touch(tmp_path, "text.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == ["text.py"]

    def test_oversize_skipped(self, tmp_path: Path) -> None:
        _touch(tmp_path, "big.py", "x" * 101 + "\n")
        _touch(tmp_path, "small.py", "x" * 50 + "\n")

        records, _, _ = walk(tmp_path, WalkOptions(max_size=100))

        assert _rels(records) == ["small.py"]

    def test_oversize_skip_is_an_unknown_row_and_fills_the_sink(self, tmp_path: Path) -> None:
        """A file over max_size was never opened, so it was never audited. It used to
        vanish: no counter, no row. UNKNOWN is listed, never hidden."""
        _touch(tmp_path, "logs/dump.log", "x" * 200 + "\n")
        _touch(tmp_path, "big.py", "x" * 101 + "\n")
        _touch(tmp_path, "small.py", "x" * 50 + "\n")
        sink: list[str] = []

        records, _, unknown = walk(tmp_path, WalkOptions(max_size=100), oversize_skipped=sink)

        assert _rels(records) == ["small.py"]
        assert sink == ["big.py", "logs/dump.log"]
        items = [u for u in unknown if u.what == "oversize files skipped"]
        assert len(items) == 1
        item = items[0]
        assert item.category is UnknownCategory.RUNTIME
        assert item.why.startswith("2 file(s) over the 100 byte limit")
        assert "big.py" in item.why and "logs/dump.log" in item.why
        assert "size limit" in item.how_to_resolve
        assert "audit those files directly" in item.how_to_resolve

    def test_oversize_row_names_a_few_paths_and_counts_the_rest(self, tmp_path: Path) -> None:
        for i in range(5):
            _touch(tmp_path, f"f{i}.py", "x" * 101 + "\n")

        _, _, unknown = walk(tmp_path, WalkOptions(max_size=100))

        item = next(u for u in unknown if u.what == "oversize files skipped")
        assert item.why.startswith("5 file(s)")
        assert "f0.py, f1.py, f2.py, +2 more" in item.why
        assert "f4.py" not in item.why

    def test_oversize_row_fires_without_the_sink(self, tmp_path: Path) -> None:
        _touch(tmp_path, "big.py", "x" * 101 + "\n")

        _, _, unknown = walk(tmp_path, WalkOptions(max_size=100))

        assert [u.what for u in unknown] == ["oversize files skipped"]

    def test_no_oversize_row_when_nothing_is_over(self, tmp_path: Path) -> None:
        _touch(tmp_path, "small.py", "x" * 50 + "\n")
        sink: list[str] = []

        _, _, unknown = walk(tmp_path, WalkOptions(max_size=100), oversize_skipped=sink)

        assert unknown == []
        assert sink == []

    def test_ignore_marker_within_first_five_lines_skips(self, tmp_path: Path) -> None:
        _touch(tmp_path, "early.py", "a\nb\n" + IGNORE_MARKER + "\nc\n")
        _touch(tmp_path, "late.py", "\n".join(["l"] * 8) + "\n" + IGNORE_MARKER + "\n")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == ["late.py"]

    def test_has_ignore_marker(self) -> None:
        assert has_ignore_marker(IGNORE_MARKER + "\n") is True
        assert has_ignore_marker("1\n2\n3\n4\n" + IGNORE_MARKER) is True
        assert has_ignore_marker("1\n2\n3\n4\n5\n" + IGNORE_MARKER) is False
        assert has_ignore_marker("") is False

    def test_unreadable_file_counted_once_never_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bad = _touch(tmp_path, "locked.py")
        _touch(tmp_path, "ok.py")
        real_stat = Path.stat

        def fake_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
            if self == bad:
                raise PermissionError("denied")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", fake_stat)

        records, _, unknown = walk(tmp_path)

        assert _rels(records) == ["ok.py"]
        items = [u for u in unknown if u.what == "unreadable files"]
        assert len(items) == 1
        assert items[0].category is UnknownCategory.RUNTIME
        assert "1" in items[0].why

    def test_symlink_skipped_and_reported_once(self, tmp_path: Path) -> None:
        real = _touch(tmp_path, "real.py")
        _touch(tmp_path, "other.py")
        try:
            os.symlink(real, tmp_path / "link.py")
            os.symlink(real, tmp_path / "link2.py")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not permitted on this machine")

        records, _, unknown = walk(tmp_path)

        assert _rels(records) == ["other.py", "real.py"]
        items = [u for u in unknown if u.what == "symlinks skipped"]
        assert len(items) == 1
        assert items[0].category is UnknownCategory.RUNTIME
        assert "2 symlink" in items[0].why
        assert items[0].how_to_resolve

    def test_symlink_path_via_islink_stub(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same contract as the real-symlink test, runnable where os.symlink is refused."""
        fake_link = _touch(tmp_path, "link.py")
        _touch(tmp_path, "real.py")
        _touch(tmp_path, "linked_dir/inner.py")
        real_islink = os.path.islink

        def fake_islink(path: object) -> bool:
            posix = str(path).replace("\\", "/")
            if posix.endswith("/link.py") or posix.endswith("/linked_dir"):
                return True
            return real_islink(path)

        monkeypatch.setattr(os.path, "islink", fake_islink)

        records, _, unknown = walk(tmp_path)

        assert fake_link.exists()
        assert _rels(records) == ["real.py"]
        items = [u for u in unknown if u.what == "symlinks skipped"]
        assert len(items) == 1
        assert items[0].category is UnknownCategory.RUNTIME
        assert "2 symlink" in items[0].why

    def test_no_unknown_items_on_plain_tree(self, tmp_path: Path) -> None:
        _touch(tmp_path, "a.py")
        _, _, unknown = walk(tmp_path)
        assert unknown == []

    def test_html_with_the_marker_comment_on_line_one_is_skipped(self, tmp_path: Path) -> None:
        """The html renderer's first line is a comment carrying the marker. It is the
        audit's own output, so it is named like the JSON report, not dropped silently."""
        _touch(tmp_path, "report.html", OWN_HTML_MARKER_LINE + "\n<p>x</p>\n")
        _touch(tmp_path, "page.html", "<p>y</p>\n")
        skipped: list[str] = []

        records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["page.html"]
        assert skipped == ["report.html"]
        assert unknown == []

    def test_marker_elsewhere_in_the_head_is_a_plain_skip(self, tmp_path: Path) -> None:
        # Only the exact renderer line names the file as own output; a hand-placed marker
        # on line two, or one with trailing text, is the ordinary ignore-file skip.
        _touch(tmp_path, "two.html", "<p>x</p>\n" + OWN_HTML_MARKER_LINE + "\n")
        _touch(tmp_path, "tail.html", OWN_HTML_MARKER_LINE + " v2\n<p>x</p>\n")
        skipped: list[str] = []

        records, _, _ = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == []
        assert skipped == []

    def test_html_with_a_bom_before_the_marker_line_is_still_own_output(
        self, tmp_path: Path
    ) -> None:
        """The head is decoded like `read_text` decodes the file: BOM stripped. With a
        plain utf-8 decode the BOM sat before the marker line, `is_own_html` said no and
        the report fell through to the silent ignore-file skip."""
        crlf = tmp_path / "crlf.html"
        crlf.write_bytes((OWN_HTML_MARKER_LINE + "\r\n<p>x</p>\r\n").encode("utf-8"))
        bom = tmp_path / "bom.html"
        bom.write_bytes(b"\xef\xbb\xbf" + (OWN_HTML_MARKER_LINE + "\n<p>x</p>\n").encode("utf-8"))
        bom_json = tmp_path / "bom.json"
        bom_json.write_bytes(b"\xef\xbb\xbf" + _report_head().encode("utf-8"))
        _touch(tmp_path, "page.html", "<p>y</p>\n")
        skipped: list[str] = []

        records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["page.html"]
        assert skipped == ["bom.html", "bom.json", "crlf.html"]
        assert unknown == []

    def test_bom_before_the_ignore_marker_still_skips(self, tmp_path: Path) -> None:
        marked = tmp_path / "vocab.py"
        marked.write_bytes(b"\xef\xbb\xbf" + (IGNORE_MARKER + "\nx = 1\n").encode("utf-8"))
        _touch(tmp_path, "app.py")

        records, _, _ = walk(tmp_path)

        assert _rels(records) == ["app.py"]

    def test_is_own_html_unit(self) -> None:
        assert is_own_html(OWN_HTML_MARKER_LINE + "\n<p>x</p>\n") is True
        assert is_own_html(OWN_HTML_MARKER_LINE + "\r\n<p>x</p>\r\n") is True
        assert is_own_html(OWN_HTML_MARKER_LINE) is True
        assert is_own_html(" " + OWN_HTML_MARKER_LINE + "\n") is False
        assert is_own_html("<p>x</p>\n" + OWN_HTML_MARKER_LINE + "\n") is False
        assert is_own_html(IGNORE_MARKER + "\n") is False
        assert is_own_html("") is False


# ---------------------------------------------------------------------------
# own output: a report the audit wrote is not audited again
# ---------------------------------------------------------------------------


def _report_head(kind: str = "audit", sep: str = " ") -> str:
    return (
        "{" + f'"schema":{sep}"{SCHEMA_VERSION}", "kind":{sep}"{kind}", "generated_at": "x"' + "}\n"
    )


def _sarif_head(
    *, sep: str = " ", second_key: str = "own_output_skipped", bag_first: bool = True
) -> str:
    """A SARIF document in the shape `report.to_sarif` writes: the run's property bag
    first, `aisg_schema` then `own_output_skipped`. `bag_first=False` puts the bag after
    `results`, past the head, the way it used to be written."""
    bag = (
        "      "
        + f'"properties":{sep}'
        + "{\n"
        + f'        "aisg_schema":{sep}"{SCHEMA_VERSION}",\n'
        + f'        "{second_key}":{sep}[]\n'
        + "      }"
    )
    tool = '      "tool": {"driver": {"name": "x", "version": "0", "rules": []}}'
    # 10 KB of results: more than the HEAD_BYTES the walker reads.
    results = '      "results": [' + ("{}, " * 2500) + "{}]"
    body = [bag, tool, results] if bag_first else [tool, results, bag]
    return (
        '{\n  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",\n'
        '  "version": "2.1.0",\n  "runs": [\n    {\n' + ",\n".join(body) + "\n    }\n  ]\n}\n"
    )


class TestOwnOutput:
    def test_own_report_skipped_named_in_sink_and_not_unknown(self, tmp_path: Path) -> None:
        _touch(tmp_path, ".aisg-audit/report.json", _report_head())
        _touch(tmp_path, "app.py")
        skipped: list[str] = []

        records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["app.py"]
        assert skipped == [".aisg-audit/report.json"]
        assert unknown == []

    def test_sink_is_optional(self, tmp_path: Path) -> None:
        _touch(tmp_path, "report.json", _report_head())
        _touch(tmp_path, "app.py")

        records, _, unknown = walk(tmp_path)

        assert _rels(records) == ["app.py"]
        assert unknown == []

    def test_inventory_document_is_own_output(self, tmp_path: Path) -> None:
        # `aisg audit --inventory-only` writes `"kind": "inventory"`; it lists every
        # secret shape and over-grant the audit found, so scanning it would double each.
        _touch(tmp_path, "inventory.json", _report_head(kind="inventory"))
        _touch(tmp_path, "app.py")
        skipped: list[str] = []

        records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["app.py"]
        assert skipped == ["inventory.json"]
        assert unknown == []

    def test_baseline_and_schemaless_json_stay_walked(self, tmp_path: Path) -> None:
        _touch(tmp_path, "baseline.json", _report_head(kind="audit-baseline"))
        _touch(tmp_path, "plain.json", '{"kind": "audit", "items": []}\n')
        _touch(tmp_path, "other.json", '{"schema": "' + SCHEMA_VERSION + '", "items": []}\n')
        skipped: list[str] = []

        records, _, _ = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["baseline.json", "other.json", "plain.json"]
        assert skipped == []

    def test_whitespace_after_the_colon_is_optional(self, tmp_path: Path) -> None:
        _touch(tmp_path, "tight.json", _report_head(sep=""))
        _touch(tmp_path, "loose.json", _report_head(sep="   "))
        skipped: list[str] = []

        records, _, _ = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == []
        assert skipped == ["loose.json", "tight.json"]

    def test_own_output_skipped_is_sorted(self, tmp_path: Path) -> None:
        # Create in reverse alpha order so a creation-order sink would fail the assert.
        _touch(tmp_path, "z.json", _report_head())
        _touch(tmp_path, "m.json", _report_head())
        _touch(tmp_path, "a.json", _report_head())
        skipped: list[str] = []

        walk(tmp_path, own_output_skipped=skipped)

        assert skipped == ["a.json", "m.json", "z.json"]

    def test_only_json_names_are_own_output(self, tmp_path: Path) -> None:
        _touch(tmp_path, "report.txt", _report_head())
        _touch(tmp_path, "report.py", "x = " + _report_head())
        skipped: list[str] = []

        records, _, _ = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["report.py", "report.txt"]
        assert skipped == []

    def test_is_own_report_unit(self) -> None:
        head = _report_head()
        assert is_own_report("r.json", head) is True
        assert is_own_report("R.JSON", head) is True
        assert is_own_report("r.jsonl", head) is False
        assert is_own_report("r.json", _report_head(kind="audit-baseline")) is False
        assert is_own_report("r.json", _report_head(kind="inventory")) is True
        assert is_own_report("r.json", _report_head(kind="measure")) is False
        assert is_own_report("r.json", '{"kind": "audit"}') is False
        assert is_own_report("r.json", "") is False
        # The JSON-report shape is not a SARIF marker: a `.sarif` needs the run bag.
        assert is_own_report("r.sarif", head) is False

    def test_sarif_with_the_run_property_bag_first_is_own_output(self, tmp_path: Path) -> None:
        """`report.to_sarif` writes the run's property bag first, `aisg_schema` then
        `own_output_skipped`. Before that the bag came after `results`, past the head
        the walker reads, so the audit's SARIF was scanned like any other file and
        reproduced its own findings on the next run."""
        _touch(tmp_path, ".aisg-audit/audit.sarif", _sarif_head())
        _touch(tmp_path, "audit-as-json.json", _sarif_head())
        _touch(tmp_path, "app.py")
        skipped: list[str] = []

        records, _, unknown = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["app.py"]
        assert sorted(skipped) == [".aisg-audit/audit.sarif", "audit-as-json.json"]
        assert unknown == []

    def test_sarif_of_another_aisg_tool_stays_walked(self, tmp_path: Path) -> None:
        # `aisg lint --format sarif` carries the same `aisg_schema` marker in its run
        # bag, but not the audit's second key. It is not our output; it is scanned.
        _touch(tmp_path, "lint.sarif", _sarif_head(second_key="scanned_files"))
        _touch(tmp_path, "later.sarif", _sarif_head(bag_first=False))
        skipped: list[str] = []

        records, _, _ = walk(tmp_path, own_output_skipped=skipped)

        assert _rels(records) == ["later.sarif", "lint.sarif"]
        assert skipped == []

    def test_is_own_report_sarif_unit(self) -> None:
        assert is_own_report("r.sarif", _sarif_head()) is True
        assert is_own_report("R.SARIF", _sarif_head()) is True
        assert is_own_report("r.json", _sarif_head()) is True
        assert is_own_report("r.sarif", _sarif_head(sep="")) is True
        assert is_own_report("r.sarif", _sarif_head(second_key="scanned_files")) is False
        assert is_own_report("r.txt", _sarif_head()) is False
        assert is_own_report("r.sarif", "") is False


# ---------------------------------------------------------------------------
# read_text
# ---------------------------------------------------------------------------


class TestReadText:
    def test_strips_bom_and_decodes(self, tmp_path: Path) -> None:
        path = tmp_path / "bom.txt"
        path.write_bytes(b"\xef\xbb\xbfhello\n")
        assert read_text(path) == "hello\n"

    def test_invalid_utf8_replaced(self, tmp_path: Path) -> None:
        path = tmp_path / "latin.txt"
        path.write_bytes(b"caf\xe9\n")
        text = read_text(path)
        assert text is not None
        assert "caf" in text

    def test_none_on_nul_size_and_missing(self, tmp_path: Path) -> None:
        nul = tmp_path / "nul.bin"
        nul.write_bytes(b"a\x00b")
        big = tmp_path / "big.txt"
        big.write_bytes(b"x" * 200)
        assert read_text(nul) is None
        assert read_text(big, max_size=100) is None
        assert read_text(big, max_size=200) == "x" * 200
        assert read_text(tmp_path / "missing.txt") is None


# ---------------------------------------------------------------------------
# units
# ---------------------------------------------------------------------------


class TestUnits:
    def test_root_and_nested_manifest_units(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pyproject.toml", "[project]\nname='x'\n")
        _touch(tmp_path, "app/main.py")
        _touch(tmp_path, "services/api/package.json", "{}\n")
        _touch(tmp_path, "services/api/src/index.ts")
        _touch(tmp_path, "services/api/README.md")

        records, units, _ = walk(tmp_path)

        assert [(u.id, u.root, u.manifest, u.language) for u in units] == [
            ("u0", ".", "pyproject.toml", "python"),
            ("u1", "services/api", "services/api/package.json", "typescript"),
        ]
        by_rel = {r.relpath: r.unit for r in records}
        assert by_rel["app/main.py"] == "u0"
        assert by_rel["pyproject.toml"] == "u0"
        assert by_rel["services/api/src/index.ts"] == "u1"
        assert by_rel["services/api/package.json"] == "u1"
        assert by_rel["services/api/README.md"] == "u1"

    def test_units_numbered_in_sorted_root_order(self, tmp_path: Path) -> None:
        _touch(tmp_path, "b/package.json", "{}\n")
        _touch(tmp_path, "a/go.mod", "module a\n")
        _touch(tmp_path, "c/svc/Api.csproj", "<Project/>\n")
        _touch(tmp_path, "c/svc/Program.cs")

        _, units, _ = walk(tmp_path)

        assert [(u.id, u.root, u.language) for u in units] == [
            ("u0", ".", "unknown"),
            ("u1", "a", "go"),
            ("u2", "b", "typescript"),
            ("u3", "c/svc", "dotnet"),
        ]
        assert units[3].manifest == "c/svc/Api.csproj"
        assert units[0].manifest is None

    def test_manifest_kinds_map_to_languages(self, tmp_path: Path) -> None:
        cases = {
            "p1/setup.py": "python",
            "p2/requirements.txt": "python",
            "r/Cargo.toml": "rust",
            "j1/pom.xml": "jvm",
            "j2/build.gradle": "jvm",
            "rb/Gemfile": "ruby",
        }
        for rel in cases:
            _touch(tmp_path, rel)

        _, units, _ = walk(tmp_path)

        langs = {u.root: u.language for u in units if u.root != "."}
        assert langs == {rel.rsplit("/", 1)[0]: lang for rel, lang in cases.items()}

    def test_manifest_less_root_takes_majority_language(self, tmp_path: Path) -> None:
        _touch(tmp_path, "a.py")
        _touch(tmp_path, "b.py")
        _touch(tmp_path, "c.ts")
        _touch(tmp_path, "README.md")
        _touch(tmp_path, "cfg.yaml")

        _, units, _ = walk(tmp_path)

        assert units[0].id == "u0"
        assert units[0].manifest is None
        assert units[0].language == "python"

    def test_manifest_less_root_without_code_is_unknown(self, tmp_path: Path) -> None:
        _touch(tmp_path, "README.md")
        _, units, _ = walk(tmp_path)
        assert units[0].language == "unknown"

    def test_root_vote_excludes_files_of_nested_units(self, tmp_path: Path) -> None:
        _touch(tmp_path, "top.py")
        _touch(tmp_path, "web/package.json", "{}\n")
        for i in range(5):
            _touch(tmp_path, f"web/src/{i}.ts")

        _, units, _ = walk(tmp_path)

        assert units[0].language == "python"
        assert units[1].language == "typescript"

    def test_unit_of_nearest_ancestor(self, tmp_path: Path) -> None:
        _touch(tmp_path, "pyproject.toml")
        _touch(tmp_path, "svc/package.json", "{}\n")
        _touch(tmp_path, "svc/inner/go.mod", "module inner\n")
        _, units, _ = walk(tmp_path)

        assert unit_of("x.py", units) == "u0"
        assert unit_of("svc/a.ts", units) == "u1"
        assert unit_of("svc/inner/main.go", units) == "u2"
        assert unit_of("svcother/a.ts", units) == "u0"
        assert unit_of("svc\\inner\\deep\\x.go", units) == "u2"


# ---------------------------------------------------------------------------
# --exclude
# ---------------------------------------------------------------------------


class TestExclude:
    def _tree(self, root: Path) -> None:
        _touch(root, "src/app.py")
        _touch(root, "tests/test_app.py")
        _touch(root, "tests/deep/test_x.py")
        _touch(root, "docs/index.md")
        _touch(root, "docs/guide/a.md")
        _touch(root, "contests/x.py")

    def test_bare_directory_name_prunes_subtree(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        records, _, _ = walk(tmp_path, WalkOptions(exclude=("tests",)))
        assert _rels(records) == [
            "contests/x.py",
            "docs/guide/a.md",
            "docs/index.md",
            "src/app.py",
        ]

    def test_glob_suffix_works(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        records, _, _ = walk(tmp_path, WalkOptions(exclude=("docs/**",)))
        assert "docs/index.md" not in _rels(records)
        assert "docs/guide/a.md" not in _rels(records)
        assert "src/app.py" in _rels(records)

    def test_fnmatch_on_relpath_and_ancestors(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        records, _, _ = walk(tmp_path, WalkOptions(exclude=("*.md", "tests/dee*")))
        assert _rels(records) == [
            "contests/x.py",
            "src/app.py",
            "tests/test_app.py",
        ]

    def test_exclude_does_not_prune_unrelated_prefix(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        records, _, _ = walk(tmp_path, WalkOptions(exclude=("test",)))
        assert "tests/test_app.py" in _rels(records)


# ---------------------------------------------------------------------------
# real fixture
# ---------------------------------------------------------------------------


class TestFixture:
    def test_py_agent_enumerates_host_configs_and_code(self, audit_fixture) -> None:
        records, units, unknown = walk(audit_fixture("py_agent"))
        rels = set(_rels(records))

        assert {
            ".claude/settings.json",
            ".mcp.json",
            "app.py",
            "tools.py",
            "prompts/system.md",
        } <= rels
        assert units[0].id == "u0"
        assert units[0].language == "python"
        assert not any(r.gitignored for r in records)
        assert unknown == []

    def test_audit_package_skips_marker_files(self) -> None:
        # Exactly the vocabulary modules carry the marker: the ones that spell out every
        # literal the audit looks for and would otherwise report themselves. Nothing
        # else may -- a real finding in the rest goes in the baseline with a reason.
        here = Path(__file__).resolve().parents[2] / "src" / "aisg" / "devtools" / "audit"
        marked = {
            p.relative_to(here).as_posix()
            for p in here.rglob("*.py")
            if "__pycache__" not in p.parts
            and has_ignore_marker(p.read_text(encoding="utf-8", errors="replace"))
        }
        rules = {p.relative_to(here).as_posix() for p in (here / "rules").glob("*.py")}
        assert rules
        assert marked == rules | {"adapters.py", "discover.py", "patterns.py", "vocab.py"}
        for name in (
            "html.py",
            "main.py",
            "model.py",
            "report.py",
            "walk.py",
            "baseline.py",
            "pydeep.py",
        ):
            assert (here / name).is_file(), name
            assert name not in marked

        records, _, _ = walk(here)
        rels = set(_rels(records))
        assert "walk.py" in rels
        assert "html.py" in rels
        assert not (marked & rels)


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------


@needs_git
class TestGitMeta:
    def test_sha_and_dirty_flag(self, tmp_path: Path) -> None:
        _touch(tmp_path, "a.py")
        _init_repo(tmp_path)

        sha, dirty = git_meta(tmp_path)

        assert sha is not None
        assert len(sha) == 40
        assert all(c in "0123456789abcdef" for c in sha)
        assert dirty is False

        _touch(tmp_path, "b.py")
        sha2, dirty2 = git_meta(tmp_path)
        assert sha2 == sha
        assert dirty2 is True

    def test_non_repo_returns_none_false(self, tmp_path: Path) -> None:
        probe = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(tmp_path),
            capture_output=True,
            encoding="utf-8",
            errors="replace",
        )
        if probe.returncode == 0 and probe.stdout.strip() == "true":
            pytest.skip("tmp_path lives inside a git work tree")
        assert git_meta(tmp_path) == (None, False)


class TestGitAbsent:
    def test_git_missing_returns_none_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_git(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("git")

        monkeypatch.setattr(subprocess, "run", no_git)
        assert git_meta(tmp_path) == (None, False)

    def test_git_missing_makes_age_unknown(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_git(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("git")

        monkeypatch.setattr(subprocess, "run", no_git)
        assert file_age(tmp_path / "missing.json", tmp_path) == (None, "unknown")


class TestFileAge:
    def test_mtime_is_utc_aware(self, tmp_path: Path) -> None:
        path = _touch(tmp_path, "report.json", "{}\n")

        when, source = file_age(path, tmp_path)

        assert source == "mtime"
        assert when is not None
        assert when.tzinfo is timezone.utc
        assert abs((datetime.now(timezone.utc) - when).total_seconds()) < 300

    @needs_git
    def test_git_fallback_when_stat_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _touch(tmp_path, "dated.txt", "v1\n")
        _init_repo(tmp_path)
        real_stat = Path.stat

        def fake_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
            if self == path:
                raise OSError("stat failed")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", fake_stat)

        when, source = file_age(path, tmp_path)

        assert source == "git"
        assert when is not None
        assert when.tzinfo is timezone.utc
        assert abs((datetime.now(timezone.utc) - when).total_seconds()) < 600

    @pytest.mark.parametrize(
        ("stamp", "expected"),
        [
            # git writes a UTC committer date with a `Z` suffix, which
            # datetime.fromisoformat rejects before 3.11; both forms must parse.
            ("2026-09-03T21:46:25Z", datetime(2026, 9, 3, 21, 46, 25, tzinfo=timezone.utc)),
            ("2026-09-03T21:46:25+00:00", datetime(2026, 9, 3, 21, 46, 25, tzinfo=timezone.utc)),
            ("2026-09-03T23:46:25+02:00", datetime(2026, 9, 3, 21, 46, 25, tzinfo=timezone.utc)),
        ],
    )
    def test_git_date_forms_parse_on_every_supported_python(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stamp: str, expected: datetime
    ) -> None:
        # Independent of the git on PATH: the git call is replaced by its output.
        from aisg.devtools.audit import walk as walk_mod

        path = _touch(tmp_path, "dated.txt", "v1\n")
        real_stat = Path.stat

        def fake_stat(self: Path, *args: object, **kwargs: object) -> os.stat_result:
            if self == path:
                raise OSError("stat failed")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", fake_stat)
        monkeypatch.setattr(walk_mod, "_git", lambda args, cwd: stamp + "\n")

        when, source = file_age(path, tmp_path)

        assert source == "git"
        assert when == expected
        assert when is not None and when.tzinfo is timezone.utc

    @needs_git
    def test_unknown_when_stat_and_git_both_fail(self, tmp_path: Path) -> None:
        _touch(tmp_path, "tracked.txt")
        _init_repo(tmp_path)
        ghost = tmp_path / "never_existed.json"

        assert file_age(ghost, tmp_path) == (None, "unknown")

    def test_unknown_outside_any_repo(self, tmp_path: Path) -> None:
        probe = None
        if GIT is not None:
            probe = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(tmp_path),
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
        if probe is not None and probe.returncode == 0 and probe.stdout.strip() == "true":
            pytest.skip("tmp_path lives inside a git work tree")
        assert file_age(tmp_path / "nope.txt", tmp_path) == (None, "unknown")
