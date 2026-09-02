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

from aisg.devtools.audit.model import UnknownCategory
from aisg.devtools.audit.patterns import IGNORE_MARKER
from aisg.devtools.audit.walk import (
    FileRecord,
    GitIgnore,
    WalkOptions,
    file_age,
    git_meta,
    has_ignore_marker,
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
        here = Path(__file__).resolve().parents[2] / "src" / "aisg" / "devtools" / "audit"
        records, _, _ = walk(here)
        rels = set(_rels(records))
        assert "walk.py" in rels
        assert "patterns.py" not in rels
        assert "vocab.py" not in rels


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
