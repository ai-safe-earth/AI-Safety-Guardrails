"""tests/unit/test_git_fetch.py
----------------------------
`aisg.devtools._git` is the one pinned-fetch implementation behind `bench/run.py` and `aisg
fleet`. These tests run it against a local repository created on the spot (no network): an
exact commit is reached and stamped, a second call is a cache hit, a short id falls back to
the branch history, and every failure is a one-line `GitError`.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from aisg.devtools._git import STAMP_FILE, GitError, clone_shallow, fetch_pinned, head_sha

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("_git opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, check=True, timeout=60
    ).stdout.strip()


@pytest.fixture
def origin(tmp_path: Path) -> tuple[Path, list[str]]:
    """A local repository with two commits on `main`; returns (path, [sha1, sha2])."""
    repo = tmp_path / "origin"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.test")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "a.py")
    _git(repo, "commit", "-q", "-m", "one")
    first = _git(repo, "rev-parse", "HEAD")
    (repo / "a.py").write_text("x = 2\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "two")
    second = _git(repo, "rev-parse", "HEAD")
    return repo, [first, second]


@needs_git
class TestFetchPinned:
    def test_reaches_the_exact_commit_and_stamps_it(self, tmp_path: Path, origin):
        repo, (first, second) = origin
        dest = tmp_path / "dest"
        resolved = fetch_pinned(str(repo), first, dest, branch="main", timeout=120)
        assert resolved == first
        assert head_sha(dest) == first
        assert (dest / STAMP_FILE).read_text(encoding="utf-8") == first
        assert (dest / "a.py").read_text(encoding="utf-8") == "x = 1\n"

    def test_second_call_with_the_same_sha_is_a_cache_hit(
        self, tmp_path: Path, origin, monkeypatch
    ):
        repo, (first, _) = origin
        dest = tmp_path / "dest"
        fetch_pinned(str(repo), first, dest, timeout=120)
        from aisg.devtools import _git as module

        def boom(*args, **kwargs):
            raise AssertionError("git was run on a cache hit")

        monkeypatch.setattr(module, "_run", boom)
        assert fetch_pinned(str(repo), first, dest, timeout=120) == first

    def test_short_id_falls_back_to_the_branch_history(self, tmp_path: Path, origin):
        repo, (first, _) = origin
        dest = tmp_path / "dest"
        resolved = fetch_pinned(str(repo), first[:8], dest, branch="main", timeout=120)
        assert resolved == first
        assert (dest / STAMP_FILE).read_text(encoding="utf-8") == first

    def test_without_a_sha_it_clones_the_tip(self, tmp_path: Path, origin):
        repo, (_, second) = origin
        dest = tmp_path / "dest"
        assert fetch_pinned(str(repo), None, dest, branch="main", timeout=120) == second
        assert clone_shallow(str(repo), tmp_path / "dest2", timeout=120) == second

    def test_failures_are_one_line_git_errors(self, tmp_path: Path, origin):
        repo, _ = origin
        with pytest.raises(GitError, match="not a commit id"):
            fetch_pinned(str(repo), "zz", tmp_path / "d1", timeout=120)
        with pytest.raises(GitError, match="git (fetch|checkout|clone) failed"):
            fetch_pinned(str(tmp_path / "missing-origin"), "a" * 40, tmp_path / "d2", timeout=120)
        with pytest.raises(GitError) as exc:
            clone_shallow(str(tmp_path / "missing-origin"), tmp_path / "d3", timeout=120)
        assert "\n" not in str(exc.value) and len(str(exc.value)) < 260
