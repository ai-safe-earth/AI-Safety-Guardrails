"""aisafe/devtools/_git.py
---------------------
Pinned, shallow git checkouts for `bench/run.py` and `aisafe fleet`: one implementation, two
callers. This module opens no socket itself; `git` is a child process, and the only remotes
it contacts are the URLs an operator wrote down in a corpus or a fleet list.

`fetch_pinned` reaches an exact commit. `git clone --depth 1` only reaches branch tips, so an
empty repository is initialised and the SHA is fetched directly, which pins a scan to the
listed commit after upstream moves on. A server that refuses fetch-by-sha gets a shallow
fetch of the recorded branch (or HEAD, depth 50) and a checkout of the SHA from that
history. `.aisafe-bench-sha` in the checkout records what it holds, so a second call with the
same SHA costs nothing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

__all__ = [
    "DEFAULT_TIMEOUT",
    "STAMP_FILE",
    "GitError",
    "clone_shallow",
    "fetch_pinned",
    "git_available",
    "head_sha",
]

STAMP_FILE = ".aisafe-bench-sha"
DEFAULT_TIMEOUT = 1800.0
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
_STDERR_CHARS = 200


class GitError(Exception):
    """A git step failed. The message is one line: the step and the start of stderr."""


def git_available() -> bool:
    return shutil.which("git") is not None


def _run(args: list[str], *, cwd: Path | None, timeout: float) -> subprocess.CompletedProcess[str]:
    # core.longpaths: several corpus repos have paths over the Windows 260-character limit
    # (deeply nested route directories, for one) and checkout fails outright without it.
    # A no-op elsewhere.
    try:
        return subprocess.run(
            ["git", "-c", "core.longpaths=true", *args],
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        detail = " ".join(((exc.stderr or exc.stdout or "").strip()).split())[:_STDERR_CHARS]
        raise GitError(f"git {args[0]} failed: {detail or 'no output'}") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {args[0]} timed out after {timeout:.0f}s") from exc


def head_sha(dest: Path, *, timeout: float = 60.0) -> str:
    """The checkout's HEAD commit id."""
    return _run(["rev-parse", "HEAD"], cwd=Path(dest), timeout=timeout).stdout.strip()


def _stamped(dest: Path) -> str | None:
    try:
        return (Path(dest) / STAMP_FILE).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _stamp(dest: Path, sha: str) -> None:
    (Path(dest) / STAMP_FILE).write_text(sha, encoding="utf-8")


def _reset(dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)


def fetch_pinned(
    url: str,
    sha: str | None,
    dest: Path,
    *,
    branch: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """
    Check `url` out at `sha` under `dest` and return the resolved HEAD id. Without a sha
    this is `clone_shallow`. A full 40-character id is fetched directly; a short one falls
    back to the branch history (depth 50) and is checked out from there. A checkout whose
    stamp already names `sha` is reused as it is.
    """
    dest = Path(dest)
    if not sha:
        return clone_shallow(url, dest, branch=branch, timeout=timeout)
    sha = sha.strip().lower()
    if not _SHA_RE.match(sha):
        raise GitError(f"not a commit id: {sha!r}")
    stamped = _stamped(dest)
    if stamped and stamped.startswith(sha) and (dest / ".git").exists():
        return stamped
    _reset(dest)
    _run(["init", "-q"], cwd=dest, timeout=timeout)
    _run(["remote", "add", "origin", url], cwd=dest, timeout=timeout)
    try:
        _run(["fetch", "--depth", "1", "--quiet", "origin", sha], cwd=dest, timeout=timeout)
    except GitError:
        # Some servers refuse fetch-by-sha; fall back to the recorded branch, else HEAD.
        _run(
            ["fetch", "--depth", "50", "--quiet", "origin", branch or "HEAD"],
            cwd=dest,
            timeout=timeout,
        )
    _run(["checkout", "-q", sha], cwd=dest, timeout=timeout)
    resolved = head_sha(dest, timeout=timeout)
    _stamp(dest, resolved)
    return resolved


def clone_shallow(
    url: str,
    dest: Path,
    *,
    branch: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """`git clone --depth 1` of `url` (optionally `--branch`) into `dest`; returns HEAD."""
    dest = Path(dest)
    _reset(dest)
    args = ["clone", "--depth", "1", "--quiet"]
    if branch:
        args += ["--branch", branch]
    args += [url, str(dest)]
    _run(args, cwd=None, timeout=timeout)
    resolved = head_sha(dest, timeout=timeout)
    _stamp(dest, resolved)
    return resolved
