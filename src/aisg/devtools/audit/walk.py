"""aisg/devtools/audit/walk.py
----------------------------
File enumeration for `aisg audit`: gitignore-lite, size/binary/marker guards, language and
unit detection, plus the two read-only git helpers (`git_meta`, `file_age`).

Rules that hold here:

- `.env*` files are always enumerated, even when `.gitignore` excludes them. The
  matcher's `match()` carries that exception; `would_ignore()` is the raw answer and is
  what sets `FileRecord.gitignored`. Without this the highest-blast-radius credentials on
  a developer machine would be invisible while the report implied `.env*` was covered.
- Dotfiles and dotdirs are walked: host configs (`.claude/`, `.cursor/`, `.codex/`) live
  there. Only `SKIP_DIRS`, `--exclude` and the gitignore matcher prune.
- The walker never raises on an unreadable file or directory; it counts and reports
  once under UNKNOWN. Silence is never a pass.
- `subprocess` is used only for read-only `git` commands, never with `shell=True`, never
  with `check=True`, always with a timeout.
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from aisg.devtools.audit.model import Unit, UnknownCategory, UnknownItem
from aisg.devtools.audit.patterns import (
    ENV_FILE_RE,
    IGNORE_MARKER,
    LANG_BY_EXT,
    SKIP_DIRS,
    UNIT_MANIFESTS,
)

__all__ = [
    "DEFAULT_MAX_SIZE",
    "HEAD_BYTES",
    "MARKER_LINES",
    "GIT_TIMEOUT",
    "ROOT_UNIT_ID",
    "WalkOptions",
    "FileRecord",
    "GitIgnore",
    "read_text",
    "has_ignore_marker",
    "unit_of",
    "walk",
    "git_meta",
    "file_age",
]

DEFAULT_MAX_SIZE = 2 * 1024 * 1024
HEAD_BYTES = 8 * 1024
MARKER_LINES = 5
GIT_TIMEOUT = 10.0
ROOT_UNIT_ID = "u0"
ROOT_UNIT_PATH = "."

_MANIFEST_LANG: dict[str, str] = {
    "pyproject.toml": "python",
    "setup.py": "python",
    "requirements.txt": "python",
    "package.json": "typescript",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "pom.xml": "jvm",
    "build.gradle": "jvm",
    "Gemfile": "ruby",
    "*.csproj": "dotnet",
}
_NON_CODE_LANGS = frozenset({"config", "other"})
_SKIP_NAMES = frozenset(s for s in SKIP_DIRS if "/" not in s)
_SKIP_PATHS = frozenset(s for s in SKIP_DIRS if "/" in s)
_SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


# ---------------------------------------------------------------------------
# Options and records
# ---------------------------------------------------------------------------


@dataclass
class WalkOptions:
    exclude: tuple[str, ...] = ()
    include_ignored: bool = False
    max_size: int = DEFAULT_MAX_SIZE
    follow_symlinks: bool = False


@dataclass
class FileRecord:
    """One enumerated file. `relpath` is POSIX and relative to the walk root."""

    path: Path
    relpath: str
    lang: str
    unit: str
    size: int
    gitignored: bool = False


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _norm_rel(relpath: str) -> str:
    rel = str(relpath).replace("\\", "/").strip("/")
    while rel.startswith("./"):
        rel = rel[2:]
    return "" if rel == "." else rel


def _join(dir_rel: str, name: str) -> str:
    return f"{dir_rel}/{name}" if dir_rel else name


def _ancestors(rel: str) -> list[str]:
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def _is_env_file(name: str) -> bool:
    return ENV_FILE_RE.match(name) is not None


def _lang_for(name: str) -> str:
    if _is_env_file(name) or name.lower() == "dockerfile":
        return "config"
    suffix = os.path.splitext(name)[1]
    return LANG_BY_EXT.get(suffix) or LANG_BY_EXT.get(suffix.lower()) or "other"


def _manifest_in(filenames: Sequence[str]) -> str | None:
    """The first `UNIT_MANIFESTS` entry present in a directory listing, else None."""
    names = set(filenames)
    for manifest in UNIT_MANIFESTS:
        if "*" in manifest:
            hits = sorted(n for n in names if fnmatch.fnmatchcase(n, manifest))
            if hits:
                return hits[0]
        elif manifest in names:
            return manifest
    return None


def _manifest_language(manifest_name: str) -> str:
    for pattern, lang in _MANIFEST_LANG.items():
        if fnmatch.fnmatchcase(manifest_name, pattern):
            return lang
    return "unknown"


# ---------------------------------------------------------------------------
# gitignore-lite
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Rule:
    base: str  # directory holding the ignore file, "" for the root
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool


def _glob_to_regex(glob: str) -> str:
    """gitignore glob -> regex body. `*`/`?` stop at `/`; `**` crosses it."""
    out: list[str] = []
    i, n = 0, len(glob)
    while i < n:
        c = glob[i]
        if c == "*":
            if glob.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif glob.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = glob.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = glob[i + 1 : j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        elif c == "\\" and i + 1 < n:
            out.append(re.escape(glob[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _compile_rule(base: str, raw: str) -> _Rule | None:
    line = raw.rstrip("\r\n")
    if not line.strip() or line.lstrip().startswith("#"):
        return None
    line = re.sub(r"(?<!\\)\s+$", "", line)
    negate = False
    if line.startswith("!"):
        negate = True
        line = line[1:]
    elif line.startswith("\\!") or line.startswith("\\#"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    # A slash at the start or in the middle anchors the pattern to the ignore file's
    # directory; a bare name matches its basename at any depth below it.
    anchored = "/" in line
    prefix = "^" if anchored else "(?:^|.*/)"
    try:
        regex = re.compile(prefix + _glob_to_regex(line.lstrip("/")) + "$")
    except re.error:
        return None
    return _Rule(base, regex, negate, dir_only)


class GitIgnore:
    """Minimal `.gitignore` matcher: enough for pruning, not a git reimplementation.

    Supported: blank and comment lines, leading `/` anchoring, trailing `/` for
    directories, `*` (does not cross `/`), `**` (does), `?`, `[...]`, `!` negation with
    last-match-wins, nested ignore files via `add()`, and "an ignored directory ignores
    everything beneath it". Case-sensitive on every platform so results do not depend on
    where the audit runs.
    """

    def __init__(self) -> None:
        self._rules: list[_Rule] = []

    @classmethod
    def load(cls, dir: Path) -> GitIgnore:
        matcher = cls()
        text = read_text(Path(dir) / ".gitignore")
        if text:
            matcher.add("", text)
        return matcher

    def add(self, dir_relpath: str, text: str) -> None:
        base = _norm_rel(dir_relpath)
        for raw in text.splitlines():
            rule = _compile_rule(base, raw)
            if rule is not None:
                self._rules.append(rule)

    def __len__(self) -> int:
        return len(self._rules)

    def _matches(self, rel: str, is_dir: bool) -> bool:
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.base:
                if not rel.startswith(rule.base + "/"):
                    continue
                sub = rel[len(rule.base) + 1 :]
            else:
                sub = rel
            if rule.regex.match(sub):
                ignored = not rule.negate
        return ignored

    def would_ignore(self, relpath: str, is_dir: bool = False) -> bool:
        """Raw answer: would git ignore this path? No `.env*` exception."""
        rel = _norm_rel(relpath)
        if not rel:
            return False
        # git never re-includes a file whose parent directory is excluded.
        for ancestor in _ancestors(rel):
            if self._matches(ancestor, True):
                return True
        return self._matches(rel, is_dir)

    def match(self, relpath: str, is_dir: bool = False) -> bool:
        """`would_ignore` with the hard exception: a `.env*` file is never ignored."""
        rel = _norm_rel(relpath)
        if not is_dir and _is_env_file(rel.rsplit("/", 1)[-1]):
            return False
        return self.would_ignore(rel, is_dir)


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------


def read_text(path: Path, max_size: int | None = None) -> str | None:
    """Decode a file as UTF-8 (errors replaced, BOM stripped).

    Returns None when the file is larger than `max_size`, has a NUL byte in its first
    8 KiB, or cannot be read.
    """
    try:
        with open(path, "rb") as fh:
            if max_size is not None and os.fstat(fh.fileno()).st_size > max_size:
                return None
            head = fh.read(HEAD_BYTES)
            if b"\x00" in head:
                return None
            data = head + fh.read()
    except OSError:
        return None
    text = data.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def has_ignore_marker(head: str) -> bool:
    """True when `IGNORE_MARKER` appears in the first five lines."""
    return any(IGNORE_MARKER in line for line in head.splitlines()[:MARKER_LINES])


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


def unit_of(relpath: str, units: Sequence[Unit]) -> str:
    """Id of the nearest unit whose root is the file's directory or an ancestor of it.

    The repo root unit (`root == "."`) is the fallback and is always present.
    """
    rel = _norm_rel(relpath)
    best_id = ROOT_UNIT_ID
    best_len = -1
    for unit in units:
        root = "" if unit.root in ("", ROOT_UNIT_PATH) else unit.root
        if root and not (rel == root or rel.startswith(root + "/")):
            continue
        if len(root) > best_len:
            best_id, best_len = unit.id, len(root)
    return best_id


def _build_units(
    manifests: dict[str, str | None], langs_by_dir: Counter[tuple[str, str]]
) -> list[Unit]:
    """Number units u0.. in sorted root order; the repo root is always u0."""
    others = sorted(r for r in manifests if r != "")
    units: list[Unit] = []
    for index, root in enumerate(["", *others]):
        manifest = manifests.get(root)
        language = _manifest_language(manifest) if manifest else "unknown"
        units.append(
            Unit(
                id=f"u{index}",
                root=root or ROOT_UNIT_PATH,
                manifest=_join(root, manifest) if manifest else None,
                language=language,
            )
        )
    root_unit = units[0]
    if root_unit.manifest is None:
        votes: Counter[str] = Counter()
        for (unit_id, lang), count in langs_by_dir.items():
            if unit_id == ROOT_UNIT_ID and lang not in _NON_CODE_LANGS:
                votes[lang] += count
        if votes:
            top = max(votes.values())
            root_unit.language = sorted(lang for lang, c in votes.items() if c == top)[0]
    return units


# ---------------------------------------------------------------------------
# Walk
# ---------------------------------------------------------------------------


def _normalise_excludes(exclude: Sequence[str]) -> tuple[str, ...]:
    out: list[str] = []
    for entry in exclude:
        rel = _norm_rel(entry)
        if rel.endswith("/**"):
            rel = rel[:-3]
        if rel:
            out.append(rel)
    return tuple(out)


def _excluded(rel: str, exclude: tuple[str, ...]) -> bool:
    if not exclude:
        return False
    ancestors = _ancestors(rel)
    for entry in exclude:
        if rel == entry or rel.startswith(entry + "/"):
            return True
        if fnmatch.fnmatchcase(rel, entry):
            return True
        if any(fnmatch.fnmatchcase(a, entry) for a in ancestors):
            return True
    return False


def _skip_dir(name: str, rel: str) -> bool:
    if name in _SKIP_NAMES:
        return True
    return any(rel == p or rel.endswith("/" + p) for p in _SKIP_PATHS)


@dataclass
class _Pending:
    path: Path
    relpath: str
    lang: str
    size: int
    gitignored: bool


def walk(
    root: Path, options: WalkOptions | None = None
) -> tuple[list[FileRecord], list[Unit], list[UnknownItem]]:
    """Enumerate `root`. Never raises on an unreadable entry; see the module docstring."""
    opts = options or WalkOptions()
    root = Path(root).resolve()
    exclude = _normalise_excludes(opts.exclude)
    ignore = GitIgnore.load(root)
    pending: list[_Pending] = []
    manifests: dict[str, str | None] = {"": None}
    symlinks = 0
    unreadable = 0
    ignored_dirs: list[str] = []

    def _onerror(_err: OSError) -> None:
        nonlocal unreadable
        unreadable += 1

    for dirpath, dirnames, filenames in os.walk(
        root, topdown=True, onerror=_onerror, followlinks=opts.follow_symlinks
    ):
        dir_rel = _norm_rel(os.path.relpath(dirpath, root))
        if dir_rel and ".gitignore" in filenames:
            text = read_text(Path(dirpath) / ".gitignore")
            if text:
                ignore.add(dir_rel, text)
        manifest = _manifest_in(filenames)
        if manifest is not None:
            manifests[dir_rel] = manifest

        keep: list[str] = []
        for name in sorted(dirnames):
            rel = _join(dir_rel, name)
            if not opts.follow_symlinks and os.path.islink(os.path.join(dirpath, name)):
                symlinks += 1
                continue
            if _skip_dir(name, rel) or _excluded(rel, exclude):
                continue
            if not opts.include_ignored and ignore.match(rel, is_dir=True):
                ignored_dirs.append(rel)
                continue
            keep.append(name)
        dirnames[:] = keep

        for name in filenames:
            rel = _join(dir_rel, name)
            full = Path(dirpath) / name
            # os.path.islink swallows OSError; Path.is_symlink does not.
            if not opts.follow_symlinks and os.path.islink(full):
                symlinks += 1
                continue
            if _excluded(rel, exclude):
                continue
            gitignored = ignore.would_ignore(rel, is_dir=False)
            if gitignored and not opts.include_ignored and ignore.match(rel, is_dir=False):
                continue
            try:
                size = full.stat().st_size
                if size > opts.max_size:
                    continue
                with open(full, "rb") as fh:
                    head = fh.read(HEAD_BYTES)
            except OSError:
                unreadable += 1
                continue
            if b"\x00" in head:
                continue
            if has_ignore_marker(head.decode("utf-8", errors="replace")):
                continue
            pending.append(_Pending(full, rel, _lang_for(name), size, gitignored))

    pending.sort(key=lambda p: p.relpath)
    # Provisional unit ids are needed for the root-language vote, so assign in two steps.
    provisional = _build_units(manifests, Counter())
    votes: Counter[tuple[str, str]] = Counter()
    assigned: list[str] = []
    for item in pending:
        unit_id = unit_of(item.relpath, provisional)
        assigned.append(unit_id)
        votes[(unit_id, item.lang)] += 1
    units = _build_units(manifests, votes)
    records = [
        FileRecord(
            path=item.path,
            relpath=item.relpath,
            lang=item.lang,
            unit=unit_id,
            size=item.size,
            gitignored=item.gitignored,
        )
        for item, unit_id in zip(pending, assigned)
    ]

    unknown: list[UnknownItem] = []
    if symlinks:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="symlinks skipped",
                why=f"{symlinks} symlink(s) not followed",
                how_to_resolve="Re-run with follow_symlinks enabled, or audit the link targets directly.",
            )
        )
    if unreadable:
        unknown.append(
            UnknownItem(
                category=UnknownCategory.RUNTIME,
                what="unreadable files",
                why=f"{unreadable} file(s) or director(ies) could not be read",
                how_to_resolve="Check permissions on the target tree; unreadable paths were not audited.",
            )
        )
    if ignored_dirs:
        unknown.append(_ignored_dirs_item(ignored_dirs))
    return records, units, unknown


_IGNORED_DIRS_NAMED = 6


def _ignored_dirs_item(ignored_dirs: list[str]) -> UnknownItem:
    """A `.gitignore`d directory is not walked, so nothing in it was audited. That is
    where logs, eval outputs and scratch data accumulate -- the files most likely to
    hold PII or the eval corpus -- so the pruning is reported, never silent."""
    names = sorted(ignored_dirs)
    shown = ", ".join(names[:_IGNORED_DIRS_NAMED])
    if len(names) > _IGNORED_DIRS_NAMED:
        shown += f", +{len(names) - _IGNORED_DIRS_NAMED} more"
    return UnknownItem(
        category=UnknownCategory.RUNTIME,
        what="gitignored directories skipped",
        why=f"{len(names)} gitignored director(ies) not walked: {shown}",
        how_to_resolve=(
            "Re-run with --include-ignored to audit them; logs/, evals/ and data "
            "directories are where PII and eval corpora accumulate."
        ),
    )


# ---------------------------------------------------------------------------
# git (read-only)
# ---------------------------------------------------------------------------


def _git(args: Sequence[str], cwd: Path) -> str | None:
    """Run a read-only git command; stdout on success, None on any failure."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_meta(root: Path) -> tuple[str | None, bool]:
    """(HEAD sha, dirty). `(None, False)` when git is absent or `root` is not a repo."""
    out = _git(["rev-parse", "HEAD"], Path(root))
    if out is None:
        return None, False
    sha = out.strip()
    if not _SHA_RE.match(sha):
        return None, False
    status = _git(["status", "--porcelain"], Path(root))
    return sha, bool(status and status.strip())


def file_age(path: Path, root: Path) -> tuple[datetime | None, str]:
    """When was this file last changed, and how do we know? Never raises.

    Sources, in order: `mtime` (stat), `git` (last commit touching the file), `unknown`.
    """
    path = Path(path)
    try:
        stamp = path.stat().st_mtime
        return datetime.fromtimestamp(stamp, tz=timezone.utc), "mtime"
    except (OSError, ValueError, OverflowError):
        pass
    try:
        rel = os.path.relpath(path, Path(root)).replace(os.sep, "/")
    except ValueError:
        return None, "unknown"
    out = _git(["log", "-1", "--format=%cI", "--", rel], Path(root))
    if out and out.strip():
        # git writes a UTC committer date as `...Z`; fromisoformat only accepts
        # that suffix from 3.11, so on 3.10 every UTC commit would fall to unknown.
        stamp = out.strip().splitlines()[0].replace("Z", "+00:00")
        try:
            when = datetime.fromisoformat(stamp)
        except ValueError:
            return None, "unknown"
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return when.astimezone(timezone.utc), "git"
    return None, "unknown"
