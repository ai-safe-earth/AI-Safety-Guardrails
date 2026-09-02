"""aisg/skills/__init__.py
-----------------------
Package-data accessor for the agent skill that `aisg skill install` copies into host dirs.

The skill directory (`ai-safety-audit/`) ships as package data next to this
module, so it is readable from an installed wheel via importlib.resources, not
just from a source checkout. `.claude/skills/` and `.agents/skills/` at the
repo root are byte-identical mirrors of it, pinned by a test.

    from aisg.skills import skill_root, iter_skill_files, skill_digest

    (skill_root() / "SKILL.md").read_text()
    for relpath, content in iter_skill_files(): ...
"""

from __future__ import annotations

import hashlib
from contextlib import ExitStack
from importlib import resources
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:  # importlib.abc.Traversable moved (and is deprecated) on 3.12+
    from importlib.abc import Traversable

__all__ = ["SKILL_NAME", "skill_root", "iter_skill_files", "skill_digest"]

SKILL_NAME = "ai-safety-audit"

# Keeps extracted resources alive for the process lifetime. Needed when the
# package is loaded from a zip, where as_file() materialises a temp copy.
_FILES = ExitStack()


def _resource() -> Traversable:
    """The packaged skill directory as a Traversable, or FileNotFoundError."""
    resource = resources.files(__package__) / SKILL_NAME
    if not resource.is_dir():
        raise FileNotFoundError(
            f"Packaged skill {SKILL_NAME!r} not found: expected a directory at {resource}"
        )
    return resource


def skill_root() -> Path:
    """
    Filesystem path to the packaged skill directory. Works from a wheel as
    well as a checkout. Raises FileNotFoundError, naming the expected path,
    when the skill is not packaged -- never at import time.
    """
    return _FILES.enter_context(resources.as_file(_resource()))


def _walk(node: Traversable, prefix: str) -> Iterator[tuple[str, Traversable]]:
    for child in node.iterdir():
        if child.name == "__pycache__":
            continue
        relpath = f"{prefix}{child.name}"
        if child.is_dir():
            yield from _walk(child, relpath + "/")
        else:
            yield relpath, child


def iter_skill_files() -> Iterator[tuple[str, bytes]]:
    """
    Yield `(relpath, content)` for every file under the skill root, sorted by
    relpath. `relpath` is POSIX-style and relative to the skill root;
    `__pycache__` directories are skipped.
    """
    for relpath, node in sorted(_walk(_resource(), ""), key=lambda item: item[0]):
        yield relpath, node.read_bytes()


def skill_digest() -> str:
    """
    sha256 hex over the sorted `(relpath, content)` stream, so any changed,
    added, renamed or removed file changes the digest. Each entry is
    length-prefixed, so the stream has one unambiguous encoding.
    """
    digest = hashlib.sha256()
    for relpath, content in iter_skill_files():
        digest.update(f"{relpath}\0{len(content)}\0".encode("utf-8"))
        digest.update(content)
    return digest.hexdigest()
