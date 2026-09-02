"""scripts/sync_skill.py
---------------------
Pin the skill's bootstrap scripts to the package version and refresh the two mirrors.

The canonical skill lives in `src/aisg/skills/ai-safety-audit/` (shipped in the wheel);
`.claude/skills/ai-safety-audit/` and `.agents/skills/ai-safety-audit/` are byte-identical
copies pinned by `tests/unit/test_skill_package.py`. This dev tool:

1. reads `[project].version` from `pyproject.toml`;
2. rewrites the `AISG_VERSION="..."` / `$AISG_VERSION = "..."` line in the four canonical
   scripts so the bootstrap stays pinned to the release (an unpinned bootstrap is exactly
   what AUD-602 flags in targets);
3. copies the canonical tree over both mirrors, deleting stale mirror files.

    python scripts/sync_skill.py          # write
    python scripts/sync_skill.py --check  # list differences, exit 1 if any, write nothing

Not shipped; run from the repo root after a version bump or a skill edit.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

REPO = Path(__file__).resolve().parents[1]
CANONICAL = REPO / "src" / "aisg" / "skills" / "ai-safety-audit"
MIRRORS = (
    REPO / ".claude" / "skills" / "ai-safety-audit",
    REPO / ".agents" / "skills" / "ai-safety-audit",
)
SCRIPTS = ("scripts/audit.sh", "scripts/audit.ps1", "scripts/verify.sh", "scripts/verify.ps1")
SKIP_DIRS = frozenset({"__pycache__"})

# `AISG_VERSION="0.1.0"` in sh, `$AISG_VERSION = "0.1.0"` in PowerShell; the quoted value is
# the only thing rewritten, so the trailing comment survives.
VERSION_LINE = re.compile(r'^(\$?AISG_VERSION\s*=\s*")([^"\n]*)(")', re.MULTILINE)


def project_version(pyproject: Path = REPO / "pyproject.toml") -> str:
    """`[project].version`, via tomllib/tomli or a line regex when neither is installed."""
    text = pyproject.read_text(encoding="utf-8")
    if tomllib is not None:
        return str(tomllib.loads(text)["project"]["version"])
    in_project = False
    for line in text.splitlines():
        if line.strip().startswith("["):
            in_project = line.strip() == "[project]"
        elif in_project:
            m = re.match(r'\s*version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    raise SystemExit("pyproject.toml: [project].version not found")


def tree(root: Path) -> dict[str, bytes]:
    """`{posix relpath: bytes}` for every file under `root`, skipping `__pycache__`."""
    files: dict[str, bytes] = {}
    if not root.is_dir():
        return files
    for path in sorted(root.rglob("*")):
        if not path.is_file() or SKIP_DIRS & set(path.relative_to(root).parts):
            continue
        files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def pin_scripts(version: str, write: bool) -> list[str]:
    """Rewrite the version line in each canonical script; return the differences found."""
    diffs: list[str] = []
    for rel in SCRIPTS:
        path = CANONICAL / rel
        if not path.is_file():
            diffs.append(f"missing canonical script: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        matches = VERSION_LINE.findall(text)
        if not matches:
            diffs.append(f"no AISG_VERSION line in {rel}")
            continue
        if any(current != version for _, current, _ in matches):
            found = ", ".join(sorted({current for _, current, _ in matches}))
            diffs.append(f"{rel}: AISG_VERSION is {found}, pyproject says {version}")
            if write:
                new = VERSION_LINE.sub(lambda m: f"{m.group(1)}{version}{m.group(3)}", text)
                path.write_bytes(new.encode("utf-8"))  # bytes: keep LF on Windows
    return diffs


def sync_mirror(canonical: dict[str, bytes], mirror: Path, write: bool) -> list[str]:
    """Make `mirror` byte-identical to `canonical`; return the differences found."""
    diffs: list[str] = []
    current = tree(mirror)
    label = mirror.relative_to(REPO).as_posix()
    for rel, content in canonical.items():
        if rel not in current:
            diffs.append(f"{label}: missing {rel}")
        elif current[rel] != content:
            diffs.append(f"{label}: differs {rel}")
        else:
            continue
        if write:
            dest = mirror / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
    for rel in current:
        if rel not in canonical:
            diffs.append(f"{label}: stale {rel}")
            if write:
                (mirror / rel).unlink()
    if write:
        for directory in sorted(mirror.rglob("*"), reverse=True):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
    return diffs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sync_skill.py",
        description="Pin the skill scripts to pyproject's version and refresh the mirrors.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="List differences and exit 1 if there are any; write nothing.",
    )
    args = parser.parse_args(argv)
    write = not args.check

    if not CANONICAL.is_dir():
        print(f"canonical skill directory not found: {CANONICAL}", file=sys.stderr)
        return 2

    version = project_version()
    diffs = pin_scripts(version, write)
    canonical = tree(CANONICAL)
    for mirror in MIRRORS:
        diffs.extend(sync_mirror(canonical, mirror, write))

    for line in diffs:
        print(("fixed: " if write else "differs: ") + line)
    if write:
        print(
            f"skill pinned to {version}; {len(canonical)} files in each of {len(MIRRORS)} mirrors"
        )
        return 0
    if diffs:
        print(f"{len(diffs)} difference(s); run without --check to fix", file=sys.stderr)
        return 1
    print(f"in sync: version {version}, {len(canonical)} files, {len(MIRRORS)} mirrors")
    return 0


if __name__ == "__main__":
    sys.exit(main())
