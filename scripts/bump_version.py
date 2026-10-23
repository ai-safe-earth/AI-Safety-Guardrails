"""scripts/bump_version.py
------------------------
One version, many places. `pyproject.toml` is the source; every other site must say
the same string or the release gate fails.

    python scripts/bump_version.py --check                # every site equals pyproject,
                                                          # CHANGELOG has the heading
    python scripts/bump_version.py --check --tag v0.1.0   # ...and the tag matches too
    python scripts/bump_version.py 0.2.0                  # rewrite every site, move the
                                                          # Unreleased entries under a
                                                          # dated heading, run sync_skill
    python scripts/bump_version.py --changelog-section v0.1.0   # print that section

Sites, in the order they are rewritten: pyproject, `aisafe.__version__`, the two legacy
CLI `--version` strings, the SARIF reporter's tool version, the GitLab template's pin,
then (when the files exist) the GitHub Action's default `version` input and the Claude
Code plugin manifest. The skill's bootstrap scripts and the mirrors are pinned by
`scripts/sync_skill.py`, which this tool runs last. Not shipped; run from the repo root.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+.][0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class Site:
    """One place the version string lives. `pattern` has three groups: prefix, version,
    suffix; the version group is the only thing rewritten. `optional` sites are files
    later waves add (the Action, the plugin manifest): absent means skipped, present
    means checked."""

    relpath: str
    pattern: re.Pattern[str]
    optional: bool = False

    def path(self, root: Path) -> Path:
        return root / self.relpath


SITES: tuple[Site, ...] = (
    Site("pyproject.toml", re.compile(r'^(version\s*=\s*")([^"]+)(")', re.M)),
    Site("src/aisafe/__init__.py", re.compile(r'^(__version__\s*=\s*")([^"]+)(")', re.M)),
    Site("src/aisafe/devtools/euaiact_lint.py", re.compile(r'(version="euaiact-lint )([^"]+)(")')),
    Site(
        "src/aisafe/devtools/misalignment_check.py",
        re.compile(r'(version="misalignment-check )([^"]+)(")'),
    ),
    # The SARIF driver block: `"version"` followed by the informationUri line, so the
    # SARIF schema version two lines above (`"version": "2.1.0"`) is left alone.
    Site(
        "src/aisafe/modules/policy/code_analyzer/reporters.py",
        re.compile(r'("version":\s*")([^"]+)(",\s*\n\s*"informationUri")'),
    ),
    Site(
        "src/aisafe/modules/policy/code_analyzer/reporters.py",
        re.compile(r'("semanticVersion":\s*")([^"]+)(")'),
    ),
    Site(".gitlab-ci-euaiact.yml", re.compile(r'^(\s*AISAFE_VERSION:\s*")([^"]+)(")', re.M)),
    Site(
        "action.yml",
        re.compile(r'(\n\s*version:\s*\n(?:[^\n]*\n)*?\s*default:\s*")([^"]+)(")'),
        optional=True,
    ),
    Site(
        "plugins/aisafe/.claude-plugin/plugin.json",
        re.compile(r'("version":\s*")([^"]+)(")'),
        optional=True,
    ),
)

CHANGELOG = "CHANGELOG.md"
_HEADING_RE = re.compile(r"^## \[([^\]]+)\](?: - (\d{4}-\d{2}-\d{2}))?\s*$", re.M)


def project_version(root: Path = REPO) -> str:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    m = SITES[0].pattern.search(text)
    if m is None:
        raise SystemExit("pyproject.toml: [project].version not found")
    return m.group(2)


def site_versions(root: Path = REPO) -> list[tuple[Site, str | None]]:
    """(site, version found) for every site; None when the pattern did not match."""
    out: list[tuple[Site, str | None]] = []
    for site in SITES:
        path = site.path(root)
        if not path.is_file():
            if site.optional:
                continue
            out.append((site, None))
            continue
        m = site.pattern.search(path.read_text(encoding="utf-8"))
        out.append((site, m.group(2) if m else None))
    return out


def changelog_versions(root: Path = REPO) -> list[str]:
    path = root / CHANGELOG
    if not path.is_file():
        return []
    return [m.group(1) for m in _HEADING_RE.finditer(path.read_text(encoding="utf-8"))]


def changelog_section(version: str, root: Path = REPO) -> str:
    """The body of `## [version]` up to the next `## ` heading; "" when absent."""
    version = version.lstrip("v")
    text = (root / CHANGELOG).read_text(encoding="utf-8")
    headings = list(_HEADING_RE.finditer(text))
    for i, m in enumerate(headings):
        if m.group(1) == version:
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            body = text[m.end() : end]
            # Drop the link reference lines that close the file.
            body = re.sub(r"^\[[^\]]+\]:\s+\S+\s*$", "", body, flags=re.M)
            return body.strip() + "\n"
    return ""


def check(root: Path = REPO, tag: str | None = None) -> list[str]:
    """Human-readable disagreements; empty when everything says what pyproject says."""
    version = project_version(root)
    problems: list[str] = []
    for site, found in site_versions(root):
        if found is None:
            problems.append(f"{site.relpath}: version site not found (pattern did not match)")
        elif found != version:
            problems.append(f"{site.relpath}: says {found}, pyproject says {version}")
    if version not in changelog_versions(root):
        problems.append(f"{CHANGELOG}: no `## [{version}]` heading")
    if tag is not None and tag.lstrip("v") != version:
        problems.append(f"tag {tag} does not match pyproject version {version}")
    return problems


def bump(version: str, root: Path = REPO, today: _dt.date | None = None) -> list[str]:
    """Rewrite every site to `version`, retitle the CHANGELOG, return what changed."""
    if not VERSION_RE.match(version):
        raise SystemExit(f"not a version: {version!r}")
    changed: list[str] = []
    for site in SITES:
        path = site.path(root)
        if not path.is_file():
            if site.optional:
                continue
            raise SystemExit(f"missing version site: {site.relpath}")
        text = path.read_text(encoding="utf-8")
        new, n = site.pattern.subn(lambda m: f"{m.group(1)}{version}{m.group(3)}", text, count=1)
        if n == 0:
            raise SystemExit(f"{site.relpath}: version site not found")
        if new != text:
            path.write_bytes(new.encode("utf-8"))  # bytes: keep the file's line endings
            changed.append(site.relpath)
    changed.extend(_retitle_changelog(version, root, today or _dt.date.today()))
    return changed


def _retitle_changelog(version: str, root: Path, today: _dt.date) -> list[str]:
    path = root / CHANGELOG
    if not path.is_file():
        raise SystemExit(f"missing {CHANGELOG}")
    text = path.read_text(encoding="utf-8")
    if version in changelog_versions(root):
        return []
    marker = "## [Unreleased]\n"
    if marker not in text:
        raise SystemExit(f"{CHANGELOG}: no `## [Unreleased]` section to release from")
    head, rest = text.split(marker, 1)
    new = f"{head}{marker}\n## [{version}] - {today.isoformat()}\n\n{rest.lstrip()}"
    repo_url = "https://github.com/ai-safe-earth/AnyAISafe"
    new = re.sub(
        r"^\[Unreleased\]:\s+\S+$",
        f"[Unreleased]: {repo_url}/compare/v{version}...HEAD\n"
        f"[{version}]: {repo_url}/releases/tag/v{version}",
        new,
        count=1,
        flags=re.M,
    )
    path.write_bytes(new.encode("utf-8"))
    return [CHANGELOG]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bump_version.py",
        description="Keep every version string equal to pyproject's, or set a new one.",
    )
    parser.add_argument("version", nargs="?", help="New version to write (X.Y.Z).")
    parser.add_argument("--check", action="store_true", help="Report disagreements, write nothing.")
    parser.add_argument("--tag", help="A git tag (vX.Y.Z) that must match pyproject.")
    parser.add_argument("--changelog-section", metavar="VERSION", help="Print that section.")
    parser.add_argument("--root", type=Path, default=REPO, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root = args.root.resolve()

    if args.changelog_section:
        section = changelog_section(args.changelog_section, root)
        if not section:
            print(f"no CHANGELOG section for {args.changelog_section}", file=sys.stderr)
            return 1
        sys.stdout.write(section)
        return 0

    if args.version and not args.check:
        changed = bump(args.version, root)
        for rel in changed:
            print(f"rewrote: {rel}")
        if root == REPO:
            import sync_skill  # scripts/sync_skill.py, same directory

            rc = sync_skill.main([])
            if rc != 0:
                return rc
        problems = check(root, args.tag)
        for line in problems:
            print("still differs: " + line, file=sys.stderr)
        return 1 if problems else 0

    problems = check(root, args.tag)
    for line in problems:
        print("differs: " + line)
    if problems:
        print(f"{len(problems)} disagreement(s)", file=sys.stderr)
        return 1
    print(f"in sync: version {project_version(root)} at {len(site_versions(root))} sites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
