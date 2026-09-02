"""aisg/devtools/skill.py
----------------------
`aisg skill install|path|list|diff` -- copy the packaged agent skill into host skill dirs.

    aisg skill install                    # claude + agents, plus hosts already present
    aisg skill install --host cursor      # one host
    aisg skill install --global --force   # home directory, overwrite a differing copy
    aisg skill diff --host all            # exit 1 when an installed copy drifted
    aisg skill path                       # where the packaged skill lives
    aisg skill list                       # host table with the vendor page each dir came from

Only `<host dir>/ai-safety-audit/` is ever written; host settings and
permission files are never touched. Exit codes: 0 ok, 1 refused or differs,
2 fatal (unknown host, packaged skill missing, write failure).
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from aisg.skills import SKILL_NAME, iter_skill_files, skill_root

__all__ = [
    "Host",
    "HOSTS",
    "SkillInstallError",
    "home_dir",
    "resolve_hosts",
    "install",
    "diff_installed",
    "build_parser",
    "main",
]

# Hosts `--host all` always installs for; every other host only when its
# directory already exists (installing into `.cursor/` on a machine that never
# ran Cursor litters the repo).
ALWAYS_HOSTS = ("claude", "agents")

UNVERIFIED_NOTE = "location not verified against vendor documentation"


class SkillInstallError(Exception):
    """The destination exists and differs from the packaged skill (no --force)."""


@dataclass(frozen=True)
class Host:
    """
    Where one agent host reads skills from. `project_dir` is relative to the
    target root, `global_dir` to the home directory, both POSIX. `source` is
    the vendor page the location was checked against; a `verified` host must
    carry one. `alias_of` marks a host that reads another host's project dir.
    """

    name: str
    project_dir: str
    global_dir: str
    verified: bool
    source: str
    alias_of: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verified and not self.source:
            raise ValueError(f"host {self.name!r} is marked verified but has no source URL")

    def base_dir(self, global_: bool) -> str:
        return self.global_dir if global_ else self.project_dir


# Verified at build time (2026-09-02) by fetching each `source` page and
# reading the stated skills directories. Where a design-time URL now redirects
# permanently, `source` is the page that actually served the text. A
# `verified: False` row keeps its URL so `list` still shows where to look;
# `note` says what was found.
HOSTS: dict[str, Host] = {
    "claude": Host(
        name="claude",
        project_dir=".claude/skills",
        global_dir=".claude/skills",
        verified=True,
        source="https://code.claude.com/docs/en/skills",
    ),
    "agents": Host(
        name="agents",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=True,
        source="https://agentskills.io/client-implementation/adding-skills-support",
    ),
    "codex": Host(
        name="codex",
        project_dir=".agents/skills",
        global_dir=".codex/skills",
        verified=False,
        source="https://learn.chatgpt.com/docs/build-skills",
        alias_of="agents",
        note=(
            "could not be re-verified at build time: the vendor page "
            "(developers.openai.com/codex/skills redirects to it) names "
            ".agents/skills in the repo and $HOME/.agents/skills for user-level "
            "skills and does not mention ~/.codex/skills; check the printed "
            "destination against your Codex layout"
        ),
    ),
    "cursor": Host(
        name="cursor",
        project_dir=".cursor/skills",
        global_dir=".cursor/skills",
        verified=True,
        source="https://cursor.com/docs/context/skills",
    ),
    "gemini": Host(
        name="gemini",
        project_dir=".gemini/skills",
        global_dir=".gemini/skills",
        verified=True,
        source="https://geminicli.com/docs/cli/skills/",
    ),
    "antigravity": Host(
        name="antigravity",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=False,
        source="",
        note=UNVERIFIED_NOTE,
    ),
}


def home_dir() -> Path:
    """The home directory; a single seam so tests never touch the real one."""
    return Path.home()


def resolve_hosts(
    name: str,
    root: Path,
    home: Path,
    global_: bool = False,
    force_all: bool = False,
) -> list[Host]:
    """
    Hosts named by `--host`. A single name maps to that host; `all` is
    `claude` + `agents` always, plus every other non-alias host whose
    directory parent (`root/.cursor`, `home/.gemini`, ...) already exists.
    `force_all` returns every non-alias host. Unknown names raise ValueError.
    """
    if name != "all":
        host = HOSTS.get(name)
        if host is None:
            choices = ", ".join(["all", *HOSTS])
            raise ValueError(f"unknown host {name!r}; expected one of: {choices}")
        return [host]

    base = home if global_ else root
    selected: list[Host] = []
    for host in HOSTS.values():
        if host.alias_of is not None:
            continue
        if force_all or host.name in ALWAYS_HOSTS:
            selected.append(host)
            continue
        parent = (base / host.base_dir(global_)).parent
        if parent.is_dir():
            selected.append(host)
    return selected


def destination(host: Host, root: Path, *, global_: bool = False, home: Path | None = None) -> Path:
    """`<root or home>/<host dir>/ai-safety-audit`."""
    if global_:
        base = home if home is not None else home_dir()
    else:
        base = root
    return base / host.base_dir(global_) / SKILL_NAME


def _packaged() -> dict[str, bytes]:
    return dict(iter_skill_files())


def _installed(dest: Path) -> dict[str, bytes]:
    """Every file under `dest` keyed by POSIX relpath; empty when absent."""
    if not dest.is_dir():
        return {}
    files: dict[str, bytes] = {}
    for path in sorted(dest.rglob("*")):
        rel = path.relative_to(dest)
        if "__pycache__" in rel.parts or not path.is_file():
            continue
        files[rel.as_posix()] = path.read_bytes()
    return files


def diff_installed(
    host: Host, root: Path, *, global_: bool = False, home: Path | None = None
) -> list[str]:
    """
    Relpaths where the installed copy departs from the packaged skill, each
    prefixed `changed: `, `missing: ` or `extra: `. Empty when identical.
    A copy that is not installed at all reports every packaged file missing.
    """
    dest = destination(host, root, global_=global_, home=home)
    packaged = _packaged()
    installed = _installed(dest)
    lines: list[str] = []
    for rel in sorted(packaged):
        if rel not in installed:
            lines.append(f"missing: {rel}")
        elif installed[rel] != packaged[rel]:
            lines.append(f"changed: {rel}")
    for rel in sorted(installed.keys() - packaged.keys()):
        lines.append(f"extra: {rel}")
    return lines


def _prune_empty_dirs(dest: Path) -> None:
    for path in sorted(dest.rglob("*"), reverse=True):
        if path.is_dir() and not any(path.iterdir()):
            path.rmdir()


def install(
    host: Host,
    root: Path,
    *,
    global_: bool = False,
    force: bool = False,
    dry_run: bool = False,
    home: Path | None = None,
) -> Path:
    """
    Copy the packaged skill to the host's directory and return the destination.

    An existing identical copy is a no-op. An existing copy that differs is
    refused with SkillInstallError unless `force`, which rewrites every
    packaged file and removes files the package does not ship. `dry_run`
    prints what would be written and writes nothing (it still refuses what a
    real run would refuse).
    """
    dest = destination(host, root, global_=global_, home=home)
    packaged = _packaged()
    installed = _installed(dest)
    if installed == packaged:
        return dest
    if installed and not force:
        raise SkillInstallError(
            f"{dest} exists and differs from the packaged skill; re-run with --force to overwrite it"
        )
    if dry_run:
        for rel in packaged:
            print(f"would write {dest / rel}")
        return dest

    for rel in installed.keys() - packaged.keys():
        (dest / rel).unlink()
    for rel, content in packaged.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    if installed:
        _prune_empty_dirs(dest)
    return dest


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _add_host_args(p: argparse.ArgumentParser, *, install_flags: bool) -> None:
    p.add_argument(
        "--host",
        default="all",
        metavar="HOST",
        help="one of: all, " + ", ".join(HOSTS) + " (default: all)",
    )
    p.add_argument(
        "--global",
        dest="global_",
        action="store_true",
        help="use the home directory instead of the project root",
    )
    if install_flags:
        p.add_argument(
            "--force",
            action="store_true",
            help="overwrite an existing copy that differs from the packaged skill",
        )
        p.add_argument(
            "--force-all",
            action="store_true",
            help="with --host all: every host, not only those whose directory exists",
        )
        p.add_argument(
            "--dry-run",
            action="store_true",
            help="print what would be written and write nothing",
        )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisg skill",
        description=f"Install the packaged '{SKILL_NAME}' agent skill into host skill directories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "--host all installs for claude and agents always, plus any other host whose\n"
            "directory (.cursor/, .gemini/, ...) already exists at the project root (or in\n"
            "the home directory with --global); --force-all installs for every host.\n"
            f"Only <host dir>/{SKILL_NAME}/ is written; host settings files are never touched.\n"
            "A host that `list` shows as verified: no was not verified against vendor\n"
            "documentation; install prints a note for it on stderr.\n"
        ),
    )
    verbs = p.add_subparsers(dest="verb", metavar="{install,path,list,diff}")
    inst = verbs.add_parser("install", help="copy the skill into host skill directories")
    _add_host_args(inst, install_flags=True)
    verbs.add_parser("path", help="print the packaged skill directory")
    verbs.add_parser("list", help="print the host table")
    diff = verbs.add_parser("diff", help="compare installed copies with the packaged skill")
    _add_host_args(diff, install_flags=False)
    return p


def _note_unverified(host: Host) -> None:
    line = f"note: {host.name}: {UNVERIFIED_NOTE}"
    if host.note and host.note != UNVERIFIED_NOTE:
        line += f" -- {host.note}"
    print(line, file=sys.stderr)


def _cmd_install(args: argparse.Namespace) -> int:
    root = Path.cwd()
    home = home_dir()
    hosts = resolve_hosts(args.host, root, home, global_=args.global_, force_all=args.force_all)
    rc = 0
    for host in hosts:
        dest = destination(host, root, global_=args.global_, home=home)
        if host.name == "codex":
            print(f"codex: resolved destination is {dest}; check it against your Codex layout")
        if not host.verified:
            _note_unverified(host)
        try:
            unchanged = not diff_installed(host, root, global_=args.global_, home=home)
            install(
                host,
                root,
                global_=args.global_,
                force=args.force,
                dry_run=args.dry_run,
                home=home,
            )
        except SkillInstallError as exc:
            print(f"refused: {host.name}: {exc}", file=sys.stderr)
            rc = 1
            continue
        if unchanged:
            verb = "unchanged"
        elif args.dry_run:
            verb = "would install"
        else:
            verb = "installed"
        print(f"{verb} {host.name} -> {dest}")
    return rc


def _cmd_path(args: argparse.Namespace) -> int:
    print(skill_root())
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    header = ("name", "project dir", "global dir", "verified", "source")
    rows = [
        (
            host.name,
            host.project_dir + "/",
            "~/" + host.global_dir + "/",
            "yes" if host.verified else "no",
            host.source or "-",
        )
        for host in HOSTS.values()
    ]
    widths = [max(len(row[i]) for row in [header, *rows]) for i in range(len(header))]
    for row in [header, *rows]:
        print(" | ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    root = Path.cwd()
    home = home_dir()
    hosts = resolve_hosts(args.host, root, home, global_=args.global_)
    rc = 0
    for host in hosts:
        dest = destination(host, root, global_=args.global_, home=home)
        if not dest.is_dir():
            print(f"not installed: {host.name} -> {dest}")
            rc = 1
            continue
        lines = diff_installed(host, root, global_=args.global_, home=home)
        if not lines:
            print(f"identical: {host.name} -> {dest}")
            continue
        rc = 1
        print(f"differs: {host.name} -> {dest}")
        for line in lines:
            print(f"  {line}")
    return rc


_VERBS = {
    "install": _cmd_install,
    "path": _cmd_path,
    "list": _cmd_list,
    "diff": _cmd_diff,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.verb is None:
        parser.print_help()
        return 2
    try:
        return _VERBS[args.verb](args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error: could not write the skill: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
