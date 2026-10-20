"""
src/aisafe/cli.py
---------------
Single entry point for the AnyAISafe developer tools.

    aisafe --version
    aisafe lint src/
    aisafe lint src/ --format sarif --output results.sarif
    aisafe misalign src/ --fail-on-warnings
    aisafe audit . --format json -o audit-report.json
    aisafe skill install --host all

Every subcommand is a thin wrapper around a tool in `aisafe.devtools`: `lint`,
`misalign`, `init`, `probe`, `measure`, `audit`, `skill`, `decide`, `hook`, `attest` and
`fleet`. Each is imported
only when invoked, so `aisafe lint` never pays for the audit engine. Everything
after the subcommand is handed to the underlying tool untouched, so their
flags, defaults and exit codes are unchanged:

    0  no errors (warnings/info allowed)
    1  errors found
    2  fatal error (bad args, parse failure)

`audit` adds 130 for an interrupted run; `skill` returns 1 when an install is
refused or an installed copy differs from the packaged skill.
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Sequence

from aisafe import __version__

__all__ = ["main", "build_parser"]

_EPILOG = """
Commands:
  lint        EU AI Act static compliance analysis (was: euaiact-lint)
  misalign    AI misalignment static analysis      (was: misalignment-check)
  init        Write an ai-system-card.yaml for the system under assessment
  probe       Send a fixed attack corpus to a live endpoint and report what got through
  measure     Report what each guard catches, what it breaks, and what it costs
  audit       Static AI-safety audit of a repository: findings describe evidence, never verdicts
  skill       Install the packaged ai-safety-audit agent skill into host skill directories
  decide      What each proposed control costs (latency, tokens, usd, human load) against the declared budgets
  hook        Agent-host hooks: gate protected paths, secret literals and unsafe shell; re-audit edits; Stop gate
  attest      Evaluate the level criteria against the written documents; a named owner signs the result
  fleet       Audit every repository in a list, one subprocess each, and aggregate the counts

Run `aisafe <command> --help` for a command's own options.

Examples:
  aisafe lint src/
  aisafe lint src/ --format sarif --output results.sarif
  aisafe lint src/ --errors-only
  aisafe lint --staged                       # pre-commit
  aisafe misalign src/ --fail-on-warnings
  aisafe init --defaults
  aisafe probe http://localhost:8000/chat --response-path '$.response'
  aisafe measure
  aisafe audit . --format json -o audit-report.json
  aisafe audit . --baseline audit-baseline.json --fail-on high
  aisafe skill install --host all
  aisafe skill diff --host all
  aisafe decide --requests-per-day 20000 --p99-budget-ms 250 --monthly-budget-usd 300
  aisafe hook install --host claude --yes
  aisafe hook list
  aisafe attest . --owner "J. Doe <risk owner>" --html
  aisafe attest . --check --require-level 2    # CI
  aisafe fleet fleet.yaml --jobs 4 --proposal
"""


def _lint(argv: Sequence[str]) -> int:
    from aisafe.devtools.euaiact_lint import main as lint_main

    return lint_main(list(argv))


def _misalign(argv: Sequence[str]) -> int:
    from aisafe.devtools.misalignment_check import main as misalign_main

    return misalign_main(list(argv))


def _init(argv: Sequence[str]) -> int:
    from aisafe.devtools.system_card import main as init_main

    return init_main(list(argv))


def _probe(argv: Sequence[str]) -> int:
    from aisafe.devtools.probe import main as probe_main

    return probe_main(list(argv))


def _measure(argv: Sequence[str]) -> int:
    from aisafe.devtools.measure import main as measure_main

    return measure_main(list(argv))


def _audit(argv: Sequence[str]) -> int:
    from aisafe.devtools.audit.main import main as audit_main

    return audit_main(list(argv))


def _skill(argv: Sequence[str]) -> int:
    from aisafe.devtools.skill import main as skill_main

    return skill_main(list(argv))


def _decide(argv: Sequence[str]) -> int:
    from aisafe.devtools.decide import main as decide_main

    return decide_main(list(argv))


def _hook(argv: Sequence[str]) -> int:
    from aisafe.devtools.hook import main as hook_main

    return hook_main(list(argv))


def _attest(argv: Sequence[str]) -> int:
    from aisafe.devtools.attest import main as attest_main

    return attest_main(list(argv))


def _fleet(argv: Sequence[str]) -> int:
    from aisafe.devtools.fleet import main as fleet_main

    return fleet_main(list(argv))


COMMANDS: dict[str, Callable[[Sequence[str]], int]] = {
    "lint": _lint,
    "misalign": _misalign,
    "init": _init,
    "probe": _probe,
    "measure": _measure,
    "audit": _audit,
    "skill": _skill,
    "decide": _decide,
    "hook": _hook,
    "attest": _attest,
    "fleet": _fleet,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisafe",
        description="AnyAISafe developer tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"aisafe {__version__}",
    )
    p.add_argument(
        "command",
        choices=sorted(COMMANDS),
        help="Subcommand to run",
    )
    # REMAINDER hands the rest through verbatim, so each tool keeps its own
    # flags, help text and pyproject-sourced defaults.
    p.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="Arguments passed through to the subcommand",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        parser.print_help()
        return 2
    ns = parser.parse_args(argv)
    return COMMANDS[ns.command](ns.args)


if __name__ == "__main__":
    sys.exit(main())
