"""
src/aisg/cli.py
---------------
Single entry point for the AI Safety Guardrails developer tools.

    aisg --version
    aisg lint src/
    aisg lint src/ --format sarif --output results.sarif
    aisg misalign src/ --fail-on-warnings

`lint` and `misalign` are thin wrappers around the static analysers in
`aisg.devtools`. Everything after the subcommand is handed to the underlying
tool untouched, so their flags, defaults and exit codes are unchanged:

    0  no errors (warnings/info allowed)
    1  errors found
    2  fatal error (bad args, parse failure)
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Sequence

from aisg import __version__

__all__ = ["main", "build_parser"]

_EPILOG = """
Commands:
  lint        EU AI Act static compliance analysis (was: euaiact-lint)
  misalign    AI misalignment static analysis      (was: misalignment-check)
  init        Write an ai-system-card.yaml for the system under assessment
  probe       Send a fixed attack corpus to a live endpoint and report what got through
  measure     Report what each guard catches, what it breaks, and what it costs

Run `aisg <command> --help` for a command's own options.

Examples:
  aisg lint src/
  aisg lint src/ --format sarif --output results.sarif
  aisg lint src/ --errors-only
  aisg lint --staged                       # pre-commit
  aisg misalign src/ --fail-on-warnings
  aisg init --defaults
  aisg probe http://localhost:8000/chat --response-path '$.response'
  aisg measure
"""


def _lint(argv: Sequence[str]) -> int:
    from aisg.devtools.euaiact_lint import main as lint_main

    return lint_main(list(argv))


def _misalign(argv: Sequence[str]) -> int:
    from aisg.devtools.misalignment_check import main as misalign_main

    return misalign_main(list(argv))


def _init(argv: Sequence[str]) -> int:
    from aisg.devtools.system_card import main as init_main

    return init_main(list(argv))


def _probe(argv: Sequence[str]) -> int:
    from aisg.devtools.probe import main as probe_main

    return probe_main(list(argv))


def _measure(argv: Sequence[str]) -> int:
    from aisg.devtools.measure import main as measure_main

    return measure_main(list(argv))


COMMANDS: dict[str, Callable[[Sequence[str]], int]] = {
    "lint": _lint,
    "misalign": _misalign,
    "init": _init,
    "probe": _probe,
    "measure": _measure,
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aisg",
        description="AI Safety Guardrails developer tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    p.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"aisg {__version__}",
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
