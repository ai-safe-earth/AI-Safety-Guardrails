#!/usr/bin/env python3
"""
devtools/euaiact_lint.py
------------------------
CLI for the EU AI Act static code analyzer.

Usage:
    # Scan a directory
    python devtools/euaiact_lint.py src/

    # Scan a single file
    python devtools/euaiact_lint.py myapp/llm_service.py

    # JSON output (for CI)
    python devtools/euaiact_lint.py src/ --format json

    # SARIF output (GitHub Code Scanning)
    python devtools/euaiact_lint.py src/ --format sarif --output results.sarif

    # Only errors (strict mode — for pre-commit)
    python devtools/euaiact_lint.py src/ --errors-only

    # Scan only changed files from git diff
    python devtools/euaiact_lint.py --diff

    # Specific rules only
    python devtools/euaiact_lint.py src/ --rules EU-AIA-005a,EU-AIA-015c

Exit codes:
    0  — no errors (warnings/info allowed)
    1  — errors found
    2  — fatal error (bad args, parse failure)
"""

import argparse
import subprocess
import sys

from aisg.devtools._config import apply_tool_config
from aisg.modules.policy.code_analyzer.analyzer import MIN_PRECISION, EUAIActCodeAnalyzer, Severity
from aisg.modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)
from aisg.modules.policy.code_analyzer.rules import (
    ALL_RULES,
    experimental_rules,
    select_rules,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="euaiact-lint",
        description="EU AI Act static code compliance analyzer for Python AI projects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  euaiact-lint src/                          # Scan directory
  euaiact-lint src/ --format json            # JSON output for CI
  euaiact-lint src/ --format sarif           # SARIF for GitHub Code Scanning
  euaiact-lint src/ --errors-only            # Only Art. 5 / critical rules
  euaiact-lint src/ --rules EU-AIA-005a      # Run specific rule(s)
  euaiact-lint --diff                        # Scan only git-changed files
  euaiact-lint src/ --no-color               # Disable terminal colors
        """,
    )

    p.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="File(s) or directory(ies) to scan (default: current directory)",
    )
    p.add_argument(
        "--format",
        "-f",
        choices=["terminal", "json", "sarif", "markdown"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        help="Write output to file instead of stdout",
    )
    p.add_argument(
        "--errors-only",
        action="store_true",
        help="Only report ERROR severity findings (useful for pre-commit hard blocks)",
    )
    p.add_argument(
        "--rules",
        default=None,
        help="Comma-separated list of rule IDs to run (e.g. EU-AIA-005a,EU-AIA-015c)",
    )
    p.add_argument(
        "--exclude",
        default="__pycache__,.git,.venv,venv,dist,build,node_modules",
        help="Comma-separated directories to exclude",
    )
    p.add_argument(
        "--diff",
        action="store_true",
        help="Scan only files changed in current git diff (HEAD vs working tree)",
    )
    p.add_argument(
        "--staged",
        action="store_true",
        help="Scan only staged files (git diff --cached) — use in pre-commit hooks",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output",
    )
    p.add_argument(
        "--no-snippet",
        action="store_true",
        help="Hide code snippets in terminal output",
    )
    p.add_argument(
        "--no-suggestion",
        action="store_true",
        help="Hide fix suggestions in terminal output",
    )
    p.add_argument(
        "--fail-on-warnings",
        action="store_true",
        help="Exit with code 1 if any WARNING findings exist (in addition to errors)",
    )
    p.add_argument(
        "--experimental",
        action="store_true",
        help=(
            "Also run rules whose measured precision is below the "
            "default-on threshold (see bench/precision.md)"
        ),
    )
    p.add_argument(
        "--list-rules",
        action="store_true",
        help="Print all available rules and exit",
    )
    p.add_argument(
        "--version",
        action="version",
        version="euaiact-lint 0.1.0",
    )
    return p


def list_rules() -> None:
    from aisg.modules.policy.code_analyzer.rules import ALL_RULES

    print(
        f"{'Rule ID':<16} {'Severity':<10} {'Precision':<11} {'Default':<9} {'Article':<22} Title"
    )
    print("-" * 118)
    for rule in sorted(ALL_RULES, key=lambda r: r.rule_id):
        if rule.measured_precision is None:
            prec = "unmeasured"
        else:
            prec = f"{rule.measured_precision:.3f}"
        default = "on" if rule.fires_by_default() else "EXPERIMENTAL"
        print(
            f"{rule.rule_id:<16} {rule.severity.value:<10} {prec:<11} {default:<9} "
            f"{rule.article:<22} {rule.title}"
        )
    print()
    print(
        f"Precision is measured against the bench/ corpus; below {MIN_PRECISION:.2f} a rule "
        "only runs with --experimental."
    )
    print(
        "'unmeasured' means the corpus has not been labelled for that rule yet -- it is not a score."
    )


def get_git_diff(staged: bool = False) -> str:
    try:
        args = ["git", "diff", "--name-only"]
        if staged:
            args.append("--cached")
        result = subprocess.run(args, capture_output=True, text=True)
        lines = [f"+++ b/{f}" for f in result.stdout.splitlines() if f.endswith(".py")]
        return "\n".join(lines)
    except Exception:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    apply_tool_config(parser, "euaiact-lint")
    # argv=None keeps the historical behaviour of reading sys.argv;
    # the aisg CLI passes the subcommand's arguments through explicitly.
    args = parser.parse_args(argv)

    if args.list_rules:
        list_rules()
        return 0

    # Select rules. Rules measured below MIN_PRECISION are excluded unless
    # --experimental is given, or the user names them explicitly with --rules.
    experimental = getattr(args, "experimental", False)
    if args.rules:
        wanted = {r.strip() for r in args.rules.split(",")}
        rules = [r for r in ALL_RULES if r.rule_id in wanted]
        if not rules:
            print(f"Error: No rules matched {args.rules}", file=sys.stderr)
            return 2
        if args.errors_only:
            rules = [r for r in rules if r.severity == Severity.ERROR]
        # Naming a rule is an explicit request, so honour it -- but say so,
        # rather than silently returning nothing.
        demoted = [r.rule_id for r in rules if not r.fires_by_default()]
        if demoted and not experimental:
            print(
                f"Note: including below-threshold rule(s) {', '.join(demoted)} "
                "because --rules named them explicitly.",
                file=sys.stderr,
            )
    else:
        rules = select_rules(experimental=experimental, errors_only=args.errors_only)
        demoted_rules = experimental_rules()
        if not experimental and demoted_rules:
            skipped = ", ".join(r.rule_id for r in demoted_rules)
            print(
                f"Note: {len(demoted_rules)} below-threshold rule(s) not run "
                f"({skipped}). Use --experimental to include them.",
                file=sys.stderr,
            )

    analyzer = EUAIActCodeAnalyzer(rules=rules)
    exclude_dirs = [d.strip() for d in args.exclude.split(",")]

    # Run scan
    if args.diff or args.staged:
        diff_text = get_git_diff(staged=args.staged)
        if not diff_text:
            print("No Python files changed. Nothing to scan.")
            return 0
        report = analyzer.scan_diff(diff_text)
    else:
        import time

        from aisg.modules.policy.code_analyzer.analyzer import ScanReport

        report = ScanReport()
        start = time.perf_counter()
        for path in args.paths:
            from pathlib import Path

            p = Path(path)
            if p.is_file():
                sub = analyzer.scan_file(p)
            elif p.is_dir():
                sub = analyzer.scan_directory(p, exclude_dirs=exclude_dirs)
            else:
                print(f"Warning: {path} is not a file or directory", file=sys.stderr)
                continue
            report.scanned_files.extend(sub.scanned_files)
            report.findings.extend(sub.findings)
            report.errors.extend(sub.errors)
        report.scan_duration_s = time.perf_counter() - start

    # Open output file if requested
    if args.output:
        out_file = open(args.output, "w", encoding="utf-8")
    else:
        out_file = sys.stdout

    # Write report
    try:
        if args.format == "json":
            JSONReporter(out=out_file).write(report)
        elif args.format == "sarif":
            SARIFReporter(out=out_file).write(report)
        elif args.format == "markdown":
            MarkdownReporter(out=out_file).write(report)
        else:
            TerminalReporter(
                color=not args.no_color,
                show_snippet=not args.no_snippet,
                show_suggestion=not args.no_suggestion,
                out=out_file,
            ).write(report)
    finally:
        if args.output:
            out_file.close()

    # Exit code
    if report.error_count > 0:
        return 1
    if args.fail_on_warnings and report.warning_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
