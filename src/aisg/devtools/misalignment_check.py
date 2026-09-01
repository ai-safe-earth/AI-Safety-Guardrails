#!/usr/bin/env python3
"""
devtools/misalignment_check.py
-------------------------------
CLI for the AI Misalignment static checker.

Detects code patterns that suggest an AI system may behave contrary to its
stated purpose: safety bypasses, hidden content, covert instructions, missing
oversight hooks, hardcoded unsafe defaults, unnecessary personal data, and
undesired objectives.

Usage:
    # Scan a directory
    python devtools/misalignment_check.py src/

    # Only staged files (pre-commit)
    python devtools/misalignment_check.py --staged

    # Scan changed files only (CI on PR)
    python devtools/misalignment_check.py --diff

    # JSON output for CI
    python devtools/misalignment_check.py src/ --format json

    # SARIF for GitHub Code Scanning
    python devtools/misalignment_check.py src/ --format sarif --output results.sarif

    # Hard-block mode: errors only
    python devtools/misalignment_check.py src/ --errors-only

    # Run specific rules
    python devtools/misalignment_check.py src/ --rules ALIGN-001,ALIGN-005

Exit codes:
    0  — no errors (warnings/info allowed)
    1  — errors found
    2  — fatal error (bad args, parse failure)
"""

import argparse
import subprocess
import sys

from aisg.devtools._config import apply_tool_config
from aisg.devtools.misalignment.rules import MISALIGNMENT_RULES, MISALIGNMENT_RULES_STRICT
from aisg.modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer
from aisg.modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="misalignment-check",
        description="AI Misalignment static checker — detects hidden goals, safety bypasses, and covert content.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Rules:
  ALIGN-001  Safety bypass patterns          (ERROR)
  ALIGN-002  Hardcoded unsafe defaults        (WARNING)
  ALIGN-003  Missing human oversight hooks    (WARNING)
  ALIGN-004  Policy-code consistency          (WARNING)
  ALIGN-005  Hidden / encoded content         (ERROR)
  ALIGN-006  Covert instructions in prompts   (ERROR)
  ALIGN-007  Unnecessary codified data        (WARNING)
  ALIGN-008  Undesired objectives             (ERROR)

Examples:
  misalignment-check src/                    # Scan directory
  misalignment-check --staged                # Pre-commit: staged files only
  misalignment-check --diff                  # CI: changed files vs HEAD
  misalignment-check src/ --format json      # JSON for CI
  misalignment-check src/ --format sarif     # SARIF for GitHub Code Scanning
  misalignment-check src/ --errors-only      # Hard-block on ERROR rules only
  misalignment-check src/ --rules ALIGN-001  # Run a specific rule
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
        help="Only report ERROR severity findings (ALIGN-001, 005, 006, 008)",
    )
    p.add_argument(
        "--rules",
        default=None,
        help="Comma-separated list of rule IDs to run (e.g. ALIGN-001,ALIGN-005)",
    )
    p.add_argument(
        "--exclude",
        default="__pycache__,.git,.venv,venv,dist,build,node_modules,tests/fixtures",
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
        help="Scan only staged files (git diff --cached) — for pre-commit hooks",
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
        "--list-rules",
        action="store_true",
        help="Print all available misalignment rules and exit",
    )
    p.add_argument(
        "--version",
        action="version",
        version="misalignment-check 0.1.0",
    )
    return p


def list_rules() -> None:
    print(f"{'Rule ID':<12} {'Severity':<10} {'Category':<36} Title")
    print("-" * 90)
    for rule in sorted(MISALIGNMENT_RULES, key=lambda r: r.rule_id):
        print(f"{rule.rule_id:<12} {rule.severity.value:<10} {rule.article:<36} {rule.title}")


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
    apply_tool_config(parser, "misalignment-check")
    # argv=None keeps the historical behaviour of reading sys.argv;
    # the aisg CLI passes the subcommand's arguments through explicitly.
    args = parser.parse_args(argv)

    if args.list_rules:
        list_rules()
        return 0

    # Select rules
    if args.errors_only:
        rules = MISALIGNMENT_RULES_STRICT
    elif args.rules:
        wanted = {r.strip() for r in args.rules.split(",")}
        rules = [r for r in MISALIGNMENT_RULES if r.rule_id in wanted]
        if not rules:
            print(f"Error: No rules matched {args.rules}", file=sys.stderr)
            return 2
    else:
        rules = MISALIGNMENT_RULES

    # Reuse the EUAIActCodeAnalyzer engine with our rule set
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
