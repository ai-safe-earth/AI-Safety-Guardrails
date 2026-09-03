"""aisg/devtools/audit/main.py
------------------------------
Parser, orchestration and exit codes for `aisg audit`.

The run is walk -> discover -> pydeep -> rules -> adapters -> baseline -> report.
Nothing here opens a socket: the only subprocess path is `adapters.run_adapters`,
and `--no-external` turns even that off. Exit codes: 0 no counted finding, 1 a
finding at or above `--fail-on` (or an UNKNOWN item under `--fail-on-unknown`),
2 fatal, 130 interrupted. A zero exit says the run found nothing it counts; it
never says the target is safe.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, Sequence

from aisg.devtools._config import apply_tool_config
from aisg.devtools.audit import adapters, discover, pydeep, walk
from aisg.devtools.audit.baseline import (
    BaselineDiff,
    BaselineError,
    diff,
    load_baseline,
    write_baseline,
)
from aisg.devtools.audit.model import (
    AuditContext,
    Bucket,
    Finding,
    Severity,
    UnknownItem,
)
from aisg.devtools.audit.report import (
    FAIL_ON_CHOICES,
    FORMATS,
    build_report,
    check_templates,
    compute_exit_code,
    render,
)
from aisg.devtools.audit.rules import ALL_RULES, AuditRule, is_demoted, run_rules, select_rules

__all__ = [
    "EXIT_FATAL",
    "EXIT_FINDINGS",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "AuditOptions",
    "build_parser",
    "main",
    "run_audit",
]

PROG = "aisg audit"
CONFIG_SECTION = "aisg-audit"

# `EXIT_OK` says "nothing counted", on purpose: a zero exit is not a bill of health.
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_FATAL = 2
EXIT_INTERRUPTED = 130

DEEP_CHOICES: tuple[str, ...] = ("python", "none")
UNKNOWN_CATEGORIES: tuple[str, ...] = ("tools", "deep", "reports", "runtime")
DEFAULT_TRUSTED_MCP_HOSTS: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
DEFAULT_TIMEOUT = 120
UNMEASURED = "UNMEASURED"

_REDACT_REFUSED = (
    "--no-redact is refused: redaction is not optional. Secret-shaped snippets are "
    "always redacted in every format; there is no flag that prints them."
)


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


def _csv(value: Any) -> tuple[str, ...]:
    """Split a CSV string (or flatten a list of them) into stripped, non-empty items."""
    if value is None:
        return ()
    if isinstance(value, str):
        parts: list[str] = value.split(",")
    else:
        parts = []
        for item in value:
            parts.extend(str(item).split(","))
    return tuple(p.strip() for p in parts if p.strip())


def _unknown_categories(value: Any) -> frozenset[str] | None:
    """`--fail-on-unknown` value -> category set. `None`/False off; True means all four."""
    if value is None or value is False:
        return None
    if value is True:
        return frozenset(UNKNOWN_CATEGORIES)
    if isinstance(value, (set, frozenset)):
        chosen = frozenset(str(v) for v in value)
    else:
        chosen = frozenset(_csv(value))
    if not chosen:
        return frozenset(UNKNOWN_CATEGORIES)
    bad = sorted(chosen - set(UNKNOWN_CATEGORIES))
    if bad:
        raise ValueError(
            f"--fail-on-unknown: unknown category {', '.join(bad)}; "
            f"expected any of {', '.join(UNKNOWN_CATEGORIES)}"
        )
    return chosen


def _fail_on_unknown_arg(text: str) -> frozenset[str]:
    """argparse `type` for `--fail-on-unknown`; also applied to a CSV default from config."""
    try:
        return _unknown_categories(text) or frozenset(UNKNOWN_CATEGORIES)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


class _ExtendCsv(argparse.Action):
    """`--exclude a,b --exclude c` accumulates; the first use replaces a config default."""

    def __call__(self, parser, namespace, values, option_string=None):
        current = getattr(namespace, self.dest, None)
        items = list(current) if isinstance(current, list) else []
        items.extend(_csv(values))
        setattr(namespace, self.dest, items)


@dataclass
class AuditOptions:
    """
    Every knob of one run, normalised. Built from the parsed namespace by
    `from_namespace`; rules, discovery and adapters read attributes off it by name
    (`include_home`, `trusted_mcp_hosts`, `run_evals`, `pip_audit_env`, ...).
    """

    path: str = "."
    format: str = "terminal"
    output: str | None = None
    fail_on: str = "low"
    fail_on_unknown: frozenset[str] | None = None
    include_ignored: bool = False
    baseline: str | None = None
    write_baseline: str | None = None
    inventory_only: bool = False
    include_home: bool = False
    deep: str = "python"
    tools: tuple[str, ...] | None = None
    no_external: bool = False
    run_evals: bool = False
    trusted_mcp_hosts: tuple[str, ...] = DEFAULT_TRUSTED_MCP_HOSTS
    rules: tuple[str, ...] | None = None
    experimental: bool = False
    exclude: tuple[str, ...] = ()
    timeout: int = DEFAULT_TIMEOUT
    list_rules: bool = False
    quiet: bool = False
    debug: bool = False
    redact: bool = True
    pip_audit_env: str | None = None

    @classmethod
    def from_namespace(cls, ns: argparse.Namespace | AuditOptions) -> AuditOptions:
        """Normalise a parsed namespace (or pass an AuditOptions through). Raises ValueError."""
        if isinstance(ns, AuditOptions):
            return ns

        def get(name: str, default: Any = None) -> Any:
            return getattr(ns, name, default)

        fmt = str(get("format", "terminal") or "terminal").lower()
        if fmt not in FORMATS:
            raise ValueError(f"--format must be one of {', '.join(FORMATS)}, not {fmt!r}")
        fail_on = str(get("fail_on", "low") or "low").lower()
        if fail_on not in FAIL_ON_CHOICES:
            raise ValueError(
                f"--fail-on must be one of {', '.join(FAIL_ON_CHOICES)}, not {fail_on!r}"
            )
        deep = str(get("deep", "python") or "python").lower()
        if deep not in DEEP_CHOICES:
            raise ValueError(f"--deep must be one of {', '.join(DEEP_CHOICES)}, not {deep!r}")
        tools = _csv(get("tools")) or None
        rules = _csv(get("rules")) or None
        hosts = get("trusted_mcp_hosts")
        trusted = _csv(hosts) if hosts is not None else DEFAULT_TRUSTED_MCP_HOSTS
        timeout_raw = get("timeout", DEFAULT_TIMEOUT)
        timeout = DEFAULT_TIMEOUT if timeout_raw is None else int(timeout_raw)
        if timeout <= 0:
            raise ValueError(f"--timeout must be a positive number of seconds, not {timeout}")
        return cls(
            path=str(get("path", ".") or "."),
            format=fmt,
            output=_opt_str(get("output")),
            fail_on=fail_on,
            fail_on_unknown=_unknown_categories(get("fail_on_unknown")),
            include_ignored=bool(get("include_ignored", False)),
            baseline=_opt_str(get("baseline")),
            write_baseline=_opt_str(get("write_baseline")),
            inventory_only=bool(get("inventory_only", False)),
            include_home=bool(get("include_home", False)),
            deep=deep,
            tools=tools,
            no_external=bool(get("no_external", False)),
            run_evals=bool(get("run_evals", False)),
            trusted_mcp_hosts=trusted,
            rules=rules,
            experimental=bool(get("experimental", False)),
            exclude=_csv(get("exclude")),
            timeout=timeout,
            list_rules=bool(get("list_rules", False)),
            quiet=bool(get("quiet", False)),
            debug=bool(get("debug", False)),
            redact=bool(get("redact", True)),
            pip_audit_env=_opt_str(get("pip_audit_env")),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if isinstance(value, frozenset):
                value = sorted(value)
            out[f.name] = value
        return out


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """The `aisg audit` parser. Defaults are the code's; `main()` layers pyproject on top."""
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Static AI-safety audit of a repository: what talks to a model, what it can "
            "reach, and what evidence exists for the guards around it. Findings describe "
            "evidence; the report never states a verdict."
        ),
        epilog=(
            "Exit codes: 0 no finding at or above --fail-on, 1 findings (or an UNKNOWN item "
            "under --fail-on-unknown), 2 fatal, 130 interrupted. Defaults may be set in "
            "[tool.aisg-audit] of pyproject.toml; an explicit flag always wins."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="repo or subdirectory to audit")
    parser.add_argument(
        "--format", choices=FORMATS, default="terminal", help="renderer (default: terminal)"
    )
    parser.add_argument(
        "--output",
        "-o",
        default=None,
        metavar="PATH",
        help="write the rendered document here instead of stdout",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_ON_CHOICES,
        default="low",
        help="minimum severity that yields exit 1 (default: low; never = findings never count)",
    )
    parser.add_argument(
        "--fail-on-unknown",
        nargs="?",
        const=frozenset(UNKNOWN_CATEGORIES),
        default=None,
        type=_fail_on_unknown_arg,
        metavar="CATEGORIES",
        help=(
            "exit 1 on an UNKNOWN item in these categories (csv of "
            + ",".join(UNKNOWN_CATEGORIES)
            + "); bare flag = all four"
        ),
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        default=False,
        help="also walk files that .gitignore excludes",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="fingerprint baseline (or a full audit report); only new findings count",
    )
    parser.add_argument(
        "--write-baseline",
        default=None,
        metavar="FILE",
        help="write this run's fingerprints as a baseline and exit 0",
    )
    parser.add_argument(
        "--inventory-only",
        action="store_true",
        default=False,
        help="print the inventory document and exit 0",
    )
    parser.add_argument(
        "--include-home",
        action="store_true",
        default=False,
        help="also read host configs under the home directory",
    )
    parser.add_argument(
        "--deep",
        choices=DEEP_CHOICES,
        default="python",
        help="AST layer (default: python)",
    )
    parser.add_argument(
        "--tools",
        default=None,
        metavar="CSV",
        help="restrict external adapters to these names (default: all)",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        default=False,
        help="skip every external adapter (each is reported as skipped_by_flag)",
    )
    parser.add_argument(
        "--run-evals",
        action="store_true",
        default=False,
        help="allow the promptfoo adapter to run (it may call model providers)",
    )
    parser.add_argument(
        "--pip-audit-env",
        default=None,
        metavar="PYTHON",
        help="python executable of the target's environment for pip-audit",
    )
    parser.add_argument(
        "--trusted-mcp-hosts",
        default=",".join(DEFAULT_TRUSTED_MCP_HOSTS),
        metavar="CSV",
        help="hosts whose MCP servers are not counted as untrusted",
    )
    parser.add_argument(
        "--rules",
        default=None,
        metavar="CSV",
        help="run only these rule ids (a demoted id runs with a stderr note)",
    )
    parser.add_argument(
        "--experimental",
        action="store_true",
        default=False,
        help="include rules measured below MIN_PRECISION",
    )
    parser.add_argument(
        "--exclude",
        action=_ExtendCsv,
        default=None,
        metavar="GLOBS",
        help="walker excludes (csv of globs; repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per external tool (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        default=False,
        help="print the rule catalogue and exit 0",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="terminal output: summary and UNKNOWN items only",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="tracebacks on fatal errors; also self-check the renderer templates",
    )
    redact = parser.add_mutually_exclusive_group()
    redact.add_argument(
        "--redact",
        dest="redact",
        action="store_true",
        default=True,
        help="redact secret-shaped snippets (always on)",
    )
    redact.add_argument(
        "--no-redact",
        dest="redact",
        action="store_false",
        help="refused: redaction is not optional",
    )
    return parser


# ---------------------------------------------------------------------------
# Pieces of the run
# ---------------------------------------------------------------------------


def _note(message: str) -> None:
    print(f"{PROG}: {message}", file=sys.stderr)


def _list_rules_text(rules: Sequence[type[AuditRule]]) -> str:
    """Catalogue table: id, priority, severity, tier, precision, default. ASCII only."""
    header = ("id", "priority", "severity", "tier", "measured_precision", "default")
    rows: list[tuple[str, ...]] = []
    for rule in sorted(rules, key=lambda r: (r.priority, r.id)):
        precision = rule.measured_precision
        rows.append(
            (
                rule.id,
                str(rule.priority),
                Severity(rule.severity).value,
                getattr(rule.tier, "value", str(rule.tier)),
                UNMEASURED if precision is None else f"{precision:.2f}",
                "demoted (--experimental)" if is_demoted(rule) else "yes",
            )
        )
    widths = [max(len(row[i]) for row in (header, *rows)) for i in range(len(header))]
    lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(header)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)).rstrip())
    lines.append("")
    lines.append(
        f"{len(rows)} rules. measured_precision {UNMEASURED} means no labelled corpus has "
        "scored the rule yet; unmeasured rules still run by default."
    )
    return "\n".join(lines) + "\n"


def _resolve_root(path: str) -> Path:
    root = Path(path)
    if not root.exists():
        raise FileNotFoundError(f"path does not exist: {path}")
    if not root.is_dir():
        raise NotADirectoryError(f"path is not a directory: {path}")
    return root.resolve()


def _build_context(options: AuditOptions, root: Path) -> AuditContext:
    """walk -> discover -> pydeep, every UNKNOWN item folded into one context."""
    files, units, walk_unknown = walk.walk(
        root,
        walk.WalkOptions(exclude=tuple(options.exclude), include_ignored=options.include_ignored),
    )
    inventory, hits, facts = discover.discover(
        root,
        files,
        units,
        discover.DiscoverOptions(
            include_home=options.include_home,
            trusted_mcp_hosts=tuple(options.trusted_mcp_hosts),
        ),
    )
    unknown: list[UnknownItem] = list(walk_unknown) + list(inventory.unknown)
    pyfacts = None
    if options.deep == "python":
        pyfacts = pydeep.analyse_unit([f for f in files if f.lang == "python"], inventory)
        unknown.extend(pyfacts.unknown)
    return AuditContext(
        root=root,
        inventory=inventory,
        pyfacts=pyfacts,
        hits=hits,
        options=options,
        unknown=unknown,
        files=files,
        reports=list(inventory.reports),
        config_facts=facts,
    )


def _dedupe_unknown(items: Sequence[UnknownItem]) -> list[UnknownItem]:
    """
    Drop exact repeats. The key includes `why`: two adapters can share a topic
    (`what`) and differ only in why they did not run, and both rows matter.
    """
    seen: set[tuple[str, str, str, str | None]] = set()
    out: list[UnknownItem] = []
    for item in items:
        key = (getattr(item.category, "value", str(item.category)), item.what, item.why, item.file)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _fold_findings(
    rule_findings: Sequence[Finding], tool_findings: Sequence[Finding]
) -> list[Finding]:
    """
    Merge adapter findings into the rule findings. A MEASURED finding at the same
    (id, file, line) as an ASSERTED one replaces it: the tool ran, so its evidence
    is the stronger claim and the pair must not count twice.
    """
    measured_at: set[tuple[str, str, int]] = set()
    for finding in tool_findings:
        if Bucket(finding.bucket) is Bucket.MEASURED:
            file, line = finding.location
            measured_at.add((finding.id, file, int(line)))
    kept: list[Finding] = []
    for finding in rule_findings:
        file, line = finding.location
        if (
            Bucket(finding.bucket) is Bucket.ASSERTED
            and (finding.id, file, int(line)) in measured_at
        ):
            continue
        kept.append(finding)
    kept.extend(tool_findings)
    return kept


def _write_output(text: str, output: str | None) -> None:
    if output is None:
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    target = Path(output)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _inventory_document(ctx: AuditContext, unknown: Sequence[UnknownItem]) -> str:
    doc = ctx.inventory.to_dict()
    doc["unknown"] = [item.to_dict() for item in unknown]
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def run_audit(args: argparse.Namespace | AuditOptions) -> int:
    """
    One audit run; the testable core behind `main()`. Returns the exit code.
    Raises on fatal conditions (`BaselineError`, a missing path, ...); `main()`
    turns those into exit 2.
    """
    options = AuditOptions.from_namespace(args)

    if not options.redact:
        _note(_REDACT_REFUSED)
        return EXIT_FATAL

    if options.list_rules:
        sys.stdout.write(_list_rules_text(ALL_RULES))
        sys.stdout.flush()
        return EXIT_OK

    if options.debug:
        leaked = check_templates()
        if leaked:
            _note("renderer template self-check failed; banned phrase(s) present:")
            for phrase in leaked:
                print(f"  - {phrase}", file=sys.stderr)
            return EXIT_FATAL

    root = _resolve_root(options.path)
    ctx = _build_context(options, root)

    if options.inventory_only:
        _write_output(_inventory_document(ctx, _dedupe_unknown(ctx.unknown)), options.output)
        if options.output is not None:
            _note(f"inventory written to {options.output}")
        return EXIT_OK

    rules, notes = select_rules(options.rules, options.experimental)
    for note in notes:
        _note(note)
    if options.rules is not None and not rules:
        _note("no rule selected; nothing ran")

    rule_findings, rule_unknown = run_rules(rules, ctx)

    results, tool_findings, tool_unknown = adapters.run_adapters(
        ctx,
        options.tools or None,
        timeout=options.timeout,
        no_external=options.no_external,
    )
    ctx.external = list(results)

    findings = _fold_findings(rule_findings, tool_findings)
    unknown = _dedupe_unknown(list(ctx.unknown) + list(rule_unknown) + list(tool_unknown))

    baseline_diff: BaselineDiff | None = None
    if options.baseline is not None:
        known = load_baseline(Path(options.baseline))
        baseline_diff = diff(findings, known, options.baseline)

    exit_code = compute_exit_code(
        findings,
        unknown,
        fail_on=options.fail_on,
        fail_on_unknown=set(options.fail_on_unknown) if options.fail_on_unknown else None,
    )
    report = build_report(
        ctx,
        findings,
        unknown,
        results,
        ctx.reports,
        baseline_diff,
        rules=rules,
        fail_on=options.fail_on,
        exit_code=exit_code,
    )

    if options.write_baseline is not None:
        write_baseline(report, Path(options.write_baseline))
        _note(
            f"baseline written to {options.write_baseline} "
            f"({len(report.findings)} fingerprint{'' if len(report.findings) == 1 else 's'}); "
            "exit 0 because a baseline write records findings, it does not judge them"
        )
        return EXIT_OK

    text = render(report, options.format, quiet=options.quiet)
    _write_output(text, options.output)
    if options.output is not None:
        _note(f"{options.format} report written to {options.output}")
        if options.format != "terminal":
            sys.stdout.write(render(report, "terminal", quiet=True))
            sys.stdout.flush()
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry: parse, apply `[tool.aisg-audit]` defaults, run, map errors to exit codes."""
    parser = build_parser()
    apply_tool_config(parser, CONFIG_SECTION)
    ns = parser.parse_args(list(argv) if argv is not None else None)
    debug = bool(getattr(ns, "debug", False))
    try:
        return run_audit(ns)
    except KeyboardInterrupt:
        _note("interrupted")
        return EXIT_INTERRUPTED
    except BaselineError as exc:
        _note(f"baseline error: {exc}")
        return EXIT_FATAL
    except Exception as exc:  # broad on purpose: the CLI maps every failure to exit 2
        if debug:
            traceback.print_exc()
        _note(f"fatal: {type(exc).__name__}: {exc}")
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
