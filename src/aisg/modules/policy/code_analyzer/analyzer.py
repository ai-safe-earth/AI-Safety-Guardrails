"""
modules/policy/code_analyzer/analyzer.py
-----------------------------------------
EU AI Act Static Code Analyzer

Scans Python source files for patterns that may indicate non-compliance
with Regulation (EU) 2024/1689. Works via:

  1. AST analysis  — inspects function calls, class definitions,
                     imports, decorators, and variable names
  2. Regex scan    — catches patterns AST misses (comments, strings,
                     config values, model names in string literals)
  3. Heuristic rules — each rule maps to a specific Article obligation

This is NOT a legal tool. It surfaces code patterns that warrant
human legal review, ranked by severity and mapped to the Article
that likely applies.

Entry points:
    analyzer = EUAIActCodeAnalyzer()
    report   = analyzer.scan_file("myapp/llm_service.py")
    report   = analyzer.scan_directory("src/", recursive=True)
"""

from __future__ import annotations

import ast
import functools
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------


# A rule measured below this precision does not fire without --experimental.
MIN_PRECISION = 0.80

# Suppression. Both forms are explicit on purpose, and both are scoped to the
# tool that reads them: this analyzer is shared by `aisg lint` and
# `aisg misalign`, and a marker written for one must not silence the other.
#
# `# euaiact-lint: ignore-file` within the first MARKER_LINES lines skips the
# file. It is for the files that ARE the linter's vocabulary -- the rule tables
# and the runtime guard's prohibited-practice patterns spell out every phrase
# the rules look for and would otherwise report themselves. A skipped file is
# recorded in `ScanReport.skipped_files`, never silently dropped.
#
# `# euaiact-lint: ignore EU-AIA-005a` on a line suppresses that rule on that
# line. The rule id is required -- an `ignore` naming nothing is not honoured,
# so every suppression says what it silences. Suppressed findings are counted
# in `ScanReport.suppressed_count`. (Not spelled `noqa`: ruff parses every
# `noqa` comment and warns about codes it does not know.)
DEFAULT_TOOL = "euaiact-lint"
MARKER_LINES = 5


def ignore_marker(tool: str = DEFAULT_TOOL) -> str:
    """The file-level marker `tool` honours."""
    return f"# {tool}: ignore-file"


@functools.lru_cache(maxsize=None)
def _line_directive_re(tool: str) -> re.Pattern[str]:
    return re.compile(rf"#\s*{re.escape(tool)}:\s*ignore[ \t]+([A-Za-z0-9_,\s-]+)")


IGNORE_MARKER = ignore_marker(DEFAULT_TOOL)


def physical_lines(source: str) -> list[str]:
    """
    `source` split the way the tokenizer counts lines: on `\\n` only.

    `str.splitlines()` also breaks on form feed, vertical tab, NEL and the
    Unicode line and paragraph separators, none of which end a line for
    `ast.parse`. After one of them -- a page break on its own line, U+2028
    inside a string literal -- every AST line number would index one entry
    too early, so a directive on the finding's own line would be missed and
    one on the line above would silence the *next* finding while
    `suppressed_count` reported success. Every rule and the directive lookup
    use this one list. `read_text` has already turned `\\r\\n` and `\\r` into
    `\\n`.
    """
    return source.split("\n")


class Severity(str, Enum):
    ERROR = "error"  # Likely non-compliant — must fix before deploy
    WARNING = "warning"  # Potentially non-compliant — legal review recommended
    INFO = "info"  # Good-practice suggestion aligned with the Act


@dataclass
class CodeFinding:
    """A single compliance finding in source code."""

    rule_id: str  # e.g. "EU-AIA-001"
    article: str  # e.g. "Art. 5(1)(c)"
    severity: Severity
    title: str
    description: str
    file: str
    line: int
    col: int = 0
    snippet: str = ""  # The offending line of code
    suggestion: str = ""  # What to do instead
    reference: str = ""  # Link to official text

    def __str__(self) -> str:
        loc = f"{self.file}:{self.line}:{self.col}"
        return f"[{self.severity.value.upper()}] {self.rule_id} {loc} — {self.title}"


@dataclass
class ScanReport:
    """Aggregated report for one scan run."""

    scanned_files: list[str] = field(default_factory=list)
    findings: list[CodeFinding] = field(default_factory=list)
    scan_duration_s: float = 0.0
    errors: list[str] = field(default_factory=list)  # parse errors
    skipped_files: list[str] = field(default_factory=list)  # carried the tool's ignore marker
    suppressed_count: int = 0  # findings silenced by a line directive naming the rule
    tool: str = DEFAULT_TOOL  # whose markers were honoured; reporters name it

    # Computed
    @property
    def error_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def passed(self) -> bool:
        return self.error_count == 0

    def by_file(self) -> dict[str, list[CodeFinding]]:
        out: dict[str, list[CodeFinding]] = {}
        for f in self.findings:
            out.setdefault(f.file, []).append(f)
        return out

    def by_article(self) -> dict[str, list[CodeFinding]]:
        out: dict[str, list[CodeFinding]] = {}
        for f in self.findings:
            out.setdefault(f.article, []).append(f)
        return out


# ---------------------------------------------------------------------------
# Rule base class
# ---------------------------------------------------------------------------


class BaseRule:
    """
    A single compliance rule. Subclass and implement:
        check_ast(tree, source_lines, filename)  → Iterator[CodeFinding]
        check_text(source, filename)             → Iterator[CodeFinding]
    """

    rule_id: str = "EU-AIA-000"
    article: str = ""
    severity: Severity = Severity.WARNING
    title: str = ""
    description: str = ""
    suggestion: str = ""
    reference: str = "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689"

    # Precision measured against the bench/ corpus: tp / (tp + fp) over
    # hand-labelled findings. `None` means NOT YET MEASURED -- it does not mean
    # bad, and it must never be filled in with a guess. Run bench/run.py, label
    # bench/findings.csv, then bench/score.py prints the value to paste here.
    measured_precision: float | None = None

    def fires_by_default(self, threshold: float = MIN_PRECISION) -> bool:
        """
        Whether this rule runs without `--experimental`.

        Unmeasured rules keep firing: absence of a measurement is not evidence
        of imprecision, and gating everything unmeasured would silence the
        entire linter until the corpus is labelled. Only a rule measured BELOW
        the threshold is demoted to experimental.
        """
        return self.measured_precision is None or self.measured_precision >= threshold

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        return iter([])

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        return iter([])

    def _finding(
        self, filename: str, line: int, col: int = 0, snippet: str = "", **overrides
    ) -> CodeFinding:
        return CodeFinding(
            rule_id=overrides.get("rule_id", self.rule_id),
            article=overrides.get("article", self.article),
            severity=overrides.get("severity", self.severity),
            title=overrides.get("title", self.title),
            description=overrides.get("description", self.description),
            suggestion=overrides.get("suggestion", self.suggestion),
            reference=overrides.get("reference", self.reference),
            file=filename,
            line=line,
            col=col,
            snippet=snippet.strip(),
        )

    def _snippet(self, lines: list[str], lineno: int) -> str:
        idx = lineno - 1
        if 0 <= idx < len(lines):
            return lines[idx].rstrip()
        return ""


# ---------------------------------------------------------------------------
# Suppression helpers
# ---------------------------------------------------------------------------


def has_ignore_marker(source: str, tool: str = DEFAULT_TOOL) -> bool:
    """True when `tool`'s ignore-file marker sits on one of the first MARKER_LINES lines."""
    marker = ignore_marker(tool)
    head = physical_lines(source)[:MARKER_LINES]
    return any(marker in line for line in head)


def ignored_rules(line: str, tool: str = DEFAULT_TOOL) -> set[str]:
    """
    Rule ids named by a `# <tool>: ignore <id>[, <id>...]` directive on this
    line, upper-cased. Empty for no directive, and for one naming no rule.
    """
    match = _line_directive_re(tool).search(line)
    if not match:
        return set()
    return {part.strip().upper() for part in match.group(1).split(",") if part.strip()}


def is_excluded(path: Path, exclude: set[str]) -> bool:
    """
    Whether `path` falls under any exclude entry.

    An entry is a directory name (`__pycache__`, matched anywhere) or a POSIX
    path fragment (`tests/fixtures`, matched as consecutive segments). The
    earlier check compared single path parts, so a multi-segment entry never
    matched and `exclude = ["tests/fixtures"]` in pyproject was silently inert.
    """
    haystack = "/" + path.as_posix().strip("/") + "/"
    for entry in exclude:
        needle = entry.replace("\\", "/").strip("/")
        if needle and f"/{needle}/" in haystack:
            return True
    return False


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class EUAIActCodeAnalyzer:
    """
    Scans Python source files for EU AI Act compliance issues.

    Usage:
        analyzer = EUAIActCodeAnalyzer()
        report   = analyzer.scan_directory("src/")
        if not report.passed:
            sys.exit(1)
    """

    def __init__(self, rules: list[BaseRule] | None = None, tool: str = DEFAULT_TOOL):
        from aisg.modules.policy.code_analyzer.rules import ALL_RULES

        self.rules: list[BaseRule] = rules if rules is not None else ALL_RULES
        # Which suppression markers this scan honours: `# <tool>: ignore-file`
        # and `# <tool>: ignore <rule>`. `aisg misalign` passes its own name.
        self.tool = tool

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> ScanReport:
        report = ScanReport(tool=self.tool)
        start = time.perf_counter()
        self._scan_single(Path(path), report)
        report.scan_duration_s = time.perf_counter() - start
        return report

    def scan_directory(
        self,
        path: str | Path,
        recursive: bool = True,
        include: str = "*.py",
        exclude_dirs: list[str] | None = None,
    ) -> ScanReport:
        report = ScanReport(tool=self.tool)
        start = time.perf_counter()
        exclude = set(
            exclude_dirs
            or ["__pycache__", ".git", ".venv", "venv", "node_modules", "dist", "build"]
        )
        root = Path(path)

        if recursive:
            for py_file in root.rglob(include):
                if is_excluded(py_file, exclude):
                    continue
                self._scan_single(py_file, report)
        else:
            for py_file in root.glob(include):
                self._scan_single(py_file, report)

        report.scan_duration_s = time.perf_counter() - start
        return report

    def scan_diff(
        self,
        diff_text: str,
        base_dir: str = ".",
        exclude_dirs: list[str] | None = None,
    ) -> ScanReport:
        """
        Scan only files that appear in a git diff output.
        Useful for pre-commit and CI — only checks changed files.

        `exclude_dirs` uses the same matching as `scan_directory`, so a
        pre-commit run on a staged fixture honours the same `exclude` as the
        full scan instead of blocking the commit.
        """
        changed_files = self._parse_diff_files(diff_text)
        report = ScanReport(tool=self.tool)
        exclude = set(exclude_dirs or [])
        start = time.perf_counter()
        for rel_path in changed_files:
            full = Path(base_dir) / rel_path
            if full.exists() and full.suffix == ".py" and not is_excluded(full, exclude):
                self._scan_single(full, report)
        report.scan_duration_s = time.perf_counter() - start
        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_single(self, path: Path, report: ScanReport) -> None:
        filename = str(path)
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            report.scanned_files.append(filename)
            report.errors.append(f"Cannot read {filename}: {e}")
            return

        if has_ignore_marker(source, self.tool):
            report.skipped_files.append(filename)
            return
        report.scanned_files.append(filename)

        # Physical lines, so AST line numbers, text-rule line numbers and the
        # directive lookup below all index the same list.
        source_lines = physical_lines(source)

        # Parse AST
        tree: ast.AST | None = None
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            report.errors.append(f"Syntax error in {filename}:{e.lineno} — {e.msg}")

        # Run each rule
        found: list[CodeFinding] = []
        for rule in self.rules:
            if tree is not None:
                try:
                    found.extend(rule.check_ast(tree, source_lines, filename))
                except Exception:
                    pass

            try:
                found.extend(rule.check_text(source, filename))
            except Exception:
                pass

        # Honour a line directive naming the rule on the finding's own line.
        for finding in found:
            idx = finding.line - 1
            line = source_lines[idx] if 0 <= idx < len(source_lines) else ""
            if finding.rule_id.upper() in ignored_rules(line, self.tool):
                report.suppressed_count += 1
            else:
                report.findings.append(finding)

        # Sort findings by line number
        report.findings.sort(key=lambda f: (f.file, f.line))

    @staticmethod
    def _parse_diff_files(diff_text: str) -> list[str]:
        files = []
        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                files.append(line[6:])
        return files
