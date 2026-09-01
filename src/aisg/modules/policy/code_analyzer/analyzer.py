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
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator

# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------


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

    def __init__(self, rules: list[BaseRule] | None = None):
        from aisg.modules.policy.code_analyzer.rules import ALL_RULES

        self.rules: list[BaseRule] = rules if rules is not None else ALL_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: str | Path) -> ScanReport:
        report = ScanReport()
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
        report = ScanReport()
        start = time.perf_counter()
        exclude = set(
            exclude_dirs
            or ["__pycache__", ".git", ".venv", "venv", "node_modules", "dist", "build"]
        )
        root = Path(path)

        if recursive:
            for py_file in root.rglob(include):
                if any(part in exclude for part in py_file.parts):
                    continue
                self._scan_single(py_file, report)
        else:
            for py_file in root.glob(include):
                self._scan_single(py_file, report)

        report.scan_duration_s = time.perf_counter() - start
        return report

    def scan_diff(self, diff_text: str, base_dir: str = ".") -> ScanReport:
        """
        Scan only files that appear in a git diff output.
        Useful for pre-commit and CI — only checks changed files.
        """
        changed_files = self._parse_diff_files(diff_text)
        report = ScanReport()
        start = time.perf_counter()
        for rel_path in changed_files:
            full = Path(base_dir) / rel_path
            if full.exists() and full.suffix == ".py":
                self._scan_single(full, report)
        report.scan_duration_s = time.perf_counter() - start
        return report

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _scan_single(self, path: Path, report: ScanReport) -> None:
        filename = str(path)
        report.scanned_files.append(filename)
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            report.errors.append(f"Cannot read {filename}: {e}")
            return

        source_lines = source.splitlines()

        # Parse AST
        tree: ast.AST | None = None
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as e:
            report.errors.append(f"Syntax error in {filename}:{e.lineno} — {e.msg}")

        # Run each rule
        for rule in self.rules:
            if tree is not None:
                try:
                    for finding in rule.check_ast(tree, source_lines, filename):
                        report.findings.append(finding)
                except Exception:
                    pass

            try:
                for finding in rule.check_text(source, filename):
                    report.findings.append(finding)
            except Exception:
                pass

        # Sort findings by line number
        report.findings.sort(key=lambda f: (f.file, f.line))

    @staticmethod
    def _parse_diff_files(diff_text: str) -> list[str]:
        files = []
        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                files.append(line[6:])
        return files
