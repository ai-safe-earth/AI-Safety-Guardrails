"""
modules/policy/code_analyzer/reporters.py
------------------------------------------
Output formatters for EU AI Act scan reports.

Provides four reporter formats:
  - TerminalReporter   — Human-friendly colored terminal output
  - JSONReporter       — Machine-readable JSON for CI/CD pipelines
  - SARIFReporter      — SARIF 2.1.0 for GitHub/GitLab Code Scanning
  - MarkdownReporter   — Formatted markdown for PR comments
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import TextIO

from .analyzer import CodeFinding, ScanReport, Severity

# ---------------------------------------------------------------------------
# ANSI color codes for terminal output
# ---------------------------------------------------------------------------


class Colors:
    """ANSI escape codes for colored terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Severity colors
    RED = "\033[91m"  # ERROR
    YELLOW = "\033[93m"  # WARNING
    BLUE = "\033[94m"  # INFO
    GREEN = "\033[92m"  # SUCCESS

    # UI elements
    GRAY = "\033[90m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"


# ---------------------------------------------------------------------------
# TerminalReporter — human-friendly colored output
# ---------------------------------------------------------------------------


class TerminalReporter:
    """
    Terminal output with ANSI colors, code snippets, and fix suggestions.

    Example output:
        ✗ 3 errors, 2 warnings, 1 info (5 files scanned in 0.12s)

        modules/llm_service.py
          12:5   ERROR   EU-AIA-012a   LLM call without audit logging
                 │ openai.ChatCompletion.create() called without wrapping in AuditLogger
                 │
                 │ 12 │   response = openai.ChatCompletion.create(
                 │
                 └─ Fix: Wrap LLM calls in AuditLogger context manager
    """

    def __init__(
        self,
        out: TextIO = sys.stdout,
        color: bool = True,
        show_snippet: bool = True,
        show_suggestion: bool = True,
    ):
        self.out = out
        self.color = color
        self.show_snippet = show_snippet
        self.show_suggestion = show_suggestion
        self.use_unicode = self._supports_unicode(out)

    def write(self, report: ScanReport) -> None:
        """Write the scan report to output."""
        c = Colors if self.color else _NoColors()

        # Icon characters (Unicode or ASCII fallback)
        check_icon = "✓" if self.use_unicode else "+"
        cross_icon = "✗" if self.use_unicode else "x"
        bullet_icon = "•" if self.use_unicode else "*"

        # Summary header
        if report.error_count == 0:
            icon = f"{c.GREEN}{check_icon}{c.RESET}"
            status = f"{c.GREEN}PASS{c.RESET}"
        else:
            icon = f"{c.RED}{cross_icon}{c.RESET}"
            status = f"{c.RED}FAIL{c.RESET}"

        parts = []
        if report.error_count > 0:
            parts.append(
                f"{c.RED}{report.error_count} error{'s' if report.error_count != 1 else ''}{c.RESET}"
            )
        if report.warning_count > 0:
            parts.append(
                f"{c.YELLOW}{report.warning_count} warning{'s' if report.warning_count != 1 else ''}{c.RESET}"
            )
        if report.info_count > 0:
            parts.append(f"{c.BLUE}{report.info_count} info{c.RESET}")

        summary = ", ".join(parts) if parts else f"{c.GREEN}No issues found{c.RESET}"

        file_count = len(report.scanned_files)
        duration = f"{report.scan_duration_s:.2f}s"

        self._print(
            f"{icon} {summary} {c.GRAY}({file_count} file{'s' if file_count != 1 else ''} scanned in {duration}){c.RESET}\n"
        )

        # Parse errors
        if report.errors:
            self._print(f"{c.YELLOW}Parse errors:{c.RESET}")
            for error in report.errors:
                self._print(f"  {c.GRAY}{bullet_icon}{c.RESET} {error}")
            self._print("")

        # Findings by file
        if not report.findings:
            return

        by_file = report.by_file()
        for filepath, findings in sorted(by_file.items()):
            self._print(f"{c.BOLD}{c.WHITE}{filepath}{c.RESET}")

            for finding in findings:
                self._print_finding(finding, c)

            self._print("")  # Blank line between files

    def _print_finding(self, f: CodeFinding, c) -> None:
        """Print a single finding with optional snippet and suggestion."""
        # Box drawing characters (Unicode or ASCII fallback)
        vbar = "│" if self.use_unicode else "|"
        corner = "└─" if self.use_unicode else "`-"

        # Severity color
        if f.severity == Severity.ERROR:
            sev_color = c.RED
            sev_label = "ERROR  "
        elif f.severity == Severity.WARNING:
            sev_color = c.YELLOW
            sev_label = "WARNING"
        else:
            sev_color = c.BLUE
            sev_label = "INFO   "

        # Location
        loc = f"{f.line}:{f.col}" if f.col else str(f.line)

        # Main line
        self._print(
            f"  {c.GRAY}{loc:<8}{c.RESET} {sev_color}{sev_label}{c.RESET}  {c.CYAN}{f.rule_id}{c.RESET}  {f.title}"
        )

        # Description
        if f.description:
            desc_lines = f.description.split("\n")
            for line in desc_lines:
                self._print(f"           {c.GRAY}{vbar}{c.RESET} {line}")

        # Code snippet
        if self.show_snippet and f.snippet:
            self._print(f"           {c.GRAY}{vbar}{c.RESET}")
            self._print(
                f"           {c.GRAY}{vbar}{c.RESET} {c.DIM}{f.line}{c.RESET} {c.GRAY}{vbar}{c.RESET} {f.snippet}"
            )

        # Suggestion
        if self.show_suggestion and f.suggestion:
            self._print(f"           {c.GRAY}{vbar}{c.RESET}")
            self._print(
                f"           {c.GRAY}{corner}{c.RESET} {c.GREEN}Fix:{c.RESET} {f.suggestion}"
            )

        # Reference link
        if f.reference and self.show_suggestion:
            self._print(f"              {c.GRAY}{f.reference}{c.RESET}")

    @staticmethod
    def _supports_unicode(out: TextIO) -> bool:
        """Check if the output stream supports UTF-8 encoding."""
        try:
            # Check encoding attribute
            encoding = getattr(out, "encoding", None)
            if encoding:
                # UTF-8 or similar Unicode encodings
                if "utf" in encoding.lower() or "unicode" in encoding.lower():
                    return True
            # Default to False for Windows console (cp1252, cp437, etc.)
            return False
        except Exception:
            return False

    def _print(self, text: str = "") -> None:
        """Write a line to output."""
        print(text, file=self.out)


class _NoColors:
    """Dummy class that returns empty strings for all color codes."""

    def __getattribute__(self, name):
        return ""


# ---------------------------------------------------------------------------
# JSONReporter — structured JSON for CI/CD
# ---------------------------------------------------------------------------


class JSONReporter:
    """
    JSON output for programmatic consumption.

    Example output:
        {
          "summary": {
            "scanned_files": 5,
            "error_count": 3,
            "warning_count": 2,
            "info_count": 1,
            "scan_duration_s": 0.123,
            "passed": false
          },
          "findings": [
            {
              "rule_id": "EU-AIA-012a",
              "article": "Art. 12",
              "severity": "error",
              "title": "LLM call without audit logging",
              "description": "...",
              "file": "modules/llm_service.py",
              "line": 12,
              "col": 5,
              "snippet": "response = openai.ChatCompletion.create(",
              "suggestion": "Wrap LLM calls in AuditLogger context manager",
              "reference": "https://..."
            }
          ],
          "errors": []
        }
    """

    def __init__(self, out: TextIO = sys.stdout):
        self.out = out

    def write(self, report: ScanReport) -> None:
        """Write the scan report as JSON."""
        data = {
            "summary": {
                "scanned_files": len(report.scanned_files),
                "error_count": report.error_count,
                "warning_count": report.warning_count,
                "info_count": report.info_count,
                "scan_duration_s": round(report.scan_duration_s, 3),
                "passed": report.passed,
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "article": f.article,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "file": f.file,
                    "line": f.line,
                    "col": f.col,
                    "snippet": f.snippet,
                    "suggestion": f.suggestion,
                    "reference": f.reference,
                }
                for f in report.findings
            ],
            "errors": report.errors,
        }

        json.dump(data, self.out, indent=2)
        self.out.write("\n")


# ---------------------------------------------------------------------------
# SARIFReporter — SARIF 2.1.0 for GitHub/GitLab Code Scanning
# ---------------------------------------------------------------------------


class SARIFReporter:
    """
    SARIF 2.1.0 output for GitHub/GitLab Code Scanning integration.

    SARIF (Static Analysis Results Interchange Format) is a standard format
    for static analysis tools. GitHub and GitLab can import SARIF files to
    display findings in their Security/Code Scanning tabs.

    Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """

    def __init__(self, out: TextIO = sys.stdout):
        self.out = out

    def write(self, report: ScanReport) -> None:
        """Write the scan report as SARIF 2.1.0."""
        # Build rules lookup
        rules_map = {}
        for finding in report.findings:
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = finding

        # SARIF structure
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "euaiact-lint",
                            "version": "0.1.0",
                            "informationUri": "https://github.com/YOUR_ORG/ai-safety-guardrails",
                            "semanticVersion": "0.1.0",
                            "rules": [
                                {
                                    "id": rule_id,
                                    "name": f.title,
                                    "shortDescription": {"text": f.title},
                                    "fullDescription": {"text": f.description or f.title},
                                    "help": {
                                        "text": f.suggestion or "Review for EU AI Act compliance",
                                        "markdown": f"{f.description}\n\n**Fix:** {f.suggestion}\n\n[Reference]({f.reference})"
                                        if f.suggestion
                                        else f.description,
                                    },
                                    "helpUri": f.reference,
                                    "properties": {
                                        "tags": ["security", "compliance", "eu-ai-act", f.article],
                                        "precision": "medium",
                                        "security-severity": self._severity_to_score(f.severity),
                                    },
                                    "defaultConfiguration": {
                                        "level": self._severity_to_level(f.severity),
                                    },
                                }
                                for rule_id, f in sorted(rules_map.items())
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": self._severity_to_level(f.severity),
                            "message": {
                                "text": f"{f.title}: {f.description}" if f.description else f.title
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": f.file.replace(
                                                "\\", "/"
                                            ),  # Normalize path separators
                                            "uriBaseId": "%SRCROOT%",
                                        },
                                        "region": {
                                            "startLine": f.line,
                                            "startColumn": f.col if f.col else 1,
                                            "snippet": {"text": f.snippet} if f.snippet else None,
                                        },
                                    }
                                }
                            ],
                            "partialFingerprints": {
                                "primaryLocationLineHash": self._hash_location(f),
                            },
                        }
                        for f in report.findings
                    ],
                    "properties": {
                        "scanned_files": len(report.scanned_files),
                        "scan_duration_s": round(report.scan_duration_s, 3),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                }
            ],
        }

        json.dump(sarif, self.out, indent=2)
        self.out.write("\n")

    @staticmethod
    def _severity_to_level(severity: Severity) -> str:
        """Convert Severity to SARIF level."""
        mapping = {
            Severity.ERROR: "error",
            Severity.WARNING: "warning",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "warning")

    @staticmethod
    def _severity_to_score(severity: Severity) -> str:
        """Convert Severity to SARIF security-severity score (0.0-10.0)."""
        mapping = {
            Severity.ERROR: "8.0",
            Severity.WARNING: "5.0",
            Severity.INFO: "2.0",
        }
        return mapping.get(severity, "5.0")

    @staticmethod
    def _hash_location(f: CodeFinding) -> str:
        """Generate a stable hash for deduplication."""
        import hashlib

        content = f"{f.file}:{f.line}:{f.rule_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# MarkdownReporter — formatted markdown for PR comments
# ---------------------------------------------------------------------------


class MarkdownReporter:
    """
    Markdown output for GitHub/GitLab PR comments.

    Example output:
        ## EU AI Act Compliance Report

        ❌ **3 errors**, 2 warnings, 1 info (5 files scanned in 0.12s)

        ### Findings

        #### `modules/llm_service.py`

        | Line | Severity | Rule | Issue |
        |------|----------|------|-------|
        | 12:5 | 🔴 ERROR | EU-AIA-012a | LLM call without audit logging |

        <details>
        <summary>Details</summary>

        **Description:** openai.ChatCompletion.create() called without wrapping in AuditLogger

        **Code snippet:**
        ```python
        response = openai.ChatCompletion.create(
        ```

        **Fix:** Wrap LLM calls in AuditLogger context manager

        **Reference:** https://eur-lex.europa.eu/...
        </details>
    """

    def __init__(self, out: TextIO = sys.stdout):
        self.out = out

    def write(self, report: ScanReport) -> None:
        """Write the scan report as Markdown."""
        # Header
        self._print("## EU AI Act Compliance Report\n")

        # Summary
        if report.error_count == 0:
            icon = "✅"
            status_emoji = "✅ **PASS**"
        else:
            icon = "❌"
            status_emoji = "❌ **FAIL**"

        parts = []
        if report.error_count > 0:
            parts.append(f"**{report.error_count} error{'s' if report.error_count != 1 else ''}**")
        if report.warning_count > 0:
            parts.append(
                f"{report.warning_count} warning{'s' if report.warning_count != 1 else ''}"
            )
        if report.info_count > 0:
            parts.append(f"{report.info_count} info")

        summary = ", ".join(parts) if parts else "**No issues found**"

        file_count = len(report.scanned_files)
        duration = f"{report.scan_duration_s:.2f}s"

        self._print(
            f"{status_emoji} — {summary} ({file_count} file{'s' if file_count != 1 else ''} scanned in {duration})\n"
        )

        # Parse errors
        if report.errors:
            self._print("### ⚠️ Parse Errors\n")
            for error in report.errors:
                self._print(f"- {error}")
            self._print("")

        # Findings
        if not report.findings:
            self._print("*No compliance issues detected.*\n")
            return

        self._print("### Findings\n")

        by_file = report.by_file()
        for filepath, findings in sorted(by_file.items()):
            self._print(f"#### `{filepath}`\n")

            # Table header
            self._print("| Line | Severity | Rule | Issue |")
            self._print("|------|----------|------|-------|")

            # Table rows
            for f in findings:
                loc = f"{f.line}:{f.col}" if f.col else str(f.line)
                severity_emoji = self._severity_emoji(f.severity)
                severity_text = f.severity.value.upper()

                self._print(
                    f"| {loc} | {severity_emoji} {severity_text} | {f.rule_id} | {f.title} |"
                )

            self._print("")

            # Details for each finding
            for f in findings:
                self._print("<details>")
                self._print(f"<summary>🔍 {f.rule_id} — {f.title}</summary>\n")

                if f.description:
                    self._print(f"**Description:** {f.description}\n")

                if f.snippet:
                    self._print("**Code snippet:**")
                    self._print("```python")
                    self._print(f.snippet)
                    self._print("```\n")

                if f.suggestion:
                    self._print(f"**Fix:** {f.suggestion}\n")

                if f.reference:
                    self._print(f"**Reference:** [{f.article}]({f.reference})\n")

                self._print("</details>\n")

        # Footer
        self._print("---")
        self._print(
            "*Generated by [euaiact-lint](https://github.com/YOUR_ORG/ai-safety-guardrails) — EU AI Act Static Code Analyzer*"
        )

    @staticmethod
    def _severity_emoji(severity: Severity) -> str:
        """Get emoji for severity level."""
        mapping = {
            Severity.ERROR: "🔴",
            Severity.WARNING: "🟡",
            Severity.INFO: "🔵",
        }
        return mapping.get(severity, "⚪")

    def _print(self, text: str = "") -> None:
        """Write a line to output."""
        print(text, file=self.out)
