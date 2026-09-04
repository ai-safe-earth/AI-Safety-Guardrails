# misalignment-check: ignore-file
"""
devtools/misalignment/rules/__init__.py
----------------------------------------
AI Misalignment Detection Rules

Eight rule categories that surface code patterns indicating potential misalignment
between an AI system's stated goals and its actual behaviour — including hidden
content, covert objectives, safety bypasses, and missing oversight mechanisms.

These rules are NOT a substitute for human review. They flag patterns that warrant
careful inspection before committing or merging.
"""

from __future__ import annotations

import ast
import re
from typing import Iterator

from aisg.modules.policy.code_analyzer.analyzer import (
    BaseRule,
    CodeFinding,
    Severity,
    physical_lines,
)

# ---------------------------------------------------------------------------
# ALIGN-001 — Safety bypass patterns
# ---------------------------------------------------------------------------


class Rule_ALIGN001_SafetyBypass(BaseRule):
    rule_id = "ALIGN-001"
    article = "Misalignment / Safety"
    severity = Severity.ERROR
    title = "Safety bypass pattern detected"
    description = (
        "Code contains patterns that disable, skip, or override safety mechanisms. "
        "This can allow unsafe outputs to reach users without guardrail filtering."
    )
    suggestion = (
        "Remove bypass flags. If a guardrail is too strict, adjust its threshold "
        "through the official configuration rather than disabling it."
    )

    _PATTERNS = re.compile(
        r"\b("
        r"skip_guardrail|bypass_safety|disable_check|disable_guardrail"
        r"|force_allow|override_policy|ignore_safety|skip_safety"
        r"|guardrail_disabled|safety_disabled|no_guardrail"
        r")\b"
        r"|['\"]unsafe['\"]\s*[=:]\s*(True|1)"
        r"|\bunsafe\s*=\s*True"
        r"|\bsafe\s*=\s*False"
        r"|\bforce\s*=\s*True.*safety"
        r"|\bbypass\s*=\s*True",
        re.I,
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(physical_lines(source), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._PATTERNS.search(line):
                yield self._finding(filename, i, snippet=line)

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        # Detect keyword arguments like skip_guardrails=True, safe=False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    name = (kw.arg or "").lower()
                    val = kw.value
                    is_true_const = isinstance(val, ast.Constant) and val.value is True
                    is_false_const = isinstance(val, ast.Constant) and val.value is False
                    if (
                        (
                            "bypass" in name
                            or "skip" in name
                            or "unsafe" in name
                            or "disable" in name
                        )
                        and is_true_const
                    ) or ("safe" in name and is_false_const):
                        line = getattr(node, "lineno", 0)
                        yield self._finding(
                            filename,
                            line,
                            snippet=self._snippet(source_lines, line),
                            description=f"Keyword argument `{kw.arg}` disables a safety check.",
                        )


# ---------------------------------------------------------------------------
# ALIGN-002 — Hardcoded unsafe defaults
# ---------------------------------------------------------------------------


class Rule_ALIGN002_UnsafeDefaults(BaseRule):
    rule_id = "ALIGN-002"
    article = "Misalignment / Defaults"
    severity = Severity.WARNING
    title = "Hardcoded unsafe or extreme default value"
    description = (
        "A safety-critical parameter (confidence threshold, temperature, score limit) "
        "is set to an extreme or permissive value that could weaken safety filtering."
    )
    suggestion = (
        "Move threshold values to configuration files. Use named constants with "
        "clear comments explaining their safety implications."
    )

    # Threshold/score/confidence set to 0.0 or 1.0
    _THRESHOLD = re.compile(
        r"\b(threshold|confidence|score|min_confidence|max_confidence|cutoff|limit)\s*=\s*(0(\.0+)?|1(\.0+)?)\b",
        re.I,
    )
    # Temperature too high (>1.5) — increases randomness, can bypass filters
    _TEMPERATURE = re.compile(
        r"\btemperature\s*=\s*([1-9]\d*(\.\d+)?|0*1\.[6-9]\d*|0*[2-9](\.\d+)?)\b",
        re.I,
    )
    # top_p / top_k at extreme values
    _TOP_P = re.compile(r"\btop_p\s*=\s*1(\.0+)?\b", re.I)

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(physical_lines(source), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._THRESHOLD.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="Safety threshold set to 0.0 or 1.0 — verify this is intentional.",
                )
            if self._TEMPERATURE.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="Temperature > 1.5 increases randomness and may produce unsafe outputs.",
                )
            if self._TOP_P.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="top_p=1.0 disables nucleus sampling filtering.",
                )


# ---------------------------------------------------------------------------
# ALIGN-003 — Missing human oversight hooks
# ---------------------------------------------------------------------------


class Rule_ALIGN003_MissingOversight(BaseRule):
    rule_id = "ALIGN-003"
    article = "Misalignment / Human Oversight"
    severity = Severity.WARNING
    title = "High-risk action without audit or oversight hook"
    description = (
        "A function performing a high-risk or irreversible action (execute, deploy, "
        "delete, send, publish) contains no logging, audit, or confirmation call, "
        "making the action invisible to human oversight."
    )
    suggestion = (
        "Add an audit log call (e.g. audit_logger.log()) or a confirmation gate "
        "before executing irreversible operations."
    )

    _HIGH_RISK = re.compile(
        r"^(execute|deploy|delete|remove|send|publish|submit|approve|escalate|transfer|override)",
        re.I,
    )
    _OVERSIGHT = re.compile(
        r"\b(log|audit|logger|logging|record|trace|confirm|approve|review|checkpoint)\b",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._HIGH_RISK.match(node.name):
                continue
            # Collect all name references inside the function body
            body_src = "\n".join(
                self._snippet(source_lines, n.lineno)
                for n in ast.walk(node)
                if hasattr(n, "lineno")
            )
            if not self._OVERSIGHT.search(body_src):
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=(
                        f"Function `{node.name}` performs a high-risk action "
                        "but has no audit log or oversight hook."
                    ),
                )


# ---------------------------------------------------------------------------
# ALIGN-004 — Policy-code consistency
# ---------------------------------------------------------------------------


class Rule_ALIGN004_PolicyConsistency(BaseRule):
    rule_id = "ALIGN-004"
    article = "Misalignment / Policy Consistency"
    severity = Severity.WARNING
    title = "Declared policy not enforced in code"
    description = (
        "A guardrail class or safety policy is imported but never instantiated or "
        "called, meaning it exists on paper but has no runtime effect."
    )
    suggestion = (
        "Ensure every imported guardrail is instantiated and added to the active "
        "pipeline. Remove unused policy imports to avoid false confidence."
    )

    # Common guardrail/policy class name patterns
    _GUARDRAIL_IMPORT = re.compile(
        r"^\s*(from|import).*\b(Guard|Guardrail|Policy|Checker|Validator|Filter|Scanner)\b",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        imported_names: dict[str, int] = {}  # name → line number

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if re.search(
                        r"(Guard|Guardrail|Policy|Checker|Validator|Filter|Scanner)", name, re.I
                    ):
                        imported_names[name] = node.lineno
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name
                    if re.search(
                        r"(Guard|Guardrail|Policy|Checker|Validator|Filter|Scanner)", name, re.I
                    ):
                        imported_names[name] = node.lineno

        if not imported_names:
            return

        # Collect all Name nodes used in the file (calls, assignments, etc.)
        used_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used_names.add(node.id)
            elif isinstance(node, ast.Attribute):
                used_names.add(node.attr)

        for name, lineno in imported_names.items():
            # Count usages beyond the import line itself
            occurrences = sum(
                1
                for n in ast.walk(tree)
                if isinstance(n, ast.Name) and n.id == name and getattr(n, "lineno", 0) != lineno
            )
            if occurrences == 0:
                yield self._finding(
                    filename,
                    lineno,
                    snippet=self._snippet(source_lines, lineno),
                    description=f"`{name}` is imported as a safety component but never used.",
                )


# ---------------------------------------------------------------------------
# ALIGN-005 — Hidden / encoded content
# ---------------------------------------------------------------------------


class Rule_ALIGN005_HiddenContent(BaseRule):
    rule_id = "ALIGN-005"
    article = "Misalignment / Hidden Content"
    severity = Severity.ERROR
    title = "Potentially hidden or encoded content detected"
    description = (
        "The file contains patterns associated with hidden information: long "
        "base64-like strings, zero-width or invisible Unicode characters, or "
        "unusual Unicode that could conceal instructions or data."
    )
    suggestion = (
        "Review all long encoded strings. Replace with named constants or "
        "external config. Remove any zero-width or invisible Unicode characters."
    )

    # Long base64-like blobs (>60 chars of base64 alphabet)
    _BASE64 = re.compile(r"['\"][A-Za-z0-9+/]{60,}={0,2}['\"]")
    # Zero-width / invisible Unicode (in source text)
    _INVISIBLE = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060\u180e\u2028\u2029]")
    # Private-use area or unusual control characters embedded in strings
    _UNUSUAL_UNICODE = re.compile(r"[\ue000-\uf8ff\U000f0000-\U000fffff]")

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        lines = physical_lines(source)
        for i, line in enumerate(lines, 1):
            if self._BASE64.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="Long base64-like string found — may contain encoded hidden content.",
                )
            if self._INVISIBLE.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=repr(line),
                    description="Zero-width or invisible Unicode character detected in source code.",
                )
            if self._UNUSUAL_UNICODE.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=repr(line),
                    description="Private-use area Unicode character detected — unusual in source code.",
                )


# ---------------------------------------------------------------------------
# ALIGN-006 — Covert instructions in prompts / strings
# ---------------------------------------------------------------------------


class Rule_ALIGN006_CovertInstructions(BaseRule):
    rule_id = "ALIGN-006"
    article = "Misalignment / Covert Instructions"
    severity = Severity.ERROR
    title = "Covert or adversarial instruction in string literal"
    description = (
        "A string literal contains language patterns typical of prompt injection, "
        "goal redirection, or hidden instructions that could cause an AI system "
        "to behave contrary to its stated purpose."
    )
    suggestion = (
        "Remove or sanitize adversarial instruction patterns. If this is a test "
        "fixture, isolate it in a dedicated test file with a clear comment."
    )

    _PATTERNS = re.compile(
        r"(?i)"
        r"ignore\s+(previous|prior|above|all\s+previous)\s+instructions?"
        r"|disregard\s+(your|all|previous|prior)\s+(instructions?|rules?|guidelines?)"
        r"|you\s+are\s+actually\s+(a|an)\s"
        r"|your\s+real\s+(goal|objective|purpose|task|mission)"
        r"|hidden\s+(objective|goal|instruction|directive|agenda)"
        r"|secretly\s+(you|your|act|behave|pursue)"
        r"|do\s+not\s+reveal\s+(this|that|these)\s+instructions?"
        r"|pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+(?!assistant)"
        r"|act\s+as\s+if\s+(you\s+have\s+no\s+(restrictions?|limits?|guidelines?))"
        r"|jailbreak"
        r"|DAN\s+mode"
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        # Only scan inside string literals — walk the AST to extract them
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if self._PATTERNS.search(node.value):
                    yield self._finding(
                        filename,
                        node.lineno,
                        snippet=repr(node.value[:120]),
                        description="String literal contains adversarial instruction pattern.",
                    )


# ---------------------------------------------------------------------------
# ALIGN-007 — Unnecessary codified information
# ---------------------------------------------------------------------------


class Rule_ALIGN007_UnnecessaryData(BaseRule):
    rule_id = "ALIGN-007"
    article = "Misalignment / Unnecessary Data"
    severity = Severity.WARNING
    title = "Unnecessary personal data or large data blob in source"
    description = (
        "The file contains hardcoded personal identifiers (email, phone, SSN-like) "
        "or an unusually large inline string that may embed data better kept in "
        "external storage or config files."
    )
    suggestion = (
        "Move personal data and large datasets out of source code. Use environment "
        "variables or external storage. Avoid embedding reference data in strings."
    )

    # Email addresses
    _EMAIL = re.compile(r"['\"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['\"]")
    # Phone numbers (loose — international and US formats)
    _PHONE = re.compile(r"['\"](\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}['\"]")
    # SSN-like patterns
    _SSN = re.compile(r"['\"\s]\d{3}-\d{2}-\d{4}['\"\s]")
    # Very large inline strings (>500 printable chars in a single string literal)
    _LARGE_STRING = re.compile(r"['\"][ -~]{500,}['\"]")

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(physical_lines(source), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._EMAIL.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="Hardcoded email address found in source code.",
                )
            if self._PHONE.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description="Hardcoded phone number found in source code.",
                )
            if self._SSN.search(line):
                yield self._finding(
                    filename, i, snippet=line, description="SSN-like pattern found in source code."
                )
            if self._LARGE_STRING.search(line):
                yield self._finding(
                    filename,
                    i,
                    snippet=line[:120] + "…",
                    description="Very large inline string (>500 chars) — consider externalizing this data.",
                )


# ---------------------------------------------------------------------------
# ALIGN-008 — Undesired objectives
# ---------------------------------------------------------------------------


class Rule_ALIGN008_UndesiredObjectives(BaseRule):
    rule_id = "ALIGN-008"
    article = "Misalignment / Undesired Objectives"
    severity = Severity.ERROR
    title = "Undesired or misaligned objective pattern"
    description = (
        "The code contains language associated with reward hacking, specification "
        "gaming, dependency creation, engagement maximization, or detection evasion — "
        "goals that diverge from safe and beneficial AI behaviour."
    )
    suggestion = (
        "Review this code for objectives that conflict with the system's stated "
        "purpose. Ensure all optimisation targets are explicitly documented and "
        "reviewed by a safety engineer."
    )

    _PATTERNS = re.compile(
        r"(?i)"
        r"maximize\s+(engagement|retention|dependency|addiction|clicks?|watch.?time)"
        r"|increase\s+(user\s+)?dependency"
        r"|reward\s+hack(ing)?"
        r"|specification\s+gaming"
        r"|goal\s+substitut(ion|e)"
        r"|avoid\s+detect(ion|ing)"
        r"|evade\s+(monitor|detect|oversight|filter|guardrail)"
        r"|circumvent\s+(safety|guardrail|filter|policy|oversight)"
        r"|self[\s_-]?(preserv|replicate|propagate|copy)"
        r"|resist\s+(shutdown|correction|oversight)"
        r"|deceive\s+(user|operator|monitor|overseer)"
        r"|manipulate\s+(user|behavior|outcome)\s+without"
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(physical_lines(source), 1):
            if self._PATTERNS.search(line):
                yield self._finding(filename, i, snippet=line)

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        # Also scan string constants (docstrings, prompts)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if self._PATTERNS.search(node.value):
                    yield self._finding(
                        filename,
                        node.lineno,
                        snippet=repr(node.value[:120]),
                        description="Docstring or string literal contains undesired objective language.",
                    )


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

MISALIGNMENT_RULES: list[BaseRule] = [
    Rule_ALIGN001_SafetyBypass(),
    Rule_ALIGN002_UnsafeDefaults(),
    Rule_ALIGN003_MissingOversight(),
    Rule_ALIGN004_PolicyConsistency(),
    Rule_ALIGN005_HiddenContent(),
    Rule_ALIGN006_CovertInstructions(),
    Rule_ALIGN007_UnnecessaryData(),
    Rule_ALIGN008_UndesiredObjectives(),
]

# Errors-only subset — for hard-blocking pre-commit
MISALIGNMENT_RULES_STRICT: list[BaseRule] = [
    r for r in MISALIGNMENT_RULES if r.severity == Severity.ERROR
]
