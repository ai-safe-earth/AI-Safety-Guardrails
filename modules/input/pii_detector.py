"""
modules/input/pii_detector.py
------------------------------
PII Detection & Redaction — input guardrail.

Detects and optionally redacts Personally Identifiable Information
from user inputs before they reach the LLM.

Supports:
    - Rule-based detection (regex) for common PII types
    - Optional integration with Microsoft Presidio for deeper analysis
    - Configurable action: redact | block | flag

Usage:
    guard = PIIDetector(action="redact", entities=["EMAIL", "PHONE", "SSN"])
    result = await guard(user_message, context)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from core.base import GuardrailBase, GuardrailStage, CheckResult, Action, Finding, Severity
from core.registry import register_guard


# ---------------------------------------------------------------------------
# PII Pattern Library
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE_US": re.compile(
        r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"
    ),
    "PHONE_INTL": re.compile(
        r"\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{1,9}"
    ),
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0{4})\d{4}\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
        r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"
    ),
    "IP_ADDRESS": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:dob|date of birth|born)[:\s]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b",
        re.IGNORECASE,
    ),
    "PASSPORT": re.compile(
        r"\b[A-Z]{1,2}\d{6,9}\b"
    ),
    "EU_TAX_ID": re.compile(
        r"\b[A-Z]{2}\d{8,12}\b"
    ),
}

DEFAULT_ENTITIES = ["EMAIL", "PHONE_US", "PHONE_INTL", "SSN", "CREDIT_CARD", "IP_ADDRESS"]

REDACTION_PLACEHOLDERS = {
    "EMAIL": "[EMAIL REDACTED]",
    "PHONE_US": "[PHONE REDACTED]",
    "PHONE_INTL": "[PHONE REDACTED]",
    "SSN": "[SSN REDACTED]",
    "CREDIT_CARD": "[CARD REDACTED]",
    "IBAN": "[IBAN REDACTED]",
    "IP_ADDRESS": "[IP REDACTED]",
    "DATE_OF_BIRTH": "[DOB REDACTED]",
    "PASSPORT": "[PASSPORT REDACTED]",
    "EU_TAX_ID": "[TAX ID REDACTED]",
}


# ---------------------------------------------------------------------------
# Guard implementation
# ---------------------------------------------------------------------------

@register_guard("pii_detector")
class PIIDetector(GuardrailBase):
    """
    Detects and optionally redacts PII in user inputs.

    Config:
        action:   "redact" | "block" | "flag"  (default: "redact")
        entities: List of entity types to detect (default: common PII)
        use_presidio: bool — enable Microsoft Presidio for richer detection
        block_message: Custom rejection message when action="block"
    """

    name = "pii_detector"
    stage = GuardrailStage.INPUT
    description = "Detects and redacts PII from user inputs."

    def setup(
        self,
        action: Literal["redact", "block", "flag"] = "redact",
        entities: list[str] | None = None,
        use_presidio: bool = False,
        block_message: str = "Your message contains personal information that cannot be processed.",
        **kwargs,
    ):
        self.action_mode = Action[action.upper()] if action.upper() in Action.__members__ else Action.REDACT
        self.entities = entities or DEFAULT_ENTITIES
        self.use_presidio = use_presidio
        self.block_message = block_message
        self._presidio_analyzer = None

        if use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine
                self._presidio_analyzer = AnalyzerEngine()
            except ImportError:
                import warnings
                warnings.warn(
                    "presidio-analyzer not installed. Falling back to regex-based PII detection. "
                    "Install with: pip install presidio-analyzer presidio-anonymizer",
                    stacklevel=2,
                )

    async def check(self, content: str, context: dict) -> CheckResult:
        findings: list[Finding] = []
        sanitized = content

        if self.use_presidio and self._presidio_analyzer:
            findings, sanitized = await self._presidio_check(content, context)
        else:
            findings, sanitized = self._regex_check(content)

        if not findings:
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        if self.action_mode == Action.BLOCK:
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=content,
                rejection_message=self.block_message,
            )

        if self.action_mode == Action.REDACT:
            return CheckResult(
                passed=True,
                action=Action.REDACT,
                findings=findings,
                sanitized_content=sanitized,
            )

        # FLAG — pass through but annotate
        return CheckResult(
            passed=True,
            action=Action.FLAG,
            findings=findings,
            sanitized_content=content,
        )

    def _regex_check(self, content: str) -> tuple[list[Finding], str]:
        findings: list[Finding] = []
        sanitized = content

        for entity in self.entities:
            pattern = PII_PATTERNS.get(entity)
            if not pattern:
                continue

            matches = list(pattern.finditer(sanitized))
            for match in matches:
                findings.append(Finding(
                    guard_name=self.name,
                    severity=Severity.HIGH,
                    category="pii",
                    description=f"Detected {entity} in content",
                    span=(match.start(), match.end()),
                    metadata={"entity_type": entity},
                ))

            if matches and self.action_mode == Action.REDACT:
                placeholder = REDACTION_PLACEHOLDERS.get(entity, f"[{entity} REDACTED]")
                sanitized = pattern.sub(placeholder, sanitized)

        return findings, sanitized

    async def _presidio_check(self, content: str, context: dict) -> tuple[list[Finding], str]:
        """Presidio-based analysis (richer entity recognition)."""
        from presidio_anonymizer import AnonymizerEngine

        language = context.get("language", "en")
        results = self._presidio_analyzer.analyze(text=content, language=language)

        findings = [
            Finding(
                guard_name=self.name,
                severity=Severity.HIGH,
                category="pii",
                description=f"Presidio detected {r.entity_type} (score={r.score:.2f})",
                span=(r.start, r.end),
                metadata={"entity_type": r.entity_type, "score": r.score},
            )
            for r in results
        ]

        if findings and self.action_mode == Action.REDACT:
            anonymizer = AnonymizerEngine()
            anonymized = anonymizer.anonymize(text=content, analyzer_results=results)
            return findings, anonymized.text

        return findings, content
