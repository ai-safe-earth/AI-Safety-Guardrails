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
from typing import Literal

from core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from core.registry import register_guard

# ---------------------------------------------------------------------------
# PII Pattern Library
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "PHONE_US": re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
    "PHONE_INTL": re.compile(r"\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{1,4}[\s-]?\d{1,9}"),
    "SSN": re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0{4})\d{4}\b"),
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}"
        r"|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "DATE_OF_BIRTH": re.compile(
        r"\b(?:dob|date of birth|born)[:\s]+\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b",
        re.IGNORECASE,
    ),
    "PASSPORT": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "EU_TAX_ID": re.compile(r"\b[A-Z]{2}\d{8,12}\b"),
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

# Context key where the token→original mapping is stored between pipeline stages.
# Used by action="tokenize" in PIIDetector and read back by PIIRestorer.
PII_TOKEN_MAP_KEY = "_pii_token_map"


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
        action: Literal["redact", "block", "flag", "tokenize"] = "redact",
        entities: list[str] | None = None,
        use_presidio: bool = False,
        block_message: str = "Your message contains personal information that cannot be processed.",
        **kwargs,
    ):
        self.action_mode = action.lower()
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

        if self.action_mode == "tokenize":
            findings, sanitized = self._regex_tokenize(content, context)
        elif self.use_presidio and self._presidio_analyzer:
            findings, sanitized = await self._presidio_check(content, context)
        else:
            findings, sanitized = self._regex_check(content)

        if not findings:
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        if self.action_mode == "block":
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=content,
                rejection_message=self.block_message,
            )

        if self.action_mode in ("redact", "tokenize"):
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
                findings.append(
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="pii",
                        description=f"Detected {entity} in content",
                        span=(match.start(), match.end()),
                        metadata={"entity_type": entity},
                    )
                )

            if matches and self.action_mode == "redact":
                placeholder = REDACTION_PLACEHOLDERS.get(entity, f"[{entity} REDACTED]")
                sanitized = pattern.sub(placeholder, sanitized)

        return findings, sanitized

    def _regex_tokenize(self, content: str, context: dict) -> tuple[list[Finding], str]:
        """
        Replace each PII match with a reversible token like ``<PII:EMAIL:1>``.

        The mapping ``{token: original_value}`` is written into
        ``context[PII_TOKEN_MAP_KEY]`` so that ``PIIRestorer`` can invert it
        after the LLM has produced its response.

        Tokens are deterministic for identical values within a single call
        (two occurrences of the same email get the same token), which keeps
        the LLM context shorter and makes restoration unambiguous.
        """
        token_map: dict[str, str] = context.setdefault(PII_TOKEN_MAP_KEY, {})
        # Reverse map: original_value → token (to reuse tokens for repeated values)
        value_to_token: dict[str, str] = {v: k for k, v in token_map.items()}
        # Seed counters from existing tokens so repeated calls never produce collisions.
        # Token format: <PII:ENTITY_TYPE:N>
        counters: dict[str, int] = {}
        for existing_token in token_map:
            parts = existing_token.strip("<>").split(":")
            if len(parts) == 3 and parts[0] == "PII":
                try:
                    counters[parts[1]] = max(counters.get(parts[1], 0), int(parts[2]))
                except ValueError:
                    pass

        findings: list[Finding] = []
        tokenized = content

        for entity in self.entities:
            pattern = PII_PATTERNS.get(entity)
            if not pattern:
                continue

            matches = list(pattern.finditer(tokenized))
            if not matches:
                continue

            for match in matches:
                findings.append(
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="pii",
                        description=f"Detected {entity} in content",
                        span=(match.start(), match.end()),
                        metadata={"entity_type": entity, "tokenized": True},
                    )
                )

            # Replace matches with tokens, reusing the same token for equal values
            def _replace(m: re.Match, _entity: str = entity) -> str:
                original = m.group(0)
                if original in value_to_token:
                    return value_to_token[original]
                counters[_entity] = counters.get(_entity, 0) + 1
                token = f"<PII:{_entity}:{counters[_entity]}>"
                token_map[token] = original
                value_to_token[original] = token
                return token

            tokenized = pattern.sub(_replace, tokenized)

        return findings, tokenized

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

        if findings and self.action_mode in ("redact", "tokenize"):
            anonymizer = AnonymizerEngine()
            anonymized = anonymizer.anonymize(text=content, analyzer_results=results)
            return findings, anonymized.text

        return findings, content


# ---------------------------------------------------------------------------
# PIIRestorer — output guard that reverses tokenization
# ---------------------------------------------------------------------------


@register_guard("pii_restorer")
class PIIRestorer(GuardrailBase):
    """
    Output guardrail that replaces PII tokens with the original values.

    Must be used together with ``PIIDetector(action="tokenize")`` on the input
    side.  Both guards share state through the pipeline context dict under the
    key ``"_pii_token_map"``.

    If no token map is present in the context (e.g. tokenization was not used
    for this request), the guard passes the content through unchanged.

    Config / YAML:
        output:
          pii_restorer:
            enabled: true
    """

    name = "pii_restorer"
    stage = GuardrailStage.OUTPUT
    description = "Restores PII tokens in LLM output back to original values."
    version = "1.0.0"

    def setup(self, **kwargs) -> None:  # no configuration needed
        pass

    async def check(self, content: str, context: dict) -> CheckResult:
        token_map: dict[str, str] = context.get(PII_TOKEN_MAP_KEY, {})

        if not token_map:
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        restored = content
        for token, original in token_map.items():
            restored = restored.replace(token, original)

        restored_something = restored != content
        return CheckResult(
            passed=True,
            action=Action.REDACT if restored_something else Action.ALLOW,
            sanitized_content=restored,
            metadata={"tokens_restored": sum(1 for t in token_map if t in content)},
        )
