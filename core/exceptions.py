"""
core/exceptions.py
------------------
Exception hierarchy for the AI Safety Guardrails library.
"""


class GuardrailBlockedError(Exception):
    """Raised when a guardrail blocks content. Carries the CheckResult."""

    def __init__(self, message: str, result=None):
        super().__init__(message)
        self.result = result  # CheckResult | None


class GuardrailConfigError(ValueError):
    """Raised when a guardrail receives invalid configuration."""


class PolicyViolationError(GuardrailBlockedError):
    """Raised when EU AI Act or policy compliance check fails."""

    def __init__(self, message: str, article: str = "", result=None):
        super().__init__(message, result)
        self.article = article  # e.g. "Art. 5(1)(c)"
