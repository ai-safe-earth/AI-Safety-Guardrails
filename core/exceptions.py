"""
core/exceptions.py
------------------
Exception hierarchy for the AI Safety Guardrails library.
"""


class GuardrailBlockedError(Exception):
    """
    Raised when a guardrail blocks content.

    Carries the PipelineResult (or CheckResult) that caused the block, plus the
    pipeline stage it came from, so callers can log or branch on it:

        try:
            result = await pipeline.run_full(user_input, call_llm)
        except GuardrailBlockedError as exc:
            log.warning("blocked at %s: %s", exc.stage, exc.message)
            return exc.result.rejection_message
    """

    def __init__(self, message: str, result=None, stage: str = ""):
        super().__init__(message)
        self.message = message
        self.result = result  # PipelineResult | CheckResult | None
        self.stage = stage  # "input" | "llm" | "output" | ""


class GuardrailConfigError(ValueError):
    """Raised when a guardrail receives invalid configuration."""


class PolicyViolationError(GuardrailBlockedError):
    """Raised when EU AI Act or policy compliance check fails."""

    def __init__(self, message: str, article: str = "", result=None, stage: str = ""):
        super().__init__(message, result, stage)
        self.article = article  # e.g. "Art. 5(1)(c)"
