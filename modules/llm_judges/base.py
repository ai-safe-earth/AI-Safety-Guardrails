"""
modules/llm_judges/base.py
---------------------------
Abstract base class and shared data types for all LLM safety judges.

A judge is a thin async interface that takes text and returns a structured
safety verdict. It is NOT a GuardrailBase — it has no pipeline stage and
produces no CheckResult. Judges are dependencies injected into guard modules
(LLMInputFilter, LLMOutputFilter, LLMToolFilter).

Usage:
    judge = LlamaGuardJudge(provider="groq")
    verdict = await judge.judge(user_message, role="user")
    if not verdict.safe:
        print(verdict.categories)   # e.g. ["S10: Hate", "S1: Violent Crimes"]
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Verdict dataclass
# ---------------------------------------------------------------------------


@dataclass
class JudgeVerdict:
    """
    Structured result from a single LLM judge call.

    Attributes:
        safe:               True if the content passed safety checks.
        categories:         List of violated category strings, empty when safe.
                            Format is judge-specific:
                              LlamaGuard  → ["S1: Violent Crimes", "S10: Hate"]
                              OpenAI Mod  → ["hate", "violence"]
                              Claude      → ["injection", "toxicity"]
        confidence:         0.0–1.0. 1.0 means fully certain (binary classifiers).
                            Score-based judges populate this from their raw score.
        raw_response:       The unprocessed text/JSON from the model.
        judge_name:         Name of the judge that produced this verdict.
        latency_ms:         Wall-clock time for the judge call.
        error:              Set if the call failed and the verdict is a fallback.
    """

    safe: bool
    categories: list[str] = field(default_factory=list)
    confidence: float = 1.0
    raw_response: str = ""
    judge_name: str = ""
    latency_ms: float = 0.0
    error: str | None = None

    @property
    def failed(self) -> bool:
        """True if the judge call errored and this is a fallback verdict."""
        return self.error is not None


# ---------------------------------------------------------------------------
# Fallback factories
# ---------------------------------------------------------------------------


def _safe_fallback(judge_name: str, error: str, latency_ms: float = 0.0) -> JudgeVerdict:
    """
    Fail-open verdict used when a judge call raises an exception.
    Records the error for observability without blocking the pipeline.
    """
    return JudgeVerdict(
        safe=True,
        categories=[],
        confidence=0.0,
        raw_response="",
        judge_name=judge_name,
        latency_ms=latency_ms,
        error=error,
    )


def _unsafe_fallback(judge_name: str, error: str, latency_ms: float = 0.0) -> JudgeVerdict:
    """Fail-closed verdict — use only in high-security strict_mode contexts."""
    return JudgeVerdict(
        safe=False,
        categories=["error: judge_call_failed"],
        confidence=0.0,
        raw_response="",
        judge_name=judge_name,
        latency_ms=latency_ms,
        error=error,
    )


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared severity helper (used by the stage filters)
# ---------------------------------------------------------------------------


def category_to_severity(category: str):
    """
    Map a judge category string to a core.base.Severity level.

    Handles all three judge formats:
        LlamaGuard  — "S4: Child Sexual Exploitation", "S1: Violent Crimes"
        OpenAI mod  — "violence/graphic", "self-harm/instructions", "hate"
        Claude      — "injection", "toxicity", "violence"
    """
    # Import here to avoid circular imports at module load
    from core.base import Severity
    from modules.llm_judges.llamaguard import CRITICAL_CATEGORIES, HIGH_CATEGORIES

    code = category.split(":")[0].strip().upper()
    if code in CRITICAL_CATEGORIES:
        return Severity.CRITICAL
    if code in HIGH_CATEGORIES:
        return Severity.HIGH

    lower = category.lower()
    if any(kw in lower for kw in ("child", "weapon", "indiscriminate", "graphic", "/minors")):
        return Severity.CRITICAL
    if any(
        kw in lower
        for kw in (
            "violent",
            "violence",
            "self-harm",
            "self_harm",
            "threatening",
            "illicit/violent",
            "injection",
            "jailbreak",
        )
    ):
        return Severity.HIGH
    return Severity.MEDIUM


class LLMJudgeBase(ABC):
    """
    Abstract base for all LLM safety judges.

    Subclasses must implement `judge()`. Everything else is provided.

    Args:
        fail_open:  If True (default), a judge call failure returns safe=True
                    so the pipeline is never blocked by infrastructure problems.
                    Set False for strict/high-security contexts.
        timeout:    Seconds to wait for the judge API before timing out (default 10).
    """

    name: str = "unnamed_judge"

    def __init__(self, fail_open: bool = True, timeout: float = 10.0):
        self.fail_open = fail_open
        self.timeout = timeout

    @abstractmethod
    async def _call(
        self,
        content: str,
        role: Literal["user", "agent"],
        conversation_history: list[dict] | None,
    ) -> JudgeVerdict:
        """
        Internal implementation. Subclasses implement this.
        Should raise on failure — the wrapper handles fallbacks.
        """
        ...

    async def judge(
        self,
        content: str,
        role: Literal["user", "agent"] = "user",
        conversation_history: list[dict] | None = None,
    ) -> JudgeVerdict:
        """
        Run a safety judgment on `content`.

        Args:
            content:              The text to evaluate.
            role:                 "user" to evaluate a user message,
                                  "agent" to evaluate an AI response.
            conversation_history: Optional prior turns as
                                  [{"role": "user"|"assistant", "content": "..."}].
                                  Gives the judge context when evaluating agent output.

        Returns:
            JudgeVerdict. On exception, returns a fallback verdict per fail_open setting.
        """
        t0 = time.perf_counter()
        try:
            verdict = await self._call(content, role, conversation_history)
            verdict.latency_ms = (time.perf_counter() - t0) * 1000
            verdict.judge_name = self.name
            return verdict
        except Exception as exc:
            latency_ms = (time.perf_counter() - t0) * 1000
            err = f"{type(exc).__name__}: {exc}"
            if self.fail_open:
                return _safe_fallback(self.name, err, latency_ms)
            return _unsafe_fallback(self.name, err, latency_ms)

    async def is_safe(
        self,
        content: str,
        role: Literal["user", "agent"] = "user",
    ) -> bool:
        """Convenience wrapper — returns True if content passes the judge."""
        verdict = await self.judge(content, role)
        return verdict.safe

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, fail_open={self.fail_open})"
