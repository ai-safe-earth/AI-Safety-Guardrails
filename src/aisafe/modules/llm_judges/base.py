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
from typing import Any, Literal

from aisafe.core.measurement import LLMUsage

# ---------------------------------------------------------------------------
# Usage readers: what a provider says a call cost, in tokens
# ---------------------------------------------------------------------------


def _int_or_none(value: Any) -> int | None:
    """An int, or None. A bool is not a count, and neither is a test's MagicMock."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def usage_from_anthropic(response: Any, model: str) -> LLMUsage:
    """`response.usage.input_tokens` / `.output_tokens` of an Anthropic Messages response."""
    usage = getattr(response, "usage", None)
    tokens_in = _int_or_none(getattr(usage, "input_tokens", None))
    tokens_out = _int_or_none(getattr(usage, "output_tokens", None))
    measured = tokens_in is not None and tokens_out is not None
    return LLMUsage(
        tokens_in, tokens_out, model, "anthropic", "measured" if measured else "unavailable"
    )


def usage_from_openai_compatible(data: Any, model: str, provider: str) -> LLMUsage:
    """`usage.prompt_tokens` / `usage.completion_tokens` of a chat-completions body."""
    usage = data.get("usage") if isinstance(data, dict) else None
    usage = usage if isinstance(usage, dict) else {}
    tokens_in = _int_or_none(usage.get("prompt_tokens"))
    tokens_out = _int_or_none(usage.get("completion_tokens"))
    measured = tokens_in is not None and tokens_out is not None
    return LLMUsage(
        tokens_in, tokens_out, model, provider, "measured" if measured else "unavailable"
    )


def usage_from_ollama(data: Any, model: str) -> LLMUsage:
    """`prompt_eval_count` / `eval_count` of an Ollama chat response."""
    body = data if isinstance(data, dict) else {}
    tokens_in = _int_or_none(body.get("prompt_eval_count"))
    tokens_out = _int_or_none(body.get("eval_count"))
    measured = tokens_in is not None and tokens_out is not None
    return LLMUsage(
        tokens_in, tokens_out, model, "ollama", "measured" if measured else "unavailable"
    )


def usage_metadata(verdict: Any, judge: Any) -> dict[str, Any]:
    """
    The `metadata["llm_usage"]` dict for a guard that consumed `verdict` from `judge`.

    A verdict with no usage (the fallback `judge()` returns on an exception, or a
    judge that predates usage recording) is `unavailable` for the judge's model: a
    call was attempted and nothing says what it cost.
    """
    usage = getattr(verdict, "usage", None)
    if not isinstance(usage, LLMUsage):
        usage = LLMUsage.unavailable_for(
            str(getattr(judge, "model", "") or ""), str(getattr(judge, "provider", "") or "")
        )
    return usage.as_metadata()


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
        reason:             The judge's own explanation, when it gives one.
                            Empty for judges that return no rationale.
        error:              Set if the call failed and the verdict is a fallback.
        usage:              Tokens the call spent and how that is known
                            (`LLMUsage`); None when the judge did not record it.
    """

    safe: bool
    categories: list[str] = field(default_factory=list)
    confidence: float = 1.0
    reason: str = ""
    raw_response: str = ""
    judge_name: str = ""
    latency_ms: float = 0.0
    error: str | None = None
    usage: LLMUsage | None = None

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
    from aisafe.core.base import Severity
    from aisafe.modules.llm_judges.llamaguard import CRITICAL_CATEGORIES, HIGH_CATEGORIES

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
