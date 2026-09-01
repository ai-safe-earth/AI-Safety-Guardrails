"""
modules/llm_judges
------------------
Provider-agnostic LLM safety judge abstraction.

    from modules.llm_judges import LlamaGuardJudge, ClaudeJudge, OpenAIModerationJudge

Judges are injected into stage-specific guard modules:
    LLMInputFilter(judge=LlamaGuardJudge(provider="groq"))
    LLMOutputFilter(judge=ClaudeJudge(mode="toxicity"))
"""

from modules.llm_judges.base import JudgeVerdict, LLMJudgeBase
from modules.llm_judges.cache import CachedJudge
from modules.llm_judges.claude_judge import ClaudeJudge
from modules.llm_judges.llamaguard import LLAMAGUARD_CATEGORIES, LlamaGuardJudge
from modules.llm_judges.openai_mod import OpenAIModerationJudge


def build_judge(
    judge_type: str = "llamaguard",
    judge_provider: str = "groq",
    model: str | None = None,
    api_key: str | None = None,
    fail_open: bool = True,
    timeout: float = 10.0,
    **kwargs,
) -> LLMJudgeBase:
    """
    Factory that builds a judge from plain config strings.
    Used by LLMInputFilter / LLMOutputFilter / LLMToolFilter when loaded
    from a YAML config file instead of being passed a judge object directly.

    Args:
        judge_type:     "llamaguard" | "openai_mod" | "claude"
        judge_provider: For llamaguard: "groq" | "together" | "ollama" | "openai" | "huggingface"
        model:          Optional model name override.
        api_key:        API key (falls back to environment variables).
        fail_open:      Return safe=True on judge failure (default True).
        timeout:        Request timeout in seconds.
        **kwargs:       Extra args forwarded to judge constructors
                        (e.g. mode="injection" for ClaudeJudge).
    """
    if judge_type == "llamaguard":
        return LlamaGuardJudge(
            provider=judge_provider,
            model=model,
            api_key=api_key,
            fail_open=fail_open,
            timeout=timeout,
        )
    if judge_type == "openai_mod":
        return OpenAIModerationJudge(
            api_key=api_key,
            fail_open=fail_open,
            timeout=timeout,
        )
    if judge_type == "claude":
        return ClaudeJudge(
            mode=kwargs.get("mode", "general"),
            model=model or "claude-haiku-4-5-20251001",
            api_key=api_key,
            fail_open=fail_open,
            timeout=timeout,
        )
    raise ValueError(
        f"Unknown judge_type {judge_type!r}. Choose from: 'llamaguard', 'openai_mod', 'claude'."
    )


__all__ = [
    "LLMJudgeBase",
    "JudgeVerdict",
    "LlamaGuardJudge",
    "LLAMAGUARD_CATEGORIES",
    "OpenAIModerationJudge",
    "ClaudeJudge",
    "CachedJudge",
    "build_judge",
]
