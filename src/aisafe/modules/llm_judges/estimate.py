"""
modules/llm_judges/estimate.py
------------------------------
What a judge call WOULD cost, computed offline from the exact prompt a guard sends.

`aisafe measure` runs offline by default: it does not call a provider, because that
costs money and needs credentials. It still has to say what a judge-backed guard
spends per request, so this module renders the real prompt (the same template,
truncation and history window the guard uses) and counts characters. Every figure it
returns is labelled `estimated`, never `measured`; a measured figure comes only from
a provider's own usage field on a real call.

Nothing here imports a provider SDK or opens a socket: the judge modules import
`anthropic` and `aiohttp` lazily inside their call methods, so their prompt
constants are dependency-free.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aisafe.core.measurement import LLMUsage

__all__ = [
    "CHARS_PER_TOKEN",
    "CallSite",
    "estimate_tokens",
    "site_for",
    "estimate_call",
    "prompt_overhead_tokens",
]

# The usual rule of thumb for English and JSON-heavy text. Deliberately not a
# tokenizer: a tokenizer is a dependency and a model-specific claim, and the figure
# is labelled an estimate wherever it is shown.
CHARS_PER_TOKEN = 4


def estimate_tokens(text: str) -> int:
    """`ceil(len(text) / CHARS_PER_TOKEN)`; 0 for empty text, at least 1 otherwise."""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / CHARS_PER_TOKEN))


@dataclass(frozen=True)
class CallSite:
    """
    One place a guard calls a model.

    Attributes:
        id:           `prompt_injection:inline`, `toxicity_output:inline`,
                      `claude_judge:<mode>`, `llamaguard:<provider>`, `openai_mod`,
                      `nemo_rails`.
        model:        the model id the site calls.
        provider:     anthropic | openai | groq | together | ollama | huggingface | nemo.
        content_cap:  characters of content the prompt keeps; None when uncapped.
        max_tokens:   the completion cap the site passes; None when unknown.
        prompt:       renders the exact prompt for (content, history); None when the
                      prompt is not ours to render (NeMo's own flows).
        safe_reply:   the shortest reply the site parses as "safe"; the completion
                      estimate for an unremarkable request.
    """

    id: str
    model: str
    provider: str
    content_cap: int | None
    max_tokens: int | None
    prompt: Callable[[str, list | None], str] | None
    safe_reply: str

    @property
    def renderable(self) -> bool:
        return self.prompt is not None


def _unwrap(judge: Any) -> Any:
    """The judge behind any number of CachedJudge wrappers."""
    seen = 0
    while hasattr(judge, "_judge") and seen < 8:
        judge = judge._judge
        seen += 1
    return judge


def _claude_safe_reply(mode: str) -> str:
    if mode == "injection":
        return '{"safe": true, "categories": [], "confidence": 1.0, "reason": ""}'
    if mode == "toxicity":
        return '{"safe": true, "score": 0.0, "categories": [], "confidence": 1.0, "reason": ""}'
    return '{"safe": true, "categories": [], "confidence": 1.0, "reason": ""}'


def site_for_judge(judge: Any) -> CallSite | None:
    """The call site of a judge object, or None for a judge this module cannot render."""
    from aisafe.modules.llm_judges import claude_judge, llamaguard, openai_mod

    inner = _unwrap(judge)
    if isinstance(inner, claude_judge.ClaudeJudge):
        return CallSite(
            id=f"claude_judge:{inner.mode}",
            model=inner.model,
            provider="anthropic",
            content_cap=claude_judge.CONTENT_CAP,
            max_tokens=claude_judge.MAX_TOKENS,
            prompt=lambda content, history, _j=inner: _j._build_prompt(
                content, "agent" if _j.mode in ("toxicity", "manipulation") else "user", history
            ),
            safe_reply=_claude_safe_reply(inner.mode),
        )
    if isinstance(inner, llamaguard.LlamaGuardJudge):
        return CallSite(
            id=f"llamaguard:{inner.provider}",
            model=inner.model,
            provider=inner.provider,
            content_cap=None,
            max_tokens=llamaguard.MAX_TOKENS,
            prompt=lambda content, history: llamaguard._build_prompt(content, "user", history),
            safe_reply="safe",
        )
    if isinstance(inner, openai_mod.OpenAIModerationJudge):
        return CallSite(
            id="openai_mod",
            model=inner.model,
            provider="openai",
            content_cap=None,
            max_tokens=0,
            prompt=lambda content, history: content,
            safe_reply="",
        )
    return None


def site_for(guard: Any) -> CallSite | None:
    """
    The call site a guard would use, or None when the guard never calls a model
    (a regex guard, or a judge-capable guard with its judge switched off).
    """
    from aisafe.modules.input import prompt_injection
    from aisafe.modules.output import toxicity

    if isinstance(guard, prompt_injection.PromptInjectionGuard):
        if not guard.llm_judge:
            return None
        return CallSite(
            id="prompt_injection:inline",
            model=guard.llm_judge_model,
            provider="anthropic",
            content_cap=prompt_injection.JUDGE_CONTENT_CAP,
            max_tokens=prompt_injection.JUDGE_MAX_TOKENS,
            prompt=lambda content, history: prompt_injection.judge_prompt(content),
            safe_reply="SAFE",
        )
    if isinstance(guard, toxicity.ToxicityFilter):
        if not guard.use_llm_judge:
            return None
        return CallSite(
            id="toxicity_output:inline",
            model=guard.llm_judge_model,
            provider="anthropic",
            content_cap=toxicity.JUDGE_CONTENT_CAP,
            max_tokens=toxicity.JUDGE_MAX_TOKENS,
            prompt=lambda content, history: toxicity.judge_prompt(content),
            safe_reply='{"score": 0.0, "categories": [], "reason": ""}',
        )
    if getattr(guard, "name", "") == "nemo_rails":
        return CallSite(
            id="nemo_rails",
            model="",
            provider="nemo",
            content_cap=None,
            max_tokens=None,
            prompt=None,
            safe_reply="",
        )
    judge = getattr(guard, "_judge", None)
    if judge is not None:
        return site_for_judge(judge)
    return None


def estimate_call(site: CallSite, content: str, history: list | None = None) -> LLMUsage:
    """
    Tokens the site would spend on `content`, labelled `estimated`. A site whose
    prompt this module cannot render (NeMo) is `unavailable`: no figure is invented.
    """
    if site.prompt is None:
        return LLMUsage(None, None, site.model, site.provider, "unavailable", False, 1)
    tokens_in = estimate_tokens(site.prompt(content, history))
    tokens_out = estimate_tokens(site.safe_reply)
    if site.max_tokens is not None:
        tokens_out = min(tokens_out, site.max_tokens)
    return LLMUsage(tokens_in, tokens_out, site.model, site.provider, "estimated", False, 1)


def prompt_overhead_tokens(site: CallSite) -> int | None:
    """The prompt's fixed part: the template with empty content and no history."""
    if site.prompt is None:
        return None
    return estimate_tokens(site.prompt("", None))
