"""tests/unit/test_estimate.py
----------------------------
The offline estimator renders the real prompt a guard sends and counts characters.
Every figure is labelled `estimated`; nothing here calls a provider or imports its SDK.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aisg.modules.llm_judges import estimate
from aisg.modules.llm_judges.estimate import (
    CHARS_PER_TOKEN,
    estimate_call,
    estimate_tokens,
    prompt_overhead_tokens,
    site_for,
    site_for_judge,
)

SRC = Path(__file__).resolve().parents[2] / "src"


def test_estimate_tokens_is_ceil_chars_over_four_and_deterministic():
    assert CHARS_PER_TOKEN == 4
    assert estimate_tokens("") == 0
    assert estimate_tokens("a") == 1
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcde") == 2
    assert estimate_tokens("x" * 4000) == 1000
    assert estimate_tokens("hello world") == estimate_tokens("hello world")


def test_import_pulls_no_provider_sdk():
    code = (
        "import sys, aisg.modules.llm_judges.estimate; "
        "print(sorted(m for m in sys.modules if m in ('anthropic', 'aiohttp', 'transformers')))"
    )
    import os

    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        env=dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8"),
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "[]"


class TestPromptInjectionSite:
    def test_judge_off_means_no_site(self):
        from aisg.modules.input.prompt_injection import PromptInjectionGuard

        assert site_for(PromptInjectionGuard()) is None

    def test_site_uses_the_hoisted_template_cap_and_completion_cap(self):
        from aisg.modules.input import prompt_injection

        guard = prompt_injection.PromptInjectionGuard(llm_judge=True)
        site = site_for(guard)
        assert site.id == "prompt_injection:inline"
        assert site.model == guard.llm_judge_model and site.provider == "anthropic"
        assert site.content_cap == prompt_injection.JUDGE_CONTENT_CAP == 2000
        assert site.max_tokens == prompt_injection.JUDGE_MAX_TOKENS == 100
        short = estimate_call(site, "hello")
        long = estimate_call(site, "x" * 10_000)
        assert short.cost_basis == "estimated" and long.cost_basis == "estimated"
        assert long.tokens_in - short.tokens_in <= (2000 - 5) // 4 + 1  # capped at 2000 chars
        assert long.tokens_in == estimate_tokens(prompt_injection.judge_prompt("x" * 10_000))
        assert short.tokens_out == 1  # "SAFE"
        assert prompt_overhead_tokens(site) == estimate_tokens(prompt_injection.judge_prompt(""))


class TestToxicitySite:
    def test_site_and_estimate(self):
        from aisg.modules.output import toxicity

        assert site_for(toxicity.ToxicityFilter()) is None
        guard = toxicity.ToxicityFilter(use_llm_judge=True)
        site = site_for(guard)
        assert site.id == "toxicity_output:inline"
        assert site.content_cap == toxicity.JUDGE_CONTENT_CAP == 3000
        assert site.max_tokens == toxicity.JUDGE_MAX_TOKENS == 200
        usage = estimate_call(site, "a response")
        assert usage.tokens_in == estimate_tokens(toxicity.judge_prompt("a response"))
        assert usage.tokens_out == estimate_tokens('{"score": 0.0, "categories": [], "reason": ""}')


class TestJudgeSites:
    def test_claude_judge_modes_and_history_window(self):
        from aisg.modules.llm_judges import claude_judge
        from aisg.modules.llm_judges.claude_judge import ClaudeJudge

        general = site_for_judge(ClaudeJudge(mode="general", api_key="k"))
        assert (
            general.id == "claude_judge:general" and general.max_tokens == claude_judge.MAX_TOKENS
        )
        no_history = estimate_call(general, "hi")
        history = [{"role": "user", "content": "x" * 5000}] * 20
        with_history = estimate_call(general, "hi", history)
        # six turns of at most 500 chars each: the window, not the whole history
        assert with_history.tokens_in - no_history.tokens_in <= (6 * (500 + 12)) // 4 + 6
        assert with_history.tokens_in > no_history.tokens_in
        injection = site_for_judge(ClaudeJudge(mode="injection", api_key="k"))
        assert injection.id == "claude_judge:injection"
        assert "safe" in injection.safe_reply

    def test_llamaguard_estimate_includes_the_safety_policy(self):
        from aisg.modules.llm_judges import llamaguard
        from aisg.modules.llm_judges.llamaguard import LlamaGuardJudge

        site = site_for_judge(LlamaGuardJudge(provider="groq", api_key="k"))
        assert site.id == "llamaguard:groq" and site.model == "llama-guard-3-8b"
        assert site.max_tokens == llamaguard.MAX_TOKENS == 20
        usage = estimate_call(site, "hello")
        assert usage.tokens_in >= estimate_tokens(llamaguard._SAFETY_POLICY)
        assert usage.tokens_out == 1  # "safe"
        assert site.content_cap is None

    def test_moderation_site_is_the_content_itself(self):
        from aisg.modules.llm_judges.openai_mod import OpenAIModerationJudge

        site = site_for_judge(OpenAIModerationJudge(api_key="k"))
        assert site.id == "openai_mod" and site.provider == "openai"
        usage = estimate_call(site, "x" * 400)
        assert usage.tokens_in == 100 and usage.tokens_out == 0

    def test_cached_judge_is_unwrapped(self):
        from aisg.modules.llm_judges.cache import CachedJudge
        from aisg.modules.llm_judges.claude_judge import ClaudeJudge

        site = site_for_judge(CachedJudge(CachedJudge(ClaudeJudge(api_key="k"))))
        assert site.id == "claude_judge:general"

    def test_filters_resolve_through_their_judge(self):
        from aisg.modules.input.llm_input_filter import LLMInputFilter
        from aisg.modules.llm_judges.claude_judge import ClaudeJudge

        guard = LLMInputFilter(judge=ClaudeJudge(mode="injection", api_key="k"))
        assert site_for(guard).id == "claude_judge:injection"

    def test_unknown_judge_and_regex_guards_have_no_site(self):
        from aisg.modules.input.pii_detector import PIIDetector
        from aisg.modules.llm_judges.base import JudgeVerdict, LLMJudgeBase

        class Odd(LLMJudgeBase):
            async def _call(self, content, role, conversation_history):
                return JudgeVerdict(safe=True)

        assert site_for_judge(Odd()) is None
        assert site_for(PIIDetector()) is None


def test_nemo_site_is_unavailable_never_estimated():
    class FakeNemo:
        name = "nemo_rails"

    site = site_for(FakeNemo())
    assert site.id == "nemo_rails" and not site.renderable
    usage = estimate_call(site, "x")
    assert usage.cost_basis == "unavailable" and usage.tokens_in is None
    assert prompt_overhead_tokens(site) is None


def test_every_rendered_estimate_is_labelled_estimated():
    from aisg.modules.input.prompt_injection import PromptInjectionGuard
    from aisg.modules.llm_judges.claude_judge import ClaudeJudge
    from aisg.modules.llm_judges.llamaguard import LlamaGuardJudge
    from aisg.modules.llm_judges.openai_mod import OpenAIModerationJudge

    sites = [
        site_for(PromptInjectionGuard(llm_judge=True)),
        site_for_judge(ClaudeJudge(api_key="k")),
        site_for_judge(LlamaGuardJudge(provider="ollama")),
        site_for_judge(OpenAIModerationJudge(api_key="k")),
    ]
    for site in sites:
        assert estimate_call(site, "text").cost_basis == "estimated", site.id
    assert estimate.__doc__ and "estimated" in estimate.__doc__
    with pytest.raises(AttributeError):
        estimate.fetch_prices  # noqa: B018  the estimator has no network path
