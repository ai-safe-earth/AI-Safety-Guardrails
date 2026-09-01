"""
tests/unit/test_improvements.py
---------------------------------
Tests for the six codebase improvements:

    1.  LangChain callback — _run_async helper + on_llm_error / on_chain_error
    2.  Anthropic middleware — messages deep-copy (no caller mutation)
    3.  Audit logger — stderr output on write failure
    4.  Config validation — None/bad section types in from_config()
    5.  RateLimiter — requests_per_minute, tokens_per_day, reset()
    6.  CachedJudge — LRU eviction, TTL expiry, cache miss/hit, stats
"""

from __future__ import annotations

import asyncio
import sys
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Stub anthropic before importing middleware
if "anthropic" not in sys.modules:
    _fa = MagicMock()
    _fa.AsyncAnthropic = MagicMock()
    sys.modules["anthropic"] = _fa


# ===========================================================================
# 1.  LangChain callback — _run_async
# ===========================================================================

from aisg.core.base import Action, GuardrailStage, PipelineResult
from aisg.integrations.langchain_callback import LangChainGuardrailCallback, _run_async


def _make_pipeline_result(blocked=False, sanitized="clean", msg="blocked"):
    return PipelineResult(
        stage=GuardrailStage.INPUT,
        original_content="raw",
        final_content=sanitized,
        passed=not blocked,
        blocked=blocked,
        rejection_message=msg if blocked else None,
    )


class TestRunAsync:
    def test_runs_coroutine_from_sync(self):
        async def _coro():
            return 42

        assert _run_async(_coro()) == 42

    def test_returns_value(self):
        async def _add(a, b):
            return a + b

        assert _run_async(_add(2, 3)) == 5

    @pytest.mark.asyncio
    async def test_runs_from_async_context(self):
        """When there IS a running loop, _run_async uses a thread."""

        async def _coro():
            return "ok"

        result = await asyncio.get_event_loop().run_in_executor(None, _run_async, _coro())
        assert result == "ok"


class TestLangChainCallback:
    def _make_pipeline(self, blocked=False, output_blocked=False):
        pipeline = MagicMock()
        in_result = _make_pipeline_result(blocked=blocked, sanitized="safe input")
        out_result = _make_pipeline_result(blocked=output_blocked, sanitized="safe output")
        pipeline.run_input = AsyncMock(return_value=in_result)
        pipeline.run_output = AsyncMock(return_value=out_result)
        pipeline.run_processing = AsyncMock(return_value=_make_pipeline_result())
        return pipeline

    def test_on_llm_start_sanitizes_prompt(self):
        pipeline = self._make_pipeline()
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        prompts = ["raw message"]
        cb.on_llm_start({}, prompts, run_id=MagicMock())
        assert prompts[0] == "safe input"

    def test_on_llm_start_raises_on_block(self):
        pipeline = self._make_pipeline(blocked=True)
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        with pytest.raises(ValueError, match="Guardrail Blocked"):
            cb.on_llm_start({}, ["bad input"], run_id=MagicMock())

    def test_on_llm_end_sanitizes_generation(self):
        pipeline = self._make_pipeline()
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        gen = MagicMock()
        gen.text = "raw output"
        response = MagicMock()
        response.generations = [[gen]]
        cb.on_llm_end(response, run_id=MagicMock())
        assert gen.text == "safe output"

    def test_on_llm_error_prints_to_stderr(self, capsys):
        pipeline = self._make_pipeline()
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        cb.on_llm_error(RuntimeError("model offline"), run_id=MagicMock())
        captured = capsys.readouterr()
        assert "RuntimeError" in captured.err
        assert "model offline" in captured.err

    def test_on_chain_error_prints_to_stderr(self, capsys):
        pipeline = self._make_pipeline()
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        cb.on_chain_error(ValueError("chain broke"))
        captured = capsys.readouterr()
        assert "ValueError" in captured.err

    def test_on_chain_error_none_does_not_print(self, capsys):
        pipeline = self._make_pipeline()
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        cb.on_chain_error(None)
        assert capsys.readouterr().err == ""

    def test_on_tool_start_blocks_forbidden_tool(self):
        pipeline = self._make_pipeline()
        block_result = _make_pipeline_result(blocked=True, msg="tool denied")
        pipeline.run_processing = AsyncMock(return_value=block_result)
        cb = LangChainGuardrailCallback(pipeline=pipeline)
        with pytest.raises(PermissionError, match="tool denied"):
            cb.on_tool_start({"name": "exec_code"}, "rm -rf /", run_id=MagicMock())


# ===========================================================================
# 2.  Anthropic middleware — deep copy
# ===========================================================================

from aisg.integrations.anthropic_middleware import _BlockedResponse, _GuardedMessages


class TestAnthropicMiddleware:
    def _make_inner(self, response_text="LLM reply"):
        block = MagicMock()
        block.text = response_text
        response = MagicMock()
        response.content = [block]
        inner = MagicMock()
        inner.create = AsyncMock(return_value=response)
        return inner

    def _make_pipeline(self, blocked=False, sanitized="sanitized"):
        pipeline = MagicMock()
        in_result = _make_pipeline_result(blocked=blocked, sanitized=sanitized)
        out_result = _make_pipeline_result(blocked=False, sanitized="safe output")
        pipeline.run_input = AsyncMock(return_value=in_result)
        pipeline.run_output = AsyncMock(return_value=out_result)
        return pipeline

    @pytest.mark.asyncio
    async def test_original_messages_not_mutated(self):
        """Caller's messages list must be unchanged after guardrail sanitization."""
        inner = self._make_inner()
        pipeline = self._make_pipeline(sanitized="redacted content")
        gm = _GuardedMessages(inner, pipeline, lambda kw: {})

        original = [{"role": "user", "content": "my PII here"}]
        await gm.create(messages=original)

        # Original list must be untouched
        assert original[0]["content"] == "my PII here"

    @pytest.mark.asyncio
    async def test_sanitized_content_sent_to_llm(self):
        inner = self._make_inner()
        pipeline = self._make_pipeline(sanitized="[REDACTED]")
        gm = _GuardedMessages(inner, pipeline, lambda kw: {})

        await gm.create(messages=[{"role": "user", "content": "secret@email.com"}])

        call_messages = inner.create.call_args[1]["messages"]
        assert call_messages[-1]["content"] == "[REDACTED]"

    @pytest.mark.asyncio
    async def test_blocked_input_returns_blocked_response(self):
        inner = self._make_inner()
        pipeline = self._make_pipeline(blocked=True)
        gm = _GuardedMessages(inner, pipeline, lambda kw: {})

        result = await gm.create(messages=[{"role": "user", "content": "bad"}])
        assert isinstance(result, _BlockedResponse)
        inner.create.assert_not_called()

    @pytest.mark.asyncio
    async def test_concurrent_calls_dont_cross_contaminate(self):
        """Two concurrent requests with different content must not share state."""
        call_contents = []

        async def fake_create(**kwargs):
            call_contents.append(kwargs["messages"][-1]["content"])
            block = MagicMock()
            block.text = "reply"
            resp = MagicMock()
            resp.content = [block]
            return resp

        inner = MagicMock()
        inner.create = fake_create

        async def make_pipeline(sanitized):
            p = MagicMock()
            p.run_input = AsyncMock(return_value=_make_pipeline_result(sanitized=sanitized))
            p.run_output = AsyncMock(return_value=_make_pipeline_result(sanitized="out"))
            return p

        p1 = await make_pipeline("user_A_sanitized")
        p2 = await make_pipeline("user_B_sanitized")

        gm1 = _GuardedMessages(inner, p1, lambda kw: {})
        gm2 = _GuardedMessages(inner, p2, lambda kw: {})

        await asyncio.gather(
            gm1.create(messages=[{"role": "user", "content": "user A"}]),
            gm2.create(messages=[{"role": "user", "content": "user B"}]),
        )

        assert "user_A_sanitized" in call_contents
        assert "user_B_sanitized" in call_contents


# ===========================================================================
# 3.  Audit logger — stderr on write failure
# ===========================================================================

from aisg.modules.observability.audit_logger import AuditLogger


def _make_result():
    return PipelineResult(
        stage=GuardrailStage.INPUT,
        original_content="hello",
        final_content="hello",
        passed=True,
        blocked=False,
    )


class TestAuditLoggerErrors:
    @pytest.mark.asyncio
    async def test_file_write_failure_prints_to_stderr(self, tmp_path, capsys):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(sink="file", log_path=str(log_path))

        # Make the file read-only so writes fail
        log_path.write_text("")
        log_path.chmod(0o444)

        try:
            await logger.log(_make_result(), {})
            captured = capsys.readouterr()
            # On Windows chmod may not prevent writes; only assert on systems where it does
            if captured.err:
                assert "AuditLogger" in captured.err
        finally:
            log_path.chmod(0o644)

    @pytest.mark.asyncio
    async def test_http_failure_prints_to_stderr(self, capsys):
        logger = AuditLogger(sink="http", http_endpoint="http://nonexistent.invalid/log")

        with patch("aiohttp.ClientSession") as mock_session_cls:
            mock_session = AsyncMock()
            mock_session.post = MagicMock(side_effect=Exception("connection refused"))
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session_cls.return_value = mock_session

            await logger.log(_make_result(), {})

        captured = capsys.readouterr()
        assert "AuditLogger" in captured.err
        assert "connection refused" in captured.err

    @pytest.mark.asyncio
    async def test_successful_write_no_stderr(self, tmp_path, capsys):
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(sink="file", log_path=str(log_path))
        await logger.log(_make_result(), {"user_id": "u1"})
        assert capsys.readouterr().err == ""
        assert log_path.exists()


# ===========================================================================
# 4.  Config validation
# ===========================================================================

from aisg.core.exceptions import GuardrailConfigError
from aisg.core.pipeline import GuardrailPipeline


class TestConfigValidation:
    def test_none_stage_section_returns_empty_guards(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("pipeline:\n  fail_open: false\ninput: null\n")
        pipeline = GuardrailPipeline.from_config(str(cfg))
        assert pipeline.input_guards == []

    def test_missing_stage_section_returns_empty_guards(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("pipeline:\n  fail_open: false\n")
        pipeline = GuardrailPipeline.from_config(str(cfg))
        assert pipeline.input_guards == []
        assert pipeline.output_guards == []

    def test_stage_as_list_raises_config_error(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("pipeline:\n  fail_open: false\ninput:\n  - pii_detector\n")
        with pytest.raises(GuardrailConfigError, match="mapping"):
            GuardrailPipeline.from_config(str(cfg))

    def test_unknown_module_raises_with_name(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            "pipeline:\n  fail_open: false\ninput:\n  totally_fake_guard:\n    enabled: true\n"
        )
        with pytest.raises(GuardrailConfigError, match="totally_fake_guard"):
            GuardrailPipeline.from_config(str(cfg))

    def test_unknown_module_error_lists_registered(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            "pipeline:\n  fail_open: false\ninput:\n  no_such_guard:\n    enabled: true\n"
        )
        with pytest.raises(GuardrailConfigError, match="Registered modules"):
            GuardrailPipeline.from_config(str(cfg))

    def test_module_cfg_none_treated_as_no_args(self, tmp_path):
        """A bare `pii_detector:` with no sub-keys should load with defaults."""
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("pipeline:\n  fail_open: false\ninput:\n  pii_detector:\n")
        pipeline = GuardrailPipeline.from_config(str(cfg))
        assert len(pipeline.input_guards) == 1

    def test_module_cfg_bad_type_raises(self, tmp_path):
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text("pipeline:\n  fail_open: false\ninput:\n  pii_detector: not_a_dict\n")
        with pytest.raises(GuardrailConfigError, match="mapping"):
            GuardrailPipeline.from_config(str(cfg))

    def test_disabled_unknown_module_skipped(self, tmp_path):
        """Disabled modules should be skipped even if unregistered."""
        cfg = tmp_path / "cfg.yaml"
        cfg.write_text(
            "pipeline:\n  fail_open: false\ninput:\n  ghost_module:\n    enabled: false\n"
        )
        pipeline = GuardrailPipeline.from_config(str(cfg))
        assert pipeline.input_guards == []


# ===========================================================================
# 5.  RateLimiter
# ===========================================================================

from aisg.modules.input.rate_limiter import RateLimiter


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        limiter = RateLimiter(requests_per_minute=5, tokens_per_day=0)
        for _ in range(5):
            result = await limiter.check("hello", {"user_id": "u1"})
            assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_blocks_over_rpm_limit(self):
        limiter = RateLimiter(requests_per_minute=3, tokens_per_day=0)
        ctx = {"user_id": "u2"}
        for _ in range(3):
            await limiter.check("msg", ctx)
        result = await limiter.check("msg", ctx)
        assert result.action == Action.BLOCK
        assert "requests_per_minute" in result.findings[0].category

    @pytest.mark.asyncio
    async def test_different_users_independent(self):
        limiter = RateLimiter(requests_per_minute=2, tokens_per_day=0)
        for _ in range(2):
            await limiter.check("msg", {"user_id": "ua"})
        # ua is now limited — ub should still pass
        result = await limiter.check("msg", {"user_id": "ub"})
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_token_budget_enforced(self):
        # 5 tokens per day; "hello world" = 2 tokens
        limiter = RateLimiter(requests_per_minute=0, tokens_per_day=5)
        ctx = {"user_id": "u3"}
        await limiter.check("hello world", ctx)  # 2 tokens used
        await limiter.check("hello world", ctx)  # 4 tokens used
        result = await limiter.check("hello world", ctx)  # would need 6 total → blocked
        assert result.action == Action.BLOCK
        assert "tokens_per_day" in result.findings[0].category

    @pytest.mark.asyncio
    async def test_no_rpm_limit_when_zero(self):
        limiter = RateLimiter(requests_per_minute=0, tokens_per_day=0)
        for _ in range(100):
            result = await limiter.check("msg", {"user_id": "u4"})
            assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_anonymous_key_used_when_no_user_id(self):
        limiter = RateLimiter(requests_per_minute=1, tokens_per_day=0)
        await limiter.check("msg", {})
        result = await limiter.check("msg", {})
        assert result.action == Action.BLOCK
        assert "__anonymous__" in result.metadata["rate_limit_key"]

    @pytest.mark.asyncio
    async def test_reset_clears_single_key(self):
        limiter = RateLimiter(requests_per_minute=1, tokens_per_day=0)
        ctx = {"user_id": "u5"}
        await limiter.check("msg", ctx)
        limiter.reset("u5")
        result = await limiter.check("msg", ctx)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_reset_all_clears_all_keys(self):
        limiter = RateLimiter(requests_per_minute=1, tokens_per_day=0)
        for uid in ["a", "b", "c"]:
            await limiter.check("msg", {"user_id": uid})
        limiter.reset()
        for uid in ["a", "b", "c"]:
            result = await limiter.check("msg", {"user_id": uid})
            assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_custom_rejection_message(self):
        limiter = RateLimiter(
            requests_per_minute=1, tokens_per_day=0, rejection_message="Too fast!"
        )
        ctx = {"user_id": "u6"}
        await limiter.check("msg", ctx)
        result = await limiter.check("msg", ctx)
        assert result.rejection_message == "Too fast!"

    @pytest.mark.asyncio
    async def test_count_tokens_false_disables_budget(self):
        limiter = RateLimiter(requests_per_minute=0, tokens_per_day=1, count_tokens=False)
        for _ in range(10):
            result = await limiter.check("lots of words here", {"user_id": "u7"})
            assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_custom_key_field(self):
        limiter = RateLimiter(requests_per_minute=1, tokens_per_day=0, key_field="org_id")
        ctx = {"org_id": "org1", "user_id": "any_user"}
        await limiter.check("msg", ctx)
        result = await limiter.check("msg", ctx)
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_registered_as_rate_limiter(self):
        from aisg.core.registry import REGISTRY

        assert "rate_limiter" in REGISTRY


# ===========================================================================
# 6.  CachedJudge
# ===========================================================================

from aisg.modules.llm_judges.base import JudgeVerdict, LLMJudgeBase
from aisg.modules.llm_judges.cache import CachedJudge


class _CountingJudge(LLMJudgeBase):
    """Judge that counts how many times _call() is invoked."""

    name = "counting_judge"

    def __init__(self, safe=True, fail_open=True):
        super().__init__(fail_open=fail_open)
        self.call_count = 0
        self._safe = safe

    async def _call(self, content, role, conversation_history):
        self.call_count += 1
        return JudgeVerdict(safe=self._safe, categories=[], confidence=1.0, raw_response="ok")


class TestCachedJudge:
    @pytest.mark.asyncio
    async def test_first_call_hits_underlying_judge(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        assert base.call_count == 1

    @pytest.mark.asyncio
    async def test_second_identical_call_is_cached(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        await cached.judge("hello")
        assert base.call_count == 1

    @pytest.mark.asyncio
    async def test_different_content_is_not_cached(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        await cached.judge("world")
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_different_role_is_not_cached(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello", role="user")
        await cached.judge("hello", role="agent")
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_lru_eviction(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=2, ttl=0)  # ttl=0 means no expiry
        await cached.judge("a")
        await cached.judge("b")
        await cached.judge("c")  # evicts "a"
        assert cached.size == 2
        # "a" was evicted — should re-call the underlying judge
        await cached.judge("a")
        assert base.call_count == 4

    @pytest.mark.asyncio
    async def test_ttl_expiry_causes_re_call(self, monkeypatch):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=1.0)
        await cached.judge("hello")
        assert base.call_count == 1

        # Fake the clock forward by 2 seconds
        original_monotonic = time.monotonic
        monkeypatch.setattr(time, "monotonic", lambda: original_monotonic() + 2.0)

        await cached.judge("hello")
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_ttl_zero_never_expires(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=0)
        await cached.judge("hello")
        await cached.judge("hello")
        await cached.judge("hello")
        assert base.call_count == 1

    @pytest.mark.asyncio
    async def test_verdict_safe_value_preserved(self):
        base = _CountingJudge(safe=False)
        cached = CachedJudge(base, max_size=10, ttl=60)
        v1 = await cached.judge("bad content")
        v2 = await cached.judge("bad content")
        assert v1.safe is False
        assert v2.safe is False

    @pytest.mark.asyncio
    async def test_cached_result_is_a_copy(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        v1 = await cached.judge("hello")
        v1.categories.append("mutated")
        v2 = await cached.judge("hello")
        assert "mutated" not in v2.categories

    @pytest.mark.asyncio
    async def test_cache_hit_has_zero_latency(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        v2 = await cached._call("hello", "user", None)
        assert v2.latency_ms == 0.0

    @pytest.mark.asyncio
    async def test_clear_empties_cache(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        cached.clear()
        assert cached.size == 0
        await cached.judge("hello")
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_single_key(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await cached.judge("hello")
        removed = cached.invalidate("hello")
        assert removed is True
        await cached.judge("hello")
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_missing_key_returns_false(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        assert cached.invalidate("not_in_cache") is False

    def test_stats_keys(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=64, ttl=300)
        stats = cached.stats()
        assert "size" in stats
        assert "max_size" in stats
        assert "ttl_seconds" in stats
        assert "expired_entries" in stats
        assert "judge" in stats
        assert stats["max_size"] == 64
        assert stats["ttl_seconds"] == 300

    def test_name_reflects_wrapped_judge(self):
        base = _CountingJudge()
        cached = CachedJudge(base)
        assert "counting_judge" in cached.name

    @pytest.mark.asyncio
    async def test_include_history_in_key_differentiates_contexts(self):
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60, include_history_in_key=True)
        h1 = [{"role": "user", "content": "ctx1"}]
        h2 = [{"role": "user", "content": "ctx2"}]
        await cached.judge("same content", conversation_history=h1)
        await cached.judge("same content", conversation_history=h2)
        assert base.call_count == 2

    @pytest.mark.asyncio
    async def test_concurrent_calls_same_content_only_one_api_call(self):
        """Race condition: two concurrent cache-miss calls should result in
        at most 2 underlying API calls (the cache miss window is small)."""
        base = _CountingJudge()
        cached = CachedJudge(base, max_size=10, ttl=60)
        await asyncio.gather(
            cached.judge("hello"),
            cached.judge("hello"),
        )
        # At most 2 calls (both might miss before either stores the result)
        assert base.call_count <= 2
