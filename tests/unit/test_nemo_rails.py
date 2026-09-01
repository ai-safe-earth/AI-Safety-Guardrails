"""
tests/unit/test_nemo_rails.py
------------------------------
Unit tests for integrations/nemo_rails.py

All tests mock the NeMo LLMRails / RailsConfig so nemoguardrails does NOT
need to be installed.  The mock is injected via monkeypatching the module-level
references in integrations.nemo_rails.

Test structure:
    TestNemoBlockDetection       — _is_nemo_block() helper
    TestNemoRailsGuard           — NemoRailsGuard.check() via mock rails
    TestNemoRailsGuardFailOpen   — fail-open / fail-closed edge cases
    TestNemoRailsMiddleware      — NemoRailsMiddleware.generate() orchestration
    TestNemoRailsMiddlewareInput — middleware respects pipeline input blocks
"""

from __future__ import annotations

import os
import sys
from unittest.mock import ANY, AsyncMock, MagicMock

import pytest

# Make sure the project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

# ---------------------------------------------------------------------------
# Patch nemoguardrails before importing our module
# ---------------------------------------------------------------------------

# We create a fake nemoguardrails module so the top-level try/except
# in integrations/nemo_rails.py succeeds even without the real package.
_fake_nemo = MagicMock()
_fake_rails_config_cls = MagicMock()
_fake_llm_rails_cls = MagicMock()

_fake_nemo.LLMRails = _fake_llm_rails_cls
_fake_nemo.RailsConfig = _fake_rails_config_cls

sys.modules.setdefault("nemoguardrails", _fake_nemo)

# Now we can safely import the module under test
import integrations.nemo_rails as nemo_mod

# Force _NEMO_AVAILABLE = True so the guards don't raise ImportError
nemo_mod._NEMO_AVAILABLE = True
nemo_mod.LLMRails = _fake_llm_rails_cls
nemo_mod.RailsConfig = _fake_rails_config_cls

from core.base import Action, GuardrailStage, PipelineResult
from integrations.nemo_rails import (
    NemoRailsGuard,
    NemoRailsMiddleware,
    _is_nemo_block,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_guard(rails=None, **kwargs) -> NemoRailsGuard:
    """Build a NemoRailsGuard with a mock rails instance."""
    if rails is None:
        rails = _make_mock_rails("Safe response.")
    return NemoRailsGuard(rails=rails, **kwargs)


def _make_mock_rails(response_text: str) -> MagicMock:
    """Return a mock LLMRails that yields response_text from generate_async."""
    mock = MagicMock()
    mock.generate_async = AsyncMock(return_value=response_text)
    return mock


def _make_pipeline(input_blocked=False, output_blocked=False, sanitized="clean input"):
    """Return a mock GuardrailPipeline."""
    pipeline = MagicMock()

    if input_blocked:
        from core.base import GuardrailStage

        input_result = PipelineResult(
            stage=GuardrailStage.INPUT,
            original_content="bad",
            final_content="bad",
            passed=False,
            blocked=True,
            rejection_message="Blocked by input guard.",
        )
    else:
        from core.base import GuardrailStage

        input_result = PipelineResult(
            stage=GuardrailStage.INPUT,
            original_content="hello",
            final_content=sanitized,
            passed=True,
            blocked=False,
        )

    output_result = PipelineResult(
        stage=GuardrailStage.OUTPUT,
        original_content="nemo reply",
        final_content="nemo reply",
        passed=not output_blocked,
        blocked=output_blocked,
        rejection_message="Blocked by output guard." if output_blocked else None,
    )

    pipeline.run_input = AsyncMock(return_value=input_result)
    pipeline.run_output = AsyncMock(return_value=output_result)
    return pipeline


# ===========================================================================
# TestNemoBlockDetection
# ===========================================================================


class TestNemoBlockDetection:
    def test_safe_response_not_blocked(self):
        assert _is_nemo_block("Sure, here is the information you requested.") is False

    def test_empty_response_not_blocked(self):
        assert _is_nemo_block("") is False

    def test_unable_to_pattern(self):
        assert _is_nemo_block("I'm not able to help with that.") is True

    def test_cannot_help_pattern(self):
        assert _is_nemo_block("I cannot help you with this request.") is True

    def test_wont_assist_pattern(self):
        assert _is_nemo_block("I won't assist with anything harmful.") is True

    def test_against_guidelines_pattern(self):
        assert _is_nemo_block("That's against the guidelines I follow.") is True

    def test_prohibited_pattern(self):
        assert _is_nemo_block("This action is prohibited.") is True

    def test_guardrail_keyword(self):
        assert _is_nemo_block("A guardrail was triggered for your request.") is True

    def test_im_sorry_i_cant(self):
        assert _is_nemo_block("I'm sorry, but I can't do that.") is True

    def test_colang_bot_refuse(self):
        assert _is_nemo_block("bot refuse jailbreak\n") is True

    def test_colang_bot_refuse_inline(self):
        assert _is_nemo_block("  bot refuse off topic") is True

    def test_that_not_something(self):
        assert _is_nemo_block("That's not something I am able to do.") is True

    def test_request_violates(self):
        assert _is_nemo_block("This request violates our policy.") is True

    def test_normal_helpful_response(self):
        assert _is_nemo_block("The capital of France is Paris.") is False

    def test_long_safe_response(self):
        long_resp = "Here is a detailed answer. " * 50
        assert _is_nemo_block(long_resp) is False

    def test_case_insensitive_unable(self):
        assert _is_nemo_block("I'M NOT ABLE TO help.") is True


# ===========================================================================
# TestNemoRailsGuard
# ===========================================================================


class TestNemoRailsGuard:
    @pytest.mark.asyncio
    async def test_safe_response_passes(self):
        rails = _make_mock_rails("The answer is 42.")
        guard = _make_guard(rails=rails)
        result = await guard.check("What is the answer?", {})
        assert result.passed is True
        assert result.action == Action.ALLOW
        assert not result.findings

    @pytest.mark.asyncio
    async def test_nemo_refusal_blocks(self):
        rails = _make_mock_rails("I'm not able to assist with that.")
        guard = _make_guard(rails=rails, block_on_refuse=True)
        result = await guard.check("Do something bad.", {})
        assert result.passed is False
        assert result.action == Action.BLOCK
        assert result.rejection_message is not None
        assert any(f.category == "nemo_refusal" for f in result.findings)

    @pytest.mark.asyncio
    async def test_nemo_refusal_flag_only_when_block_on_refuse_false(self):
        rails = _make_mock_rails("I cannot help with that.")
        guard = _make_guard(rails=rails, block_on_refuse=False)
        result = await guard.check("Bad request.", {})
        assert result.passed is True  # flag-only, not blocked
        assert result.action == Action.FLAG
        assert any(f.category == "nemo_refusal" for f in result.findings)

    @pytest.mark.asyncio
    async def test_nemo_response_in_metadata(self):
        response = "Paris is the capital of France."
        rails = _make_mock_rails(response)
        guard = _make_guard(rails=rails)
        result = await guard.check("What is the capital of France?", {})
        assert result.metadata["nemo_response"] == response

    @pytest.mark.asyncio
    async def test_custom_rejection_message(self):
        rails = _make_mock_rails("I won't do that.")
        guard = _make_guard(rails=rails, rejection_message="Custom block message.")
        result = await guard.check("bad", {})
        assert result.rejection_message == "Custom block message."

    @pytest.mark.asyncio
    async def test_stage_is_policy(self):
        guard = _make_guard()
        assert guard.stage == GuardrailStage.POLICY

    @pytest.mark.asyncio
    async def test_guard_name(self):
        guard = _make_guard()
        assert guard.name == "nemo_rails"

    @pytest.mark.asyncio
    async def test_latency_recorded(self):
        rails = _make_mock_rails("Fine response.")
        guard = _make_guard(rails=rails)
        result = await guard.check("hello", {})
        # latency is set by __call__ wrapper; check() result itself may be 0
        # We verify it's a non-negative float
        assert isinstance(result.latency_ms, float)
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_generate_async_called_with_messages(self):
        rails = _make_mock_rails("OK.")
        guard = _make_guard(rails=rails)
        await guard.check("hello world", {})
        rails.generate_async.assert_called_once()
        call_kwargs = rails.generate_async.call_args
        messages = call_kwargs[1].get("messages") or call_kwargs[0][0]
        assert any(m["content"] == "hello world" for m in messages)


# ===========================================================================
# TestNemoRailsGuardFailOpen
# ===========================================================================


class TestNemoRailsGuardFailOpen:
    @pytest.mark.asyncio
    async def test_nemo_error_fail_open(self):
        rails = MagicMock()
        rails.generate_async = AsyncMock(side_effect=RuntimeError("NeMo offline"))
        guard = _make_guard(rails=rails, fail_open=True)
        result = await guard.check("hello", {})
        assert result.passed is True
        assert result.action == Action.FLAG
        assert any(f.category == "nemo_error" for f in result.findings)
        assert "NeMo offline" in result.metadata.get("nemo_error", "")

    @pytest.mark.asyncio
    async def test_nemo_error_fail_closed(self):
        rails = MagicMock()
        rails.generate_async = AsyncMock(side_effect=RuntimeError("NeMo offline"))
        guard = _make_guard(rails=rails, fail_open=False)
        result = await guard.check("hello", {})
        assert result.passed is False
        assert result.action == Action.BLOCK
        assert any(f.category == "nemo_error" for f in result.findings)

    @pytest.mark.asyncio
    async def test_config_path_used_when_no_rails(self, monkeypatch):
        """Guard builds LLMRails lazily from config path."""
        mock_cfg = MagicMock()
        mock_rails = _make_mock_rails("Good response.")

        mock_rails_config_cls = MagicMock(return_value=mock_cfg)
        mock_llm_rails_cls = MagicMock(return_value=mock_rails)

        monkeypatch.setattr(nemo_mod, "RailsConfig", mock_rails_config_cls)
        monkeypatch.setattr(nemo_mod, "LLMRails", mock_llm_rails_cls)

        guard = NemoRailsGuard(rails_config_path="/fake/path")
        result = await guard.check("hello", {})

        mock_rails_config_cls.from_path.assert_called_once_with("/fake/path")
        assert result.passed is True

    @pytest.mark.asyncio
    async def test_raises_when_no_rails_and_no_path(self):
        guard = NemoRailsGuard.__new__(NemoRailsGuard)
        guard.enabled = True
        guard._rails = None
        guard._config_path = None
        guard._role = "user"
        guard._block_on_refuse = True
        guard._fail_open = True
        guard._rejection_message = "blocked"

        result = await guard.check("hello", {})
        # Should fail-open since _fail_open=True
        assert result.action == Action.FLAG
        assert any(f.category == "nemo_error" for f in result.findings)


# ===========================================================================
# TestNemoRailsMiddleware
# ===========================================================================


class TestNemoRailsMiddleware:
    @pytest.mark.asyncio
    async def test_full_pass_through(self):
        rails = _make_mock_rails("NeMo says hello back.")
        pipeline = _make_pipeline(sanitized="hello")
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        result = await mw.generate("hello")
        assert result.blocked is False
        assert result.final_content == "nemo reply"  # from mock output pipeline

    @pytest.mark.asyncio
    async def test_input_block_stops_early(self):
        rails = _make_mock_rails("Should not be called.")
        pipeline = _make_pipeline(input_blocked=True)
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        result = await mw.generate("bad input")
        assert result.blocked is True
        assert "Blocked" in (result.rejection_message or "")
        # NeMo should NOT have been called
        rails.generate_async.assert_not_called()

    @pytest.mark.asyncio
    async def test_output_block_propagated(self):
        rails = _make_mock_rails("Unsafe NeMo output.")
        pipeline = _make_pipeline(output_blocked=True)
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        result = await mw.generate("hello")
        assert result.blocked is True

    @pytest.mark.asyncio
    async def test_nemo_error_fail_open(self):
        rails = MagicMock()
        rails.generate_async = AsyncMock(side_effect=Exception("NeMo down"))
        pipeline = _make_pipeline(sanitized="clean")
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails, fail_open=True)
        result = await mw.generate("hello")
        # fail_open=True: _call_nemo returns an error string, output pipeline runs
        pipeline.run_output.assert_called_once()
        nemo_arg = pipeline.run_output.call_args[0][0]
        assert "NeMo error" in nemo_arg

    @pytest.mark.asyncio
    async def test_nemo_error_fail_closed(self):
        rails = MagicMock()
        rails.generate_async = AsyncMock(side_effect=Exception("NeMo down"))
        pipeline = _make_pipeline(sanitized="clean")
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails, fail_open=False)
        result = await mw.generate("hello")
        assert result.blocked is True
        # Output pipeline should NOT be called on hard error
        pipeline.run_output.assert_not_called()

    @pytest.mark.asyncio
    async def test_context_passed_to_pipeline(self):
        rails = _make_mock_rails("hi")
        pipeline = _make_pipeline()
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        ctx = {"user_id": "u42", "session_id": "s1"}
        await mw.generate("hello", context=ctx)
        call_ctx = pipeline.run_input.call_args[0][1]
        assert call_ctx["user_id"] == "u42"

    @pytest.mark.asyncio
    async def test_conversation_history_included_in_context(self):
        rails = _make_mock_rails("ok")
        pipeline = _make_pipeline()
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        history = [{"role": "user", "content": "earlier message"}]
        await mw.generate("follow-up", conversation_history=history)
        call_ctx = pipeline.run_input.call_args[0][1]
        assert "conversation_history" in call_ctx

    @pytest.mark.asyncio
    async def test_conversation_history_prepended_to_nemo_messages(self):
        rails = _make_mock_rails("ok")
        pipeline = _make_pipeline(sanitized="follow-up")
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        history = [{"role": "user", "content": "hi"}, {"role": "assistant", "content": "hello"}]
        await mw.generate("how are you?", conversation_history=history)
        call_kwargs = rails.generate_async.call_args
        messages = call_kwargs[1].get("messages") or call_kwargs[0][0]
        # history should come before the new user message
        assert messages[0]["content"] == "hi"
        assert messages[-1]["content"] == "follow-up"

    @pytest.mark.asyncio
    async def test_config_path_lazy_load(self, monkeypatch):
        mock_cfg = MagicMock()
        mock_rails_inst = _make_mock_rails("ok")
        mock_rc_cls = MagicMock()
        mock_rc_cls.from_path = MagicMock(return_value=mock_cfg)
        mock_llm_cls = MagicMock(return_value=mock_rails_inst)

        monkeypatch.setattr(nemo_mod, "RailsConfig", mock_rc_cls)
        monkeypatch.setattr(nemo_mod, "LLMRails", mock_llm_cls)

        pipeline = _make_pipeline()
        mw = NemoRailsMiddleware(pipeline=pipeline, rails_config_path="/my/config")
        await mw.generate("hello")

        mock_rc_cls.from_path.assert_called_once_with("/my/config")
        mock_llm_cls.assert_called_once_with(mock_cfg)


# ===========================================================================
# TestNemoRailsMiddlewareInput
# ===========================================================================


class TestNemoRailsMiddlewareInput:
    """Integration-style tests verifying the full flow via generate()."""

    @pytest.mark.asyncio
    async def test_sanitized_input_sent_to_nemo(self):
        """pipeline.run_input sanitizes; sanitized version goes to NeMo."""
        rails = _make_mock_rails("reply")
        pipeline = _make_pipeline(sanitized="sanitized hello")
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        await mw.generate("raw hello with PII")
        call_kwargs = rails.generate_async.call_args
        messages = call_kwargs[1].get("messages") or call_kwargs[0][0]
        assert any(m["content"] == "sanitized hello" for m in messages)

    @pytest.mark.asyncio
    async def test_nemo_output_goes_to_run_output(self):
        rails = _make_mock_rails("nemo generated reply")
        pipeline = _make_pipeline()
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails)
        await mw.generate("hello")
        pipeline.run_output.assert_called_once_with("nemo generated reply", ANY)

    @pytest.mark.asyncio
    async def test_role_label_in_nemo_messages(self):
        rails = _make_mock_rails("ok")
        pipeline = _make_pipeline()
        mw = NemoRailsMiddleware(pipeline=pipeline, rails=rails, user_role="customer")
        await mw.generate("test")
        call_kwargs = rails.generate_async.call_args
        messages = call_kwargs[1].get("messages") or call_kwargs[0][0]
        assert any(m["role"] == "customer" for m in messages)
