"""
tests/unit/test_langchain_callback.py
--------------------------------------
LangChainGuardrailCallback against a real pipeline (no mocks): the session
context is one dict, shared across every hook and with the caller.

on_tool_start used to run the processing stage on a shallow copy of
`self.context`, so ToolPolicyGuard's per-session counters landed on the copy
and vanished after each call: `max_tool_calls_per_session` and
`max_calls_per_tool` never tripped through this integration.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aisg.core.pipeline import GuardrailPipeline
from aisg.integrations.langchain_callback import LangChainGuardrailCallback
from aisg.modules.input.pii_detector import PII_TOKEN_MAP_KEY, PIIDetector, PIIRestorer
from aisg.modules.processing.tool_policy import ToolPolicy, ToolPolicyGuard


def _pipeline(**guard_kwargs) -> GuardrailPipeline:
    guard = ToolPolicyGuard(
        policies={"user": ToolPolicy(allow=["search", "read_file"], deny=[])},
        **guard_kwargs,
    )
    return GuardrailPipeline(processing_guards=[guard], parallel=False)


class TestToolBudgetThroughTheCallback:
    def test_session_budget_trips_on_the_third_call(self):
        cb = LangChainGuardrailCallback(
            pipeline=_pipeline(max_tool_calls_per_session=2),
            context={"role": "user", "user_id": "u1"},
        )
        cb.on_tool_start({"name": "search"}, "q1", run_id=MagicMock())
        cb.on_tool_start({"name": "search"}, "q2", run_id=MagicMock())
        with pytest.raises(PermissionError, match=r"\[Tool Policy\]") as exc_info:
            cb.on_tool_start({"name": "search"}, "q3", run_id=MagicMock())
        assert "limit" in str(exc_info.value)
        assert cb.context["_tool_session_counters"]["__total__"] == 2

    def test_per_tool_budget_trips(self):
        cb = LangChainGuardrailCallback(
            pipeline=_pipeline(max_calls_per_tool=1), context={"role": "user"}
        )
        cb.on_tool_start({"name": "search"}, "q1", run_id=MagicMock())
        cb.on_tool_start({"name": "read_file"}, "a.txt", run_id=MagicMock())
        with pytest.raises(PermissionError, match="search"):
            cb.on_tool_start({"name": "search"}, "q2", run_id=MagicMock())

    def test_tool_call_does_not_linger_between_calls(self):
        cb = LangChainGuardrailCallback(pipeline=_pipeline(), context={"role": "user"})
        cb.on_tool_start({"name": "search"}, "q1", run_id=MagicMock())
        assert "tool_call" not in cb.context, "run_processing restores what it found"
        assert cb.context["role"] == "user"

    def test_denied_tool_still_raises(self):
        cb = LangChainGuardrailCallback(pipeline=_pipeline(), context={"role": "user"})
        with pytest.raises(PermissionError, match="shell_command"):
            cb.on_tool_start({"name": "shell_command"}, "rm -rf /", run_id=MagicMock())


class TestContextIsSharedWithTheCaller:
    def test_callers_empty_dict_is_the_session_dict(self):
        """`context or {}` swapped an empty caller dict for a private one."""
        ctx: dict = {}
        cb = LangChainGuardrailCallback(
            pipeline=_pipeline(max_tool_calls_per_session=1), context=ctx
        )
        assert cb.context is ctx
        # No role in the dict: the guard's default_role is "user", so the call is allowed.
        cb.on_tool_start({"name": "search"}, "q1", run_id=MagicMock())
        assert ctx["_tool_session_counters"]["__total__"] == 1
        with pytest.raises(PermissionError):
            cb.on_tool_start({"name": "search"}, "q2", run_id=MagicMock())

    def test_no_context_gets_a_private_dict(self):
        cb = LangChainGuardrailCallback(pipeline=_pipeline())
        assert cb.context == {}

    def test_pii_token_map_survives_from_llm_start_to_llm_end(self):
        pipeline = GuardrailPipeline(
            input_guards=[PIIDetector(action="tokenize", entities=["EMAIL"])],
            output_guards=[PIIRestorer()],
            parallel=False,
        )
        ctx: dict = {}
        cb = LangChainGuardrailCallback(pipeline=pipeline, context=ctx)
        prompts = ["Write to alice@example.com"]
        cb.on_llm_start({}, prompts, run_id=MagicMock())
        assert "alice@example.com" not in prompts[0]
        assert PII_TOKEN_MAP_KEY in ctx

        token = next(iter(ctx[PII_TOKEN_MAP_KEY]))
        gen = MagicMock()
        gen.text = f"Done, I wrote to {token}."
        response = MagicMock()
        response.generations = [[gen]]
        cb.on_llm_end(response, run_id=MagicMock())
        assert "alice@example.com" in gen.text
