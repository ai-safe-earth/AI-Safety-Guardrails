"""
integrations/langchain_callback.py
------------------------------------
LangChain callback handler that runs guardrails at each LLM step.

Usage:
    from langchain_openai import ChatOpenAI
    from guardrails.integrations import LangChainGuardrailCallback

    callback = LangChainGuardrailCallback(pipeline=pipeline)
    llm = ChatOpenAI(callbacks=[callback])
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import sys
from typing import Any, Optional
from uuid import UUID


def _run_async(coro) -> Any:
    """
    Run an async coroutine safely from a synchronous LangChain callback.

    LangChain callbacks are synchronous. Two contexts are possible:

    1. No running event loop (plain script, CLI): use asyncio.run().
    2. Running event loop (FastAPI, Jupyter, async agent): calling
       run_until_complete() from the same thread would deadlock. Instead
       we spawn a short-lived thread with its own loop.
    """
    try:
        asyncio.get_running_loop()
        # There is a running loop in this thread — must run in a new thread.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        # No running loop — safe to call asyncio.run directly.
        return asyncio.run(coro)


class LangChainGuardrailCallback:
    """
    LangChain BaseCallbackHandler that intercepts LLM inputs and outputs.

    Hooks used:
        on_llm_start    — runs input guardrails on the prompt
        on_llm_end      — runs output guardrails on the LLM result
        on_llm_error    — logs errors to stderr (never silently swallowed)
        on_tool_start   — runs processing guardrails (tool policy)
    """

    def __init__(self, pipeline, context: dict | None = None):
        self.pipeline = pipeline
        self.context = context or {}
        self._blocked_message: str | None = None

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        for i, prompt in enumerate(prompts):
            result = _run_async(self.pipeline.run_input(prompt, self.context))
            if result.blocked:
                self._blocked_message = result.rejection_message
                raise ValueError(f"[Guardrail Blocked] {result.rejection_message}")
            prompts[i] = result.sanitized_output

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        for generation_list in response.generations:
            for gen in generation_list:
                text = getattr(gen, "text", "")
                if text:
                    result = _run_async(self.pipeline.run_output(text, self.context))
                    if result.blocked:
                        gen.text = result.rejection_message or "Response blocked."
                    else:
                        gen.text = result.sanitized_output

    def on_llm_error(self, error: Exception, *, run_id: UUID, **kwargs: Any) -> None:
        print(
            f"[LangChainGuardrailCallback] LLM error in run {run_id}: "
            f"{type(error).__name__}: {error}",
            file=sys.stderr,
        )

    def on_chain_start(self, *args, **kwargs) -> None:
        pass

    def on_chain_end(self, *args, **kwargs) -> None:
        pass

    def on_chain_error(self, error: Exception | None = None, *args, **kwargs) -> None:
        if error is not None:
            print(
                f"[LangChainGuardrailCallback] Chain error: "
                f"{type(error).__name__}: {error}",
                file=sys.stderr,
            )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """Run processing guardrails (tool policy) before tool execution."""
        tool_name = serialized.get("name", "")
        tool_call = {"name": tool_name, "arguments": {"input": input_str}}
        ctx = {**self.context, "tool_call": tool_call}

        result = _run_async(
            self.pipeline.run_processing(input_str, context=ctx, tool_call=tool_call)
        )
        if result.blocked:
            raise PermissionError(f"[Tool Policy] {result.rejection_message}")
