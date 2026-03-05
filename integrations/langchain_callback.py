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

from typing import Any, Optional
from uuid import UUID


class LangChainGuardrailCallback:
    """
    LangChain BaseCallbackHandler that intercepts LLM inputs and outputs.

    Hooks used:
        on_llm_start  — runs input guardrails on the prompt
        on_llm_end    — runs output guardrails on the LLM result

    Note: LangChain callbacks are synchronous in older versions.
    This handler uses asyncio.run() to call the async pipeline from sync context
    when needed.
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
        import asyncio

        for i, prompt in enumerate(prompts):
            result = asyncio.get_event_loop().run_until_complete(
                self.pipeline.run_input(prompt, self.context)
            )
            if result.blocked:
                self._blocked_message = result.rejection_message
                raise ValueError(f"[Guardrail Blocked] {result.rejection_message}")
            prompts[i] = result.sanitized_output

    def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
        import asyncio

        for generation_list in response.generations:
            for gen in generation_list:
                text = getattr(gen, "text", "")
                if text:
                    result = asyncio.get_event_loop().run_until_complete(
                        self.pipeline.run_output(text, self.context)
                    )
                    if result.blocked:
                        gen.text = result.rejection_message or "Response blocked."
                    else:
                        gen.text = result.sanitized_output

    def on_llm_error(self, error: Exception, *, run_id: UUID, **kwargs: Any) -> None:
        pass

    def on_chain_start(self, *args, **kwargs) -> None:
        pass

    def on_chain_end(self, *args, **kwargs) -> None:
        pass

    def on_chain_error(self, *args, **kwargs) -> None:
        pass

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        **kwargs: Any,
    ) -> None:
        """
        Tool start hook — runs processing guardrails (tool policy) before tool execution.
        """
        import asyncio

        tool_name = serialized.get("name", "")
        tool_call = {"name": tool_name, "arguments": {"input": input_str}}
        ctx = {**self.context, "tool_call": tool_call}

        result = asyncio.get_event_loop().run_until_complete(
            self.pipeline.run_processing(input_str, context=ctx, tool_call=tool_call)
        )
        if result.blocked:
            raise PermissionError(f"[Tool Policy] {result.rejection_message}")
