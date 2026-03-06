"""
integrations/anthropic_middleware.py
--------------------------------------
Drop-in Anthropic client wrapper that automatically applies guardrails
before and after every messages.create() call.

Usage:
    from guardrails.integrations import AnthropicGuardrail

    client = AnthropicGuardrail(pipeline=pipeline)

    # Use exactly like the normal Anthropic client:
    response = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{"role": "user", "content": user_message}],
    )
"""

from __future__ import annotations

import copy
from typing import Any


class _GuardedMessages:
    def __init__(self, inner, pipeline, context_fn):
        self._inner = inner
        self._pipeline = pipeline
        self._context_fn = context_fn

    async def create(self, **kwargs) -> Any:
        context = self._context_fn(kwargs)

        # Deep-copy messages so we never mutate the caller's list.
        # Without this, a sanitized message would permanently replace the
        # original on retry, and concurrent calls sharing a message list
        # would corrupt each other.
        messages = copy.deepcopy(kwargs.get("messages", []))
        kwargs = {**kwargs, "messages": messages}

        # ---- INPUT: Guard the last user message ----
        user_messages = [m for m in messages if m.get("role") == "user"]
        if user_messages:
            last_user = user_messages[-1]
            content = last_user.get("content", "")
            if isinstance(content, str):
                input_result = await self._pipeline.run_input(content, context)
                if input_result.blocked:
                    # Return a synthetic response instead of calling the LLM
                    return _BlockedResponse(input_result.rejection_message)
                # Replace with sanitized content (safe: this is our deep copy)
                last_user["content"] = input_result.sanitized_output

        # ---- LLM CALL ----
        response = await self._inner.create(**kwargs)

        # ---- OUTPUT: Guard the response ----
        if hasattr(response, "content") and response.content:
            for block in response.content:
                if hasattr(block, "text"):
                    output_result = await self._pipeline.run_output(block.text, context)
                    if output_result.blocked:
                        block.text = output_result.rejection_message or "Response blocked by safety guardrails."
                    else:
                        block.text = output_result.sanitized_output

        return response


class _BlockedResponse:
    """Synthetic response object returned when input is blocked."""

    def __init__(self, message: str):
        self.content = [_TextBlock(message)]
        self.stop_reason = "guardrail_blocked"
        self.model = "guardrail"
        self.usage = None

    def __repr__(self):
        return f"BlockedResponse(message={self.content[0].text!r})"


class _TextBlock:
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class AnthropicGuardrail:
    """
    Drop-in replacement for anthropic.AsyncAnthropic that wraps all
    messages.create() calls with guardrail checks.

    Args:
        pipeline:       GuardrailPipeline instance
        context_fn:     Optional callable(kwargs) -> dict to extract context
                        from API call parameters (e.g., to get user_id from metadata)
        **client_kwargs: Passed directly to anthropic.AsyncAnthropic()
    """

    def __init__(self, pipeline, context_fn=None, **client_kwargs):
        import anthropic
        self._client = anthropic.AsyncAnthropic(**client_kwargs)
        self._pipeline = pipeline
        self._context_fn = context_fn or (lambda kwargs: kwargs.get("metadata", {}))
        self.messages = _GuardedMessages(self._client.messages, pipeline, self._context_fn)

    def __getattr__(self, name: str):
        """Proxy all other attributes to the underlying client."""
        return getattr(self._client, name)
