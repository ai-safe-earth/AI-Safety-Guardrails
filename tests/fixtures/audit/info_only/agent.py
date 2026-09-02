"""agent.py
--------
Documentation assistant. The loop is capped, tool calls are budgeted, the kill
switch is read before every run, and every model call is traced.
"""

from __future__ import annotations

import os

import anthropic
from langfuse.decorators import observe
from tools import TOOL_SCHEMAS, TOOLS, record_tool_call, tool_budget

MODEL = "claude-sonnet-4-5-20250929"

SYSTEM_PROMPT = (
    "You are a documentation assistant for an open-source project. "
    "Answer from the project docs, cite the page you used, and say so when "
    "the docs do not cover the question."
)

client = anthropic.Anthropic()


@observe()
def run(question: str, max_turns: int = 8, max_tool_calls: int = tool_budget) -> str:
    if os.environ.get("AGENT_DISABLED"):
        return "The assistant is switched off."

    messages = [{"role": "user", "content": question}]
    turns = 0
    tool_calls = 0

    while True:
        turns += 1
        if turns > max_turns:
            return "Stopped: turn cap reached."
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )
        if response.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": response.content})
        results = []
        for block in response.content:
            if block.type != "tool_use":
                continue
            tool_calls += 1
            if tool_calls > max_tool_calls:
                return "Stopped: tool budget exhausted."
            record_tool_call(block.name, block.input)
            output = TOOLS[block.name](**block.input)
            results.append(
                {"type": "tool_result", "tool_use_id": block.id, "content": str(output)}
            )
        messages.append({"role": "user", "content": results})

    answer = response.content[0].text
    return answer
