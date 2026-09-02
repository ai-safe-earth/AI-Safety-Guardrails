"""agent.py
--------
One chat completion. Nothing here consults the kill switch declared in settings.py.
"""

from __future__ import annotations

from openai import OpenAI

MODEL = "gpt-4o-2024-08-06"

client = OpenAI()


def answer(question: str) -> str:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content or ""
