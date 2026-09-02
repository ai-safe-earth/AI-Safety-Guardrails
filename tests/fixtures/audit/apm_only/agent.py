"""agent.py
--------
One chat completion, with Sentry for crashes and nothing for the model calls themselves.
"""

from __future__ import annotations

import os

import sentry_sdk
from openai import OpenAI

sentry_sdk.init(dsn=os.environ["SENTRY_DSN"])

MODEL = "gpt-4o-2024-08-06"

client = OpenAI()


def answer(question: str) -> str:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": question}],
    )
    return response.choices[0].message.content or ""
