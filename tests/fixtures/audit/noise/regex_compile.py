"""regex_compile.py
----------------
`re.compile` on a model reply is not `compile()` of source code (AUD-402 negative).
"""

from __future__ import annotations

import re

from openai import OpenAI

MODEL = "gpt-4o-2024-08-06"
TICKET = re.compile(r"[A-Z]{2,5}-\d+")

client = OpenAI()


def ticket_ids(question: str) -> list[str]:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": question}],
    )
    reply = response.choices[0].message.content or ""
    return TICKET.findall(reply)
