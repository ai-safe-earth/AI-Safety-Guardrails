"""max_tokens.py
-------------
`max_tokens` and `token_count` bound into a prompt are not secrets (AUD-503 negative).
"""

from __future__ import annotations

from openai import OpenAI

MODEL = "gpt-4o-2024-08-06"

client = OpenAI()


def summarise(text: str) -> str:
    max_tokens = 4096
    token_count = 3
    prompt = f"Summarise in at most {max_tokens} tokens ({token_count} words minimum):\n{text}"
    response = client.chat.completions.create(
        model=MODEL,
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.choices[0].message.content or ""
