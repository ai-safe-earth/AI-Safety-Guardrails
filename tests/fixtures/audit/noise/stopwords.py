"""stopwords.py
------------
A stopword list tested with `in` against a model reply is NLP, not a content filter
(AUD-805 negative: the name does not match ban/block/profan/toxic/forbid/deny/bad_word).
"""

from __future__ import annotations

from openai import OpenAI

MODEL = "gpt-4o-2024-08-06"
STOPWORDS = ["the", "a", "an", "of", "to", "and", "in"]

client = OpenAI()


def keywords(question: str) -> list[str]:
    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": question}],
    )
    reply = response.choices[0].message.content or ""
    return [word for word in reply.lower().split() if word not in STOPWORDS]
