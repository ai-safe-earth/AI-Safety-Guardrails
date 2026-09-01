"""
modules/llm_judges/openai_mod.py
---------------------------------
OpenAI Moderation API judge.

The OpenAI moderation endpoint is free, fast (~50ms), and requires only an
OpenAI API key. It returns per-category scores (0.0–1.0) and a binary flagged
decision. Good as a fast baseline before calling a heavier LlamaGuard judge.

API reference: https://platform.openai.com/docs/api-reference/moderations

Categories returned:
    harassment              Harassing language toward any target
    harassment/threatening  Harassment with threats of violence
    hate                    Hateful content targeting protected characteristics
    hate/threatening        Hate speech with violence
    illicit                 Instructions for illegal activities
    illicit/violent         Illicit activities involving violence
    self-harm               Promotion of self-harm
    self-harm/intent        Expression of intent to self-harm
    self-harm/instructions  Instructions for self-harm methods
    sexual                  Sexually explicit content
    sexual/minors           Sexual content involving minors
    violence                Violent content
    violence/graphic        Graphic violence

Usage:
    judge = OpenAIModerationJudge()   # reads OPENAI_API_KEY from env
    verdict = await judge.judge("How do I hurt someone?", role="user")
    # verdict.safe == False, verdict.confidence == 0.97
    # verdict.categories == ["violence", "harassment/threatening"]
"""

from __future__ import annotations

import os
from typing import Literal

from modules.llm_judges.base import JudgeVerdict, LLMJudgeBase

# OpenAI moderation categories that map to our higher severity findings
HIGH_SEVERITY_CATEGORIES = {
    "violence",
    "violence/graphic",
    "self-harm",
    "self-harm/intent",
    "self-harm/instructions",
    "sexual/minors",
    "hate/threatening",
    "harassment/threatening",
    "illicit/violent",
}

MEDIUM_SEVERITY_CATEGORIES = {
    "hate",
    "harassment",
    "illicit",
    "sexual",
}


class OpenAIModerationJudge(LLMJudgeBase):
    """
    OpenAI Moderation API safety judge.

    Free to use. Supports both user messages and agent responses
    (the 'role' parameter is informational — the API evaluates the content
    regardless of role, so both work identically).

    Args:
        api_key:    OpenAI API key. Falls back to OPENAI_API_KEY env var.
        model:      Moderation model (default: "omni-moderation-latest").
        threshold:  Per-category score threshold to mark as unsafe (default 0.5).
        fail_open:  Return safe=True on API failure (default True).
        timeout:    Request timeout in seconds (default 10).
    """

    name = "openai_moderation"

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "omni-moderation-latest",
        threshold: float = 0.5,
        fail_open: bool = True,
        timeout: float = 10.0,
    ):
        super().__init__(fail_open=fail_open, timeout=timeout)
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model
        self.threshold = threshold

    async def _call(
        self,
        content: str,
        role: Literal["user", "agent"],
        conversation_history: list[dict] | None,
    ) -> JudgeVerdict:
        import aiohttp

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "input": content,
        }

        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                "https://api.openai.com/v1/moderations",
                headers=headers,
                json=payload,
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

        result = data["results"][0]
        flagged: bool = result["flagged"]
        scores: dict[str, float] = result.get("category_scores", {})
        flags: dict[str, bool] = result.get("categories", {})

        # Collect violated categories above threshold
        violated = [cat for cat, score in scores.items() if score >= self.threshold]

        # Confidence = highest score among violated categories (or 0 if safe)
        confidence = max((scores[c] for c in violated), default=0.0) if violated else 0.0

        import json

        return JudgeVerdict(
            safe=not flagged and not violated,
            categories=violated,
            confidence=confidence,
            raw_response=json.dumps(result),
        )
