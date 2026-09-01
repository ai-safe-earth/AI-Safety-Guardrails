"""
modules/llm_judges/cache.py
----------------------------
Optional LRU + TTL cache wrapper for any LLMJudgeBase judge.

Identical content always produces the same safety verdict from a deterministic
judge, so caching is safe and effective for repeated inputs (e.g. a system
prompt that appears in every request, common short messages, batch processing).

Usage:
    from aisg.modules.llm_judges import LlamaGuardJudge
    from aisg.modules.llm_judges.cache import CachedJudge

    base_judge = LlamaGuardJudge(provider="groq", api_key="gsk_...")
    judge = CachedJudge(base_judge, max_size=512, ttl=3600)

    # Subsequent calls with the same content skip the API entirely:
    verdict = await judge.judge("Hello world")   # API call
    verdict = await judge.judge("Hello world")   # cache hit (~0 ms)

The cache key is SHA-256(role + "|" + content).
Conversation history is intentionally excluded from the cache key because
the same content can mean different things in different conversation contexts.
Set ``include_history_in_key=True`` to enable history-aware caching if your
use case requires it (reduces hit rate significantly).

Thread/async safety: the cache is protected by an asyncio.Lock.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from typing import Literal

from aisg.modules.llm_judges.base import JudgeVerdict, LLMJudgeBase


class CachedJudge(LLMJudgeBase):
    """
    LRU + TTL caching wrapper for any LLMJudgeBase judge.

    Parameters
    ----------
    judge : LLMJudgeBase
        The underlying judge to cache.
    max_size : int
        Maximum number of cached verdicts (LRU eviction, default 512).
    ttl : float
        Time-to-live in seconds for each cached entry (default 3600 = 1 hour).
        Pass 0 to disable TTL (entries live until evicted by LRU).
    include_history_in_key : bool
        If True, conversation history is included in the cache key.
        Improves correctness at the cost of much lower hit rates (default False).
    """

    def __init__(
        self,
        judge: LLMJudgeBase,
        max_size: int = 512,
        ttl: float = 3600.0,
        include_history_in_key: bool = False,
    ):
        # Inherit fail_open and timeout from the wrapped judge
        super().__init__(fail_open=judge.fail_open, timeout=judge.timeout)
        self._judge = judge
        self._max_size = max_size
        self._ttl = ttl
        self._include_history = include_history_in_key
        # OrderedDict used as an LRU cache: most-recently-used at the end
        self._cache: OrderedDict[str, tuple[JudgeVerdict, float]] = OrderedDict()
        self._lock = asyncio.Lock()
        self.name = f"cached({judge.name})"

    # ------------------------------------------------------------------
    # LLMJudgeBase implementation
    # ------------------------------------------------------------------

    async def _call(
        self,
        content: str,
        role: Literal["user", "agent"],
        conversation_history: list[dict] | None,
    ) -> JudgeVerdict:
        cache_key = self._make_key(content, role, conversation_history)

        async with self._lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                verdict, stored_at = entry
                if self._ttl == 0 or (time.monotonic() - stored_at) < self._ttl:
                    # Cache hit — move to end (most-recently-used)
                    self._cache.move_to_end(cache_key)
                    # Return a copy so callers can't mutate cached data
                    return JudgeVerdict(
                        safe=verdict.safe,
                        categories=list(verdict.categories),
                        confidence=verdict.confidence,
                        raw_response=verdict.raw_response,
                        judge_name=verdict.judge_name,
                        latency_ms=0.0,  # cache hit has ~0 latency
                        error=verdict.error,
                    )
                # Expired — remove
                del self._cache[cache_key]

        # Cache miss — call underlying judge (outside lock to avoid blocking)
        verdict = await self._judge._call(content, role, conversation_history)

        async with self._lock:
            self._cache[cache_key] = (verdict, time.monotonic())
            self._cache.move_to_end(cache_key)
            # Evict oldest entry if over capacity
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

        # Return a copy so callers can't mutate the cached entry
        return JudgeVerdict(
            safe=verdict.safe,
            categories=list(verdict.categories),
            confidence=verdict.confidence,
            raw_response=verdict.raw_response,
            judge_name=verdict.judge_name,
            latency_ms=verdict.latency_ms,
            error=verdict.error,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_key(
        self,
        content: str,
        role: str,
        conversation_history: list[dict] | None,
    ) -> str:
        parts = [role, content]
        if self._include_history and conversation_history:
            parts.append(json.dumps(conversation_history, sort_keys=True))
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        return len(self._cache)

    def invalidate(self, content: str, role: str = "user") -> bool:
        """
        Remove a specific entry from the cache.
        Returns True if the entry existed and was removed.
        """
        key = self._make_key(content, role, None)
        return self._cache.pop(key, None) is not None

    def clear(self) -> None:
        """Remove all cached entries."""
        self._cache.clear()

    def stats(self) -> dict:
        """Return cache statistics."""
        now = time.monotonic()
        expired = sum(
            1
            for _, (_, stored_at) in self._cache.items()
            if self._ttl > 0 and (now - stored_at) >= self._ttl
        )
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "ttl_seconds": self._ttl,
            "expired_entries": expired,
            "judge": self._judge.name,
        }
