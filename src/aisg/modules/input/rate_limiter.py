"""
modules/input/rate_limiter.py
------------------------------
Per-user / per-org request and token rate limiting.

Uses a sliding-window counter keyed on user_id (or org_id for org-level limits).
No external dependencies — pure Python with asyncio.Lock for thread safety.

Usage:
    from aisg.modules.input.rate_limiter import RateLimiter

    limiter = RateLimiter(
        requests_per_minute=60,
        tokens_per_day=100_000,
    )
    pipeline = GuardrailPipeline(input_guards=[limiter])

    # Context must include user_id for per-user limits:
    result = await pipeline.run_input(message, context={"user_id": "u42"})

YAML config:
    input:
      rate_limiter:
        enabled: true
        requests_per_minute: 60
        tokens_per_day: 100000
        key_field: user_id        # context field to key limits on (default: user_id)
        count_tokens: true        # also enforce token budget (default: true)
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Deque

from aisg.core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    Severity,
)
from aisg.core.registry import register_guard


@register_guard("rate_limiter")
class RateLimiter(GuardrailBase):
    """
    Sliding-window rate limiter for requests and tokens.

    Two independent limits can be enforced:

    - **requests_per_minute**: maximum number of requests in any 60-second window.
    - **tokens_per_day**: maximum cumulative token count (≈ words) in any 24-hour
      window.  Token count is estimated as ``len(content.split())``.

    Both limits are tracked per identity key. The key is resolved from the
    pipeline context dict using ``key_field`` (default ``"user_id"``).
    Requests with no identity key share a single ``"__anonymous__"`` bucket.

    Parameters
    ----------
    requests_per_minute : int
        Max requests per 60-second sliding window per key.  0 = no limit.
    tokens_per_day : int
        Max token budget per 24-hour sliding window per key.  0 = no limit.
    key_field : str
        Context field used to identify the caller (default ``"user_id"``).
    count_tokens : bool
        Whether to enforce the token budget (default ``True``).
    rejection_message : str
        Message returned to callers when rate-limited.
    """

    name = "rate_limiter"
    stage = GuardrailStage.INPUT
    description = "Sliding-window per-user request and token rate limiter"
    version = "1.0.0"

    def setup(  # type: ignore[override]
        self,
        requests_per_minute: int = 60,
        tokens_per_day: int = 100_000,
        key_field: str = "user_id",
        count_tokens: bool = True,
        rejection_message: str = "Rate limit exceeded. Please slow down.",
        **kwargs,
    ) -> None:
        self._rpm = requests_per_minute
        self._tpd = tokens_per_day
        self._key_field = key_field
        self._count_tokens = count_tokens
        self._rejection_message = rejection_message

        # request timestamps: key -> deque of float (unix seconds)
        self._req_windows: dict[str, Deque[float]] = defaultdict(deque)
        # token timestamps+counts: key -> deque of (timestamp, token_count)
        self._tok_windows: dict[str, Deque[tuple[float, int]]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, content: str, context: dict) -> CheckResult:
        key = str(context.get(self._key_field) or "__anonymous__")
        now = time.monotonic()
        token_count = len(content.split()) if self._count_tokens else 0

        async with self._lock:
            # ---- Request-per-minute check ----
            if self._rpm > 0:
                window = self._req_windows[key]
                cutoff = now - 60.0
                while window and window[0] < cutoff:
                    window.popleft()
                if len(window) >= self._rpm:
                    return self._blocked(key, "requests_per_minute", len(window), self._rpm)
                window.append(now)

            # ---- Tokens-per-day check ----
            if self._count_tokens and self._tpd > 0:
                tok_window = self._tok_windows[key]
                cutoff_day = now - 86_400.0
                while tok_window and tok_window[0][0] < cutoff_day:
                    tok_window.popleft()
                used = sum(t for _, t in tok_window)
                if used + token_count > self._tpd:
                    return self._blocked(key, "tokens_per_day", used, self._tpd)
                tok_window.append((now, token_count))

        return CheckResult(
            passed=True,
            action=Action.ALLOW,
            metadata={"rate_limit_key": key},
        )

    def _blocked(
        self,
        key: str,
        limit_type: str,
        current: int,
        limit: int,
    ) -> CheckResult:
        return CheckResult(
            passed=False,
            action=Action.BLOCK,
            findings=[
                Finding(
                    guard_name=self.name,
                    severity=Severity.LOW,
                    category=f"rate_limit:{limit_type}",
                    description=(
                        f"Rate limit exceeded for key '{key}': "
                        f"{current}/{limit} {limit_type.replace('_', ' ')}."
                    ),
                )
            ],
            rejection_message=self._rejection_message,
            metadata={"rate_limit_key": key, "limit_type": limit_type},
        )

    def reset(self, key: str | None = None) -> None:
        """
        Reset rate-limit counters.  Pass a key to reset one identity,
        or call with no arguments to reset all counters (useful in tests).
        """
        if key is None:
            self._req_windows.clear()
            self._tok_windows.clear()
        else:
            self._req_windows.pop(key, None)
            self._tok_windows.pop(key, None)
