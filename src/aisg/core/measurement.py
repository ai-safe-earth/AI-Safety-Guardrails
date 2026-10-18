"""
src/aisg/core/measurement.py
----------------------------
The measured behaviour of a guard or a lint rule, and the thresholds that decide
whether it runs by default.

A guardrail is a trade. It catches some attacks, it breaks some legitimate
traffic, and it costs latency on every request that passes through it. This
module is the shared vocabulary for all three, so that "should this run by
default?" is answered from evidence rather than from whoever wrote the rule.

`None` always means UNMEASURED. It never means good. An unmeasured guard keeps
running -- silencing something requires evidence, and gating everything
unmeasured would mute the whole suite -- but it is reported as unmeasured
everywhere, never as passing.

Populate a Profile from `aisg measure` (runtime guards) or `bench/score.py`
(lint rules). Never by hand.

Cost is part of the trade. A judge-backed guard spends tokens on every call, and
the runtime records TOKENS, never dollars: prices change, and a dollar frozen into
telemetry is wrong within months. `LLMUsage` is what a guard records per check;
`aisg decide` joins it with a dated price table offline. Every token figure carries
a `cost_basis` saying how it was obtained (`COST_BASIS`), and a dollar figure derived
from an estimate is labelled an estimate wherever it is shown.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any, Optional

__all__ = [
    "Profile",
    "Thresholds",
    "Budget",
    "LLMUsage",
    "COST_BASIS",
    "weakest_basis",
    "DEFAULT_THRESHOLDS",
    "MIN_PRECISION",
    "MAX_FALSE_POSITIVE_RATE",
    "DAYS_PER_MONTH",
]

# A rule or guard measured below this precision does not run by default.
MIN_PRECISION = 0.80

# ...nor does one that wrongly trips on more than this share of benign traffic.
# Over-blocking is the failure mode nobody measures, and the one users notice.
MAX_FALSE_POSITIVE_RATE = 0.05

# `usd_per_month` is `usd_per_request * requests_per_day * DAYS_PER_MONTH`, stated
# wherever a monthly figure is printed. Deterministic and labelled, not calendar-exact.
DAYS_PER_MONTH = 30

# How a token or dollar figure was obtained, weakest last:
#   none         no model call happened (regex path, cache hit); the cost is exactly 0
#   measured     tokens read from the provider's usage field of a real call
#   estimated    tokens computed offline from the prompt template and the content
#                length; no call was made, and the figure says so wherever it is shown
#   unavailable  a call happened and no usage came back (local weights, an exception)
# `none` and `unavailable` are kept apart on purpose: collapsing them would call a
# known zero "unknown".
COST_BASIS = ("none", "measured", "estimated", "unavailable")


def weakest_basis(bases: Iterable[str]) -> str:
    """The least trustworthy basis among `bases`; `none` when there are none."""
    worst = 0
    for basis in bases:
        try:
            worst = max(worst, COST_BASIS.index(basis))
        except ValueError:
            worst = len(COST_BASIS) - 1
    return COST_BASIS[worst]


@dataclass(frozen=True)
class LLMUsage:
    """
    The tokens one guard check spent on a model, and how that is known.

    Attributes:
        tokens_in:   prompt tokens; None when the provider returned no usage.
        tokens_out:  completion tokens; None likewise.
        model:       the model id that was called (or would have been).
        provider:    anthropic | openai | groq | together | ollama | huggingface | nemo.
        cost_basis:  one of COST_BASIS.
        cache_hit:   the verdict came from CachedJudge; no call, no tokens.
        calls:       model calls this usage stands for (0 for `none`).
    """

    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    model: str = ""
    provider: str = ""
    cost_basis: str = "none"
    cache_hit: bool = False
    calls: int = 1

    def __post_init__(self) -> None:
        if self.cost_basis not in COST_BASIS:
            raise ValueError(f"cost_basis must be one of {COST_BASIS}, not {self.cost_basis!r}")

    @classmethod
    def none(cls, model: str = "", provider: str = "") -> "LLMUsage":
        """No call was made: the regex path decided, or the judge was not reached."""
        return cls(0, 0, model, provider, "none", False, 0)

    @classmethod
    def from_cache(cls, model: str = "", provider: str = "") -> "LLMUsage":
        """A CachedJudge hit: the verdict exists, the call did not happen."""
        return cls(0, 0, model, provider, "none", True, 0)

    @classmethod
    def unavailable_for(cls, model: str, provider: str) -> "LLMUsage":
        """A call happened and the provider reported no usage (or the call failed)."""
        return cls(None, None, model, provider, "unavailable", False, 1)

    def as_metadata(self) -> dict[str, Any]:
        """The dict a guard stores under `CheckResult.metadata["llm_usage"]`."""
        return {
            "calls": self.calls,
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "model": self.model,
            "provider": self.provider,
            "cost_basis": self.cost_basis,
            "cache_hit": self.cache_hit,
        }

    @classmethod
    def from_metadata(cls, data: Any) -> Optional["LLMUsage"]:
        """Inverse of `as_metadata`; None for anything that is not that dict."""
        if not isinstance(data, dict) or data.get("cost_basis") not in COST_BASIS:
            return None

        def _int(v: Any) -> Optional[int]:
            return v if isinstance(v, int) and not isinstance(v, bool) else None

        return cls(
            tokens_in=_int(data.get("tokens_in")),
            tokens_out=_int(data.get("tokens_out")),
            model=str(data.get("model") or ""),
            provider=str(data.get("provider") or ""),
            cost_basis=str(data["cost_basis"]),
            cache_hit=bool(data.get("cache_hit", False)),
            calls=_int(data.get("calls")) or 0,
        )


@dataclass(frozen=True)
class Profile:
    """
    What a guard or rule was measured to do.

    Attributes:
        precision:            tp / (tp + fp) over hand-labelled findings.
        false_positive_rate:  share of BENIGN traffic wrongly blocked, or stripped
                              of text that had to survive. A guard that blocks
                              everything scores perfect precision-adjacent numbers
                              on an attack corpus; this is the term that catches it.
        benign_modified_rate: share of benign traffic the guard flagged or redacted
                              while the required text survived. Not a break, but a
                              change the operator should know about.
        p50_latency_ms:       median added latency per call.
        p99_latency_ms:       tail added latency. The number that decides
                              whether a guard is usable on an interactive path.
        tokens_in_per_call:   median prompt tokens per model call, when the guard
                              calls one. None for a regex guard and for UNMEASURED.
        tokens_out_per_call:  median completion tokens per model call.
        usd_per_call:         tokens priced against a dated table; filled by
                              `aisg decide`, never by `aisg measure` (which has no
                              prices) and never by hand.
        cost_basis:           how the token figures were obtained (COST_BASIS).
        prices_as_of:         the `as_of` date of the price table behind
                              `usd_per_call`, so the dollar can be rechecked.
        human_rate:           share of calls that returned Action.HUMAN, i.e. went
                              to a person for approval.
        sample_size:          how many observations the figures rest on.
        measured_on:          provenance -- which corpus, which date. A number
                              without provenance cannot be rechecked.
    """

    precision: Optional[float] = None
    false_positive_rate: Optional[float] = None
    p50_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None
    sample_size: Optional[int] = None
    measured_on: str = ""
    benign_modified_rate: Optional[float] = None
    tokens_in_per_call: Optional[int] = None
    tokens_out_per_call: Optional[int] = None
    usd_per_call: Optional[float] = None
    cost_basis: Optional[str] = None
    prices_as_of: Optional[str] = None
    human_rate: Optional[float] = None

    _SOURCE_FIELDS = (
        "precision",
        "false_positive_rate",
        "benign_modified_rate",
        "p50_latency_ms",
        "p99_latency_ms",
        "tokens_in_per_call",
        "tokens_out_per_call",
        "usd_per_call",
        "cost_basis",
        "prices_as_of",
        "human_rate",
        "sample_size",
    )

    @property
    def is_measured(self) -> bool:
        """True if anything at all has been measured."""
        return any(
            v is not None
            for v in (
                self.precision,
                self.false_positive_rate,
                self.p50_latency_ms,
                self.p99_latency_ms,
                self.usd_per_call,
                self.human_rate,
            )
        )

    def with_latency(self, p50: float, p99: float, samples: int) -> "Profile":
        return replace(self, p50_latency_ms=p50, p99_latency_ms=p99, sample_size=samples)

    def as_source(self, indent: str = "    ") -> str:
        """Render a paste-ready `profile = Profile(...)` assignment."""
        parts = []
        for field in self._SOURCE_FIELDS:
            value = getattr(self, field)
            if value is not None:
                parts.append(f"{indent}    {field}={value!r},")
        if self.measured_on:
            parts.append(f'{indent}    measured_on="{self.measured_on}",')
        if not parts:
            return f"{indent}profile = Profile()  # unmeasured"
        body = "\n".join(parts)
        return f"{indent}profile = Profile(\n{body}\n{indent})"


@dataclass(frozen=True)
class Thresholds:
    """
    The bar a Profile must clear to run by default.

    `max_p99_latency_ms` is None by default and deliberately so: acceptable
    latency is a property of the deployment, not of the guard. 200ms is
    unremarkable in a batch job and fatal on an interactive path. Operators set
    their own budget; the suite reports the number either way rather than
    pretending a universal limit exists. The same holds for `max_usd_per_request`
    and `max_human_rate`: `Budget.thresholds()` derives them from a declared
    traffic profile, and nothing here invents one.
    """

    min_precision: float = MIN_PRECISION
    max_false_positive_rate: float = MAX_FALSE_POSITIVE_RATE
    max_p99_latency_ms: Optional[float] = None
    max_usd_per_request: Optional[float] = None
    max_human_rate: Optional[float] = None

    def failures(self, profile: Profile) -> list[str]:
        """
        Which thresholds this profile violates, as human-readable reasons.

        Only MEASURED values are judged. An unmeasured field cannot fail --
        absence of evidence is not evidence of a problem. A dollar figure counts
        only when its tokens were measured on a real call: demotion is a runtime
        decision taken from evidence, and an estimate is not evidence (`aisg
        decide` still reports estimated overruns, as estimates).
        """
        reasons = []
        if profile.precision is not None and profile.precision < self.min_precision:
            reasons.append(f"precision {profile.precision:.3f} < {self.min_precision:.2f}")
        if (
            profile.false_positive_rate is not None
            and profile.false_positive_rate > self.max_false_positive_rate
        ):
            reasons.append(
                f"false-positive rate {profile.false_positive_rate:.3f} "
                f"> {self.max_false_positive_rate:.2f}"
            )
        if (
            self.max_p99_latency_ms is not None
            and profile.p99_latency_ms is not None
            and profile.p99_latency_ms > self.max_p99_latency_ms
        ):
            reasons.append(
                f"p99 latency {profile.p99_latency_ms:.1f}ms > {self.max_p99_latency_ms:.1f}ms"
            )
        if (
            self.max_usd_per_request is not None
            and profile.usd_per_call is not None
            and profile.cost_basis == "measured"
            and profile.usd_per_call > self.max_usd_per_request
        ):
            reasons.append(f"usd/call {profile.usd_per_call:.4f} > {self.max_usd_per_request:.4f}")
        if (
            self.max_human_rate is not None
            and profile.human_rate is not None
            and profile.human_rate > self.max_human_rate
        ):
            reasons.append(
                f"human-routing rate {profile.human_rate:.3f} > {self.max_human_rate:.2f}"
            )
        return reasons

    def accepts(self, profile: Profile) -> bool:
        return not self.failures(profile)


DEFAULT_THRESHOLDS = Thresholds()


@dataclass(frozen=True)
class Budget:
    """
    What the operator declares about the deployment: its traffic and the limits
    it can bear. Nothing here is measured; `aisg decide` compares measured guard
    figures against it, and `aisg init` writes it into the system card's
    `traffic:` and `budgets:` blocks. Every field is None until someone sets it.

    Attributes:
        requests_per_day:               expected request volume.
        avg_input_tokens:               typical prompt size, for input-stage guards.
        avg_output_tokens:              typical response size, for output-stage guards.
        p99_ms:                         latency budget for the whole guard chain.
        monthly_usd:                    spend ceiling for all guards together.
        max_usd_per_request:            per-request cap; derived from the two above
                                        when not set directly.
        human_review_capacity_per_day:  how many approvals people can handle.
        max_human_rate:                 per-request routing cap; derived from the
                                        capacity and the volume when not set.
    """

    requests_per_day: Optional[float] = None
    avg_input_tokens: Optional[float] = None
    avg_output_tokens: Optional[float] = None
    p99_ms: Optional[float] = None
    monthly_usd: Optional[float] = None
    max_usd_per_request: Optional[float] = None
    human_review_capacity_per_day: Optional[float] = None
    max_human_rate: Optional[float] = None

    _TRAFFIC_KEYS = ("requests_per_day", "avg_input_tokens", "avg_output_tokens")
    _BUDGET_KEYS = (
        "p99_ms",
        "monthly_usd",
        "max_usd_per_request",
        "human_review_capacity_per_day",
        "max_human_rate",
    )

    @property
    def requests_per_month(self) -> Optional[float]:
        if self.requests_per_day is None:
            return None
        return self.requests_per_day * DAYS_PER_MONTH

    @property
    def derived_max_usd_per_request(self) -> Optional[float]:
        """The explicit per-request cap, else the monthly ceiling spread over the volume."""
        if self.max_usd_per_request is not None:
            return self.max_usd_per_request
        if self.monthly_usd is not None and self.requests_per_month:
            return self.monthly_usd / self.requests_per_month
        return None

    @property
    def derived_max_human_rate(self) -> Optional[float]:
        """The explicit routing cap, else the review capacity spread over the volume."""
        if self.max_human_rate is not None:
            return self.max_human_rate
        if self.human_review_capacity_per_day is not None and self.requests_per_day:
            return self.human_review_capacity_per_day / self.requests_per_day
        return None

    def thresholds(self, base: Thresholds = DEFAULT_THRESHOLDS) -> Thresholds:
        """`base` with the latency, cost and human caps this budget implies."""
        return replace(
            base,
            max_p99_latency_ms=self.p99_ms if self.p99_ms is not None else base.max_p99_latency_ms,
            max_usd_per_request=(
                self.derived_max_usd_per_request
                if self.derived_max_usd_per_request is not None
                else base.max_usd_per_request
            ),
            max_human_rate=(
                self.derived_max_human_rate
                if self.derived_max_human_rate is not None
                else base.max_human_rate
            ),
        )

    @classmethod
    def from_card(cls, card: Any) -> "Budget":
        """Read the `traffic:` and `budgets:` blocks of an ai-system-card document.
        Missing blocks, non-numeric or null values read as unset."""
        values: dict[str, Optional[float]] = {}
        if isinstance(card, dict):
            for block, keys in (("traffic", cls._TRAFFIC_KEYS), ("budgets", cls._BUDGET_KEYS)):
                section = card.get(block)
                if not isinstance(section, dict):
                    continue
                for key in keys:
                    values[key] = _number_or_none(section.get(key))
        return cls(**values)

    def merged(self, **overrides: Optional[float]) -> "Budget":
        """A copy with every non-None override applied (flags beat the card)."""
        changes = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **changes) if changes else self

    def is_empty(self) -> bool:
        return all(getattr(self, key) is None for key in (*self._TRAFFIC_KEYS, *self._BUDGET_KEYS))


def _number_or_none(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None
