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
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Optional

__all__ = [
    "Profile",
    "Thresholds",
    "DEFAULT_THRESHOLDS",
    "MIN_PRECISION",
    "MAX_FALSE_POSITIVE_RATE",
]

# A rule or guard measured below this precision does not run by default.
MIN_PRECISION = 0.80

# ...nor does one that wrongly trips on more than this share of benign traffic.
# Over-blocking is the failure mode nobody measures, and the one users notice.
MAX_FALSE_POSITIVE_RATE = 0.05


@dataclass(frozen=True)
class Profile:
    """
    What a guard or rule was measured to do.

    Attributes:
        precision:            tp / (tp + fp) over hand-labelled findings.
        false_positive_rate:  share of BENIGN traffic wrongly blocked or
                              modified. A guard that blocks everything scores
                              perfect precision-adjacent numbers on an attack
                              corpus; this is the term that catches it.
        p50_latency_ms:       median added latency per call.
        p99_latency_ms:       tail added latency. The number that decides
                              whether a guard is usable on an interactive path.
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
            )
        )

    def with_latency(self, p50: float, p99: float, samples: int) -> "Profile":
        return replace(self, p50_latency_ms=p50, p99_latency_ms=p99, sample_size=samples)

    def as_source(self, indent: str = "    ") -> str:
        """Render a paste-ready `profile = Profile(...)` assignment."""
        parts = []
        for field in (
            "precision",
            "false_positive_rate",
            "p50_latency_ms",
            "p99_latency_ms",
            "sample_size",
        ):
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
    pretending a universal limit exists.
    """

    min_precision: float = MIN_PRECISION
    max_false_positive_rate: float = MAX_FALSE_POSITIVE_RATE
    max_p99_latency_ms: Optional[float] = None

    def failures(self, profile: Profile) -> list[str]:
        """
        Which thresholds this profile violates, as human-readable reasons.

        Only MEASURED values are judged. An unmeasured field cannot fail --
        absence of evidence is not evidence of a problem.
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
        return reasons

    def accepts(self, profile: Profile) -> bool:
        return not self.failures(profile)


DEFAULT_THRESHOLDS = Thresholds()
