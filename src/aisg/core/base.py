"""
core/base.py
------------
Core abstractions for the AI Safety Guardrails framework.
All guardrail modules inherit from GuardrailBase.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .measurement import DEFAULT_THRESHOLDS, Profile, Thresholds

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """How serious a guardrail finding is."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """What action to take when a check fires."""

    ALLOW = "allow"  # Pass through unchanged
    FLAG = "flag"  # Pass through but annotate
    REDACT = "redact"  # Sanitize and pass through
    BLOCK = "block"  # Hard stop — return rejection_message
    HUMAN = "human"  # Route to human review queue


class GuardrailStage(str, Enum):
    INPUT = "input"
    PROCESSING = "processing"
    OUTPUT = "output"
    POLICY = "policy"


# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single finding from a guardrail check."""

    guard_name: str
    severity: Severity
    category: str
    description: str
    span: Optional[tuple[int, int]] = None  # character span in content
    metadata: dict = field(default_factory=dict)


@dataclass
class CheckResult:
    """
    The result of running content through one guardrail module.

    Attributes:
        passed:             True if content should proceed.
        action:             What the pipeline should do with the content.
        sanitized_content:  The (possibly modified) content after redaction/cleanup.
        findings:           List of individual findings (even if passed=True for audit).
        rejection_message:  User-facing message when action=BLOCK.
        latency_ms:         Time taken for this check.
        check_id:           UUID for correlation with audit logs.
    """

    passed: bool
    action: Action = Action.ALLOW
    sanitized_content: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)
    rejection_message: Optional[str] = None
    latency_ms: float = 0.0
    check_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK

    @property
    def requires_human(self) -> bool:
        return self.action == Action.HUMAN

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.findings, key=lambda f: order.index(f.severity)).severity


@dataclass
class PipelineResult:
    """
    Aggregated result from running content through all guardrails in a stage.
    """

    stage: GuardrailStage
    original_content: str
    final_content: str
    passed: bool
    blocked: bool
    checks: list[CheckResult] = field(default_factory=list)
    rejection_message: Optional[str] = None
    total_latency_ms: float = 0.0
    pipeline_run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def sanitized_output(self) -> str:
        return self.final_content

    @property
    def requires_human(self) -> bool:
        """
        True when any guard returned Action.HUMAN -- the content is not rejected,
        but a person must approve before it proceeds.

        This is distinct from `blocked`, which means a hard refusal. A caller
        that only inspects `blocked` would wave a human-review request straight
        through, so `passed` is False whenever this is True.
        """
        return any(c.requires_human for c in self.checks)

    @property
    def human_review_reasons(self) -> list[str]:
        """Messages from the guards that asked for human review."""
        out = []
        for c in self.checks:
            if not c.requires_human:
                continue
            if c.rejection_message:
                out.append(c.rejection_message)
            elif c.findings:
                # CheckResult carries no guard identity; Finding does.
                out.append(f"{c.findings[0].guard_name} requires human review")
            else:
                out.append("human review required")
        return out

    @property
    def all_findings(self) -> list[Finding]:
        return [f for c in self.checks for f in c.findings]


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class GuardrailBase(ABC):
    """
    Abstract base class for all guardrail modules.

    Subclasses implement `check()` and optionally `setup()`.

    Example:
        class MyGuard(GuardrailBase):
            name = "my_guard"
            stage = GuardrailStage.INPUT

            async def check(self, content: str, context: dict) -> CheckResult:
                # ... your logic ...
                return CheckResult(passed=True)
    """

    name: str = "unnamed_guard"
    stage: GuardrailStage = GuardrailStage.INPUT
    description: str = ""
    version: str = "1.0.0"

    # What this guard was measured to do: what it catches, what it breaks, what
    # it costs. Populate from `aisg measure`, never by hand. An empty Profile
    # means UNMEASURED -- which is not the same as good, and is reported as
    # unmeasured everywhere rather than as passing.
    profile: Profile = Profile()

    def fires_by_default(self, thresholds: Thresholds | None = None) -> bool:
        """
        Whether this guard runs without --experimental.

        An unmeasured guard keeps running: silencing one needs evidence, and
        gating everything unmeasured would mute the suite. Only a guard measured
        past a threshold -- too imprecise, too noisy on benign traffic, or too
        slow for the configured budget -- is demoted.
        """
        return (thresholds or DEFAULT_THRESHOLDS).accepts(self.profile)

    def demotion_reasons(self, thresholds: Thresholds | None = None) -> list[str]:
        return (thresholds or DEFAULT_THRESHOLDS).failures(self.profile)

    def __init__(self, enabled: bool = True, **kwargs: Any):
        self.enabled = enabled
        self._config = kwargs
        self.setup(**kwargs)

    def setup(self, **kwargs: Any) -> None:
        """Optional setup hook for subclasses (e.g., loading models)."""
        pass

    @abstractmethod
    async def check(self, content: str, context: dict) -> CheckResult:
        """
        Run the guardrail check.

        Args:
            content: The text to evaluate (prompt or response).
            context: Runtime context (user_id, session_id, role, etc.)

        Returns:
            CheckResult with pass/fail, action, and findings.
        """
        ...

    async def __call__(self, content: str, context: dict | None = None) -> CheckResult:
        """Callable interface — wraps check() with timing."""
        if not self.enabled:
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        ctx = context or {}
        start = time.perf_counter()
        result = await self.check(content, ctx)
        result.latency_ms = (time.perf_counter() - start) * 1000

        if result.sanitized_content is None:
            result.sanitized_content = content

        return result

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, enabled={self.enabled})"
