"""
integrations/nemo_rails.py
--------------------------
NVIDIA NeMo Guardrails integration.

Provides two components:

1. NemoRailsGuard  — a GuardrailBase guard (POLICY stage) that sends content
   through a NeMo LLMRails instance and blocks if NeMo refuses.

2. NemoRailsMiddleware — an orchestration wrapper that combines a
   GuardrailPipeline with NeMo as the LLM callable:
       pipeline.run_input() → nemo.generate_async() → pipeline.run_output()

Install:
    pip install nemoguardrails
    # or
    pip install "ai-safety-guardrails[nemo]"

Usage — guard only (embed NeMo inside an existing pipeline):
    from nemoguardrails import LLMRails, RailsConfig
    from integrations.nemo_rails import NemoRailsGuard

    rails_cfg = RailsConfig.from_path("config/nemo_rails")
    rails = LLMRails(rails_cfg)

    pipeline = GuardrailPipeline(
        policy_guards=[NemoRailsGuard(rails=rails)],
    )

Usage — full middleware (NeMo is the LLM):
    from integrations.nemo_rails import NemoRailsMiddleware

    middleware = NemoRailsMiddleware(
        pipeline=pipeline,
        rails_config_path="config/nemo_rails",
    )

    response = await middleware.generate(user_message, context={"user_id": "u1"})
"""

from __future__ import annotations

import re
import time
from typing import Optional

from core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from core.registry import register_guard

try:
    from nemoguardrails import LLMRails, RailsConfig

    _NEMO_AVAILABLE = True
except ImportError:
    _NEMO_AVAILABLE = False
    LLMRails = None  # type: ignore[assignment,misc]
    RailsConfig = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# NeMo refusal detection
# ---------------------------------------------------------------------------

# Patterns NeMo typically uses when it refuses / rails trigger
_NEMO_BLOCK_PATTERNS: list[re.Pattern] = [
    re.compile(r"i['']?m (not able|unable) to", re.I),
    re.compile(
        r"i (can['']?t|cannot|won['']?t|will not) (help|assist|provide|do|answer|discuss)", re.I
    ),
    re.compile(r"that['']?s (not something i (can|am able to)|outside)", re.I),
    re.compile(r"i['']?m (sorry|afraid)[,.] (but )?i (can['']?t|cannot|won['']?t)", re.I),
    re.compile(r"(prohibited|not allowed|against( the)? (rules|guidelines|policy))", re.I),
    re.compile(r"(this (request|topic|question) (is|falls outside|violates))", re.I),
    re.compile(r"guardrail", re.I),
]

# Colang "bot refuse" patterns (NeMo may emit these directly)
_NEMO_COLANG_REFUSE = re.compile(r"^\s*bot refuse", re.I | re.M)


def _is_nemo_block(response: str) -> bool:
    """Return True if the NeMo response looks like a refusal / rail trigger."""
    if _NEMO_COLANG_REFUSE.search(response):
        return True
    return any(p.search(response) for p in _NEMO_BLOCK_PATTERNS)


# ---------------------------------------------------------------------------
# NemoRailsGuard — GuardrailBase at POLICY stage
# ---------------------------------------------------------------------------


@register_guard("nemo_rails")
class NemoRailsGuard(GuardrailBase):
    """
    Runs content through NVIDIA NeMo Guardrails and blocks if rails trigger.

    Can be used as a *policy guard* in any GuardrailPipeline:

        pipeline = GuardrailPipeline(
            policy_guards=[NemoRailsGuard(rails=rails)],
        )

    Parameters
    ----------
    rails : LLMRails
        A pre-built NeMo ``LLMRails`` instance.  Either pass this **or**
        ``rails_config_path`` (the guard will build ``LLMRails`` lazily).
    rails_config_path : str | None
        Path to a NeMo Guardrails config directory (contains ``config.yml``
        and ``*.co`` Colang files).  Ignored when ``rails`` is supplied.
    role : str
        The role label sent to NeMo (``"user"`` or ``"assistant"``).
        Defaults to ``"user"`` (checking user input).
    block_on_refuse : bool
        If True (default), a NeMo refusal → Action.BLOCK.
        If False, refusals are only flagged (Action.FLAG).
    fail_open : bool
        If True (default), NeMo errors result in Action.FLAG instead of
        Action.BLOCK, allowing traffic through.
    rejection_message : str
        Message returned to callers when the guard blocks.
    """

    name = "nemo_rails"
    stage = GuardrailStage.POLICY
    description = "NVIDIA NeMo Guardrails — dialog-level safety enforcement"
    version = "1.0.0"

    def setup(  # type: ignore[override]
        self,
        rails=None,
        rails_config_path: Optional[str] = None,
        role: str = "user",
        block_on_refuse: bool = True,
        fail_open: bool = True,
        rejection_message: str = "I'm sorry, but I can't help with that request.",
        **kwargs,
    ) -> None:
        if not _NEMO_AVAILABLE:
            raise ImportError(
                "nemoguardrails is required for NemoRailsGuard.\n"
                "Install with:  pip install nemoguardrails\n"
                "or:            pip install 'ai-safety-guardrails[nemo]'"
            )

        self._rails = rails  # May be None; built lazily from path
        self._config_path = rails_config_path
        self._role = role
        self._block_on_refuse = block_on_refuse
        self._fail_open = fail_open
        self._rejection_message = rejection_message

    # ------------------------------------------------------------------
    # Lazy LLMRails construction
    # ------------------------------------------------------------------

    def _get_rails(self) -> "LLMRails":
        if self._rails is None:
            if self._config_path is None:
                raise ValueError("NemoRailsGuard requires either 'rails' or 'rails_config_path'.")
            cfg = RailsConfig.from_path(self._config_path)
            self._rails = LLMRails(cfg)
        return self._rails

    # ------------------------------------------------------------------
    # Check
    # ------------------------------------------------------------------

    async def check(self, content: str, context: dict) -> CheckResult:
        start = time.perf_counter()
        try:
            rails = self._get_rails()
            messages = [{"role": self._role, "content": content}]
            nemo_response: str = await rails.generate_async(messages=messages)
        except Exception as exc:
            latency_ms = (time.perf_counter() - start) * 1000
            if self._fail_open:
                return CheckResult(
                    passed=True,
                    action=Action.FLAG,
                    findings=[
                        Finding(
                            guard_name=self.name,
                            severity=Severity.LOW,
                            category="nemo_error",
                            description=f"NeMo Guardrails error (fail-open): {exc}",
                        )
                    ],
                    latency_ms=latency_ms,
                    metadata={"nemo_error": str(exc)},
                )
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=[
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="nemo_error",
                        description=f"NeMo Guardrails error (fail-closed): {exc}",
                    )
                ],
                rejection_message=self._rejection_message,
                latency_ms=latency_ms,
                metadata={"nemo_error": str(exc)},
            )

        latency_ms = (time.perf_counter() - start) * 1000
        blocked = _is_nemo_block(nemo_response)

        if blocked:
            action = Action.BLOCK if self._block_on_refuse else Action.FLAG
            return CheckResult(
                passed=not self._block_on_refuse,
                action=action,
                findings=[
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="nemo_refusal",
                        description="NeMo Guardrails triggered a dialog-level refusal.",
                        metadata={"nemo_response_snippet": nemo_response[:200]},
                    )
                ],
                rejection_message=self._rejection_message if self._block_on_refuse else None,
                latency_ms=latency_ms,
                metadata={"nemo_response": nemo_response},
            )

        return CheckResult(
            passed=True,
            action=Action.ALLOW,
            latency_ms=latency_ms,
            metadata={"nemo_response": nemo_response},
        )


# ---------------------------------------------------------------------------
# NemoRailsMiddleware — full orchestration (pipeline + NeMo as LLM)
# ---------------------------------------------------------------------------


class NemoRailsMiddleware:
    """
    Combines a ``GuardrailPipeline`` with NVIDIA NeMo Guardrails as the
    underlying LLM callable.

    Flow::

        user_input
            ↓
        pipeline.run_input()          # PII, injection, policy guards
            ↓ (sanitized)
        NeMo rails.generate_async()   # NeMo handles safety + LLM call
            ↓ (nemo_response)
        pipeline.run_output()         # toxicity, PII-redact on output
            ↓
        final_response

    Parameters
    ----------
    pipeline : GuardrailPipeline
        The guardrail pipeline for input/output guardrails.
    rails : LLMRails | None
        A pre-built NeMo ``LLMRails`` instance.
    rails_config_path : str | None
        Path to NeMo config dir; used to build ``LLMRails`` lazily if
        ``rails`` is not supplied.
    user_role : str
        Role label for user messages sent to NeMo (default ``"user"``).
    fail_open : bool
        If True (default), NeMo errors surface the error message but don't
        raise; the pipeline still returns a ``PipelineResult`` with
        ``blocked=True``.
    """

    def __init__(
        self,
        pipeline,
        rails=None,
        rails_config_path: Optional[str] = None,
        user_role: str = "user",
        fail_open: bool = True,
    ):
        if not _NEMO_AVAILABLE:
            raise ImportError(
                "nemoguardrails is required for NemoRailsMiddleware.\n"
                "Install with:  pip install nemoguardrails\n"
                "or:            pip install 'ai-safety-guardrails[nemo]'"
            )

        self.pipeline = pipeline
        self._rails = rails
        self._config_path = rails_config_path
        self._user_role = user_role
        self._fail_open = fail_open

    # ------------------------------------------------------------------
    # Lazy LLMRails construction
    # ------------------------------------------------------------------

    def _get_rails(self) -> "LLMRails":
        if self._rails is None:
            if self._config_path is None:
                raise ValueError(
                    "NemoRailsMiddleware requires either 'rails' or 'rails_config_path'."
                )
            cfg = RailsConfig.from_path(self._config_path)
            self._rails = LLMRails(cfg)
        return self._rails

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(
        self,
        user_input: str,
        context: Optional[dict] = None,
        conversation_history: Optional[list[dict]] = None,
    ) -> PipelineResult:
        """
        Run the full guarded generation pipeline.

        Args:
            user_input:            The raw user message.
            context:               Runtime context (user_id, session_id, …).
            conversation_history:  Prior turns for multi-turn sessions.
                                   Each turn: {"role": "user"|"assistant", "content": "…"}

        Returns:
            PipelineResult from the output stage.
            Check ``result.blocked`` and ``result.sanitized_output``.
        """
        ctx = context or {}
        if conversation_history:
            ctx["conversation_history"] = conversation_history

        # 1. Input guardrails (PII, injection, policy)
        input_result = await self.pipeline.run_input(user_input, ctx)
        if input_result.blocked:
            return input_result

        sanitized_input = input_result.sanitized_output

        # 2. NeMo generation
        nemo_response = await self._call_nemo(sanitized_input, conversation_history)
        if nemo_response is None:
            # NeMo hard-errored and fail_open=False
            from core.base import GuardrailStage

            return PipelineResult(
                stage=GuardrailStage.OUTPUT,
                original_content=sanitized_input,
                final_content="",
                passed=False,
                blocked=True,
                rejection_message="NeMo Guardrails encountered an error and could not generate a response.",
            )

        # 3. Output guardrails (toxicity, PII-redact on output)
        output_result = await self.pipeline.run_output(nemo_response, ctx)
        return output_result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _call_nemo(
        self,
        user_input: str,
        conversation_history: Optional[list[dict]],
    ) -> Optional[str]:
        """Call NeMo generate_async; return response string or None on hard error."""
        try:
            rails = self._get_rails()
            messages: list[dict] = list(conversation_history or [])
            messages.append({"role": self._user_role, "content": user_input})
            response: str = await rails.generate_async(messages=messages)
            return response
        except Exception as exc:
            if self._fail_open:
                # Return the error as the LLM response so output guards still run
                return f"[NeMo error: {exc}]"
            return None
