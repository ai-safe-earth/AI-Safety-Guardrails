"""
core/pipeline.py
----------------
GuardrailPipeline — the main orchestrator.
Runs input, processing, and output guardrails in order,
supporting parallel execution and configurable fail modes.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import uuid
from pathlib import Path

import yaml

from .base import (
    Action,
    CheckResult,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
)
from .exceptions import GuardrailBlockedError, GuardrailConfigError
from .registry import REGISTRY

_nullcontext = contextlib.nullcontext


class GuardrailPipeline:
    """
    Orchestrates a sequence of guardrail modules across pipeline stages.

    Usage:
        pipeline = GuardrailPipeline(
            input_guards=[PIIDetector(), PromptInjectionGuard()],
            output_guards=[ToxicityFilter(), PIIRedactor()],
            policy_guards=[EUAIActCompliance(risk_tier="high")],
        )

        # In your request handler:
        input_result = await pipeline.run_input(user_message, context={"user_id": uid})
        if input_result.blocked:
            return input_result.rejection_message

        llm_resp = await your_llm(input_result.sanitized_output)

        output_result = await pipeline.run_output(llm_resp, context={"user_id": uid})
        return output_result.sanitized_output
    """

    def __init__(
        self,
        input_guards: list[GuardrailBase] | None = None,
        processing_guards: list[GuardrailBase] | None = None,
        output_guards: list[GuardrailBase] | None = None,
        policy_guards: list[GuardrailBase] | None = None,
        *,
        parallel: bool = True,
        fail_open: bool = False,
        audit_logger=None,
        telemetry_provider=None,
        request_timeout: float | None = None,
    ):
        self.input_guards: list[GuardrailBase] = input_guards or []
        self.processing_guards: list[GuardrailBase] = processing_guards or []
        self.output_guards: list[GuardrailBase] = output_guards or []
        self.policy_guards: list[GuardrailBase] = policy_guards or []
        self.parallel = parallel
        self.fail_open = fail_open  # If True, errors in guardrails allow traffic through
        self._audit_logger = audit_logger
        self._telemetry = telemetry_provider
        self.request_timeout = request_timeout  # Per-request wall-clock timeout (seconds)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_input(self, content: str, context: dict | None = None) -> PipelineResult:
        """Run all input-stage guardrails + policy guards."""
        guards = self.input_guards + self.policy_guards
        return await self._run_stage(GuardrailStage.INPUT, content, guards, context)

    async def run_processing(
        self,
        content: str,
        context: dict | None = None,
        tool_call: dict | None = None,
    ) -> PipelineResult:
        """
        Run processing-stage guardrails (tool policies, context controls).
        Pass the tool_call dict for tool-policy checks.
        """
        ctx = {**(context or {}), "tool_call": tool_call or {}}
        return await self._run_stage(
            GuardrailStage.PROCESSING, content, self.processing_guards, ctx
        )

    async def run_output(self, content: str, context: dict | None = None) -> PipelineResult:
        """Run all output-stage guardrails."""
        return await self._run_stage(GuardrailStage.OUTPUT, content, self.output_guards, context)

    async def run_full(
        self,
        user_input: str,
        llm_callable,
        context: dict | None = None,
    ) -> PipelineResult:
        """
        Convenience method: run input guards, call llm_callable, run output guards.

        Args:
            user_input:     The raw user message.
            llm_callable:   async callable(sanitized_input: str) -> str
            context:        Runtime context dict.

        Returns:
            PipelineResult from the output stage.

        Raises:
            GuardrailBlockedError if input or output is blocked.
        """
        # 1. Input
        input_result = await self.run_input(user_input, context)
        if input_result.blocked:
            raise GuardrailBlockedError(
                stage="input",
                message=input_result.rejection_message or "Request blocked by safety guardrails.",
                result=input_result,
            )

        # 2. LLM call — with optional wall-clock timeout
        try:
            if self.request_timeout:
                llm_response = await asyncio.wait_for(
                    llm_callable(input_result.sanitized_output),
                    timeout=self.request_timeout,
                )
            else:
                llm_response = await llm_callable(input_result.sanitized_output)
        except asyncio.TimeoutError:
            raise GuardrailBlockedError(
                stage="llm",
                message=f"LLM call timed out after {self.request_timeout}s.",
                result=input_result,
            )

        # 3. Output
        output_result = await self.run_output(llm_response, context)
        if output_result.blocked:
            raise GuardrailBlockedError(
                stage="output",
                message=output_result.rejection_message or "Response blocked by safety guardrails.",
                result=output_result,
            )

        return output_result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_guard(
        self,
        guard: GuardrailBase,
        content: str,
        ctx: dict,
        stage_str: str,
    ) -> CheckResult:
        """Run one guard, wrapped in an OTel child span when telemetry is active."""
        if self._telemetry:
            with self._telemetry.guard_span(guard.name, stage_str) as span:
                result = await guard(content, ctx)
                self._telemetry.record_check_result(
                    result, guard_name=guard.name, stage=stage_str, span=span
                )
                return result
        return await guard(content, ctx)

    async def _run_stage(
        self,
        stage: GuardrailStage,
        content: str,
        guards: list[GuardrailBase],
        context: dict | None,
    ) -> PipelineResult:
        ctx = context or {}
        ctx["guardrail_stage"] = (
            stage.value
        )  # consumed by eu_ai_act, nist_ai_rmf transparency logic
        stage_str = stage.value
        run_id = str(uuid.uuid4())

        start = time.perf_counter()
        current_content = content
        checks: list[CheckResult] = []
        blocked = False
        rejection_message = None

        enabled_guards = [g for g in guards if g.enabled]

        with (
            self._telemetry.pipeline_stage_span(stage_str, run_id)
            if self._telemetry
            else _nullcontext()
        ) as stage_span:
            if self.parallel and stage != GuardrailStage.PROCESSING:
                # Run all checks in parallel on the original content
                tasks = [
                    self._run_guard(guard, current_content, ctx, stage_str)
                    for guard in enabled_guards
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for guard, result in zip(enabled_guards, results):
                    if isinstance(result, Exception):
                        if self.fail_open:
                            continue
                        raise result
                    checks.append(result)
                    # Apply redaction in order after all checks complete
                    if result.action == Action.REDACT and result.sanitized_content:
                        current_content = result.sanitized_content
                    elif result.action == Action.BLOCK:
                        blocked = True
                        rejection_message = result.rejection_message or f"Blocked by {guard.name}."
            else:
                # Sequential — each guard sees the output of the previous (important for redaction chains)
                for guard in enabled_guards:
                    try:
                        result = await self._run_guard(guard, current_content, ctx, stage_str)
                    except Exception:
                        if self.fail_open:
                            continue
                        raise

                    checks.append(result)

                    if result.action == Action.REDACT and result.sanitized_content:
                        current_content = result.sanitized_content
                    elif result.action == Action.BLOCK:
                        blocked = True
                        rejection_message = result.rejection_message or f"Blocked by {guard.name}."
                        break  # Stop processing on first block

            total_ms = (time.perf_counter() - start) * 1000

            pipeline_result = PipelineResult(
                stage=stage,
                original_content=content,
                final_content=current_content,
                passed=not blocked,
                blocked=blocked,
                checks=checks,
                rejection_message=rejection_message,
                total_latency_ms=total_ms,
                pipeline_run_id=run_id,
            )

            if self._telemetry:
                self._telemetry.record_pipeline_result(pipeline_result, span=stage_span)

        if self._audit_logger:
            await self._audit_logger.log(pipeline_result, ctx)

        return pipeline_result

    # ------------------------------------------------------------------
    # Config loading
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config_path: str | Path) -> "GuardrailPipeline":
        """
        Load a pipeline from a YAML config file.

        Example config: see config/default.yaml
        """
        path = Path(config_path)
        if not path.exists():
            raise GuardrailConfigError(f"Config file not found: {path}")

        with open(path) as f:
            cfg = yaml.safe_load(f)

        pipeline_cfg = cfg.get("pipeline", {})
        parallel = pipeline_cfg.get("parallel_checks", True)
        fail_open = pipeline_cfg.get("fail_open", False)
        request_timeout_raw = pipeline_cfg.get("request_timeout", 0)
        request_timeout = float(request_timeout_raw) if request_timeout_raw else None

        def build_guards(stage_key: str) -> list[GuardrailBase]:
            stage_cfg = cfg.get(stage_key)
            if not stage_cfg:
                return []
            if not isinstance(stage_cfg, dict):
                raise GuardrailConfigError(
                    f"Config section '{stage_key}' must be a mapping, "
                    f"got {type(stage_cfg).__name__}."
                )
            guards = []
            for module_name, module_cfg in stage_cfg.items():
                # Allow bare `module_name:` with no sub-keys (treat as enabled, no args)
                module_cfg = module_cfg or {}
                if not isinstance(module_cfg, dict):
                    raise GuardrailConfigError(
                        f"Config for module '{module_name}' must be a mapping, "
                        f"got {type(module_cfg).__name__}."
                    )
                if not module_cfg.get("enabled", True):
                    continue
                guard_cls = REGISTRY.get(module_name)
                if guard_cls is None:
                    raise GuardrailConfigError(
                        f"Unknown guardrail module '{module_name}' in [{stage_key}]. "
                        f"Registered modules: {sorted(REGISTRY.keys())}"
                    )
                guards.append(guard_cls(**{k: v for k, v in module_cfg.items() if k != "enabled"}))
            return guards

        return cls(
            input_guards=build_guards("input"),
            processing_guards=build_guards("processing"),
            output_guards=build_guards("output"),
            policy_guards=build_guards("policy"),
            parallel=parallel,
            fail_open=fail_open,
            request_timeout=request_timeout,
        )
