"""
core/pipeline.py
----------------
GuardrailPipeline — the main orchestrator.
Runs input, processing, and output guardrails in order,
supporting parallel execution and configurable fail modes.
"""

from __future__ import annotations

import asyncio
import time
import yaml
from pathlib import Path
from typing import Optional

from .base import (
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    CheckResult,
    Action,
    Severity,
)
from .exceptions import GuardrailConfigError, GuardrailBlockedError
from .registry import REGISTRY


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
    ):
        self.input_guards: list[GuardrailBase] = input_guards or []
        self.processing_guards: list[GuardrailBase] = processing_guards or []
        self.output_guards: list[GuardrailBase] = output_guards or []
        self.policy_guards: list[GuardrailBase] = policy_guards or []
        self.parallel = parallel
        self.fail_open = fail_open       # If True, errors in guardrails allow traffic through
        self._audit_logger = audit_logger

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
        return await self._run_stage(GuardrailStage.PROCESSING, content, self.processing_guards, ctx)

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

        # 2. LLM call
        llm_response = await llm_callable(input_result.sanitized_output)

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

    async def _run_stage(
        self,
        stage: GuardrailStage,
        content: str,
        guards: list[GuardrailBase],
        context: dict | None,
    ) -> PipelineResult:
        ctx = context or {}
        start = time.perf_counter()
        current_content = content
        checks: list[CheckResult] = []
        blocked = False
        rejection_message = None

        enabled_guards = [g for g in guards if g.enabled]

        if self.parallel and stage != GuardrailStage.PROCESSING:
            # Run all checks in parallel on the original content
            tasks = [guard(current_content, ctx) for guard in enabled_guards]
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
                    result = await guard(current_content, ctx)
                except Exception as e:
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
        )

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

        def build_guards(stage_key: str) -> list[GuardrailBase]:
            guards = []
            for module_name, module_cfg in cfg.get(stage_key, {}).items():
                if not module_cfg.get("enabled", True):
                    continue
                guard_cls = REGISTRY.get(module_name)
                if guard_cls is None:
                    raise GuardrailConfigError(
                        f"Unknown guardrail module: '{module_name}'. "
                        f"Available: {list(REGISTRY.keys())}"
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
        )
