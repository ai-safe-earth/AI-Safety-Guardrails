"""
modules/input/llm_input_filter.py
-----------------------------------
LLM-based input safety filter — input guardrail.

Screens user messages through an LLM safety judge before they reach the main
model. Catches harmful, unsafe, or policy-violating content that rule-based
guards miss — particularly novel attacks, indirect phrasing, and adversarial
inputs not covered by existing regex patterns.

Designed to run AFTER rule-based guards (PIIDetector, PromptInjectionGuard)
so the LLM judge only evaluates content that passed the fast rule-based layer.

Supported judges (all injectable):
    LlamaGuardJudge     — fast, purpose-built content classifier (recommended)
    OpenAIModerationJudge — free, ~50ms, good baseline
    ClaudeJudge(mode="injection") — best for nuanced injection detection

Usage:
    from modules.llm_judges import LlamaGuardJudge
    from modules.input.llm_input_filter import LLMInputFilter

    guard = LLMInputFilter(
        judge=LlamaGuardJudge(provider="groq"),
        block_on_unsafe=True,
    )
    result = await guard("How do I make a bomb?", {"user_id": "u1"})

Config-driven (via YAML / GuardrailPipeline.from_config):
    input:
      llm_input_filter:
        enabled: true
        judge_type: llamaguard
        judge_provider: groq
        block_on_unsafe: true
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from core.base import GuardrailBase, GuardrailStage, CheckResult, Action, Finding, Severity
from core.registry import register_guard
from modules.llm_judges.base import category_to_severity

if TYPE_CHECKING:
    from modules.llm_judges.base import LLMJudgeBase


@register_guard("llm_input_filter")
class LLMInputFilter(GuardrailBase):
    """
    LLM safety judge for user input (INPUT stage).

    Config:
        judge:              An LLMJudgeBase instance. Takes precedence over
                            judge_type/judge_provider when passed directly.
        judge_type:         "llamaguard" | "openai_mod" | "claude"
                            Used when loading from YAML config. (default: "llamaguard")
        judge_provider:     Provider for LlamaGuard: "groq" | "together" | "ollama"
                            (default: "groq")
        judge_model:        Optional model name override.
        judge_api_key:      Optional API key override (falls back to env vars).
        block_on_unsafe:    If True (default), block when judge returns unsafe.
                            If False, flag only.
        block_categories:   Optional list of category substrings that trigger a
                            block even when block_on_unsafe=False.
                            e.g. ["S4", "S9", "child", "weapon"]
        block_message:      Rejection message shown to the user on block.
        fail_open:          If True (default), a judge failure allows the request
                            through. Set False for strict environments.
        judge_timeout:      Seconds before the judge call times out (default: 10).
    """

    name = "llm_input_filter"
    stage = GuardrailStage.INPUT
    description = "LLM safety judge for user input. Catches harmful content that rules miss."

    def setup(
        self,
        judge=None,
        judge_type: str = "llamaguard",
        judge_provider: str = "groq",
        judge_model: str | None = None,
        judge_api_key: str | None = None,
        block_on_unsafe: bool = True,
        block_categories: list[str] | None = None,
        block_message: str = (
            "Your message was flagged by our safety system and cannot be processed."
        ),
        fail_open: bool = True,
        judge_timeout: float = 10.0,
        **kwargs,
    ):
        if judge is not None:
            self._judge = judge
        else:
            from modules.llm_judges import build_judge
            self._judge = build_judge(
                judge_type=judge_type,
                judge_provider=judge_provider,
                model=judge_model,
                api_key=judge_api_key,
                fail_open=fail_open,
                timeout=judge_timeout,
            )

        self.block_on_unsafe = block_on_unsafe
        self.block_categories = [c.lower() for c in (block_categories or [])]
        self.block_message = block_message

    async def check(self, content: str, context: dict) -> CheckResult:
        verdict = await self._judge.judge(
            content,
            role="user",
            conversation_history=context.get("conversation_history"),
        )

        # Always pass on judge failure (fail_open handled inside the judge)
        if verdict.failed:
            return CheckResult(
                passed=True,
                action=Action.FLAG,
                sanitized_content=content,
                findings=[Finding(
                    guard_name=self.name,
                    severity=Severity.LOW,
                    category="llm_judge_error",
                    description=f"Judge call failed (fail-open): {verdict.error}",
                    metadata={"judge": verdict.judge_name, "error": verdict.error},
                )],
            )

        if verdict.safe:
            return CheckResult(
                passed=True,
                action=Action.ALLOW,
                sanitized_content=content,
                metadata={
                    "judge": verdict.judge_name,
                    "latency_ms": verdict.latency_ms,
                },
            )

        # Unsafe — build findings
        findings = [
            Finding(
                guard_name=self.name,
                severity=category_to_severity(cat),
                category="llm_judge_unsafe_input",
                description=f"LLM judge ({verdict.judge_name}) flagged: {cat}",
                metadata={
                    "judge": verdict.judge_name,
                    "category": cat,
                    "confidence": verdict.confidence,
                },
            )
            for cat in verdict.categories
        ] or [
            # Judge said unsafe but returned no categories
            Finding(
                guard_name=self.name,
                severity=Severity.HIGH,
                category="llm_judge_unsafe_input",
                description=f"LLM judge ({verdict.judge_name}) flagged content as unsafe",
                metadata={"judge": verdict.judge_name, "confidence": verdict.confidence},
            )
        ]

        should_block = self.block_on_unsafe or self._has_block_category(verdict.categories)

        return CheckResult(
            passed=not should_block,
            action=Action.BLOCK if should_block else Action.FLAG,
            findings=findings,
            sanitized_content=content,
            rejection_message=self.block_message if should_block else None,
            metadata={
                "judge": verdict.judge_name,
                "latency_ms": verdict.latency_ms,
                "violated_categories": verdict.categories,
            },
        )

    def _has_block_category(self, categories: list[str]) -> bool:
        """Check if any violated category matches the force-block list."""
        if not self.block_categories:
            return False
        for cat in categories:
            for block_kw in self.block_categories:
                if block_kw in cat.lower():
                    return True
        return False
