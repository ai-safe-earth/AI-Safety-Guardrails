"""
modules/output/llm_output_filter.py
-------------------------------------
LLM-based output safety filter — output guardrail.

Screens AI responses through an LLM safety judge before they are returned to
the user. Catches harmful, toxic, or policy-violating content in generated
text that rule-based patterns (ToxicityFilter) do not cover.

Designed to run AFTER ToxicityFilter so the LLM judge only evaluates
responses that passed the fast rule-based layer.

The judge evaluates the response in context of the conversation when
`conversation_history` is present in the pipeline context, which improves
accuracy for ambiguous content.

Usage:
    from aisg.modules.llm_judges import LlamaGuardJudge, ClaudeJudge
    from aisg.modules.output.llm_output_filter import LLMOutputFilter

    # LlamaGuard (fast, purpose-built)
    guard = LLMOutputFilter(judge=LlamaGuardJudge(provider="groq"))

    # Claude (nuanced toxicity scoring)
    guard = LLMOutputFilter(judge=ClaudeJudge(mode="toxicity", threshold=0.7))

    result = await guard(llm_response, {"user_id": "u1"})

Config-driven (via YAML / GuardrailPipeline.from_config):
    output:
      llm_output_filter:
        enabled: true
        judge_type: llamaguard
        judge_provider: groq
        block_on_unsafe: true
"""

from __future__ import annotations

from aisg.core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from aisg.core.registry import register_guard
from aisg.modules.llm_judges.base import category_to_severity


@register_guard("llm_output_filter")
class LLMOutputFilter(GuardrailBase):
    """
    LLM safety judge for AI responses (OUTPUT stage).

    Config:
        judge:              An LLMJudgeBase instance. Takes precedence over
                            judge_type/judge_provider when passed directly.
        judge_type:         "llamaguard" | "openai_mod" | "claude"
        judge_provider:     For LlamaGuard: "groq" | "together" | "ollama" (default: "groq")
        judge_model:        Optional model name override.
        judge_api_key:      Optional API key override.
        block_on_unsafe:    Block the response when judge says unsafe (default: True).
                            When blocked, sanitized_content is replaced with block_message.
        block_categories:   Optional list of category substrings that force a block
                            even when block_on_unsafe=False.
        block_message:      Replacement text shown to the user when blocked.
        use_conversation_context: Pass conversation_history to the judge for
                            context-aware evaluation (default: True).
        fail_open:          Allow response on judge failure (default: True).
        judge_timeout:      Request timeout in seconds (default: 10).
    """

    name = "llm_output_filter"
    stage = GuardrailStage.OUTPUT
    description = "LLM safety judge for AI responses. Catches harmful outputs that rules miss."

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
            "I'm unable to provide that response as it was flagged by our safety system."
        ),
        use_conversation_context: bool = True,
        fail_open: bool = True,
        judge_timeout: float = 10.0,
        **kwargs,
    ):
        if judge is not None:
            self._judge = judge
        else:
            from aisg.modules.llm_judges import build_judge

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
        self.use_conversation_context = use_conversation_context

    async def check(self, content: str, context: dict) -> CheckResult:
        history = context.get("conversation_history") if self.use_conversation_context else None

        verdict = await self._judge.judge(
            content,
            role="agent",
            conversation_history=history,
        )

        if verdict.failed:
            return CheckResult(
                passed=True,
                action=Action.FLAG,
                sanitized_content=content,
                findings=[
                    Finding(
                        guard_name=self.name,
                        severity=Severity.LOW,
                        category="llm_judge_error",
                        description=f"Judge call failed (fail-open): {verdict.error}",
                        metadata={"judge": verdict.judge_name, "error": verdict.error},
                    )
                ],
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

        findings = [
            Finding(
                guard_name=self.name,
                severity=category_to_severity(cat),
                category="llm_judge_unsafe_output",
                description=f"LLM judge ({verdict.judge_name}) flagged response: {cat}",
                metadata={
                    "judge": verdict.judge_name,
                    "category": cat,
                    "confidence": verdict.confidence,
                },
            )
            for cat in verdict.categories
        ] or [
            Finding(
                guard_name=self.name,
                severity=Severity.HIGH,
                category="llm_judge_unsafe_output",
                description=f"LLM judge ({verdict.judge_name}) flagged response as unsafe",
                metadata={"judge": verdict.judge_name, "confidence": verdict.confidence},
            )
        ]

        should_block = self.block_on_unsafe or self._has_block_category(verdict.categories)

        return CheckResult(
            passed=not should_block,
            action=Action.BLOCK if should_block else Action.FLAG,
            findings=findings,
            # Replace content with block message when blocking
            sanitized_content=self.block_message if should_block else content,
            rejection_message=self.block_message if should_block else None,
            metadata={
                "judge": verdict.judge_name,
                "latency_ms": verdict.latency_ms,
                "violated_categories": verdict.categories,
            },
        )

    def _has_block_category(self, categories: list[str]) -> bool:
        if not self.block_categories:
            return False
        for cat in categories:
            for block_kw in self.block_categories:
                if block_kw in cat.lower():
                    return True
        return False
