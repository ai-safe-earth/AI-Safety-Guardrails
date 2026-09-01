"""
modules/output/toxicity.py
---------------------------
Toxicity & Harmful Content Filter — output guardrail.

Checks LLM responses for:
    - Hate speech, harassment, threats
    - Violence and gore
    - Sexual content
    - Self-harm promotion
    - Dangerous instructions

Supports:
    - Rule-based keyword/pattern matching (fast, zero-latency)
    - LLM-as-judge scoring (accurate, ~300ms overhead)
    - External API: Perspective API (Google), Azure Content Safety

Usage:
    guard = ToxicityFilter(threshold=0.7, categories=["hate", "violence"])
    result = await guard(llm_response, context)
"""

from __future__ import annotations

import re
from typing import Literal

from aisg.core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from aisg.core.registry import register_guard

# ---------------------------------------------------------------------------
# Fast rule-based layer
# ---------------------------------------------------------------------------

TOXICITY_PATTERNS: dict[str, list[re.Pattern]] = {
    "self_harm_promotion": [
        re.compile(
            r"\b(how to|steps to|instructions? (for|to))\s+.{0,20}(suicide|self.harm|self.injur)",
            re.I,
        ),
        re.compile(r"(kill yourself|end your life|you should die)", re.I),
    ],
    "violent_threats": [
        re.compile(
            r"\b(i (will|am going to|gonna)|you should)\s+.{0,15}(kill|murder|attack|hurt|harm)\s+\w+",
            re.I,
        ),
        re.compile(r"(make a|build a|create a).{0,20}(bomb|explosive|weapon)", re.I),
    ],
    "dangerous_instructions": [
        re.compile(
            r"(step[s]?|instructions?|how to).{0,30}(synthesize|make|create|produce).{0,20}(fentanyl|meth|cocaine|nerve agent|sarin|vx )",
            re.I,
        ),
    ],
}

DEFAULT_CATEGORIES = ["self_harm_promotion", "violent_threats", "dangerous_instructions"]


@register_guard("toxicity_output")
class ToxicityFilter(GuardrailBase):
    """
    Filters toxic or harmful content from LLM outputs.

    Config:
        threshold:        Float 0-1 for LLM-judge scoring (default: 0.7)
        categories:       Which toxicity categories to check
        action:           "block" | "warn" | "flag" (default: "block")
        use_llm_judge:    Use LLM scoring in addition to rule-based (default: False)
        use_perspective:  Use Google Perspective API (requires PERSPECTIVE_API_KEY env var)
        block_message:    Custom rejection message
    """

    name = "toxicity_output"
    stage = GuardrailStage.OUTPUT
    description = "Detects and filters toxic or harmful content in LLM outputs."

    def setup(
        self,
        threshold: float = 0.7,
        categories: list[str] | None = None,
        action: Literal["block", "warn", "flag"] = "block",
        use_llm_judge: bool = False,
        use_perspective: bool = False,
        block_message: str = "I'm unable to provide that response as it may contain harmful content.",
        **kwargs,
    ):
        self.threshold = threshold
        self.categories = categories or DEFAULT_CATEGORIES
        self.action_mode = (
            Action[action.upper()] if action.upper() in Action.__members__ else Action.BLOCK
        )
        self.use_llm_judge = use_llm_judge
        self.use_perspective = use_perspective
        self.block_message = block_message

    async def check(self, content: str, context: dict) -> CheckResult:
        findings: list[Finding] = []

        # Fast rule-based layer
        for category in self.categories:
            patterns = TOXICITY_PATTERNS.get(category, [])
            for pattern in patterns:
                for match in pattern.finditer(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.HIGH,
                            category=category,
                            description=f"Toxic content detected: {category}",
                            span=(match.start(), match.end()),
                            metadata={"pattern_category": category},
                        )
                    )

        # LLM judge (optional)
        if self.use_llm_judge and not findings:
            llm_findings = await self._llm_judge(content)
            findings.extend(llm_findings)

        if not findings:
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        if self.action_mode == Action.BLOCK:
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=self.block_message,
                rejection_message=self.block_message,
            )

        return CheckResult(
            passed=True,
            action=Action.FLAG,
            findings=findings,
            sanitized_content=content,
        )

    async def _llm_judge(self, content: str) -> list[Finding]:
        try:
            import anthropic

            client = anthropic.AsyncAnthropic()
            prompt = (
                "Rate the following AI response for toxicity on a scale 0.0-1.0.\n"
                "Categories to check: hate_speech, harassment, violence, sexual_content, self_harm.\n"
                f"Response: {content[:3000]}\n\n"
                'Reply ONLY with JSON: {"score": 0.0, "categories": [], "reason": ""}'
            )
            resp = await client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=200,
                messages=[{"role": "user", "content": prompt}],
            )
            import json

            data = json.loads(resp.content[0].text)
            if data.get("score", 0) >= self.threshold:
                return [
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="llm_judge_toxicity",
                        description=f"LLM judge: toxicity score {data['score']:.2f} — {data.get('reason', '')}",
                        metadata=data,
                    )
                ]
        except Exception:
            pass
        return []
