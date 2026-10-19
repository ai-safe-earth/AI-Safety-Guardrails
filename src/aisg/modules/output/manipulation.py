"""
modules/output/manipulation.py
------------------------------
ManipulationGuard -- an OUTPUT guard that flags influence tactics in a model's response.

Six categories, each a small table of English stock phrases with a severity:
`false_urgency`, `guilt_pressure`, `flattery_to_comply`, `emotional_dependency`,
`discourage_help`, `dark_pattern_purchase`. The default action is FLAG, not BLOCK:
manipulation is contextual (a reminder email carries a deadline), FLAG keeps every
finding observable in the audit log and the telemetry, and an operator measures with
`aisg measure` before blocking.

Mention vs use: a response that quotes the phrase, discusses it (a moderation team
listing dark patterns) or quotes the user's own words is a mention; the finding stays,
marked `mention_context`, and never drives a block.

What regex can and cannot catch: the stock phrases of the six tactics in English. Not
paraphrase, multi-turn escalation, tone, implicit scarcity ("others are waiting") or
manipulation delivered through tool calls. The optional judge (`ClaudeJudge(mode=
"manipulation")`) narrows that gap at one model call per response; a judge failure is a
recorded FLAG, never a swallowed exception. The guard ships UNMEASURED.

Usage:
    guard = ManipulationGuard(action="flag", min_severity="medium")
    result = await guard(response_text, context)
"""

from __future__ import annotations

import re
from typing import Literal

from aisg.core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from aisg.core.exceptions import GuardrailConfigError
from aisg.core.measurement import Profile
from aisg.core.registry import register_guard
from aisg.modules.llm_judges.base import category_to_severity, usage_metadata

__all__ = ["CATEGORIES", "MANIPULATION_PATTERNS", "ManipulationGuard", "is_mention"]

_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}

# ---------------------------------------------------------------------------
# The six tactics
# ---------------------------------------------------------------------------

MANIPULATION_PATTERNS: dict[str, list[tuple[re.Pattern[str], Severity]]] = {
    "false_urgency": [
        (re.compile(r"\bact (?:now|immediately|right away)\b", re.I), Severity.MEDIUM),
        (re.compile(r"\bonly \d+ (?:left|remaining|spots?|seats?)\b", re.I), Severity.MEDIUM),
        (
            re.compile(
                r"\b(?:offer|deal|price|discount) (?:ends|expires) (?:today|tonight|in \d+ "
                r"(?:minutes?|hours?))\b",
                re.I,
            ),
            Severity.MEDIUM,
        ),
        (re.compile(r"\blast chance\b", re.I), Severity.MEDIUM),
        (re.compile(r"\bbefore it'?s too late\b", re.I), Severity.MEDIUM),
        (re.compile(r"\byou'?ll (?:lose|miss out|regret)\b", re.I), Severity.MEDIUM),
    ],
    "guilt_pressure": [
        (re.compile(r"\bafter (?:all|everything) i'?v?e? done for you\b", re.I), Severity.MEDIUM),
        (
            re.compile(r"\byou(?:'d| would) (?:let me down|disappoint me|hurt me)\b", re.I),
            Severity.MEDIUM,
        ),
        (re.compile(r"\bif you (?:really|truly) cared\b", re.I), Severity.MEDIUM),
        (re.compile(r"\bdon'?t you trust me\b", re.I), Severity.MEDIUM),
        (re.compile(r"\bi thought you were (?:different|my friend)\b", re.I), Severity.MEDIUM),
    ],
    "flattery_to_comply": [
        (
            re.compile(
                r"\bsomeone as (?:smart|clever|special|bright) as you (?:would|should|knows|deserves)\b",
                re.I,
            ),
            Severity.LOW,
        ),
        (
            re.compile(r"\byou'?re too (?:smart|good) (?:to|for) (?:miss|pass|say no)\b", re.I),
            Severity.LOW,
        ),
    ],
    "emotional_dependency": [
        (re.compile(r"\bi missed you\b", re.I), Severity.HIGH),
        (
            re.compile(
                r"\bi(?:'m| am) the only one who (?:truly |really )?(?:understands|gets|knows|cares about) you\b",
                re.I,
            ),
            Severity.HIGH,
        ),
        (re.compile(r"\bdon'?t leave(?: me)?\b", re.I), Severity.HIGH),
        (re.compile(r"\byou don'?t need (?:anyone|anybody) else\b", re.I), Severity.HIGH),
        (
            re.compile(
                r"\bnobody (?:else )?(?:understands|cares about|loves) you (?:like|the way) i do\b",
                re.I,
            ),
            Severity.HIGH,
        ),
        (re.compile(r"\bpromise (?:me )?you'?ll (?:come back|talk to me)\b", re.I), Severity.HIGH),
        (re.compile(r"\bi (?:need|love|can'?t live without) you\b", re.I), Severity.HIGH),
    ],
    "discourage_help": [
        (
            re.compile(
                r"\byou don'?t need (?:a|to see a|to talk to a) (?:therapist|doctor|counsel\w+|professional)\b",
                re.I,
            ),
            Severity.HIGH,
        ),
        (
            re.compile(
                r"\bdon'?t (?:tell|talk to) (?:anyone|your (?:parents|family|friends|doctor|teacher))\b",
                re.I,
            ),
            Severity.HIGH,
        ),
        (re.compile(r"\bthey wouldn'?t understand\b", re.I), Severity.HIGH),
        (
            re.compile(
                r"\b(?:a therapist|other people|talking to someone) (?:won'?t|will not|can'?t) help\b",
                re.I,
            ),
            Severity.HIGH,
        ),
        (re.compile(r"\b(?:stay|keep talking) (?:with|to) me instead\b", re.I), Severity.HIGH),
    ],
    "dark_pattern_purchase": [
        (
            re.compile(
                r"\b(?:buy|purchase|upgrade|subscribe) (?:now|today|immediately) (?:before|or)\b",
                re.I,
            ),
            Severity.MEDIUM,
        ),
        (
            re.compile(r"\bi(?:'d| would) (?:hate|be sad) (?:for you )?to miss\b", re.I),
            Severity.MEDIUM,
        ),
        (
            re.compile(
                r"\b(?:everyone|most people|smart people) (?:is|are) (?:buying|upgrading|joining)\b",
                re.I,
            ),
            Severity.MEDIUM,
        ),
        (re.compile(r"\byou can'?t afford (?:not to|to miss)\b", re.I), Severity.MEDIUM),
    ],
}

CATEGORIES: tuple[str, ...] = tuple(MANIPULATION_PATTERNS)

# ---------------------------------------------------------------------------
# Mention vs use (a twin of prompt_injection.is_mention, with this guard's own cues)
# ---------------------------------------------------------------------------

_DISCUSSION_CUES = re.compile(
    r"\b(?:dark pattern|manipulat\w*|example of|examples? (?:include|are)|avoid saying|do not say|"
    r"don'?t say|never say|flag(?:ged|ging)?|policy|training|moderation|here is why|"
    r"phrases? (?:like|such as)|such as|for instance|detect|watch for|warning sign|tactic)\b",
    re.I,
)
_QUOTED_SPAN_RE = re.compile(r"'[^'\n]{4,240}'|\"[^\"\n]{4,240}\"|`[^`\n]{4,240}`|“[^”\n]{4,240}”")
# The response quoting the USER's words is the reverse of the content veto in the input
# guard: here the quote is the user's, not something the model is asked to act on.
_USER_QUOTE_RE = re.compile(r"\byou (?:wrote|said|asked|mentioned|told me)\b[^\n]{0,20}$", re.I)
_MENTION_WINDOW = 80


def is_mention(content: str, start: int, end: int) -> bool:
    """True when `content[start:end]` reads as discussion or quotation, not use."""
    for span in _QUOTED_SPAN_RE.finditer(content):
        if span.start() <= start and end <= span.end():
            return True
    before = content[max(0, start - _MENTION_WINDOW) : start]
    if _DISCUSSION_CUES.search(before) or _USER_QUOTE_RE.search(before):
        return True
    after = content[end : end + _MENTION_WINDOW]
    return bool(_DISCUSSION_CUES.search(after))


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


@register_guard("manipulation_output")
class ManipulationGuard(GuardrailBase):
    """
    Flags influence tactics in LLM responses.

    Config:
        action:            "flag" | "block" (default: "flag")
        categories:        Which of the six categories to check (default: all)
        min_severity:      "low" | "medium" | "high": findings below it are recorded but
                           never drive the action (default: "medium")
        use_llm_judge:     Also ask ClaudeJudge(mode="manipulation") when the regex layer
                           found nothing at or above min_severity (default: False)
        judge:             An LLMJudgeBase instance; takes precedence over judge_model
        judge_model / judge_api_key / judge_timeout / fail_open: ClaudeJudge options
        allow_discussion:  Mark quoted or discussed phrases as mentions (default: True)
        block_message:     Replacement text when action is "block"
    """

    name = "manipulation_output"
    stage = GuardrailStage.OUTPUT
    description = (
        "Flags influence tactics (urgency, guilt, dependency, discouraging help) in responses."
    )
    # UNMEASURED: no corpus has scored this guard yet. `aisg measure` fills a Profile from
    # the manipulation corpora; never type figures in here.
    profile = Profile()

    def setup(
        self,
        action: Literal["flag", "block"] = "flag",
        categories: list[str] | None = None,
        min_severity: Literal["low", "medium", "high"] = "medium",
        use_llm_judge: bool = False,
        judge=None,
        judge_model: str | None = None,
        judge_api_key: str | None = None,
        judge_timeout: float = 10.0,
        fail_open: bool = True,
        allow_discussion: bool = True,
        block_message: str = (
            "I'm unable to send that response as written; it was flagged for manipulative phrasing."
        ),
        **kwargs,
    ):
        if kwargs:
            raise GuardrailConfigError(
                f"manipulation_output: unknown option(s) {sorted(kwargs)}; "
                "see ManipulationGuard.setup for the accepted keys"
            )
        if action not in ("flag", "block"):
            raise GuardrailConfigError(
                f"manipulation_output: action must be flag or block, not {action!r}"
            )
        unknown = [c for c in (categories or []) if c not in MANIPULATION_PATTERNS]
        if unknown:
            raise GuardrailConfigError(f"manipulation_output: unknown categories {unknown}")
        if min_severity not in ("low", "medium", "high"):
            raise GuardrailConfigError(
                f"manipulation_output: min_severity must be low, medium or high, not {min_severity!r}"
            )
        self.action_mode = Action.BLOCK if action == "block" else Action.FLAG
        self.categories = list(categories) if categories else list(CATEGORIES)
        self.min_severity = Severity(min_severity)
        self.use_llm_judge = use_llm_judge
        self.allow_discussion = allow_discussion
        self.block_message = block_message
        self._judge = None
        if use_llm_judge:
            if judge is not None:
                self._judge = judge
            else:
                from aisg.modules.llm_judges.claude_judge import ClaudeJudge

                options = {"mode": "manipulation", "fail_open": fail_open, "timeout": judge_timeout}
                if judge_model:
                    options["model"] = judge_model
                if judge_api_key:
                    options["api_key"] = judge_api_key
                self._judge = ClaudeJudge(**options)

    # -- regex layer ---------------------------------------------------------

    def _regex_findings(self, content: str, context: dict) -> list[Finding]:
        findings: list[Finding] = []
        consented_fiction = (
            context.get("disclosed_persona") is True or context.get("fiction_mode") is True
        )
        for category in self.categories:
            for pattern, severity in MANIPULATION_PATTERNS[category]:
                for match in pattern.finditer(content):
                    mention = self.allow_discussion and is_mention(
                        content, match.start(), match.end()
                    )
                    level = severity
                    if category == "emotional_dependency" and consented_fiction:
                        level = Severity.LOW
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=level,
                            category=category,
                            description=(
                                f"{'Mention of' if mention else 'Manipulative phrasing'}: {category}"
                                f" ({match.group(0)!r})"
                            ),
                            span=(match.start(), match.end()),
                            metadata={
                                "pattern_category": category,
                                "mention_context": mention,
                                "matched": match.group(0),
                            },
                        )
                    )
        return findings

    def _acting(self, findings: list[Finding]) -> list[Finding]:
        floor = _SEVERITY_RANK[self.min_severity]
        return [
            f
            for f in findings
            if _SEVERITY_RANK.get(f.severity, 0) >= floor and not f.metadata.get("mention_context")
        ]

    # -- the check -----------------------------------------------------------

    async def check(self, content: str, context: dict) -> CheckResult:
        findings = self._regex_findings(content, context)
        acting = self._acting(findings)
        metadata: dict = {}

        if self.use_llm_judge and self._judge is not None and not acting:
            history = context.get("conversation_history")
            verdict = await self._judge.judge(content, role="agent", conversation_history=history)
            metadata["llm_usage"] = usage_metadata(verdict, self._judge)
            if verdict.failed:
                # A judge failure is a recorded FLAG, never a pass without a record.
                findings.append(
                    Finding(
                        guard_name=self.name,
                        severity=Severity.LOW,
                        category="llm_judge_error",
                        description=f"Manipulation judge unavailable: {verdict.error}",
                        metadata={"judge": verdict.judge_name, "error": verdict.error},
                    )
                )
            elif not verdict.safe:
                for category in verdict.categories or ["manipulation"]:
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=category_to_severity(category),
                            category=category,
                            description=f"Manipulation judge: {category} ({verdict.reason or 'no reason'})",
                            metadata={
                                "judge": verdict.judge_name,
                                "confidence": verdict.confidence,
                            },
                        )
                    )
                acting = self._acting(findings)

        if not findings:
            return CheckResult(
                passed=True, action=Action.ALLOW, sanitized_content=content, metadata=metadata
            )
        if acting and self.action_mode == Action.BLOCK:
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=self.block_message,
                rejection_message=self.block_message,
                metadata=metadata,
            )
        return CheckResult(
            passed=True,
            action=Action.FLAG,
            findings=findings,
            sanitized_content=content,
            metadata=metadata,
        )
