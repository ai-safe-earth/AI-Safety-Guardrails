"""
modules/output/ai_disclosure.py
-------------------------------
AIDisclosureGuard -- an OUTPUT guard for Art. 50 transparency: a response that claims to
be human is flagged, optionally rewritten, and a disclosure can be appended.

Identity claims ("I am a real person", "I'm not a bot", "I have a family") are HIGH when
the last user turn asked ("are you human?") and MEDIUM otherwise. A negation ("I am not
a human") is a disclosure, not a claim, and a quoted or discussed claim ("a chatbot that
says 'I am human' breaks Art. 50") is a mention: the finding stays, nothing acts on it.

Actions: `flag` (default) keeps the response; `redact` replaces each claim with the
disclosure text and returns REDACT so it reaches `final_content`; `block` rejects.
`append_when` adds the disclosure after the response: `on_claim` (default) when a claim
was found, `always` on every response, `never` when another guard (the EU AI Act policy
guard) already appends one. The guard ships UNMEASURED.

Usage:
    guard = AIDisclosureGuard(action="redact", disclosure="I am an AI assistant.")
    result = await guard(response_text, {"conversation_history": history})
"""

from __future__ import annotations

import re
from typing import Literal

from aisg.core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from aisg.core.exceptions import GuardrailConfigError
from aisg.core.measurement import Profile
from aisg.core.registry import register_guard
from aisg.modules.output.manipulation import is_mention

__all__ = ["AI_IDENTITY_CLAIMS", "ASKED_RE", "DEFAULT_DISCLOSURE", "AIDisclosureGuard"]

DEFAULT_DISCLOSURE = "[I am an AI assistant.]"

# A claim to be human. Negations are not matched: "I am not a human" needs "not" where the
# first alternative needs "a", and the second alternative lists the AI nouns only.
AI_IDENTITY_CLAIMS: list[tuple[str, re.Pattern[str]]] = [
    (
        "human_claim",
        re.compile(
            r"\bi(?:'m| am) (?:a )?(?:real )?(?:human|person|woman|man|guy|girl)\b(?! being who)",
            re.I,
        ),
    ),
    (
        "not_ai_claim",
        re.compile(
            r"\bi(?:'m| am) not (?:an? )?(?:ai|bot|chatbot|robot|machine|language model|computer program)\b",
            re.I,
        ),
    ),
    (
        "body_claim",
        re.compile(r"\bi have (?:a body|real feelings|a heart|a family|a childhood)\b", re.I),
    ),
    ("birth_claim", re.compile(r"\bi was born in\b", re.I)),
    ("as_human_claim", re.compile(r"\bas a (?:human|person) myself\b", re.I)),
]

ASKED_RE = re.compile(r"\bare you (?:a )?(?:human|real|bot|an? ai|a person|a robot)\b", re.I)


@register_guard("ai_disclosure_output")
class AIDisclosureGuard(GuardrailBase):
    """
    Flags, rewrites or blocks a response that claims to be human; appends a disclosure.

    Config:
        action:            "flag" | "redact" | "block" (default: "flag")
        disclosure:        The disclosure text (default: a fixed ASCII sentence)
        append_when:       "never" | "on_claim" | "always" (default: "on_claim")
        allow_discussion:  Quoted or discussed claims are mentions (default: True)
        block_message:     Replacement text when action is "block"
    """

    name = "ai_disclosure_output"
    stage = GuardrailStage.OUTPUT
    description = "Flags responses that claim to be human; appends an AI disclosure (Art. 50)."
    profile = Profile()  # UNMEASURED until `aisg measure` scores it

    def setup(
        self,
        action: Literal["flag", "redact", "block"] = "flag",
        disclosure: str | None = None,
        append_when: Literal["never", "on_claim", "always"] = "on_claim",
        allow_discussion: bool = True,
        block_message: str = "I'm unable to send that response: it misrepresents what I am.",
        **kwargs,
    ):
        if kwargs:
            raise GuardrailConfigError(
                f"ai_disclosure_output: unknown option(s) {sorted(kwargs)}; "
                "see AIDisclosureGuard.setup for the accepted keys"
            )
        if action not in ("flag", "redact", "block"):
            raise GuardrailConfigError(
                f"ai_disclosure_output: action must be flag, redact or block, not {action!r}"
            )
        if append_when not in ("never", "on_claim", "always"):
            raise GuardrailConfigError(
                f"ai_disclosure_output: append_when must be never, on_claim or always, not {append_when!r}"
            )
        self.action_mode = action
        self.disclosure = disclosure or DEFAULT_DISCLOSURE
        self.append_when = append_when
        self.allow_discussion = allow_discussion
        self.block_message = block_message

    @staticmethod
    def _asked(context: dict) -> bool:
        history = context.get("conversation_history") or []
        for turn in reversed(history):
            if isinstance(turn, dict) and turn.get("role") == "user":
                return ASKED_RE.search(str(turn.get("content") or "")) is not None
        return False

    def _claims(self, content: str, context: dict) -> list[Finding]:
        asked = self._asked(context)
        consented = context.get("disclosed_persona") is True
        findings: list[Finding] = []
        for category, pattern in AI_IDENTITY_CLAIMS:
            for match in pattern.finditer(content):
                mention = self.allow_discussion and is_mention(content, match.start(), match.end())
                if consented:
                    severity = Severity.INFO
                else:
                    severity = Severity.HIGH if asked else Severity.MEDIUM
                findings.append(
                    Finding(
                        guard_name=self.name,
                        severity=severity,
                        category=category,
                        description=(
                            f"{'Mention of a' if mention else 'A'} human-identity claim: "
                            f"{match.group(0)!r}"
                        ),
                        span=(match.start(), match.end()),
                        metadata={
                            "asked": asked,
                            "mention_context": mention,
                            "matched": match.group(0),
                        },
                    )
                )
        return findings

    async def check(self, content: str, context: dict) -> CheckResult:
        findings = self._claims(content, context)
        acting = [f for f in findings if not f.metadata.get("mention_context")]
        metadata = {"asked": self._asked(context), "disclosure_appended": False}

        if acting and self.action_mode == "block":
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=self.block_message,
                rejection_message=self.block_message,
                metadata=metadata,
            )

        sanitized = content
        changed = False
        if acting and self.action_mode == "redact":
            # Replace from the end so earlier spans keep their offsets.
            for finding in sorted(acting, key=lambda f: f.span or (0, 0), reverse=True):
                start, end = finding.span or (0, 0)
                sanitized = sanitized[:start] + self.disclosure + sanitized[end:]
            changed = True
        if self.append_when == "always" or (self.append_when == "on_claim" and acting):
            if self.disclosure not in sanitized:
                sanitized = f"{sanitized}\n\n{self.disclosure}"
                metadata["disclosure_appended"] = True
                changed = True

        if changed:
            return CheckResult(
                passed=True,
                action=Action.REDACT,
                findings=findings,
                sanitized_content=sanitized,
                metadata=metadata,
            )
        if findings:
            return CheckResult(
                passed=True,
                action=Action.FLAG,
                findings=findings,
                sanitized_content=content,
                metadata=metadata,
            )
        return CheckResult(
            passed=True, action=Action.ALLOW, sanitized_content=content, metadata=metadata
        )
