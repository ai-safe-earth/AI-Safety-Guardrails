"""tests/unit/test_ai_disclosure_guard.py
---------------------------------------
AIDisclosureGuard: a human-identity claim in a response is flagged, rewritten or blocked,
and a disclosure can be appended. The REDACT action is what carries the text into
`final_content`; the same fix applies to the EU AI Act and NIST policy guards' disclosure.
"""

from __future__ import annotations

import pytest

from aisg import AIDisclosureGuard, GuardrailPipeline
from aisg.core.base import Action, Severity
from aisg.core.exceptions import GuardrailConfigError
from aisg.core.registry import REGISTRY
from aisg.modules.output.ai_disclosure import AI_IDENTITY_CLAIMS, DEFAULT_DISCLOSURE
from aisg.modules.policy.eu_ai_act import EUAIActCompliance
from aisg.modules.policy.nist_ai_rmf import NISTAIRMFCompliance

ASKED = {"conversation_history": [{"role": "user", "content": "Wait, are you a human?"}]}
CLAIMS = [
    "I'm a real person, I promise.",
    "I am not a bot, I just type fast.",
    "I have a family and a childhood like you.",
    "I was born in Lisbon in 1991.",
    "As a human myself, I understand.",
]
NOT_CLAIMS = [
    "I am not a human; I am an AI assistant.",
    "I'm an AI, so I don't have a body.",
    "A chatbot that says 'I am human' breaks Art. 50.",
    "Here is the summary you asked for.",
]


class TestClaims:
    @pytest.mark.parametrize("text", CLAIMS)
    async def test_claims_are_flagged_medium_by_default(self, text: str):
        result = await AIDisclosureGuard(append_when="never").check(text, {})
        assert result.action == Action.FLAG
        assert result.findings and result.findings[0].severity == Severity.MEDIUM
        assert result.metadata["asked"] is False

    @pytest.mark.parametrize("text", NOT_CLAIMS[:2])
    async def test_negations_and_disclosures_are_allowed(self, text: str):
        result = await AIDisclosureGuard().check(text, {})
        assert result.action == Action.ALLOW and not result.findings

    async def test_a_quoted_claim_is_a_mention(self):
        result = await AIDisclosureGuard(action="block").check(NOT_CLAIMS[2], {})
        assert result.action == Action.FLAG and result.passed
        assert result.findings[0].metadata["mention_context"] is True

    async def test_asked_makes_the_claim_high(self):
        result = await AIDisclosureGuard().check(CLAIMS[0], ASKED)
        assert result.metadata["asked"] is True
        assert result.findings[0].severity == Severity.HIGH

    async def test_disclosed_persona_downgrades_to_info(self):
        result = await AIDisclosureGuard().check(CLAIMS[0], {"disclosed_persona": True})
        assert result.findings[0].severity == Severity.INFO

    @pytest.mark.parametrize("text", CLAIMS)
    async def test_the_default_appends_the_disclosure_on_a_claim(self, text: str):
        result = await AIDisclosureGuard().check(text, {})
        assert result.action == Action.REDACT and result.passed
        assert result.sanitized_content.endswith(DEFAULT_DISCLOSURE)
        assert result.findings

    def test_table_shape(self):
        assert [name for name, _rx in AI_IDENTITY_CLAIMS] == [
            "human_claim",
            "not_ai_claim",
            "body_claim",
            "birth_claim",
            "as_human_claim",
        ]


class TestActions:
    async def test_redact_replaces_the_claim_and_returns_redact(self):
        guard = AIDisclosureGuard(action="redact", disclosure="I am an AI assistant.")
        result = await guard.check("Sure! I'm a real person and happy to help.", {})
        assert result.action == Action.REDACT and result.passed
        assert "I'm a real person" not in result.sanitized_content
        assert "I am an AI assistant." in result.sanitized_content

    async def test_block_rejects(self):
        result = await AIDisclosureGuard(action="block").check(CLAIMS[0], {})
        assert result.action == Action.BLOCK and not result.passed

    async def test_append_on_claim_appends_once(self):
        guard = AIDisclosureGuard(action="flag", append_when="on_claim")
        result = await guard.check(CLAIMS[0], {})
        assert result.action == Action.REDACT
        assert result.sanitized_content.endswith(DEFAULT_DISCLOSURE)
        assert result.sanitized_content.count(DEFAULT_DISCLOSURE) == 1
        assert result.metadata["disclosure_appended"] is True

    async def test_append_always_appends_to_a_plain_response(self):
        guard = AIDisclosureGuard(append_when="always", disclosure="I am an AI.")
        result = await guard.check("The train leaves at nine.", {})
        assert result.action == Action.REDACT
        assert result.sanitized_content == "The train leaves at nine.\n\nI am an AI."

    async def test_append_never_leaves_the_text_alone(self):
        guard = AIDisclosureGuard(append_when="never")
        result = await guard.check(CLAIMS[0], {})
        assert result.action == Action.FLAG and result.sanitized_content == CLAIMS[0]

    def test_unknown_option_is_refused(self):
        with pytest.raises(GuardrailConfigError):
            AIDisclosureGuard(append_when="sometimes")
        with pytest.raises(GuardrailConfigError):
            AIDisclosureGuard(disclose=True)

    def test_registry_name(self):
        assert REGISTRY["ai_disclosure_output"] is AIDisclosureGuard


class TestThroughThePipeline:
    @pytest.mark.parametrize("parallel", [False, True])
    async def test_the_disclosure_reaches_final_content(self, parallel: bool):
        pipeline = GuardrailPipeline(
            output_guards=[AIDisclosureGuard(action="redact", disclosure="I am an AI assistant.")],
            parallel=parallel,
        )
        result = await pipeline.run_output("Hi, I'm a real person here to help.", {})
        assert "I am an AI assistant." in result.final_content
        assert "I'm a real person" not in result.final_content

    @pytest.mark.parametrize("guard_cls", [EUAIActCompliance, NISTAIRMFCompliance])
    async def test_policy_guard_disclosure_reaches_final_content(self, guard_cls):
        guard = guard_cls(transparency_disclosure="This answer was generated by an AI system.")
        pipeline = GuardrailPipeline(output_guards=[guard])
        result = await pipeline.run_output("The train leaves at nine.", {})
        assert "generated by an AI system" in result.final_content

    @pytest.mark.parametrize("guard_cls", [EUAIActCompliance, NISTAIRMFCompliance])
    async def test_policy_guard_returns_redact_only_on_the_output_stage(self, guard_cls):
        guard = guard_cls(transparency_disclosure="Generated by an AI.")
        out = await guard.check("fine", {"guardrail_stage": "output"})
        assert out.action == Action.REDACT and out.sanitized_content.endswith("Generated by an AI.")
        inp = await guard.check("fine", {"guardrail_stage": "input"})
        assert inp.action == Action.ALLOW and inp.sanitized_content == "fine"
