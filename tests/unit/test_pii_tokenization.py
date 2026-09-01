"""
tests/unit/test_pii_tokenization.py
------------------------------------
Tests for PIIDetector(action="tokenize") and PIIRestorer.

The tokenize mode replaces PII with reversible tokens like <PII:EMAIL:1>
and stores the mapping in context["_pii_token_map"].  PIIRestorer reads
that map and swaps tokens back in the LLM output so the user sees originals.
"""

from __future__ import annotations

import pytest

from core.base import Action
from modules.input.pii_detector import PII_TOKEN_MAP_KEY, PIIDetector, PIIRestorer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_detector(**kwargs) -> PIIDetector:
    d = PIIDetector()
    d.setup(**kwargs)
    return d


def make_restorer() -> PIIRestorer:
    r = PIIRestorer()
    r.setup()
    return r


# ---------------------------------------------------------------------------
# PIIDetector — tokenize mode
# ---------------------------------------------------------------------------


class TestPIIDetectorTokenize:
    @pytest.mark.asyncio
    async def test_email_replaced_with_token(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check("Contact me at alice@example.com please.", context)
        assert result.action == Action.REDACT
        assert "alice@example.com" not in result.sanitized_content
        assert "<PII:EMAIL:1>" in result.sanitized_content

    @pytest.mark.asyncio
    async def test_token_map_written_to_context(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        await detector.check("alice@example.com", context)
        assert PII_TOKEN_MAP_KEY in context
        token_map = context[PII_TOKEN_MAP_KEY]
        assert "<PII:EMAIL:1>" in token_map
        assert token_map["<PII:EMAIL:1>"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_same_value_gets_same_token(self):
        """Two occurrences of the same email → single token reused."""
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check("alice@example.com and alice@example.com", context)
        token_map = context[PII_TOKEN_MAP_KEY]
        assert len(token_map) == 1
        assert result.sanitized_content == "<PII:EMAIL:1> and <PII:EMAIL:1>"

    @pytest.mark.asyncio
    async def test_different_values_get_different_tokens(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check("alice@example.com and bob@example.com", context)
        token_map = context[PII_TOKEN_MAP_KEY]
        assert len(token_map) == 2
        assert "<PII:EMAIL:1>" in result.sanitized_content
        assert "<PII:EMAIL:2>" in result.sanitized_content

    @pytest.mark.asyncio
    async def test_multiple_entity_types_tokenized(self):
        detector = make_detector(action="tokenize", entities=["EMAIL", "SSN"])
        context: dict = {}
        text = "Email: alice@example.com  SSN: 123-45-6789"
        result = await detector.check(text, context)
        token_map = context[PII_TOKEN_MAP_KEY]
        assert any("EMAIL" in k for k in token_map)
        assert any("SSN" in k for k in token_map)
        assert "alice@example.com" not in result.sanitized_content
        assert "123-45-6789" not in result.sanitized_content

    @pytest.mark.asyncio
    async def test_no_pii_passes_through(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check("Hello, how are you?", context)
        assert result.action == Action.ALLOW
        assert result.sanitized_content == "Hello, how are you?"
        # token map key not present or empty
        assert not context.get(PII_TOKEN_MAP_KEY)

    @pytest.mark.asyncio
    async def test_findings_include_tokenized_metadata(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check("alice@example.com", context)
        assert result.findings
        assert result.findings[0].metadata.get("tokenized") is True

    @pytest.mark.asyncio
    async def test_context_map_accumulates_across_calls(self):
        """Second call with the same context extends the token map."""
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        await detector.check("alice@example.com", context)
        await detector.check("bob@example.com", context)
        token_map = context[PII_TOKEN_MAP_KEY]
        originals = set(token_map.values())
        assert "alice@example.com" in originals
        assert "bob@example.com" in originals

    @pytest.mark.asyncio
    async def test_token_format_is_angle_bracket_pii_type_index(self):
        detector = make_detector(action="tokenize", entities=["SSN"])
        context: dict = {}
        await detector.check("SSN 123-45-6789", context)
        token_map = context[PII_TOKEN_MAP_KEY]
        token = list(token_map.keys())[0]
        assert token.startswith("<PII:SSN:")
        assert token.endswith(">")

    @pytest.mark.asyncio
    async def test_phone_tokenized(self):
        detector = make_detector(action="tokenize", entities=["PHONE_US"])
        context: dict = {}
        result = await detector.check("Call me at 555-867-5309", context)
        assert "555-867-5309" not in result.sanitized_content
        assert "<PII:PHONE_US:1>" in result.sanitized_content


# ---------------------------------------------------------------------------
# PIIRestorer — output guard
# ---------------------------------------------------------------------------


class TestPIIRestorer:
    @pytest.mark.asyncio
    async def test_restores_single_token(self):
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {"<PII:EMAIL:1>": "alice@example.com"}}
        result = await restorer.check("You can reach <PII:EMAIL:1> for support.", context)
        assert result.sanitized_content == "You can reach alice@example.com for support."

    @pytest.mark.asyncio
    async def test_restores_multiple_tokens(self):
        restorer = make_restorer()
        context = {
            PII_TOKEN_MAP_KEY: {
                "<PII:EMAIL:1>": "alice@example.com",
                "<PII:SSN:1>": "123-45-6789",
            }
        }
        result = await restorer.check("Email <PII:EMAIL:1>, SSN <PII:SSN:1>.", context)
        assert "alice@example.com" in result.sanitized_content
        assert "123-45-6789" in result.sanitized_content
        assert "<PII:" not in result.sanitized_content

    @pytest.mark.asyncio
    async def test_restores_repeated_token(self):
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {"<PII:EMAIL:1>": "alice@example.com"}}
        result = await restorer.check("<PII:EMAIL:1> sent to <PII:EMAIL:1>.", context)
        assert result.sanitized_content == "alice@example.com sent to alice@example.com."

    @pytest.mark.asyncio
    async def test_no_token_map_passes_through(self):
        restorer = make_restorer()
        context: dict = {}
        result = await restorer.check("Hello world", context)
        assert result.action == Action.ALLOW
        assert result.sanitized_content == "Hello world"

    @pytest.mark.asyncio
    async def test_empty_token_map_passes_through(self):
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {}}
        result = await restorer.check("Hello world", context)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_token_not_in_llm_output_is_ignored(self):
        """LLM may not echo every token; that's fine — no KeyError."""
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {"<PII:EMAIL:1>": "alice@example.com"}}
        result = await restorer.check("The answer is 42.", context)
        assert result.sanitized_content == "The answer is 42."

    @pytest.mark.asyncio
    async def test_action_redact_when_something_restored(self):
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {"<PII:EMAIL:1>": "alice@example.com"}}
        result = await restorer.check("<PII:EMAIL:1>", context)
        assert result.action == Action.REDACT

    @pytest.mark.asyncio
    async def test_action_allow_when_nothing_restored(self):
        restorer = make_restorer()
        context = {PII_TOKEN_MAP_KEY: {"<PII:EMAIL:1>": "alice@example.com"}}
        result = await restorer.check("No tokens here.", context)
        assert result.action == Action.ALLOW

    @pytest.mark.asyncio
    async def test_tokens_restored_metadata_count(self):
        restorer = make_restorer()
        context = {
            PII_TOKEN_MAP_KEY: {
                "<PII:EMAIL:1>": "alice@example.com",
                "<PII:SSN:1>": "123-45-6789",
            }
        }
        result = await restorer.check("<PII:EMAIL:1> only here.", context)
        assert result.metadata["tokens_restored"] == 1


# ---------------------------------------------------------------------------
# End-to-end: detector + restorer with shared context
# ---------------------------------------------------------------------------


class TestTokenizeEndToEnd:
    @pytest.mark.asyncio
    async def test_full_round_trip(self):
        """Simulate: user input → tokenize → LLM echoes token → restore."""
        detector = make_detector(action="tokenize", entities=["EMAIL", "SSN"])
        restorer = make_restorer()
        context: dict = {}

        # Input stage
        user_msg = "My email is alice@example.com and my SSN is 123-45-6789."
        input_result = await detector.check(user_msg, context)
        tokenized = input_result.sanitized_content

        assert "alice@example.com" not in tokenized
        assert "123-45-6789" not in tokenized

        # Simulate LLM echoing the tokens in its response
        # tokenized = "My email is <PII:EMAIL:1> and ..." → split()[3] is the email token
        llm_response = f"Got it. I'll contact you at {tokenized.split()[3]} shortly."

        # Output stage
        output_result = await restorer.check(llm_response, context)
        final = output_result.sanitized_content

        assert "alice@example.com" in final
        assert "<PII:" not in final

    @pytest.mark.asyncio
    async def test_redact_mode_is_permanent(self):
        """action='redact' should NOT populate the token map."""
        detector = make_detector(action="redact", entities=["EMAIL"])
        context: dict = {}
        await detector.check("alice@example.com", context)
        assert PII_TOKEN_MAP_KEY not in context

    @pytest.mark.asyncio
    async def test_tokenize_preserves_non_pii_text(self):
        detector = make_detector(action="tokenize", entities=["EMAIL"])
        context: dict = {}
        result = await detector.check(
            "Hello! My email is alice@example.com. Have a nice day.", context
        )
        assert "Hello!" in result.sanitized_content
        assert "Have a nice day." in result.sanitized_content

    @pytest.mark.asyncio
    async def test_restorer_registered_in_registry(self):
        from core.registry import REGISTRY

        assert "pii_restorer" in REGISTRY

    @pytest.mark.asyncio
    async def test_detector_tokenize_registered(self):
        from core.registry import REGISTRY

        assert "pii_detector" in REGISTRY
