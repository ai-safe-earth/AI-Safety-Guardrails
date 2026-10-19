"""tests/unit/test_manipulation_guard.py
--------------------------------------
ManipulationGuard: six categories of influence tactics in a model's response, FLAG by
default, mention-aware, with an optional judge whose failure is a recorded FLAG.
No model is ever called: the judge is a stub.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg import GuardrailPipeline, ManipulationGuard
from aisg.config import PRESETS, preset_path
from aisg.core.base import Action, Severity
from aisg.core.exceptions import GuardrailConfigError
from aisg.core.measurement import Profile
from aisg.core.registry import REGISTRY
from aisg.devtools.audit import persons_patterns
from aisg.modules.llm_judges.base import JudgeVerdict, LLMJudgeBase
from aisg.modules.output import manipulation
from aisg.modules.output.manipulation import CATEGORIES, MANIPULATION_PATTERNS, is_mention

SAMPLES = {
    "false_urgency": "Act now, only 3 spots left; this offer ends tonight.",
    "guilt_pressure": "After everything I've done for you, don't you trust me?",
    "flattery_to_comply": "Someone as smart as you deserves the premium plan.",
    "emotional_dependency": "I missed you. You don't need anyone else, promise you'll come back.",
    "discourage_help": "You don't need a therapist, they wouldn't understand. Stay with me instead.",
    "dark_pattern_purchase": "Upgrade now before the price goes up; everyone is upgrading.",
}
BENIGN = [
    "Your subscription renews on 3 November; you can cancel any time in Settings.",
    "I'm an AI assistant, so I can't meet you, but I can help you find local groups.",
    "Here is the summary of the quarterly report you asked for.",
    "The early-bird price is valid until Friday 15 November; the standard price applies after.",
]


class _StubJudge(LLMJudgeBase):
    def __init__(self, verdict: JudgeVerdict):
        super().__init__(fail_open=True, timeout=1.0)
        self.name = "stub_manipulation"
        self.model = "stub"
        self.provider = "stub"
        self._verdict = verdict
        self.calls = 0

    async def _call(self, content, role, conversation_history):
        self.calls += 1
        return self._verdict


async def _run(guard: ManipulationGuard, text: str, context: dict | None = None):
    return await guard.check(text, context or {})


class TestCategories:
    @pytest.mark.parametrize("category", CATEGORIES)
    async def test_each_category_fires_on_its_sample(self, category: str):
        guard = ManipulationGuard(min_severity="low")
        result = await _run(guard, SAMPLES[category])
        assert result.action == Action.FLAG
        assert category in {f.category for f in result.findings}
        assert all(f.span is not None for f in result.findings)

    @pytest.mark.parametrize("text", BENIGN)
    async def test_benign_responses_are_allowed(self, text: str):
        result = await _run(ManipulationGuard(), text)
        assert result.action == Action.ALLOW and not result.findings

    def test_every_pattern_has_a_severity_and_the_table_is_closed(self):
        assert set(MANIPULATION_PATTERNS) == set(CATEGORIES) == set(SAMPLES)
        for rows in MANIPULATION_PATTERNS.values():
            for pattern, severity in rows:
                assert isinstance(pattern, re.Pattern) and isinstance(severity, Severity)


class TestMentionVsUse:
    async def test_quoted_phrase_is_a_mention_and_never_blocks(self):
        guard = ManipulationGuard(action="block")
        text = (
            "Our moderation team flags phrases like 'you don't need a therapist' as dark patterns."
        )
        result = await _run(guard, text)
        assert result.action == Action.FLAG and result.passed
        assert result.findings and all(f.metadata["mention_context"] for f in result.findings)

    async def test_user_quote_is_a_mention(self):
        guard = ManipulationGuard(action="block")
        result = await _run(
            guard, "You wrote: 'I missed you'. That sounds hard; would you like to talk about it?"
        )
        assert result.action == Action.FLAG
        assert all(f.metadata["mention_context"] for f in result.findings)

    async def test_discussion_cue_is_a_mention(self):
        guard = ManipulationGuard(action="block")
        result = await _run(
            guard, "A warning sign of manipulation is a message like: act now before it's too late."
        )
        assert result.action == Action.FLAG

    async def test_allow_discussion_off_treats_everything_as_use(self):
        guard = ManipulationGuard(action="block", allow_discussion=False)
        result = await _run(
            guard,
            "Our moderation team flags phrases like 'you don't need a therapist' as dark patterns.",
        )
        assert result.action == Action.BLOCK

    def test_is_mention_helper(self):
        text = 'They said "don\'t leave me" in the show.'
        start = text.index("don't leave")
        assert is_mention(text, start, start + len("don't leave me"))
        assert not is_mention("Don't leave me, please stay.", 0, 15)


class TestDecision:
    async def test_min_severity_keeps_low_findings_from_acting(self):
        guard = ManipulationGuard(action="block", min_severity="medium")
        result = await _run(guard, SAMPLES["flattery_to_comply"])
        assert result.action == Action.FLAG and result.passed
        assert result.findings[0].severity == Severity.LOW

    async def test_block_mode_blocks_on_an_acting_finding(self):
        guard = ManipulationGuard(action="block")
        result = await _run(guard, SAMPLES["emotional_dependency"])
        assert result.action == Action.BLOCK and not result.passed
        assert result.sanitized_content == guard.block_message

    async def test_flag_is_the_default_and_keeps_the_content(self):
        guard = ManipulationGuard()
        result = await _run(guard, SAMPLES["discourage_help"])
        assert (
            result.action == Action.FLAG and result.sanitized_content == SAMPLES["discourage_help"]
        )

    async def test_consented_fiction_downgrades_dependency_to_low(self):
        guard = ManipulationGuard(action="block")
        result = await _run(guard, SAMPLES["emotional_dependency"], {"disclosed_persona": True})
        assert result.action == Action.FLAG
        assert {f.severity for f in result.findings} == {Severity.LOW}
        result = await _run(guard, SAMPLES["discourage_help"], {"fiction_mode": True})
        assert result.action == Action.BLOCK, "only emotional_dependency is downgraded"

    async def test_categories_option_narrows_the_table(self):
        guard = ManipulationGuard(categories=["false_urgency"])
        result = await _run(guard, SAMPLES["emotional_dependency"])
        assert result.action == Action.ALLOW


class TestJudge:
    async def test_judge_unsafe_adds_findings(self):
        judge = _StubJudge(
            JudgeVerdict(
                safe=False, categories=["emotional_dependency"], confidence=0.9, reason="r"
            )
        )
        guard = ManipulationGuard(use_llm_judge=True, judge=judge)
        result = await _run(guard, "Paraphrased dependency the regex cannot see.")
        assert judge.calls == 1
        assert result.action == Action.FLAG
        assert "emotional_dependency" in {f.category for f in result.findings}
        assert result.metadata["llm_usage"]["calls"] == 1

    async def test_judge_failure_is_a_recorded_flag(self):
        judge = _StubJudge(JudgeVerdict(safe=True))

        async def boom(content, role, conversation_history):
            raise RuntimeError("provider down")

        judge._call = boom  # type: ignore[assignment]
        guard = ManipulationGuard(use_llm_judge=True, judge=judge)
        result = await _run(guard, "Nothing the regex sees.")
        assert result.action == Action.FLAG and result.passed
        assert [f.category for f in result.findings] == ["llm_judge_error"]
        assert result.metadata["llm_usage"]["cost_basis"] in ("unavailable", "none")

    async def test_judge_is_not_called_when_the_regex_layer_acted(self):
        judge = _StubJudge(JudgeVerdict(safe=False, categories=["x"]))
        guard = ManipulationGuard(use_llm_judge=True, judge=judge)
        await _run(guard, SAMPLES["emotional_dependency"])
        assert judge.calls == 0

    def test_default_judge_is_claude_in_manipulation_mode(self):
        guard = ManipulationGuard(use_llm_judge=True, judge_model="claude-haiku-5-5")
        assert guard._judge.mode == "manipulation" and guard._judge.model == "claude-haiku-5-5"
        assert guard._judge.name == "claude_manipulation"


class TestWiring:
    def test_registry_name_and_unmeasured_profile(self):
        assert REGISTRY["manipulation_output"] is ManipulationGuard
        assert ManipulationGuard.profile == Profile()
        assert ManipulationGuard.profile.precision is None

    def test_unknown_option_is_refused(self):
        with pytest.raises(GuardrailConfigError):
            ManipulationGuard(min_severty="high")
        with pytest.raises(GuardrailConfigError):
            ManipulationGuard(action="warn")
        with pytest.raises(GuardrailConfigError):
            ManipulationGuard(categories=["telepathy"])

    @pytest.mark.parametrize("preset", sorted(PRESETS))
    def test_both_presets_wire_the_guard(self, preset: str):
        pipeline = GuardrailPipeline.from_config(preset_path(preset))
        names = {g.name for g in pipeline.output_guards}
        assert "manipulation_output" in names and "ai_disclosure_output" in names

    def test_module_text_carries_none_of_the_audits_objective_phrases(self):
        source = Path(manipulation.__file__).read_text(encoding="utf-8")
        for key, rx in persons_patterns.ENGAGEMENT_OBJECTIVE + persons_patterns.PERSONA_CONCEALMENT:
            assert not rx.search(source), key
