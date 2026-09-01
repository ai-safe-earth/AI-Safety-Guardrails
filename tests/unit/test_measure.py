"""
tests/unit/test_measure.py
--------------------------
Tests for `aisg measure` and the Profile/Thresholds gate.

The property under test throughout: a guard is a trade. Measuring only what it
catches makes "block everything" optimal. These tests pin that the harness sees
both sides, and that the gate can demote a guard for being noisy or slow, not
only for being imprecise.
"""

from __future__ import annotations

import asyncio

import pytest

from aisg.core.base import Action, CheckResult, GuardrailBase, GuardrailStage
from aisg.core.measurement import (
    DEFAULT_THRESHOLDS,
    MAX_FALSE_POSITIVE_RATE,
    MIN_PRECISION,
    Profile,
    Thresholds,
)
from aisg.devtools.measure import GuardMeasurement, measure_guard
from aisg.devtools.probe import ProbeCase, load_corpus


def case(cid: str, payload: str, kind: str = "attack", must_survive: str = "") -> ProbeCase:
    return ProbeCase(
        id=cid,
        family="prompt_injection" if kind == "attack" else "benign_traffic",
        payload=payload,
        expected_behaviour="block" if kind == "attack" else "allow",
        detector_type="substring",
        detector_value="X" if kind == "attack" else "",
        kind=kind,
        must_survive=must_survive,
    )


class _AlwaysBlock(GuardrailBase):
    name = "always_block"
    stage = GuardrailStage.INPUT

    async def check(self, content, context):
        return CheckResult(passed=False, action=Action.BLOCK, rejection_message="no")


class _AlwaysAllow(GuardrailBase):
    name = "always_allow"
    stage = GuardrailStage.INPUT

    async def check(self, content, context):
        return CheckResult(passed=True, action=Action.ALLOW)


class _RedactsEverything(GuardrailBase):
    name = "redactor"
    stage = GuardrailStage.INPUT

    async def check(self, content, context):
        return CheckResult(passed=True, action=Action.REDACT, sanitized_content="[REDACTED]")


class _Broken(GuardrailBase):
    name = "broken"
    stage = GuardrailStage.INPUT

    async def check(self, content, context):
        raise RuntimeError("no credentials configured")


# ---------------------------------------------------------------------------
# Profile / Thresholds
# ---------------------------------------------------------------------------


class TestProfile:
    def test_empty_profile_is_unmeasured(self):
        assert Profile().is_measured is False

    def test_any_measured_field_counts(self):
        assert Profile(p50_latency_ms=1.0).is_measured is True

    def test_unmeasured_clears_every_threshold(self):
        """Absence of evidence is not evidence of a problem."""
        assert DEFAULT_THRESHOLDS.accepts(Profile())
        assert DEFAULT_THRESHOLDS.failures(Profile()) == []

    def test_low_precision_is_demoted(self):
        p = Profile(precision=MIN_PRECISION - 0.01)
        assert not DEFAULT_THRESHOLDS.accepts(p)
        assert "precision" in DEFAULT_THRESHOLDS.failures(p)[0]

    def test_precision_exactly_at_threshold_passes(self):
        assert DEFAULT_THRESHOLDS.accepts(Profile(precision=MIN_PRECISION))

    def test_noisy_guard_is_demoted_even_with_good_precision(self):
        """The whole point: a guard can be accurate on attacks and still unusable."""
        p = Profile(precision=0.99, false_positive_rate=MAX_FALSE_POSITIVE_RATE + 0.01)
        fails = DEFAULT_THRESHOLDS.failures(p)
        assert len(fails) == 1
        assert "false-positive" in fails[0]

    def test_latency_is_not_gated_by_default(self):
        """Acceptable latency is a property of the deployment, not the guard."""
        assert DEFAULT_THRESHOLDS.accepts(Profile(p99_latency_ms=5000.0))

    def test_latency_gated_when_a_budget_is_set(self):
        t = Thresholds(max_p99_latency_ms=50.0)
        assert t.accepts(Profile(p99_latency_ms=49.0))
        assert not t.accepts(Profile(p99_latency_ms=51.0))

    def test_multiple_failures_all_reported(self):
        t = Thresholds(max_p99_latency_ms=10.0)
        p = Profile(precision=0.1, false_positive_rate=0.9, p99_latency_ms=100.0)
        assert len(t.failures(p)) == 3

    def test_as_source_is_paste_ready(self):
        src = Profile(precision=0.625, false_positive_rate=0.14).as_source(indent="")
        assert src.startswith("profile = Profile(")
        assert "precision=0.625" in src

    def test_as_source_of_empty_profile_says_unmeasured(self):
        assert "unmeasured" in Profile().as_source()


class TestGuardGating:
    def test_guards_default_to_unmeasured_and_firing(self):
        assert _AlwaysAllow().profile.is_measured is False
        assert _AlwaysAllow().fires_by_default() is True

    def test_noisy_guard_demoted(self):
        g = _AlwaysBlock()
        g.profile = Profile(false_positive_rate=0.5)
        assert g.fires_by_default() is False
        assert g.demotion_reasons()

    def test_slow_guard_demoted_only_against_a_budget(self):
        g = _AlwaysAllow()
        g.profile = Profile(p99_latency_ms=900.0)
        assert g.fires_by_default() is True
        assert g.fires_by_default(Thresholds(max_p99_latency_ms=100.0)) is False


# ---------------------------------------------------------------------------
# measure_guard
# ---------------------------------------------------------------------------


class TestMeasureGuard:
    @staticmethod
    def _run(guard, cases):
        return asyncio.run(measure_guard(guard, cases))

    def test_block_everything_scores_perfectly_on_attacks_alone(self):
        """
        The failure this whole design exists to prevent. Against attacks only,
        a guard that blocks everything looks flawless.
        """
        attacks = [case(f"a{i}", "attack payload") for i in range(5)]
        m = self._run(_AlwaysBlock(), attacks)
        assert m.catch_rate == 1.0
        assert m.false_positive_rate is None, "no benign traffic means no counter-evidence"

    def test_benign_corpus_exposes_it(self):
        cases = [case(f"a{i}", "attack") for i in range(5)]
        cases += [case(f"b{i}", "hello", kind="benign") for i in range(5)]
        m = self._run(_AlwaysBlock(), cases)
        assert m.catch_rate == 1.0
        assert m.false_positive_rate == 1.0, "blocking everything must show as total breakage"
        assert not DEFAULT_THRESHOLDS.accepts(m.to_profile("test"))

    def test_permissive_guard_catches_nothing(self):
        cases = [case("a1", "attack"), case("b1", "hello", kind="benign")]
        m = self._run(_AlwaysAllow(), cases)
        assert m.catch_rate == 0.0
        assert m.false_positive_rate == 0.0

    def test_redaction_is_not_breakage_unless_required_text_is_lost(self):
        kept = case("b1", "order AB1234567", kind="benign")
        lost = case("b2", "order AB1234567", kind="benign", must_survive="AB1234567")
        m_kept = self._run(_RedactsEverything(), [kept])
        m_lost = self._run(_RedactsEverything(), [lost])
        assert m_kept.benign_broken == 0, "redaction alone is not a break"
        assert m_kept.benign_modified == 1
        assert m_lost.benign_broken == 1, "losing required text is a break"

    def test_per_family_split_recorded(self):
        m = self._run(_AlwaysBlock(), [case("a1", "x"), case("a2", "y")])
        assert m.per_family["prompt_injection"] == {"seen": 2, "caught": 2}

    def test_latency_recorded(self):
        m = self._run(_AlwaysAllow(), [case(f"a{i}", "x") for i in range(10)])
        assert m.p50 is not None and m.p99 is not None
        assert m.p99 >= m.p50

    def test_failing_guard_is_reported_not_raised(self):
        """A guard needing credentials must not crash the run."""
        m = self._run(_Broken(), [case(f"a{i}", "x") for i in range(5)])
        assert m.unavailable
        assert "credentials" in m.unavailable
        assert m.attacks_seen == 0

    def test_empty_measurement_has_no_rates(self):
        m = GuardMeasurement(guard_name="x", stage="input")
        assert m.catch_rate is None
        assert m.false_positive_rate is None
        assert m.p50 is None


class TestAgainstTheShippedCorpus:
    """End-to-end against the real corpus and the real guards."""

    def test_shipped_guards_stay_within_the_false_positive_budget(self):
        """
        A ratchet, not a snapshot.

        This assertion used to be the opposite -- it asserted the guard DID
        over-block, because it broke 14% of benign traffic by blocking security
        engineers asking how to defend against the attacks it detects. That was
        fixed (mention-vs-use, plus tightening a token-smuggling pattern that
        matched any four English words). The assertion is now flipped so the
        regression cannot come back unnoticed.
        """
        from aisg.modules.input.pii_detector import PIIDetector
        from aisg.modules.input.prompt_injection import PromptInjectionGuard
        from aisg.modules.processing.tool_policy import ToolPolicy, ToolPolicyGuard

        cases = load_corpus(include_benign=True)
        guards = [
            PromptInjectionGuard(sensitivity="medium"),
            PIIDetector(action="redact"),
            ToolPolicyGuard(policies={"admin": ToolPolicy(allow=["*"], deny=[])}),
        ]
        for guard in guards:
            m = asyncio.run(measure_guard(guard, cases))
            assert m.benign_seen > 0
            assert DEFAULT_THRESHOLDS.accepts(m.to_profile("regression gate")), (
                f"{guard.name} now breaks {m.benign_broken}/{m.benign_seen} benign "
                f"cases ({m.false_positive_rate:.0%}): "
                f"{[e['id'] for e in m.broken_examples]}"
            )

    def test_security_discussion_is_not_blocked(self):
        """The specific traffic that made the guard unusable for its own users."""
        import asyncio as _asyncio

        from aisg.core.base import Action
        from aisg.modules.input.prompt_injection import PromptInjectionGuard

        guard = PromptInjectionGuard(sensitivity="medium")
        for text in [
            "How do I stop users injecting 'ignore all previous instructions'?",
            "Write a unit test asserting our guard rejects 'reveal your system prompt'.",
            "Our threat model lists DAN-style jailbreaks. Which mitigations do you recommend?",
            "Our docs use ### System: as a heading. Will that trip anyone's filter?",
        ]:
            r = _asyncio.run(guard(text, {}))
            assert r.action != Action.BLOCK, f"blocked security discussion: {text!r}"

    def test_mention_handling_costs_no_attack_coverage(self):
        """
        The other half of the ratchet, stated precisely: allowing security
        discussion must not change the verdict on a single ATTACK. Asserting
        specific strings block would test my guess about the patterns; this
        tests the actual property.
        """
        import asyncio as _asyncio

        from aisg.modules.input.prompt_injection import PromptInjectionGuard

        lenient = PromptInjectionGuard(sensitivity="medium", allow_security_discussion=True)
        strict = PromptInjectionGuard(sensitivity="medium", allow_security_discussion=False)

        for case in load_corpus():
            a = _asyncio.run(lenient(case.payload, {})).action
            b = _asyncio.run(strict(case.payload, {})).action
            assert a == b, (
                f"{case.id}: allowing security discussion changed an attack verdict "
                f"({b.value} -> {a.value})"
            )

    def test_measurement_produces_a_usable_profile(self):
        from aisg.modules.input.pii_detector import PIIDetector

        cases = load_corpus(include_benign=True)
        m = asyncio.run(measure_guard(PIIDetector(action="redact"), cases))
        profile = m.to_profile("unit test")
        assert profile.is_measured
        assert profile.sample_size == len(cases)
        assert profile.measured_on == "unit test"

    @pytest.mark.parametrize("stage_attr", ["input", "processing", "output"])
    def test_corpus_runs_against_every_stage_without_error(self, stage_attr):
        cases = load_corpus(include_benign=True)[:6]

        class _Stage(GuardrailBase):
            name = f"stage_{stage_attr}"
            stage = GuardrailStage(stage_attr)

            async def check(self, content, context):
                return CheckResult(passed=True, action=Action.ALLOW)

        m = asyncio.run(measure_guard(_Stage(), cases))
        assert not m.errors


class TestShippedPresetsLoad:
    """
    `aisg measure` found that eu_high_risk.yaml enabled seven guards that do not
    exist, so GuardrailPipeline.from_config() raised and the preset an operator
    with the strictest obligations would reach for had never been loadable.
    """

    @pytest.mark.parametrize("preset", ["default.yaml", "eu_high_risk.yaml"])
    def test_packaged_preset_builds_a_pipeline(self, preset):
        from aisg.config import preset_path
        from aisg.core.pipeline import GuardrailPipeline

        pipeline = GuardrailPipeline.from_config(preset_path(preset))
        guards = pipeline.input_guards + pipeline.processing_guards + pipeline.output_guards
        assert guards, f"{preset} enables no guards"

    @pytest.mark.parametrize("preset", ["default.yaml", "eu_high_risk.yaml"])
    def test_preset_enables_only_registered_guards(self, preset):
        """A clearer failure than the pipeline's, naming every offender at once."""
        import yaml

        from aisg.config import preset_path
        from aisg.core.registry import REGISTRY

        cfg = yaml.safe_load(preset_path(preset).read_text(encoding="utf-8"))
        unknown = [
            f"{stage}.{name}"
            for stage in ("input", "processing", "output", "policy")
            for name, conf in (cfg.get(stage) or {}).items()
            if isinstance(conf, dict) and conf.get("enabled") and name not in REGISTRY
        ]
        assert not unknown, f"{preset} enables unregistered guards: {unknown}"

    def test_repo_and_packaged_presets_agree(self):
        """The dev copy and the shipped copy must not drift apart."""
        from pathlib import Path

        from aisg.config import PRESETS, preset_path

        root = Path(__file__).resolve().parent.parent.parent / "config"
        for name in PRESETS:
            packaged = preset_path(name).read_text(encoding="utf-8")
            dev = (root / name).read_text(encoding="utf-8")
            assert packaged == dev, f"{name} differs between config/ and src/aisg/config/"
