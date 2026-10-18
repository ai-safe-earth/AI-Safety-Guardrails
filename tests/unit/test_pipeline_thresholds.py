"""tests/unit/test_pipeline_thresholds.py
---------------------------------------
Opt-in demotion. With no thresholds the pipeline behaves as it always has; with
thresholds, a guard whose MEASURED Profile fails them does not run, and an unmeasured
guard keeps running because an empty Profile cannot fail anything.
"""

from __future__ import annotations

import asyncio

import pytest

from aisg.core.base import Action, CheckResult, GuardrailBase, GuardrailStage
from aisg.core.exceptions import GuardrailConfigError
from aisg.core.measurement import Profile, Thresholds
from aisg.core.pipeline import GuardrailPipeline


class _Blocker(GuardrailBase):
    name = "blocker"
    stage = GuardrailStage.INPUT

    async def check(self, content, context):
        return CheckResult(passed=False, action=Action.BLOCK, rejection_message="no")


class _NoisyBlocker(_Blocker):
    name = "noisy_blocker"
    profile = Profile(false_positive_rate=0.5, measured_on="unit test")


def test_without_thresholds_every_enabled_guard_runs():
    pipeline = GuardrailPipeline(input_guards=[_NoisyBlocker()])
    assert pipeline.thresholds is None and pipeline.demoted == []
    result = asyncio.run(pipeline.run_input("hi", {}))
    assert result.blocked


def test_measured_guard_over_threshold_is_demoted_and_announced(capsys):
    pipeline = GuardrailPipeline(
        input_guards=[_NoisyBlocker(), _Blocker()], thresholds=Thresholds()
    )
    assert pipeline.demoted == [("noisy_blocker", ["false-positive rate 0.500 > 0.05"])]
    assert "noisy_blocker demoted by thresholds" in capsys.readouterr().err
    result = asyncio.run(pipeline.run_input("hi", {}))
    assert result.blocked  # the unmeasured blocker still runs
    assert [c.metadata["guard_name"] for c in result.checks] == ["blocker"]


def test_unmeasured_guard_is_never_demoted():
    pipeline = GuardrailPipeline(
        input_guards=[_Blocker()], thresholds=Thresholds(max_p99_latency_ms=1)
    )
    assert pipeline.demoted == []
    assert asyncio.run(pipeline.run_input("hi", {})).blocked


def test_from_config_reads_the_thresholds_block(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(
        "pipeline:\n  thresholds:\n    max_p99_latency_ms: 25\n    max_usd_per_request: 0.001\n"
        "input:\n  pii_detector:\n    action: redact\n",
        encoding="utf-8",
    )
    pipeline = GuardrailPipeline.from_config(cfg)
    assert pipeline.thresholds == Thresholds(max_p99_latency_ms=25.0, max_usd_per_request=0.001)
    assert pipeline.demoted == []  # pii_detector ships unmeasured


def test_from_config_without_the_block_keeps_none(tmp_path):
    cfg = tmp_path / "p.yaml"
    cfg.write_text("input:\n  pii_detector: {}\n", encoding="utf-8")
    assert GuardrailPipeline.from_config(cfg).thresholds is None


@pytest.mark.parametrize(
    "block",
    [
        "  thresholds: 3\n",
        "  thresholds:\n    max_p99_latency: 25\n",
        "  thresholds:\n    max_p99_latency_ms: fast\n",
    ],
)
def test_from_config_refuses_a_malformed_thresholds_block(tmp_path, block):
    cfg = tmp_path / "p.yaml"
    cfg.write_text(f"pipeline:\n{block}input:\n  pii_detector: {{}}\n", encoding="utf-8")
    with pytest.raises(GuardrailConfigError):
        GuardrailPipeline.from_config(cfg)
