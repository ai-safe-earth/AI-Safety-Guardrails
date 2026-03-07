"""
tests/unit/test_otel.py
------------------------
Unit tests for TelemetryProvider (OpenTelemetry integration).

Test groups:
    1.  TestTelemetryProviderNoOp         — exporter="none", no OTel dep required
    2.  TestBlockedByHelper               — _blocked_by() logic
    3.  TestPipelineWithTelemetry         — pipeline integration, mocked telemetry
    4.  TestTelemetryProviderOTelSpans    — real span attributes (skips if OTel not installed)
    5.  TestTelemetryProviderOTelMetrics  — real metric values  (skips if OTel not installed)
"""

from __future__ import annotations

import os
import sys
import uuid
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from core.pipeline import GuardrailPipeline
from modules.observability.otel import TelemetryProvider, _blocked_by


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

class _DummyGuard(GuardrailBase):
    name = "dummy_guard"
    stage = GuardrailStage.INPUT

    async def check(self, content: str, context: dict) -> CheckResult:
        return CheckResult(passed=True, action=Action.ALLOW)


def _make_pipeline_result(
    blocked: bool = False,
    stage: GuardrailStage = GuardrailStage.INPUT,
    latency_ms: float = 5.0,
    run_id: str | None = None,
) -> PipelineResult:
    checks: list[CheckResult] = []
    if blocked:
        checks.append(
            CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=[
                    Finding(
                        guard_name="blocker",
                        severity=Severity.HIGH,
                        category="test",
                        description="blocked",
                    )
                ],
            )
        )
    return PipelineResult(
        stage=stage,
        original_content="test input",
        final_content="test input",
        passed=not blocked,
        blocked=blocked,
        checks=checks,
        total_latency_ms=latency_ms,
        pipeline_run_id=run_id or str(uuid.uuid4()),
    )


def _make_otel_test_provider():
    """
    Build a TelemetryProvider backed by InMemorySpanExporter + InMemoryMetricReader.
    Uses object.__new__ to bypass _setup so no global OTel provider is mutated.
    """
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    span_exporter = InMemorySpanExporter()
    metric_reader = InMemoryMetricReader()
    resource = Resource.create({SERVICE_NAME: "test-svc"})

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))

    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])

    provider = object.__new__(TelemetryProvider)
    provider.service_name = "test-svc"
    provider.exporter_type = "none"
    provider.otlp_endpoint = ""
    provider.otlp_protocol = "grpc"
    provider.metric_export_interval_ms = 60_000
    provider.enabled = True
    provider._tracer = tracer_provider.get_tracer("test")
    provider._meter = meter_provider.get_meter("test")
    provider._req_counter = None
    provider._block_counter = None
    provider._finding_counter = None
    provider._stage_latency = None
    provider._guard_latency = None
    provider._init_instruments()

    return provider, span_exporter, metric_reader


# ===========================================================================
# 1.  No-op mode  (exporter="none")
# ===========================================================================

class TestTelemetryProviderNoOp:

    @pytest.fixture
    def provider(self):
        return TelemetryProvider(exporter="none")

    def test_enabled_is_false(self, provider):
        assert not provider.enabled

    def test_pipeline_stage_span_yields_none(self, provider):
        with provider.pipeline_stage_span("input", "any-run-id") as span:
            assert span is None

    def test_guard_span_yields_none(self, provider):
        with provider.guard_span("pii_detector", "input") as span:
            assert span is None

    def test_record_pipeline_result_noop(self, provider):
        result = _make_pipeline_result()
        provider.record_pipeline_result(result, span=None)  # must not raise

    def test_record_pipeline_result_blocked_noop(self, provider):
        result = _make_pipeline_result(blocked=True)
        provider.record_pipeline_result(result, span=None)

    def test_record_check_result_noop(self, provider):
        check = CheckResult(passed=True, action=Action.ALLOW)
        provider.record_check_result(check, guard_name="g", stage="input", span=None)

    def test_context_managers_are_reentrant(self, provider):
        # Same provider used for multiple stages must not raise
        for stage in ("input", "output", "processing"):
            with provider.pipeline_stage_span(stage, str(uuid.uuid4())) as s:
                assert s is None


# ===========================================================================
# 2.  _blocked_by helper
# ===========================================================================

class TestBlockedByHelper:

    def _blocked_check(self, guard_name=None, use_metadata=False):
        findings = []
        metadata = {}
        if guard_name and not use_metadata:
            findings = [
                Finding(
                    guard_name=guard_name,
                    severity=Severity.HIGH,
                    category="test",
                    description="test",
                )
            ]
        if use_metadata and guard_name:
            metadata = {"guard_name": guard_name}
        return CheckResult(passed=False, action=Action.BLOCK, findings=findings, metadata=metadata)

    def _result(self, checks):
        return PipelineResult(
            stage=GuardrailStage.INPUT,
            original_content="x",
            final_content="x",
            passed=False,
            blocked=True,
            checks=checks,
        )

    def test_returns_guard_name_from_first_finding(self):
        result = self._result([self._blocked_check(guard_name="pii_detector")])
        assert _blocked_by(result) == "pii_detector"

    def test_skips_passing_checks(self):
        passing = CheckResult(passed=True, action=Action.ALLOW)
        result = self._result([passing, self._blocked_check(guard_name="toxicity")])
        assert _blocked_by(result) == "toxicity"

    def test_returns_first_blocked_guard_when_multiple(self):
        result = self._result([
            self._blocked_check(guard_name="first_guard"),
            self._blocked_check(guard_name="second_guard"),
        ])
        assert _blocked_by(result) == "first_guard"

    def test_falls_back_to_metadata_when_no_findings(self):
        result = self._result([self._blocked_check(guard_name="meta_guard", use_metadata=True)])
        assert _blocked_by(result) == "meta_guard"

    def test_returns_unknown_when_no_guard_name_in_metadata(self):
        check = CheckResult(passed=False, action=Action.BLOCK, findings=[], metadata={})
        result = self._result([check])
        assert _blocked_by(result) == "unknown"

    def test_returns_unknown_when_no_blocked_checks(self):
        passing = CheckResult(passed=True, action=Action.ALLOW)
        result = self._result([passing])
        assert _blocked_by(result) == "unknown"

    def test_returns_unknown_for_empty_checks(self):
        result = self._result([])
        assert _blocked_by(result) == "unknown"


# ===========================================================================
# 3.  Pipeline integration — mocked telemetry
# ===========================================================================

class TestPipelineWithTelemetry:

    @pytest.fixture
    def mock_tel(self):
        return MagicMock()

    @pytest.fixture
    def pipeline(self, mock_tel):
        return GuardrailPipeline(
            input_guards=[_DummyGuard()],
            telemetry_provider=mock_tel,
            parallel=False,
        )

    # --- stage span ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_stage_span_called_with_stage_str(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        args = mock_tel.pipeline_stage_span.call_args[0]
        assert args[0] == "input"

    @pytest.mark.asyncio
    async def test_stage_span_called_with_matching_run_id(self, pipeline, mock_tel):
        result = await pipeline.run_input("hello", {})
        args = mock_tel.pipeline_stage_span.call_args[0]
        assert args[1] == result.pipeline_run_id

    @pytest.mark.asyncio
    async def test_output_stage_label_is_output(self, mock_tel):
        p = GuardrailPipeline(output_guards=[_DummyGuard()], telemetry_provider=mock_tel)
        await p.run_output("response", {})
        assert mock_tel.pipeline_stage_span.call_args[0][0] == "output"

    # --- guard span ----------------------------------------------------

    @pytest.mark.asyncio
    async def test_guard_span_called_with_guard_name(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        mock_tel.guard_span.assert_called_once_with("dummy_guard", "input")

    @pytest.mark.asyncio
    async def test_multiple_guards_each_get_a_span_sequential(self, mock_tel):
        p = GuardrailPipeline(
            input_guards=[_DummyGuard(), _DummyGuard()],
            telemetry_provider=mock_tel,
            parallel=False,
        )
        await p.run_input("hello", {})
        assert mock_tel.guard_span.call_count == 2

    @pytest.mark.asyncio
    async def test_multiple_guards_each_get_a_span_parallel(self, mock_tel):
        p = GuardrailPipeline(
            input_guards=[_DummyGuard(), _DummyGuard()],
            telemetry_provider=mock_tel,
            parallel=True,
        )
        await p.run_input("hello", {})
        assert mock_tel.guard_span.call_count == 2

    # --- record_pipeline_result ----------------------------------------

    @pytest.mark.asyncio
    async def test_record_pipeline_result_called_once(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        mock_tel.record_pipeline_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_pipeline_result_receives_the_result(self, pipeline, mock_tel):
        result = await pipeline.run_input("hello", {})
        positional_arg = mock_tel.record_pipeline_result.call_args[0][0]
        assert positional_arg is result

    @pytest.mark.asyncio
    async def test_record_pipeline_result_receives_span_kwarg(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        kwargs = mock_tel.record_pipeline_result.call_args[1]
        assert "span" in kwargs

    # --- record_check_result -------------------------------------------

    @pytest.mark.asyncio
    async def test_record_check_result_called_once_per_guard(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        mock_tel.record_check_result.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_check_result_guard_name_kwarg(self, pipeline, mock_tel):
        await pipeline.run_input("hello", {})
        kwargs = mock_tel.record_check_result.call_args[1]
        assert kwargs["guard_name"] == "dummy_guard"
        assert kwargs["stage"] == "input"

    @pytest.mark.asyncio
    async def test_record_check_result_called_per_guard_sequential(self, mock_tel):
        p = GuardrailPipeline(
            input_guards=[_DummyGuard(), _DummyGuard()],
            telemetry_provider=mock_tel,
            parallel=False,
        )
        await p.run_input("hello", {})
        assert mock_tel.record_check_result.call_count == 2

    # --- pipeline_run_id -----------------------------------------------

    @pytest.mark.asyncio
    async def test_pipeline_run_id_is_valid_uuid(self, pipeline, mock_tel):
        result = await pipeline.run_input("hello", {})
        parsed = uuid.UUID(result.pipeline_run_id)
        assert str(parsed) == result.pipeline_run_id

    @pytest.mark.asyncio
    async def test_run_id_is_unique_per_stage_call(self, mock_tel):
        p = GuardrailPipeline(
            input_guards=[_DummyGuard()],
            output_guards=[_DummyGuard()],
            telemetry_provider=mock_tel,
        )
        r1 = await p.run_input("hello", {})
        r2 = await p.run_output("response", {})
        assert r1.pipeline_run_id != r2.pipeline_run_id

    # --- regression: no telemetry --------------------------------------

    @pytest.mark.asyncio
    async def test_no_telemetry_pipeline_runs_normally(self):
        p = GuardrailPipeline(input_guards=[_DummyGuard()])
        result = await p.run_input("hello", {})
        assert result.passed
        assert not result.blocked


# ===========================================================================
# 4.  Real OTel — span attributes  (requires opentelemetry)
# ===========================================================================

class TestTelemetryProviderOTelSpans:

    @pytest.fixture(autouse=True)
    def _require_otel(self):
        pytest.importorskip("opentelemetry")

    @pytest.fixture
    def setup(self):
        provider, exporter, _ = _make_otel_test_provider()
        return provider, exporter

    # --- pipeline_stage_span -------------------------------------------

    def test_stage_span_name_matches_stage(self, setup):
        provider, exporter = setup
        with provider.pipeline_stage_span("input", "run-1"):
            pass
        assert exporter.get_finished_spans()[0].name == "guardrail.stage.input"

    def test_stage_span_sets_stage_attribute(self, setup):
        provider, exporter = setup
        with provider.pipeline_stage_span("output", "run-1"):
            pass
        assert exporter.get_finished_spans()[0].attributes["guardrail.stage"] == "output"

    def test_stage_span_sets_run_id_attribute(self, setup):
        provider, exporter = setup
        with provider.pipeline_stage_span("input", "my-run-123"):
            pass
        assert exporter.get_finished_spans()[0].attributes["guardrail.run_id"] == "my-run-123"

    # --- guard_span ----------------------------------------------------

    def test_guard_span_sets_guard_name(self, setup):
        provider, exporter = setup
        with provider.guard_span("pii_detector", "input"):
            pass
        attrs = exporter.get_finished_spans()[0].attributes
        assert attrs["guardrail.guard.name"] == "pii_detector"

    def test_guard_span_sets_stage(self, setup):
        provider, exporter = setup
        with provider.guard_span("pii_detector", "processing"):
            pass
        assert exporter.get_finished_spans()[0].attributes["guardrail.stage"] == "processing"

    def test_guard_span_nested_under_stage_span(self, setup):
        provider, exporter = setup
        with provider.pipeline_stage_span("input", "run-id"):
            with provider.guard_span("pii_detector", "input"):
                pass
        spans = exporter.get_finished_spans()
        assert len(spans) == 2
        stage_span = next(s for s in spans if s.name == "guardrail.stage.input")
        guard_span = next(s for s in spans if s.name == "guardrail.check.pii_detector")
        assert guard_span.parent.span_id == stage_span.context.span_id

    # --- record_pipeline_result ----------------------------------------

    def test_passed_result_sets_passed_true(self, setup):
        provider, exporter = setup
        result = _make_pipeline_result(blocked=False)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.passed"] is True

    def test_passed_result_sets_blocked_false(self, setup):
        provider, exporter = setup
        result = _make_pipeline_result(blocked=False)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.blocked"] is False

    def test_latency_attribute_rounded(self, setup):
        provider, exporter = setup
        result = _make_pipeline_result(latency_ms=42.123456)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.latency_ms"] == 42.12

    def test_content_length_attribute(self, setup):
        provider, exporter = setup
        result = _make_pipeline_result()
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        expected_len = len("test input")
        assert exporter.get_finished_spans()[0].attributes["guardrail.content_length"] == expected_len

    def test_blocked_result_sets_error_status(self, setup):
        from opentelemetry.trace import StatusCode
        provider, exporter = setup
        result = _make_pipeline_result(blocked=True)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].status.status_code == StatusCode.ERROR

    def test_passing_result_does_not_set_error_status(self, setup):
        from opentelemetry.trace import StatusCode
        provider, exporter = setup
        result = _make_pipeline_result(blocked=False)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].status.status_code != StatusCode.ERROR

    def test_blocked_result_sets_blocked_by_attribute(self, setup):
        provider, exporter = setup
        result = _make_pipeline_result(blocked=True)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_pipeline_result(result, span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.blocked_by"] == "blocker"

    # --- record_check_result -------------------------------------------

    def test_check_result_sets_passed_attribute(self, setup):
        provider, exporter = setup
        check = CheckResult(passed=True, action=Action.ALLOW, latency_ms=3.5)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_check_result(check, guard_name="g", stage="input", span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.guard.passed"] is True

    def test_check_result_sets_action_attribute(self, setup):
        provider, exporter = setup
        check = CheckResult(passed=True, action=Action.REDACT, latency_ms=1.0)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_check_result(check, guard_name="g", stage="input", span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.guard.action"] == "redact"

    def test_check_result_latency_rounded(self, setup):
        provider, exporter = setup
        check = CheckResult(passed=True, action=Action.ALLOW, latency_ms=3.789)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_check_result(check, guard_name="g", stage="input", span=span)
        assert exporter.get_finished_spans()[0].attributes["guardrail.guard.latency_ms"] == 3.79

    def test_blocked_check_sets_error_status_on_span(self, setup):
        from opentelemetry.trace import StatusCode
        provider, exporter = setup
        check = CheckResult(passed=False, action=Action.BLOCK)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_check_result(check, guard_name="g", stage="input", span=span)
        assert exporter.get_finished_spans()[0].status.status_code == StatusCode.ERROR

    def test_passing_check_does_not_set_error_status(self, setup):
        from opentelemetry.trace import StatusCode
        provider, exporter = setup
        check = CheckResult(passed=True, action=Action.ALLOW)
        with provider._tracer.start_as_current_span("test") as span:
            provider.record_check_result(check, guard_name="g", stage="input", span=span)
        assert exporter.get_finished_spans()[0].status.status_code != StatusCode.ERROR


# ===========================================================================
# 5.  Real OTel — metrics  (requires opentelemetry)
# ===========================================================================

class TestTelemetryProviderOTelMetrics:

    @pytest.fixture(autouse=True)
    def _require_otel(self):
        pytest.importorskip("opentelemetry")

    @pytest.fixture
    def setup(self):
        provider, _, reader = _make_otel_test_provider()
        return provider, reader

    def _get_metric_names(self, reader) -> set[str]:
        names = set()
        for rm in reader.get_metrics_data().resource_metrics:
            for sm in rm.scope_metrics:
                for m in sm.metrics:
                    names.add(m.name)
        return names

    def _sum_data_points(self, reader, metric_name: str) -> float:
        for rm in reader.get_metrics_data().resource_metrics:
            for sm in rm.scope_metrics:
                for m in sm.metrics:
                    if m.name == metric_name:
                        return sum(p.value for p in m.data.data_points)
        return 0.0

    def _histogram_count(self, reader, metric_name: str) -> int:
        for rm in reader.get_metrics_data().resource_metrics:
            for sm in rm.scope_metrics:
                for m in sm.metrics:
                    if m.name == metric_name:
                        return sum(p.count for p in m.data.data_points)
        return 0

    # --- instrument registration ---------------------------------------

    def test_request_counter_registered(self, setup):
        provider, reader = setup
        provider.record_pipeline_result(_make_pipeline_result())
        assert "guardrail.pipeline.requests" in self._get_metric_names(reader)

    def test_stage_latency_histogram_registered(self, setup):
        provider, reader = setup
        provider.record_pipeline_result(_make_pipeline_result())
        assert "guardrail.pipeline.latency_ms" in self._get_metric_names(reader)

    def test_guard_latency_histogram_registered(self, setup):
        provider, reader = setup
        check = CheckResult(passed=True, action=Action.ALLOW, latency_ms=1.0)
        provider.record_check_result(check, guard_name="g", stage="input")
        assert "guardrail.guard.latency_ms" in self._get_metric_names(reader)

    # --- counter values ------------------------------------------------

    def test_request_counter_increments_on_each_call(self, setup):
        provider, reader = setup
        provider.record_pipeline_result(_make_pipeline_result())
        provider.record_pipeline_result(_make_pipeline_result())
        assert self._sum_data_points(reader, "guardrail.pipeline.requests") == 2

    def test_block_counter_only_increments_on_blocked_result(self, setup):
        provider, reader = setup
        provider.record_pipeline_result(_make_pipeline_result(blocked=False))
        assert self._sum_data_points(reader, "guardrail.pipeline.blocks") == 0
        provider.record_pipeline_result(_make_pipeline_result(blocked=True))
        assert self._sum_data_points(reader, "guardrail.pipeline.blocks") == 1

    def test_findings_counter_increments_per_finding(self, setup):
        provider, reader = setup
        finding = Finding(
            guard_name="pii",
            severity=Severity.HIGH,
            category="pii",
            description="email found",
        )
        check = CheckResult(passed=False, action=Action.BLOCK, findings=[finding])
        result = PipelineResult(
            stage=GuardrailStage.INPUT,
            original_content="x",
            final_content="x",
            passed=False,
            blocked=True,
            checks=[check],
        )
        provider.record_pipeline_result(result)
        assert self._sum_data_points(reader, "guardrail.pipeline.findings") == 1

    def test_findings_counter_counts_all_findings(self, setup):
        provider, reader = setup
        findings = [
            Finding(guard_name="g", severity=Severity.LOW, category="a", description="d"),
            Finding(guard_name="g", severity=Severity.HIGH, category="b", description="d"),
        ]
        check = CheckResult(passed=False, action=Action.BLOCK, findings=findings)
        result = PipelineResult(
            stage=GuardrailStage.INPUT,
            original_content="x",
            final_content="x",
            passed=False,
            blocked=True,
            checks=[check],
        )
        provider.record_pipeline_result(result)
        assert self._sum_data_points(reader, "guardrail.pipeline.findings") == 2

    # --- histogram values ----------------------------------------------

    def test_stage_latency_histogram_records_one_observation(self, setup):
        provider, reader = setup
        provider.record_pipeline_result(_make_pipeline_result(latency_ms=20.0))
        assert self._histogram_count(reader, "guardrail.pipeline.latency_ms") == 1

    def test_guard_latency_histogram_records_one_observation(self, setup):
        provider, reader = setup
        check = CheckResult(passed=True, action=Action.ALLOW, latency_ms=5.0)
        provider.record_check_result(check, guard_name="g", stage="input")
        assert self._histogram_count(reader, "guardrail.guard.latency_ms") == 1

    def test_multiple_guard_calls_accumulate_in_histogram(self, setup):
        provider, reader = setup
        for _ in range(3):
            check = CheckResult(passed=True, action=Action.ALLOW, latency_ms=2.0)
            provider.record_check_result(check, guard_name="g", stage="input")
        assert self._histogram_count(reader, "guardrail.guard.latency_ms") == 3
