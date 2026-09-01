"""
modules/observability/otel.py
------------------------------
OpenTelemetry tracing and metrics for the AI Safety Guardrails pipeline.

Provides:
    - A span per pipeline stage  (guardrail.stage.<stage>)
    - A child span per guard     (guardrail.check.<guard_name>)
    - Metrics:
        guardrail.pipeline.requests   counter   (stage, passed)
        guardrail.pipeline.blocks     counter   (stage, blocked_by)
        guardrail.pipeline.findings   counter   (stage, category, severity)
        guardrail.pipeline.latency_ms histogram (stage)
        guardrail.guard.latency_ms    histogram (guard_name, stage, action)

Exporters:
    "console"  → stdout JSON  (development / smoke-testing)
    "otlp"     → OTLP gRPC or HTTP (Jaeger, Zipkin, Datadog, Honeycomb, ...)
    "none"     → no-op

Install:
    pip install "ai-safety-guardrails[otel]"
    # OTLP gRPC:  pip install opentelemetry-exporter-otlp-proto-grpc
    # OTLP HTTP:  pip install opentelemetry-exporter-otlp-proto-http

Usage:
    from aisg.modules.observability.otel import TelemetryProvider

    telemetry = TelemetryProvider(
        service_name="my-ai-system",
        exporter="otlp",
        otlp_endpoint="http://localhost:4317",
    )
    pipeline = GuardrailPipeline(..., telemetry_provider=telemetry)
"""

from __future__ import annotations

import contextlib
import sys
from typing import TYPE_CHECKING, Generator, Optional

if TYPE_CHECKING:
    from aisg.core.base import CheckResult, PipelineResult

try:
    from opentelemetry import metrics as otel_metrics
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.trace import StatusCode

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    StatusCode = None  # type: ignore[assignment]


class TelemetryProvider:
    """
    OpenTelemetry provider for the AI Safety Guardrails pipeline.

    Configures a TracerProvider and MeterProvider once, then exposes
    context-manager helpers that pipeline.py uses to wrap each stage
    and each individual guard check.

    All methods degrade gracefully to no-ops when opentelemetry-sdk is
    not installed or when exporter="none".
    """

    def __init__(
        self,
        service_name: str = "ai-safety-guardrails",
        exporter: str = "console",  # "otlp" | "console" | "none"
        otlp_endpoint: str = "http://localhost:4317",
        otlp_protocol: str = "grpc",  # "grpc" | "http"
        metric_export_interval_ms: int = 60_000,
        enabled: bool = True,
    ):
        self.service_name = service_name
        self.exporter_type = exporter
        self.otlp_endpoint = otlp_endpoint
        self.otlp_protocol = otlp_protocol
        self.metric_export_interval_ms = metric_export_interval_ms
        self.enabled = enabled and _OTEL_AVAILABLE and exporter != "none"

        self._tracer = None
        self._meter = None
        # Metric instruments — populated by _init_instruments()
        self._req_counter = None
        self._block_counter = None
        self._finding_counter = None
        self._stage_latency = None
        self._guard_latency = None

        if self.enabled:
            self._setup()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup(self) -> None:
        resource = Resource.create({SERVICE_NAME: self.service_name})
        self._setup_tracer(resource)
        self._setup_meter(resource)
        self._init_instruments()

    def _setup_tracer(self, resource) -> None:
        provider = TracerProvider(resource=resource)
        exporter = self._build_span_exporter()
        if exporter is not None:
            provider.add_span_processor(BatchSpanProcessor(exporter))
        otel_trace.set_tracer_provider(provider)
        self._tracer = otel_trace.get_tracer(__name__)

    def _setup_meter(self, resource) -> None:
        reader = self._build_metric_reader()
        if reader is not None:
            provider = MeterProvider(resource=resource, metric_readers=[reader])
        else:
            provider = MeterProvider(resource=resource)
        otel_metrics.set_meter_provider(provider)
        self._meter = otel_metrics.get_meter(__name__)

    def _build_span_exporter(self):
        if self.exporter_type == "console":
            return ConsoleSpanExporter()
        if self.exporter_type == "otlp":
            try:
                if self.otlp_protocol == "http":
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )
                else:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )
                return OTLPSpanExporter(endpoint=self.otlp_endpoint)
            except ImportError:
                print(
                    "[TelemetryProvider] OTLP span exporter not installed. "
                    "Run: pip install opentelemetry-exporter-otlp-proto-grpc  "
                    "(or -http). Falling back to console exporter.",
                    file=sys.stderr,
                )
                return ConsoleSpanExporter()
        return None

    def _build_metric_reader(self):
        if self.exporter_type == "console":
            return PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=self.metric_export_interval_ms,
            )
        if self.exporter_type == "otlp":
            try:
                if self.otlp_protocol == "http":
                    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                        OTLPMetricExporter,
                    )
                else:
                    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                        OTLPMetricExporter,
                    )
                return PeriodicExportingMetricReader(
                    OTLPMetricExporter(endpoint=self.otlp_endpoint),
                    export_interval_millis=self.metric_export_interval_ms,
                )
            except ImportError:
                print(
                    "[TelemetryProvider] OTLP metric exporter not installed. "
                    "Falling back to console exporter.",
                    file=sys.stderr,
                )
                return PeriodicExportingMetricReader(
                    ConsoleMetricExporter(),
                    export_interval_millis=self.metric_export_interval_ms,
                )
        return None

    def _init_instruments(self) -> None:
        m = self._meter
        self._req_counter = m.create_counter(
            name="guardrail.pipeline.requests",
            description="Total pipeline stage invocations",
            unit="1",
        )
        self._block_counter = m.create_counter(
            name="guardrail.pipeline.blocks",
            description="Total requests blocked by guardrails",
            unit="1",
        )
        self._finding_counter = m.create_counter(
            name="guardrail.pipeline.findings",
            description="Total findings emitted by all guards",
            unit="1",
        )
        self._stage_latency = m.create_histogram(
            name="guardrail.pipeline.latency_ms",
            description="End-to-end wall-clock latency per pipeline stage",
            unit="ms",
        )
        self._guard_latency = m.create_histogram(
            name="guardrail.guard.latency_ms",
            description="Latency per individual guardrail check",
            unit="ms",
        )

    # ------------------------------------------------------------------
    # Span context managers
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def pipeline_stage_span(
        self, stage: str, run_id: str
    ) -> Generator[Optional[object], None, None]:
        """
        Wraps an entire pipeline stage in an OTel span.

        Yields the span (or None if telemetry is disabled) so the caller
        can attach the completed PipelineResult attributes via
        record_pipeline_result().
        """
        if not self.enabled or self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(f"guardrail.stage.{stage}") as span:
            span.set_attribute("guardrail.stage", stage)
            span.set_attribute("guardrail.run_id", run_id)
            yield span

    @contextlib.contextmanager
    def guard_span(self, guard_name: str, stage: str) -> Generator[Optional[object], None, None]:
        """
        Wraps one guardrail check in a child OTel span.

        Because asyncio propagates contextvars, child spans created inside
        asyncio.gather() tasks correctly nest under the parent stage span.
        """
        if not self.enabled or self._tracer is None:
            yield None
            return
        with self._tracer.start_as_current_span(f"guardrail.check.{guard_name}") as span:
            span.set_attribute("guardrail.guard.name", guard_name)
            span.set_attribute("guardrail.stage", stage)
            yield span

    # ------------------------------------------------------------------
    # Record results → metrics + span attributes
    # ------------------------------------------------------------------

    def record_pipeline_result(self, result: "PipelineResult", span=None) -> None:
        """
        Emit stage-level metrics and enrich the stage span once a
        PipelineResult is available.
        """
        if not self.enabled:
            return

        stage = result.stage.value
        base = {"guardrail.stage": stage}

        self._req_counter.add(1, {**base, "guardrail.passed": str(result.passed)})

        if result.blocked:
            self._block_counter.add(1, {**base, "guardrail.blocked_by": _blocked_by(result)})

        for finding in result.all_findings:
            self._finding_counter.add(
                1,
                {
                    **base,
                    "guardrail.finding.category": finding.category,
                    "guardrail.finding.severity": finding.severity.value,
                },
            )

        self._stage_latency.record(result.total_latency_ms, base)

        if span is not None:
            span.set_attribute("guardrail.passed", result.passed)
            span.set_attribute("guardrail.blocked", result.blocked)
            span.set_attribute("guardrail.total_findings", len(result.all_findings))
            span.set_attribute("guardrail.latency_ms", round(result.total_latency_ms, 2))
            span.set_attribute("guardrail.content_length", len(result.original_content))
            if result.blocked:
                span.set_attribute("guardrail.blocked_by", _blocked_by(result))
                if StatusCode is not None:
                    span.set_status(StatusCode.ERROR, "request blocked by guardrail")

    def record_check_result(
        self,
        result: "CheckResult",
        guard_name: str,
        stage: str,
        span=None,
    ) -> None:
        """
        Emit guard-level latency metric and enrich the check span once a
        CheckResult is available.
        """
        if not self.enabled:
            return

        self._guard_latency.record(
            result.latency_ms,
            {
                "guardrail.guard.name": guard_name,
                "guardrail.stage": stage,
                "guardrail.guard.action": result.action.value,
            },
        )

        if span is not None:
            span.set_attribute("guardrail.guard.passed", result.passed)
            span.set_attribute("guardrail.guard.action", result.action.value)
            span.set_attribute("guardrail.guard.findings", len(result.findings))
            span.set_attribute("guardrail.guard.latency_ms", round(result.latency_ms, 2))
            if result.blocked and StatusCode is not None:
                span.set_status(StatusCode.ERROR, "blocked")


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _blocked_by(result: "PipelineResult") -> str:
    """Return the guard name that caused the block, or 'unknown'."""
    for check in result.checks:
        if check.blocked:
            if check.findings:
                return check.findings[0].guard_name
            return check.metadata.get("guard_name", "unknown")
    return "unknown"
