"""
modules/observability/audit_logger.py
---------------------------------------
Structured audit logging for all guardrail pipeline runs.

Provides:
    - JSON-structured logs for ELK/Splunk/Datadog compatibility
    - Per-pipeline-run event records
    - Configurable sinks: file, stdout, HTTP endpoint
    - Optional OpenTelemetry span enrichment

Usage:
    from aisg.modules.observability.audit_logger import AuditLogger

    logger = AuditLogger(
        sink="file",
        log_path="logs/guardrails.jsonl",
        include_content_hash=True,
    )
    pipeline = GuardrailPipeline(..., audit_logger=logger)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

from aisg.core.base import PipelineResult


@dataclass
class AuditRecord:
    """
    Fully structured audit record for one pipeline run stage.
    Compatible with SIEM ingestion and EU AI Act Art. 12 requirements.
    """

    record_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    timestamp_unix: float = field(default_factory=time.time)

    # Identity
    user_id: str = "anonymous"
    session_id: str = ""
    org_id: str = ""
    ip_address: str = ""

    # Pipeline
    stage: str = ""
    pipeline_run_id: str = ""
    passed: bool = True
    blocked: bool = False
    total_latency_ms: float = 0.0

    # Content (hashed for privacy, not raw)
    input_hash: str = ""
    output_hash: str = ""
    content_length: int = 0

    # Findings summary
    total_findings: int = 0
    blocked_by: str = ""
    finding_categories: list[str] = field(default_factory=list)
    highest_severity: str = ""

    # Checks run
    checks_run: list[dict] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str)


class AuditLogger:
    """
    Audit logger for guardrail pipeline runs.

    Config:
        sink:                "file" | "stdout" | "http" | "none"
        log_path:            Path for file sink (default: "logs/guardrails.jsonl")
        http_endpoint:       URL for HTTP sink
        include_content_hash: Hash input/output for tamper evidence (default: True)
        redact_user_id:      Hash user_id in logs (default: False)
        min_severity:        Only log findings at this severity or above
    """

    def __init__(
        self,
        sink: Literal["file", "stdout", "http", "none"] = "file",
        log_path: str = "logs/guardrails.jsonl",
        http_endpoint: str | None = None,
        include_content_hash: bool = True,
        redact_user_id: bool = False,
        enabled: bool = True,
    ):
        self.sink = sink
        self.log_path = Path(log_path)
        self.http_endpoint = http_endpoint
        self.include_content_hash = include_content_hash
        self.redact_user_id = redact_user_id
        self.enabled = enabled

        if sink == "file":
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

    async def log(self, result: PipelineResult, context: dict) -> None:
        if not self.enabled or self.sink == "none":
            return

        record = self._build_record(result, context)
        line = record.to_json()

        if self.sink == "file":
            try:
                with open(self.log_path, "a") as f:
                    f.write(line + "\n")
            except Exception as exc:
                print(
                    f"[AuditLogger] Failed to write to {self.log_path}: "
                    f"{type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )

        elif self.sink == "stdout":
            print(line, file=sys.stdout, flush=True)

        elif self.sink == "http" and self.http_endpoint:
            await self._post_http(line)

    def _build_record(self, result: PipelineResult, context: dict) -> AuditRecord:
        user_id = context.get("user_id", "anonymous")
        if self.redact_user_id and user_id != "anonymous":
            user_id = hashlib.sha256(user_id.encode()).hexdigest()[:16]

        input_hash = ""
        output_hash = ""
        if self.include_content_hash:
            input_hash = hashlib.sha256(result.original_content.encode()).hexdigest()
            output_hash = hashlib.sha256(result.final_content.encode()).hexdigest()

        all_findings = result.all_findings
        finding_categories = list({f.category for f in all_findings})

        severity_order = ["info", "low", "medium", "high", "critical"]
        highest = ""
        if all_findings:
            highest = max(
                (f.severity.value for f in all_findings),
                key=lambda s: severity_order.index(s) if s in severity_order else -1,
            )

        checks_run = [
            {
                "guard": c.check_id[:8],
                "passed": c.passed,
                "action": c.action.value,
                "latency_ms": round(c.latency_ms, 2),
                "findings": len(c.findings),
            }
            for c in result.checks
        ]

        blocked_by = ""
        if result.blocked:
            for check in result.checks:
                if check.blocked:
                    # Prefer the guard name from the first finding; fall back to metadata
                    if check.findings:
                        blocked_by = check.findings[0].guard_name
                    else:
                        blocked_by = check.metadata.get("guard_name", "unknown")
                    break

        return AuditRecord(
            user_id=user_id,
            session_id=context.get("session_id", ""),
            org_id=context.get("org_id", ""),
            ip_address=context.get("ip_address", ""),
            stage=result.stage.value,
            pipeline_run_id=result.pipeline_run_id,
            passed=result.passed,
            blocked=result.blocked,
            total_latency_ms=round(result.total_latency_ms, 2),
            input_hash=input_hash,
            output_hash=output_hash,
            content_length=len(result.original_content),
            total_findings=len(all_findings),
            blocked_by=blocked_by,
            finding_categories=finding_categories,
            highest_severity=highest,
            checks_run=checks_run,
        )

    async def _post_http(self, payload: str) -> None:
        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                await session.post(
                    self.http_endpoint,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=2),
                )
        except Exception as exc:
            # Never block the pipeline on log failure, but surface it to stderr
            print(
                f"[AuditLogger] HTTP sink failed ({self.http_endpoint}): "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
