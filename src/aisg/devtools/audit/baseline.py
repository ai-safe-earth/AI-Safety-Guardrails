"""aisg/devtools/audit/baseline.py
----------------------------
Fingerprint baseline for `aisg audit`: load, write and diff. Only `new` findings count
toward the exit code; `unchanged` ones are still rendered, still findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from aisg.devtools.audit.model import SCHEMA_VERSION, Finding, Report, now_iso

__all__ = [
    "BASELINE_KIND",
    "REPORT_KIND",
    "BaselineDiff",
    "BaselineError",
    "diff",
    "load_baseline",
    "write_baseline",
]

BASELINE_KIND = "audit-baseline"
REPORT_KIND = "audit"
TOOL_NAME = "aisg-audit"


class BaselineError(Exception):
    """A baseline file that cannot be used. The message is a single line; main maps it to exit 2."""


def load_baseline(path: Path) -> set[str]:
    """
    Read the fingerprint set from a baseline file or from a full audit report.

    Accepts `{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [...]}` or
    `{"schema": "aisg/1", "kind": "audit", "findings": [{"fingerprint": ...}, ...]}`.
    Anything else raises `BaselineError` with a one-line reason.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise BaselineError(f"baseline {path.as_posix()}: {reason}") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline {path.as_posix()}: invalid JSON ({exc.msg} at line {exc.lineno})"
        ) from exc
    if not isinstance(doc, dict):
        raise BaselineError(f"baseline {path.as_posix()}: top level is not a JSON object")
    schema = doc.get("schema")
    if schema != SCHEMA_VERSION:
        raise BaselineError(
            f"baseline {path.as_posix()}: schema {schema!r} is not {SCHEMA_VERSION!r}"
        )
    kind = doc.get("kind")
    if kind == BASELINE_KIND:
        raw = doc.get("fingerprints")
        if not isinstance(raw, list):
            raise BaselineError(f"baseline {path.as_posix()}: 'fingerprints' is not a list")
        candidates: list[Any] = raw
    elif kind == REPORT_KIND:
        findings = doc.get("findings")
        if not isinstance(findings, list):
            raise BaselineError(f"baseline {path.as_posix()}: 'findings' is not a list")
        candidates = [f.get("fingerprint") for f in findings if isinstance(f, dict)]
    else:
        raise BaselineError(
            f"baseline {path.as_posix()}: kind {kind!r} is neither "
            f"{BASELINE_KIND!r} nor {REPORT_KIND!r}"
        )
    fingerprints: set[str] = set()
    for value in candidates:
        if not isinstance(value, str) or not value:
            raise BaselineError(
                f"baseline {path.as_posix()}: every fingerprint must be a non-empty string"
            )
        fingerprints.add(value)
    return fingerprints


def _fingerprints_of(report_or_findings: Report | Iterable[Finding]) -> list[str]:
    findings = (
        report_or_findings.findings
        if isinstance(report_or_findings, Report)
        else list(report_or_findings)
    )
    return sorted({f.fingerprint for f in findings if f.fingerprint})


def _tool_block(report_or_findings: Report | Iterable[Finding]) -> dict[str, Any]:
    if isinstance(report_or_findings, Report) and report_or_findings.tool:
        return dict(report_or_findings.tool)
    # Local import: report.py imports BaselineDiff from here, so the dependency is
    # resolved at call time to keep the version lookup in one place.
    from aisg.devtools.audit.report import tool_version

    return {"name": TOOL_NAME, "version": tool_version()}


def write_baseline(report_or_findings: Report | Iterable[Finding], path: Path) -> None:
    """Write the baseline document: schema, kind, generated_at, tool, fingerprints (sorted, unique)."""
    doc = {
        "schema": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "generated_at": now_iso(),
        "tool": _tool_block(report_or_findings),
        "fingerprints": _fingerprints_of(report_or_findings),
    }
    Path(path).write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


@dataclass
class BaselineDiff:
    """Findings partitioned against a baseline. `fixed` holds fingerprints no longer present."""

    new: list[Finding] = field(default_factory=list)
    fixed: list[str] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "new": len(self.new),
            "fixed": len(self.fixed),
            "unchanged": len(self.unchanged),
        }


def diff(findings: Iterable[Finding], baseline: set[str], file: str) -> BaselineDiff:
    """
    Partition `findings` into new/unchanged by fingerprint and set `Finding.baseline_status`
    in place. Fingerprints in the baseline that no finding carries any more are `fixed`.
    """
    result = BaselineDiff(file=str(file).replace("\\", "/"))
    seen: set[str] = set()
    for finding in findings:
        seen.add(finding.fingerprint)
        if finding.fingerprint in baseline:
            finding.baseline_status = "unchanged"
            result.unchanged.append(finding)
        else:
            finding.baseline_status = "new"
            result.new.append(finding)
    result.fixed = sorted(baseline - seen)
    return result
