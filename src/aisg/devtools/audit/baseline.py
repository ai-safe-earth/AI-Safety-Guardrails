"""aisg/devtools/audit/baseline.py
----------------------------
Fingerprint baseline for `aisg audit`: load, write and diff. Only `new` findings count
toward the exit code; `unchanged` ones are still rendered, still findings.

A baseline may carry an `accepted` list next to `fingerprints`: one entry per fingerprint
that a human looked at, with the reason it stays. `load_baseline` validates the list (a
reason is mandatory, and the fingerprint must also be in `fingerprints`) but returns the
same set either way: a fingerprint without a reason is a suppression, not an acceptance,
and the committed `audit-baseline.json` is held to the stricter shape by its own test.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from aisg.devtools.audit.model import SCHEMA_VERSION, Finding, Report, now_iso

__all__ = [
    "BASELINE_KIND",
    "REPORT_KIND",
    "BaselineDiff",
    "BaselineError",
    "diff",
    "load_accepted",
    "load_baseline",
    "write_baseline",
]

BASELINE_KIND = "audit-baseline"
REPORT_KIND = "audit"
TOOL_NAME = "aisg-audit"


class BaselineError(Exception):
    """A baseline file that cannot be used. The message is a single line; main maps it to exit 2."""


def _read_document(path: Path) -> dict[str, Any]:
    """Parse `path` as a JSON object with the audit schema; anything else is a BaselineError."""
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
    return doc


def _validate_accepted(doc: dict[str, Any], fingerprints: set[str], path: Path) -> dict[str, str]:
    """
    Check the optional `accepted` list and return `{fingerprint: reason}`.

    Every entry needs a non-empty `reason` and a `fingerprint` that is also listed under
    `fingerprints`; the error names the offending fingerprint so it can be found in the file.
    An absent `accepted` key is fine (a `--write-baseline` document has none).
    """
    raw = doc.get("accepted")
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise BaselineError(f"baseline {path.as_posix()}: 'accepted' is not a list")
    reasons: dict[str, str] = {}
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry #{index} is not an object"
            )
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry #{index} has no fingerprint"
            )
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry {fingerprint} has no reason"
            )
        if fingerprint not in fingerprints:
            raise BaselineError(
                f"baseline {path.as_posix()}: accepted entry {fingerprint} is not in 'fingerprints'"
            )
        reasons[fingerprint] = reason
    return reasons


def load_baseline(path: Path) -> set[str]:
    """
    Read the fingerprint set from a baseline file or from a full audit report.

    Accepts `{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [...]}` (with an
    optional `accepted` list, validated) or
    `{"schema": "aisg/1", "kind": "audit", "findings": [{"fingerprint": ...}, ...]}`.
    Anything else raises `BaselineError` with a one-line reason.
    """
    path = Path(path)
    doc = _read_document(path)
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
    if kind == BASELINE_KIND:
        _validate_accepted(doc, fingerprints, path)
    return fingerprints


def load_accepted(path: Path) -> dict[str, str]:
    """
    `{fingerprint: reason}` from a baseline file's `accepted` list, after the same validation
    `load_baseline` applies. A full audit report, or a baseline without the list, yields `{}`.
    """
    path = Path(path)
    fingerprints = load_baseline(path)
    doc = _read_document(path)
    if doc.get("kind") != BASELINE_KIND:
        return {}
    return _validate_accepted(doc, fingerprints, path)


def _findings_of(report_or_findings: Report | Iterable[Finding]) -> list[Finding]:
    if isinstance(report_or_findings, Report):
        return list(report_or_findings.findings)
    return list(report_or_findings)


def _fingerprints_of(findings: Iterable[Finding]) -> list[str]:
    return sorted({f.fingerprint for f in findings if f.fingerprint})


def _tool_block(report_or_findings: Report | Iterable[Finding]) -> dict[str, Any]:
    if isinstance(report_or_findings, Report) and report_or_findings.tool:
        return dict(report_or_findings.tool)
    # Local import: report.py imports BaselineDiff from here, so the dependency is
    # resolved at call time to keep the version lookup in one place.
    from aisg.devtools.audit.report import tool_version

    return {"name": TOOL_NAME, "version": tool_version()}


def _location_of(finding: Finding) -> str:
    """`file:line` of the first evidence entry; the scope name for a finding without one."""
    if finding.evidence:
        file, line = finding.location
        return f"{file}:{line}"
    return finding.scope.name or ""


def _accepted_of(findings: Iterable[Finding], reasons: Mapping[str, str]) -> list[dict[str, str]]:
    """
    One `accepted` entry per reason, in the order the findings were given (a report's order
    when a report was passed), taken from the first finding that carries the fingerprint.
    A reason for a fingerprint no finding carries, or an empty reason, is a `BaselineError`:
    the document it would produce could not be loaded back.
    """
    for fingerprint, reason in reasons.items():
        if not isinstance(reason, str) or not reason.strip():
            raise BaselineError(f"baseline: accepted entry {fingerprint} has no reason")
    accepted: list[dict[str, str]] = []
    pending = set(reasons)
    for finding in findings:
        if finding.fingerprint not in pending:
            continue
        pending.discard(finding.fingerprint)
        accepted.append(
            {
                "fingerprint": finding.fingerprint,
                "rule": finding.display_id,
                "file": _location_of(finding),
                "reason": reasons[finding.fingerprint],
            }
        )
    if pending:
        missing = ", ".join(sorted(pending))
        raise BaselineError(f"baseline: accepted entry {missing} matches no finding in this run")
    return accepted


def write_baseline(
    report_or_findings: Report | Iterable[Finding],
    path: Path,
    reasons: Mapping[str, str] | None = None,
) -> None:
    """
    Write the baseline document: schema, kind, generated_at, tool, fingerprints (sorted,
    unique) and, when `reasons` (`{fingerprint: reason}`) is given, an `accepted` list with
    `rule` (display id) and `file` (`file:line` of the first evidence) per reason.
    """
    findings = _findings_of(report_or_findings)
    doc: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "generated_at": now_iso(),
        "tool": _tool_block(report_or_findings),
        "fingerprints": _fingerprints_of(findings),
    }
    if reasons is not None:
        doc["accepted"] = _accepted_of(findings, reasons)
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
