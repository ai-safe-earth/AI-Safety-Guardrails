"""aisg/devtools/audit/report.py
----------------------------
Summary block, rule catalogue, exit-code rule and the four renderers (json, sarif,
markdown, terminal) for `aisg audit`. ASCII only, key order fixed, nothing re-derived
from raw files: every snippet arrives already redacted inside a `Finding`.

Honesty rules carried here:

- The disclaimer is the first thing every format says.
- `[UNMEASURED]` sits next to every finding whose rule has no precision figure.
- A finding read from a report on disk renders `[REPORTED <age>d, <source>]` and stays
  ASSERTED; only an external tool that ran now is MEASURED.
- Findings below `--fail-on` are still findings: the summary line always says how many
  were not counted toward the exit code, and zero findings still print the UNKNOWN block.
- The debug self-check (`check_templates`) runs over this module's own fixed strings
  only, never over target text, so a comment in the audited repo cannot trip it.
"""

from __future__ import annotations

import json
import re
import textwrap
from importlib import metadata
from typing import Any, Iterable, Sequence

from aisg.devtools.audit.baseline import BaselineDiff
from aisg.devtools.audit.model import (
    DISCLAIMER,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    TRIFECTA_RULE_ID,
    AuditContext,
    Bucket,
    Evidence,
    ExternalToolResult,
    Finding,
    Inventory,
    Report,
    ReportRecord,
    Severity,
    Status,
    UnknownCategory,
    UnknownItem,
    sort_findings,
)
from aisg.devtools.audit.rules import ALL_RULES, AuditRule, is_demoted

__all__ = [
    "BANNED_PHRASES",
    "DISTRIBUTION",
    "FAIL_ON_CHOICES",
    "FORMATS",
    "SARIF_LEVEL",
    "TOOL_NAME",
    "WIDTH",
    "build_report",
    "catalogue",
    "check_templates",
    "compute_exit_code",
    "render",
    "summarise",
    "to_json",
    "to_markdown",
    "to_sarif",
    "to_terminal",
    "tool_version",
]

DISTRIBUTION = "ai-safety-guardrails"
TOOL_NAME = "aisg-audit"
FORMATS: tuple[str, ...] = ("terminal", "json", "sarif", "markdown")
FAIL_ON_CHOICES: tuple[str, ...] = ("critical", "high", "medium", "low", "info", "never")
WIDTH = 100

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_FINGERPRINT_KEY = "aisgFingerprint/v1"

SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# The compliance-language ban list (design section 10, item 1), lowercase. Assembled from
# fragments so this module never carries one of the phrases as a contiguous literal.
BANNED_PHRASES: tuple[str, ...] = tuple(
    " ".join(words)
    for words in (
        ("is", "compliant"),
        ("compliance", "verified"),
        ("certi" + "fied",),
        ("meets", "the", "requirements"),
        ("fully", "compliant"),
        ("passes", "the", "eu"),
        ("nist", "compliant"),
    )
)

# ---------------------------------------------------------------------------
# Templates: every fixed string a renderer emits. `check_templates` scans these and
# nothing else.
# ---------------------------------------------------------------------------

_T_TITLE = "aisg audit"
_T_MD_H1 = "# aisg audit"
_T_SUMMARY = (
    "{n} finding{s} ({m} below --fail-on {level}, not counted in exit code); {k} unknown item{ks}"
)
_T_SEVERITY_LINE = "severity: {items}"
_T_BUCKET_LINE = "buckets: {items}"
_T_UNMEASURED = "[UNMEASURED]"
_T_MEASURED = "[MEASURED p={p}]"
_T_REPORTED = "[REPORTED {age}d, {source}]"
_T_REPORTED_UNKNOWN = "[REPORTED age unknown]"
_T_GITIGNORED = "(gitignored)"
_T_BASELINE_STATUS = "[baseline: {status}]"
_T_NONE = "(none)"
_T_NOT_INCLUDED = "(not included)"
_T_PINNED = "Pinned"
_T_PRIORITY = "P{p}"
_T_FINDINGS = "Findings"
_T_UNKNOWN = "UNKNOWN"
_T_EXTERNAL = "External tools"
_T_INVENTORY = "Inventory"
_T_BUCKET_MEASURED = "MEASURED"
_T_BUCKET_ASSERTED = "ASSERTED"
_T_BUCKET_UNKNOWN = "UNKNOWN"
_T_OF_WHICH_REPORTED = "{n} (of which REPORTED {reported})"
_T_BUCKET_MEANING_MEASURED = "an external tool ran during this audit"
_T_BUCKET_MEANING_ASSERTED = "this audit's own rules, or a report read from disk (REPORTED)"
_T_BUCKET_MEANING_UNKNOWN = "not established: nobody checked, never a pass"
_T_BUCKET_TABLE_HEADER = "| bucket | count | meaning |"
_T_TABLE_RULE_3 = "|---|---|---|"
_T_TABLE_RULE_5 = "|---|---|---|---|---|"
_T_EXTERNAL_TABLE_HEADER = "| name | status | network | version | argv |"
_T_SCOPE = "scope: {kind} {name}"
_T_EVIDENCE = "[{role}] {file}:{line}: {snippet}"
_T_FIX = "fix ({tier}): {summary}"
_T_ALTERNATIVES = "alternatives: {items}"
_T_CONTROLS = "controls: {items}"
_T_FAILURE_MODES = "known failure modes: {items}"
_T_NOTE = "note: {text}"
_T_UNKNOWN_ITEM = "[{category}] {what}: {why}"
_T_RESOLVE = "resolve: {text}"
_T_FILE = "file: {file}"
_T_RULES = "rules: {items}"
_T_YES = "yes"
_T_NO = "no"
_T_DASH = "-"
_T_INV_UNITS = "units: {n}"
_T_INV_LANGUAGES = "languages: {n} ({items})"
_T_INV_LLM_CALLS = "llm_calls: {n}"
_T_INV_TOOLS = "tools: {n}"
_T_INV_MCP = "mcp servers: {n}"
_T_INV_HOSTS = "hosts: {n}"
_T_BASELINE = "baseline {file}: {new} new, {fixed} fixed, {unchanged} unchanged"
_T_SARIF_MESSAGE = "[{label}] {title}"
_T_EXIT = "exit code: {code}"

_TEMPLATES: tuple[str, ...] = (
    DISCLAIMER,
    _T_TITLE,
    _T_MD_H1,
    _T_SUMMARY,
    _T_SEVERITY_LINE,
    _T_BUCKET_LINE,
    _T_UNMEASURED,
    _T_MEASURED,
    _T_REPORTED,
    _T_REPORTED_UNKNOWN,
    _T_GITIGNORED,
    _T_BASELINE_STATUS,
    _T_NONE,
    _T_NOT_INCLUDED,
    _T_PINNED,
    _T_PRIORITY,
    _T_FINDINGS,
    _T_UNKNOWN,
    _T_EXTERNAL,
    _T_INVENTORY,
    _T_BUCKET_MEASURED,
    _T_BUCKET_ASSERTED,
    _T_BUCKET_UNKNOWN,
    _T_OF_WHICH_REPORTED,
    _T_BUCKET_MEANING_MEASURED,
    _T_BUCKET_MEANING_ASSERTED,
    _T_BUCKET_MEANING_UNKNOWN,
    _T_BUCKET_TABLE_HEADER,
    _T_TABLE_RULE_3,
    _T_TABLE_RULE_5,
    _T_EXTERNAL_TABLE_HEADER,
    _T_SCOPE,
    _T_EVIDENCE,
    _T_FIX,
    _T_ALTERNATIVES,
    _T_CONTROLS,
    _T_FAILURE_MODES,
    _T_NOTE,
    _T_UNKNOWN_ITEM,
    _T_RESOLVE,
    _T_FILE,
    _T_RULES,
    _T_YES,
    _T_NO,
    _T_DASH,
    _T_INV_UNITS,
    _T_INV_LANGUAGES,
    _T_INV_LLM_CALLS,
    _T_INV_TOOLS,
    _T_INV_MCP,
    _T_INV_HOSTS,
    _T_BASELINE,
    _T_SARIF_MESSAGE,
    _T_EXIT,
)


def check_templates() -> list[str]:
    """Banned phrases present in the renderer's own fixed strings. Never scans findings."""
    found: list[str] = []
    for template in _TEMPLATES:
        lowered = template.lower()
        for phrase in BANNED_PHRASES:
            if phrase in lowered and phrase not in found:
                found.append(phrase)
    return found


# ---------------------------------------------------------------------------
# Version, catalogue, exit code, summary
# ---------------------------------------------------------------------------


def tool_version() -> str:
    """Installed distribution version, or "unknown" for a source checkout. Never a literal."""
    try:
        return metadata.version(DISTRIBUTION)
    except metadata.PackageNotFoundError:
        return "unknown"


def catalogue(rules: Sequence[type[AuditRule]], ran_ids: set[str]) -> list[dict[str, Any]]:
    """The section 3.2 `rules[]` block. `measured_precision` is the attribute value, `None` included."""
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "measured_precision": rule.measured_precision,
            "ran": rule.id in ran_ids,
            "experimental": is_demoted(rule),
        }
        for rule in rules
    ]


def _threshold_rank(fail_on: str) -> int | None:
    """Severity rank at or above which a finding counts; `None` for "never"."""
    level = str(fail_on).lower()
    if level == "never":
        return None
    try:
        return Severity(level).rank()
    except ValueError:
        raise ValueError(
            f"fail_on must be one of {', '.join(FAIL_ON_CHOICES)}, not {fail_on!r}"
        ) from None


def _counts_toward_exit(finding: Finding, threshold: int | None) -> bool:
    if threshold is None or finding.baseline_status == "unchanged":
        return False
    return Severity(finding.severity).rank() >= threshold


def _category(item: UnknownItem) -> str:
    return getattr(item.category, "value", str(item.category))


def compute_exit_code(
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    *,
    fail_on: str,
    fail_on_unknown: set[str] | None = None,
) -> int:
    """
    0 or 1. A finding counts when its severity is at or above `fail_on` and it is not
    `unchanged` against a baseline; "never" means findings never count. With
    `fail_on_unknown`, any UnknownItem in one of those categories also yields 1.
    """
    threshold = _threshold_rank(fail_on)
    if any(_counts_toward_exit(f, threshold) for f in findings):
        return 1
    if fail_on_unknown:
        selected = {getattr(c, "value", str(c)) for c in fail_on_unknown}
        if any(_category(u) in selected for u in unknown):
            return 1
    return 0


def summarise(
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    external: Iterable[ExternalToolResult],
    reports: Iterable[ReportRecord],
    baseline: BaselineDiff | None,
    fail_on: str,
    exit_code: int,
) -> dict[str, Any]:
    """
    The section 3.2 `summary` block, keys in that order. `external` and `reports` are
    accepted for signature stability; the block is computed from findings and unknown
    items only.
    """
    findings = list(findings)
    unknown = list(unknown)
    threshold = _threshold_rank(fail_on)
    by_severity = {sev.value: 0 for sev in SEVERITY_ORDER}
    by_bucket = {bucket.value: 0 for bucket in Bucket}
    below = reported = suppressed = 0
    for finding in findings:
        severity = Severity(finding.severity)
        by_severity[severity.value] += 1
        by_bucket[Bucket(finding.bucket).value] += 1
        if threshold is None or severity.rank() < threshold:
            below += 1
        if finding.report is not None:
            reported += 1
        if finding.suppressed:
            suppressed += 1
    by_category = {category.value: 0 for category in UnknownCategory}
    for item in unknown:
        key = _category(item)
        by_category[key] = by_category.get(key, 0) + 1
    return {
        "findings": len(findings),
        "by_severity": by_severity,
        "by_bucket": by_bucket,
        "reported": reported,
        "below_threshold": below,
        "fail_on": str(fail_on).lower(),
        "unknown_items": len(unknown),
        "unknown_by_category": by_category,
        "exit_code": exit_code,
        "top": findings[0].display_id if findings else None,
        "suppressed": suppressed,
        "baseline_new": len(baseline.new) if baseline is not None else None,
    }


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _as_dict(obj: Any) -> Any:
    return obj.to_dict() if hasattr(obj, "to_dict") else obj


def _target(ctx: AuditContext) -> dict[str, Any]:
    source = (_as_dict(ctx.inventory) or {}).get("target") or {}
    return {
        "path": _posix(source.get("path") or ctx.root),
        "git_sha": source.get("git_sha"),
        "dirty": source.get("dirty"),
    }


def _measured_entry(result: ExternalToolResult) -> dict[str, Any]:
    return {
        "source": result.name,
        "status": Status(result.status).value,
        "version": result.version,
        "duration_ms": result.duration_ms,
        "findings": result.findings,
        "network": bool(result.network),
    }


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return value


def _measure_extract(body: Any) -> dict[str, dict[str, Any]]:
    """Per-guard catch rate, false-positive rate and threshold failures. Nothing else is read."""
    guards = body.get("guards") if isinstance(body, dict) else None
    items: list[tuple[Any, Any]] = []
    if isinstance(guards, dict):
        items = list(guards.items())
    elif isinstance(guards, list):
        items = [(g.get("name"), g) for g in guards if isinstance(g, dict)]
    out: dict[str, dict[str, Any]] = {}
    for name, guard in items:
        if not isinstance(name, str) or not isinstance(guard, dict):
            continue
        failures = guard.get("threshold_failures")
        out[name] = {
            "catch_rate": _number(guard.get("catch_rate")),
            "false_positive_rate": _number(guard.get("false_positive_rate")),
            "threshold_failures": [str(x) for x in failures] if isinstance(failures, list) else [],
        }
    return out


def _probe_extract(body: Any) -> dict[str, Any]:
    summary = body.get("summary") if isinstance(body, dict) else None
    if not isinstance(summary, dict):
        return {}
    return {str(key): value for key, value in summary.items() if _number(value) is not None}


def _report_entry(record: ReportRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(record, ReportRecord):
        meta = record.to_dict()
        body: Any = record.body
    else:
        meta = dict(record)
        body = meta.pop("body", None)
    entry: dict[str, Any] = {"source": meta.pop("file", None)}
    entry.update(meta)
    kind = entry.get("kind")
    if kind == "measure":
        entry["guards"] = _measure_extract(body)
    elif kind == "probe":
        entry["summary"] = _probe_extract(body)
    return entry


def build_report(
    ctx: AuditContext,
    findings: Iterable[Finding],
    unknown: Iterable[UnknownItem],
    external: Iterable[ExternalToolResult],
    reports: Iterable[ReportRecord],
    baseline: BaselineDiff | None,
    *,
    rules: Sequence[type[AuditRule]],
    fail_on: str,
    exit_code: int,
    inventory_included: bool = True,
) -> Report:
    """
    Assemble the `Report`. `rules` are the rules that ran; the catalogue lists the
    registry plus any ran rule missing from it, each flagged `ran` true/false.
    Findings are sorted here, AUD-301 pinned first.
    """
    ordered = sort_findings(findings)
    unknown_items = list(unknown)
    external_results = list(external)
    report_records = list(reports)
    ran_ids = {rule.id for rule in rules}
    base = list(ALL_RULES)
    for rule in rules:
        if rule not in base:
            base.append(rule)
    return Report(
        tool={"name": TOOL_NAME, "version": tool_version()},
        target=_target(ctx),
        summary=summarise(
            ordered, unknown_items, external_results, report_records, baseline, fail_on, exit_code
        ),
        findings=ordered,
        measured=[_measured_entry(t) for t in external_results if Status(t.status) is Status.RAN],
        reports=[_report_entry(r) for r in report_records],
        unknown=unknown_items,
        external_tools=external_results,
        baseline=baseline.to_dict() if baseline is not None else None,
        inventory=ctx.inventory if inventory_included else None,
        rules=catalogue(base, ran_ids),
    )


# ---------------------------------------------------------------------------
# Shared rendering helpers
# ---------------------------------------------------------------------------


def _summary_of(report: Report) -> dict[str, Any]:
    if report.summary and "findings" in report.summary:
        return report.summary
    # A hand-built Report without a summary block: compute one rather than print zeros.
    code = compute_exit_code(report.findings, report.unknown, fail_on="low")
    return summarise(
        report.findings, report.unknown, report.external_tools, report.reports, None, "low", code
    )


def _plural(n: int) -> str:
    return "" if n == 1 else "s"


def _summary_line(summary: dict[str, Any]) -> str:
    n = int(summary.get("findings", 0))
    k = int(summary.get("unknown_items", 0))
    return _T_SUMMARY.format(
        n=n,
        s=_plural(n),
        m=int(summary.get("below_threshold", 0)),
        level=summary.get("fail_on", "low"),
        k=k,
        ks=_plural(k),
    )


def _severity_items(summary: dict[str, Any]) -> str:
    counts = summary.get("by_severity") or {}
    return ", ".join(f"{sev.value} {int(counts.get(sev.value, 0))}" for sev in SEVERITY_ORDER)


def _bucket_counts(summary: dict[str, Any]) -> tuple[int, str, int]:
    """(measured, asserted-with-reported, unknown) as rendered in the three-bucket table."""
    buckets = summary.get("by_bucket") or {}
    asserted = int(buckets.get("asserted", 0))
    reported = int(summary.get("reported", 0))
    asserted_text = _T_OF_WHICH_REPORTED.format(n=asserted, reported=reported)
    unknown = int(buckets.get("unknown", 0)) + int(summary.get("unknown_items", 0))
    return int(buckets.get("measured", 0)), asserted_text, unknown


def _tags(finding: Finding) -> str:
    """Bucket, then the confidence/report/gitignored/baseline tags, in a fixed order."""
    precision = finding.confidence.precision
    parts = [
        Bucket(finding.bucket).value,
        _T_UNMEASURED if precision is None else _T_MEASURED.format(p=precision),
    ]
    if finding.report is not None:
        block = finding.report if isinstance(finding.report, dict) else {}
        age = block.get("age_days")
        if age is None:
            parts.append(_T_REPORTED_UNKNOWN)
        else:
            parts.append(_T_REPORTED.format(age=age, source=block.get("age_source") or "unknown"))
    if finding.gitignored:
        parts.append(_T_GITIGNORED)
    if finding.baseline_status:
        parts.append(_T_BASELINE_STATUS.format(status=finding.baseline_status))
    return " ".join(parts)


def _grouped(findings: Sequence[Finding]) -> list[tuple[str, list[Finding]]]:
    """Pinned trifecta findings first, then one group per priority in ascending order."""
    groups: list[tuple[str, list[Finding]]] = []
    pinned = [f for f in findings if f.id == TRIFECTA_RULE_ID]
    if pinned:
        groups.append((_T_PINNED, pinned))
    by_priority: dict[int, list[Finding]] = {}
    for finding in findings:
        if finding.id != TRIFECTA_RULE_ID:
            by_priority.setdefault(int(finding.priority), []).append(finding)
    for priority in sorted(by_priority):
        groups.append((_T_PRIORITY.format(p=priority), by_priority[priority]))
    return groups


def _scope_text(finding: Finding) -> str:
    name = finding.scope.name or finding.scope.unit or _T_DASH
    return _T_SCOPE.format(kind=finding.scope.kind, name=name)


def _evidence_text(evidence: Evidence) -> str:
    return _T_EVIDENCE.format(
        role=evidence.role, file=evidence.file, line=evidence.line, snippet=evidence.snippet
    )


def _finding_detail_lines(finding: Finding) -> list[str]:
    """Detail lines shared by markdown and terminal, in a fixed order."""
    lines = [_scope_text(finding)]
    lines.extend(_evidence_text(e) for e in finding.evidence)
    rec = finding.recommendation
    lines.append(_T_FIX.format(tier=rec.tier.value, summary=rec.summary))
    if rec.alternatives:
        lines.append(_T_ALTERNATIVES.format(items="; ".join(rec.alternatives)))
    if finding.controls:
        lines.append(_T_CONTROLS.format(items=", ".join(finding.controls)))
    if finding.known_failure_modes:
        lines.append(_T_FAILURE_MODES.format(items="; ".join(finding.known_failure_modes)))
    if finding.notes:
        lines.append(_T_NOTE.format(text=finding.notes))
    return lines


def _unknown_head(item: UnknownItem) -> str:
    return _T_UNKNOWN_ITEM.format(category=_category(item), what=item.what, why=item.why)


def _unknown_detail_lines(item: UnknownItem) -> list[str]:
    lines: list[str] = []
    if item.how_to_resolve:
        lines.append(_T_RESOLVE.format(text=item.how_to_resolve))
    if item.file:
        lines.append(_T_FILE.format(file=item.file))
    if item.rule_ids:
        lines.append(_T_RULES.format(items=", ".join(item.rule_ids)))
    return lines


def _external_row(result: ExternalToolResult) -> tuple[str, str, str, str, str]:
    return (
        result.name,
        Status(result.status).value,
        _T_YES if result.network else _T_NO,
        result.version or _T_DASH,
        " ".join(result.argv) if result.argv else _T_DASH,
    )


def _inventory_lines(inventory: Inventory | dict[str, Any] | None) -> list[str]:
    """Counts only: the full inventory is in the JSON document, not in a rendered page."""
    inv = _as_dict(inventory)
    if not isinstance(inv, dict) or not inv:
        return [_T_NOT_INCLUDED]
    languages = inv.get("languages") or {}
    mcp = inv.get("mcp") or {}
    items = ", ".join(f"{lang} {n}" for lang, n in sorted(languages.items())) or _T_NONE
    return [
        _T_INV_UNITS.format(n=len(inv.get("units") or [])),
        _T_INV_LANGUAGES.format(n=len(languages), items=items),
        _T_INV_LLM_CALLS.format(n=len(inv.get("llm_calls") or [])),
        _T_INV_TOOLS.format(n=len(inv.get("tools") or [])),
        _T_INV_MCP.format(n=len(mcp.get("servers") or []) if isinstance(mcp, dict) else 0),
        _T_INV_HOSTS.format(n=len(inv.get("hosts") or [])),
    ]


def _baseline_line(report: Report) -> str | None:
    block = report.baseline
    if not block:
        return None
    return _T_BASELINE.format(
        file=block.get("file") or _T_DASH,
        new=block.get("new", 0),
        fixed=block.get("fixed", 0),
        unchanged=block.get("unchanged", 0),
    )


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------


def _sarif_location(evidence: Evidence) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": evidence.file, "uriBaseId": "%SRCROOT%"},
            "region": {
                "startLine": max(int(evidence.line), 1),
                "snippet": {"text": evidence.snippet},
            },
        }
    }


def _sarif_rule(
    rule_id: str,
    title: str | None,
    precision: float | None,
    findings: Sequence[Finding],
    *,
    ran: bool | None,
    experimental: bool | None,
) -> dict[str, Any]:
    buckets = {Bucket(f.bucket).value for f in findings}
    if not buckets:
        bucket: str | None = None
    elif Bucket.ASSERTED.value in buckets:
        bucket = Bucket.ASSERTED.value
    else:
        bucket = sorted(buckets)[0]
    tier = findings[0].recommendation.tier.value if findings else None
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": title or rule_id,
        "shortDescription": {"text": title or rule_id},
    }
    if findings:
        entry["help"] = {"text": findings[0].recommendation.summary}
    entry["properties"] = {
        "measured_precision": precision,
        "bucket": bucket,
        "tier": tier,
        "ran": ran,
        "experimental": experimental,
    }
    return entry


def _sarif_result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.display_id,
        "level": SARIF_LEVEL[Severity(finding.severity)],
        "message": {
            "text": _T_SARIF_MESSAGE.format(label=finding.confidence.label, title=finding.title)
        },
    }
    if finding.evidence:
        result["locations"] = [_sarif_location(finding.evidence[0])]
        if len(finding.evidence) > 1:
            result["relatedLocations"] = [
                dict(_sarif_location(e), message={"text": e.role}) for e in finding.evidence[1:]
            ]
    result["partialFingerprints"] = {SARIF_FINGERPRINT_KEY: finding.fingerprint}
    properties: dict[str, Any] = {
        "severity": Severity(finding.severity).value,
        "priority": finding.priority,
        "bucket": Bucket(finding.bucket).value,
        "basis": finding.basis.value,
        "confidence": finding.confidence.to_dict(),
        "scope": finding.scope.to_dict(),
        "sub": finding.sub,
        "report": finding.report,
        "gitignored": finding.gitignored,
        "baseline_status": finding.baseline_status,
    }
    if finding.notes is not None:
        properties["notes"] = finding.notes
    result["properties"] = properties
    return result


def to_sarif(report: Report) -> str:
    findings = list(report.findings)
    by_display_id: dict[str, list[Finding]] = {}
    for finding in findings:
        by_display_id.setdefault(finding.display_id, []).append(finding)
    rules_out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in report.rules:
        rule_id = str(entry.get("id"))
        seen.add(rule_id)
        rules_out.append(
            _sarif_rule(
                rule_id,
                entry.get("title"),
                entry.get("measured_precision"),
                by_display_id.get(rule_id, []),
                ran=entry.get("ran"),
                experimental=entry.get("experimental"),
            )
        )
    for display_id, group in by_display_id.items():
        if display_id in seen:
            continue
        seen.add(display_id)
        first = group[0]
        rules_out.append(
            _sarif_rule(
                display_id,
                first.title,
                first.confidence.precision,
                group,
                ran=True,
                experimental=None,
            )
        )
    version = (report.tool or {}).get("version") or tool_version()
    doc = {
        "schema": SCHEMA_VERSION,
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "version": version, "rules": rules_out}},
                "results": [_sarif_result(f) for f in findings],
                "properties": {
                    "disclaimer": report.disclaimer,
                    "generated_at": report.generated_at,
                    "target": _as_dict(report.target),
                    "summary": _summary_of(report),
                    "unknown": [_as_dict(u) for u in report.unknown],
                    "external_tools": [_as_dict(t) for t in report.external_tools],
                    "baseline": report.baseline,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|")


def _md_finding(finding: Finding) -> list[str]:
    head = (
        f"- **{finding.display_id}** {finding.title} -- "
        f"{Severity(finding.severity).value} {_tags(finding)}"
    )
    return [head] + [f"  - {line}" for line in _finding_detail_lines(finding)]


def to_markdown(report: Report) -> str:
    summary = _summary_of(report)
    measured, asserted_text, unknown_count = _bucket_counts(summary)
    lines: list[str] = [
        _T_MD_H1,
        "",
        f"> {report.disclaimer}",
        "",
        _summary_line(summary),
        "",
        _T_SEVERITY_LINE.format(items=_severity_items(summary)),
        "",
        _T_BUCKET_TABLE_HEADER,
        _T_TABLE_RULE_3,
        f"| {_T_BUCKET_MEASURED} | {measured} | {_T_BUCKET_MEANING_MEASURED} |",
        f"| {_T_BUCKET_ASSERTED} | {asserted_text} | {_T_BUCKET_MEANING_ASSERTED} |",
        f"| {_T_BUCKET_UNKNOWN} | {unknown_count} | {_T_BUCKET_MEANING_UNKNOWN} |",
        "",
        f"## {_T_FINDINGS}",
        "",
    ]
    findings = list(report.findings)
    if not findings:
        lines.append(_T_NONE)
    for label, group in _grouped(findings):
        lines.append(f"### {label}")
        lines.append("")
        for finding in group:
            lines.extend(_md_finding(finding))
        lines.append("")
    lines += ["", f"## {_T_UNKNOWN}", ""]
    if not report.unknown:
        lines.append(_T_NONE)
    for item in report.unknown:
        lines.append(f"- {_unknown_head(item)}")
        lines.extend(f"  - {line}" for line in _unknown_detail_lines(item))
    lines += ["", f"## {_T_EXTERNAL}", ""]
    if not report.external_tools:
        lines.append(_T_NONE)
    else:
        lines.append(_T_EXTERNAL_TABLE_HEADER)
        lines.append(_T_TABLE_RULE_5)
        for result in report.external_tools:
            cells = " | ".join(_md_cell(c) for c in _external_row(result))
            lines.append(f"| {cells} |")
    lines += ["", f"## {_T_INVENTORY}", ""]
    lines.extend(f"- {line}" for line in _inventory_lines(report.inventory))
    baseline_line = _baseline_line(report)
    if baseline_line:
        lines += ["", baseline_line]
    lines += ["", _T_EXIT.format(code=summary.get("exit_code"))]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

_INDENT = " " * 8


def _ascii(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _emit(out: list[str], text: str, indent: str = "", first: str | None = None) -> None:
    """Append `text` wrapped to WIDTH columns, ASCII-escaped, with a hanging indent."""
    wrapped = textwrap.wrap(
        _ascii(text),
        width=WIDTH,
        initial_indent=indent if first is None else first,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=False,
    )
    out.extend(wrapped or [(indent if first is None else first).rstrip()])


def _disclaimer(out: list[str], text: str) -> None:
    """One sentence per line so no sentence is cut by the column wrap."""
    for sentence in re.split(r"(?<=\.)\s+", text):
        _emit(out, sentence)


def _heading(out: list[str], title: str) -> None:
    out.append("")
    out.append(title)
    out.append("-" * len(title))


def _severity_bar(severity: Severity) -> str:
    rank = Severity(severity).rank()
    width = len(SEVERITY_ORDER)
    return "[" + "#" * (rank + 1) + "." * (width - rank - 1) + "]"


def _terminal_finding(out: list[str], finding: Finding) -> None:
    severity = Severity(finding.severity)
    head = (
        f"{_severity_bar(severity)} {finding.display_id} {severity.value} "
        f"{_tags(finding)} {finding.title}"
    )
    _emit(out, head, indent=_INDENT, first="")
    for line in _finding_detail_lines(finding):
        _emit(out, line, indent=_INDENT + "  ", first=_INDENT)


def _terminal_unknown(out: list[str], items: Sequence[UnknownItem]) -> None:
    _heading(out, _T_UNKNOWN)
    if not items:
        out.append(_T_NONE)
    for item in items:
        _emit(out, _unknown_head(item), indent=_INDENT, first="")
        for line in _unknown_detail_lines(item):
            _emit(out, line, indent=_INDENT + "  ", first=_INDENT)


def _terminal_external(out: list[str], results: Sequence[ExternalToolResult]) -> None:
    _heading(out, _T_EXTERNAL)
    if not results:
        out.append(_T_NONE)
        return
    rows = [_external_row(r) for r in results]
    header = ("name", "status", "network", "version", "argv")
    widths = [max(len(header[i]), *(len(row[i]) for row in rows)) for i in range(4)]
    for cells in (header, *rows):
        fixed = "  ".join(cells[i].ljust(widths[i]) for i in range(4))
        _emit(out, f"{fixed}  {cells[4]}", indent=_INDENT, first="")


def to_terminal(report: Report, quiet: bool = False) -> str:
    """Same order as Markdown. `quiet` keeps the disclaimer, summary line, UNKNOWN and tools."""
    summary = _summary_of(report)
    out: list[str] = [_T_TITLE, "=" * len(_T_TITLE)]
    _disclaimer(out, report.disclaimer)
    out.append("")
    _emit(out, _summary_line(summary))
    if quiet:
        _terminal_unknown(out, list(report.unknown))
        _terminal_external(out, list(report.external_tools))
        return "\n".join(out) + "\n"
    measured, asserted_text, unknown_count = _bucket_counts(summary)
    _emit(out, _T_SEVERITY_LINE.format(items=_severity_items(summary)))
    buckets = (
        f"{_T_BUCKET_MEASURED} {measured} | {_T_BUCKET_ASSERTED} {asserted_text} | "
        f"{_T_BUCKET_UNKNOWN} {unknown_count}"
    )
    _emit(out, _T_BUCKET_LINE.format(items=buckets))
    _heading(out, _T_FINDINGS)
    findings = list(report.findings)
    if not findings:
        out.append(_T_NONE)
    for label, group in _grouped(findings):
        out.append("")
        out.append(label)
        for finding in group:
            _terminal_finding(out, finding)
    _terminal_unknown(out, list(report.unknown))
    _terminal_external(out, list(report.external_tools))
    _heading(out, _T_INVENTORY)
    for line in _inventory_lines(report.inventory):
        _emit(out, line)
    baseline_line = _baseline_line(report)
    if baseline_line:
        out.append("")
        _emit(out, baseline_line)
    out.append("")
    _emit(out, _T_EXIT.format(code=summary.get("exit_code")))
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def render(report: Report, fmt: str, *, quiet: bool = False) -> str:
    """One renderer per run. `quiet` only affects the terminal format."""
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif(report)
    if fmt == "markdown":
        return to_markdown(report)
    if fmt == "terminal":
        return to_terminal(report, quiet=quiet)
    raise ValueError(f"unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")
