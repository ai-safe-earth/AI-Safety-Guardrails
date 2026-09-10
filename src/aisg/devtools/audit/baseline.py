"""aisg/devtools/audit/baseline.py
----------------------------
Fingerprint baseline for `aisg audit`: load, write, amend and diff. Only `new` findings
count toward the exit code; `unchanged` ones are still rendered, still findings.

A baseline may carry an `accepted` list next to `fingerprints`: one entry per fingerprint
that a human looked at, with the reason it stays. `load_baseline` validates the list (a
reason is mandatory, and the fingerprint must also be in `fingerprints`) but returns the
same set either way: a fingerprint without a reason is a suppression, not an acceptance,
and the committed `audit-baseline.json` is held to the stricter shape by its own test.

A baseline written by this version also carries a trailing `index`: `{fingerprint: {rule,
file, title}}`, so a later run can name a fingerprint it no longer reports, and `amend_baseline`
can fill `rule`/`file` for an accepted entry without re-scanning. Older files without the
index still load; they simply yield less detail.

A reason is checked on the way in (`amend_baseline`, the one writer that takes free text
from the operator) and again on the way out (`read_baseline`, so a hand-edited file is held
to the same bar): it must be non-empty, a single line of printable ASCII (no newline,
tab or other control character: it is rendered as one `accepted: <reason>` line), carry
no verdict language (the `report.BANNED_PHRASES` list and the banned word) and contain
nothing secret-shaped, because the baseline file is itself scanned by the audit and would
otherwise reproduce the finding it accepts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from aisg.devtools.audit.model import SCHEMA_VERSION, Finding, Report, now_iso, redact

__all__ = [
    "BASELINE_KIND",
    "REPORT_KIND",
    "BaselineDiff",
    "BaselineDocument",
    "BaselineError",
    "amend_baseline",
    "diff",
    "load_accepted",
    "load_baseline",
    "load_generated_at",
    "load_index",
    "parse_accept",
    "read_baseline",
    "write_baseline",
]

BASELINE_KIND = "audit-baseline"
REPORT_KIND = "audit"
TOOL_NAME = "aisg-audit"

# The one word the audit never says about a target. Built from fragments so this module
# does not carry it as a literal; the same construction is pinned in the report tests.
_BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# Control characters (below space, plus DEL): ASCII, but not a single printable line.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_INDEX_FIELDS = ("rule", "file", "title")


class BaselineError(Exception):
    """A baseline file that cannot be used. The message is a single line; main maps it to exit 2."""


def _read_document(path: Path) -> dict[str, Any]:
    """Parse `path` as a JSON object with the audit schema; anything else is a BaselineError."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise BaselineError(f"baseline {path.as_posix()}: {reason}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        # A file in another encoding is a baseline error like any other, not a traceback
        # class name on stderr.
        raise BaselineError(f"baseline {path.as_posix()}: not UTF-8 ({exc})") from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline {path.as_posix()}: invalid JSON ({exc.msg} at line {exc.lineno})"
        ) from exc
    except ValueError as exc:
        raise BaselineError(f"baseline {path.as_posix()}: invalid JSON ({exc})") from exc
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

    Every entry needs a non-empty `reason` that `_check_reason` would have let in, and a
    `fingerprint` that is also listed under `fingerprints`; the error names the offending
    fingerprint so it can be found in the file. An absent `accepted` key is fine (a
    `--write-baseline` document without reasons has none).
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
        # The same bar as `--accept`: a reason edited by hand into the file is no exception.
        try:
            reasons[fingerprint] = _check_reason(fingerprint, reason)
        except BaselineError as exc:
            raise BaselineError(f"baseline {path.as_posix()}: {exc}") from None
    return reasons


def _validate_index(doc: dict[str, Any], path: Path) -> dict[str, dict[str, Any]]:
    """
    The optional `index` block as `{fingerprint: {rule, file, title}}`. Absent means an older
    file and yields `{}`; present but malformed is a BaselineError. Only the three named
    fields are kept, each a string or `None`.
    """
    raw = doc.get("index")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise BaselineError(f"baseline {path.as_posix()}: 'index' is not an object")
    index: dict[str, dict[str, Any]] = {}
    for fingerprint, entry in raw.items():
        if not isinstance(fingerprint, str) or not fingerprint:
            raise BaselineError(f"baseline {path.as_posix()}: index key is not a fingerprint")
        if not isinstance(entry, dict):
            raise BaselineError(
                f"baseline {path.as_posix()}: index entry {fingerprint} is not an object"
            )
        index[fingerprint] = {
            name: entry.get(name) if isinstance(entry.get(name), str) else None
            for name in _INDEX_FIELDS
        }
    return index


@dataclass
class BaselineDocument:
    """
    A parsed baseline (or full report used as one). `accepted` and `index` are empty for a
    report and for an older baseline file; `generated_at` is `None` when the file has none.
    `raw` is the parsed JSON, kept so `amend_baseline` can rewrite what it did not touch.
    """

    kind: str
    fingerprints: set[str]
    accepted: dict[str, str] = field(default_factory=dict)
    index: dict[str, dict[str, Any]] = field(default_factory=dict)
    generated_at: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def read_baseline(path: Path) -> BaselineDocument:
    """
    Read and validate a baseline file or a full audit report, once.

    Accepts `{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [...]}` (with an
    optional `accepted` list and `index` block, both validated) or
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
    generated_at = doc.get("generated_at")
    result = BaselineDocument(
        kind=str(kind),
        fingerprints=fingerprints,
        generated_at=generated_at if isinstance(generated_at, str) else None,
        raw=doc,
    )
    if kind == BASELINE_KIND:
        result.accepted = _validate_accepted(doc, fingerprints, path)
        result.index = _validate_index(doc, path)
    return result


def load_baseline(path: Path) -> set[str]:
    """The fingerprint set of a baseline file or a full audit report (see `read_baseline`)."""
    return read_baseline(path).fingerprints


def load_accepted(path: Path) -> dict[str, str]:
    """
    `{fingerprint: reason}` from a baseline file's `accepted` list, after the same validation
    `load_baseline` applies. A full audit report, or a baseline without the list, yields `{}`.
    """
    return read_baseline(path).accepted


def load_index(path: Path) -> dict[str, dict[str, Any]]:
    """`{fingerprint: {rule, file, title}}` from a baseline's `index`; `{}` for a report or an older file."""
    return read_baseline(path).index


def load_generated_at(path: Path) -> str | None:
    """The `generated_at` string of a baseline file or report, or `None` when it has none."""
    return read_baseline(path).generated_at


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


def _index_of(findings: Iterable[Finding]) -> dict[str, dict[str, str]]:
    """
    The `index` block: rule (display id), file (`file:line`) and title per fingerprint, from
    the first finding that carries it, keyed in the same sorted order as `fingerprints`.
    """
    first: dict[str, Finding] = {}
    for finding in findings:
        if finding.fingerprint and finding.fingerprint not in first:
            first[finding.fingerprint] = finding
    return {
        fingerprint: {
            "rule": finding.display_id,
            "file": _location_of(finding),
            "title": finding.title,
        }
        for fingerprint, finding in sorted(first.items())
    }


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


def _dump(doc: dict[str, Any], path: Path) -> None:
    # Like `main._write_output`: the parent is created (`.aisg-audit/` usually does not
    # exist on the first run, and the scan and the render are already done by now), and
    # LF on every platform, because a baseline is committed and a Windows write must not
    # turn into a whole-file diff on the next Linux refresh.
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(doc, indent=2, ensure_ascii=True) + "\n")


def write_baseline(
    report_or_findings: Report | Iterable[Finding],
    path: Path,
    reasons: Mapping[str, str] | None = None,
) -> None:
    """
    Write the baseline document: schema, kind, generated_at, tool, fingerprints (sorted,
    unique), then, when `reasons` (`{fingerprint: reason}`) is given, an `accepted` list with
    `rule` (display id) and `file` (`file:line` of the first evidence) per reason, and last
    the `index` block naming every fingerprint's rule, file and title.
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
    doc["index"] = _index_of(findings)
    _dump(doc, Path(path))


# ---------------------------------------------------------------------------
# Amend: record a reason for a fingerprint the baseline already carries
# ---------------------------------------------------------------------------


def parse_accept(text: str) -> tuple[str, str]:
    """
    Split one `--accept FINGERPRINT=REASON` argument on its first `=`. The fingerprint must
    be non-empty; the reason is validated later by `amend_baseline`, where the file is known.
    """
    fingerprint, sep, reason = str(text).partition("=")
    fingerprint = fingerprint.strip()
    if not sep or not fingerprint:
        raise BaselineError(f"--accept expects FINGERPRINT=REASON, got {text!r}")
    return fingerprint, reason.strip()


def _check_reason(fingerprint: str, reason: str) -> str:
    """
    The reason as it will be written, or a `BaselineError` saying why it cannot be. A reason
    says why a finding stays; it never says the finding is fine, and it never carries the
    secret it may be about, because the baseline file is scanned by the audit too.
    """
    # Local import: report.py imports BaselineDiff from this module.
    from aisg.devtools.audit.report import BANNED_PHRASES

    text = reason.strip()
    if not text:
        raise BaselineError(f"accepted reason for {fingerprint} is empty")
    if not text.isascii():
        raise BaselineError(f"accepted reason for {fingerprint} is not ASCII")
    if _CONTROL_RE.search(text):
        # A newline, tab or other control character is ASCII too, but the reason is
        # rendered as one `accepted: <reason>` line in the terminal and markdown reports
        # (a newline there breaks out of the markdown list item).
        raise BaselineError(
            f"accepted reason for {fingerprint} must be a single line of printable ASCII"
        )
    lowered = text.lower()
    if _BANNED_WORD_RE.search(text) or any(phrase in lowered for phrase in BANNED_PHRASES):
        raise BaselineError(
            f"accepted reason for {fingerprint} reads as a verdict; a reason says why the "
            "finding stays, not that the target is safe"
        )
    if redact(text) != text:
        raise BaselineError(
            f"accepted reason for {fingerprint} contains a secret-shaped token; the baseline "
            "file is scanned by the audit and would report it"
        )
    return text


def amend_baseline(path: Path, accepts: Mapping[str, str]) -> int:
    """
    Record `accepts` (`{fingerprint: reason}`) in the baseline at `path` and rewrite it in
    the pinned key order. Returns the number of reasons recorded.

    Refused with `BaselineError`: a file that is not `kind: audit-baseline` (a report cannot
    carry acceptances), a fingerprint the file does not list, and any reason `_check_reason`
    rejects. An existing entry for the same fingerprint has its reason replaced in place;
    a new entry is appended with `rule`/`file` from the `index` (or `None` when the file
    predates the index). Nothing is written until every accept has passed.
    """
    path = Path(path)
    document = read_baseline(path)
    if document.kind != BASELINE_KIND:
        raise BaselineError(
            f"baseline {path.as_posix()}: kind {document.kind!r} cannot be amended; "
            f"only {BASELINE_KIND!r} carries accepted reasons"
        )
    if not accepts:
        raise BaselineError(f"baseline {path.as_posix()}: nothing to accept")
    checked: dict[str, str] = {}
    for fingerprint, reason in accepts.items():
        if fingerprint not in document.fingerprints:
            raise BaselineError(
                f"baseline {path.as_posix()}: fingerprint {fingerprint} is not in 'fingerprints'; "
                "run the audit with --write-baseline first"
            )
        checked[fingerprint] = _check_reason(fingerprint, str(reason))

    raw = document.raw
    existing = raw.get("accepted") if isinstance(raw.get("accepted"), list) else []
    accepted: list[dict[str, Any]] = []
    for entry in existing:
        fingerprint = entry["fingerprint"]
        accepted.append(
            {
                "fingerprint": fingerprint,
                "rule": entry.get("rule"),
                "file": entry.get("file"),
                "reason": checked.get(fingerprint, entry["reason"]),
            }
        )
    present = {entry["fingerprint"] for entry in accepted}
    for fingerprint, reason in checked.items():
        if fingerprint in present:
            continue
        named = document.index.get(fingerprint, {})
        accepted.append(
            {
                "fingerprint": fingerprint,
                "rule": named.get("rule"),
                "file": named.get("file"),
                "reason": reason,
            }
        )

    doc: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "generated_at": raw.get("generated_at"),
        "tool": raw.get("tool"),
        "fingerprints": sorted(document.fingerprints),
        "accepted": accepted,
    }
    if "index" in raw:
        doc["index"] = raw["index"]
    _dump(doc, path)
    return len(checked)


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


@dataclass
class BaselineDiff:
    """
    Findings partitioned against a baseline. `gone` holds the baseline fingerprints no
    finding carries any more; `no_longer_reported` names each of them (rule, file, title)
    when the baseline's `index` knows them. Neither is called "fixed" anywhere: a rename or
    a move produces the same absence. `accepted` lists the baseline's reasons that matched a
    finding in this run. `kind` is the compared document's kind (`audit-baseline` or
    `audit`): a report used as a baseline carries no reasons, and a renderer says so rather
    than "none recorded".

    `to_dict` carries no count for `gone`: the list is `no_longer_reported`, one entry per
    fingerprint, and its length is the count.
    """

    new: list[Finding] = field(default_factory=list)
    gone: list[str] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)
    file: str = ""
    accepted: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str | None = None
    no_longer_reported: list[dict[str, Any]] = field(default_factory=list)
    kind: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "kind": self.kind,
            "new": len(self.new),
            "unchanged": len(self.unchanged),
            "accepted": [dict(entry) for entry in self.accepted],
            "generated_at": self.generated_at,
            "no_longer_reported": [dict(entry) for entry in self.no_longer_reported],
        }


def _named(fingerprint: str, index: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    entry = index.get(fingerprint)
    if not entry:
        return {"fingerprint": fingerprint}
    return {"fingerprint": fingerprint, **{name: entry.get(name) for name in _INDEX_FIELDS}}


def diff(
    findings: Iterable[Finding],
    baseline: set[str],
    file: str,
    *,
    accepted: Mapping[str, str] | None = None,
    index: Mapping[str, Mapping[str, Any]] | None = None,
    generated_at: str | None = None,
    kind: str | None = None,
) -> BaselineDiff:
    """
    Partition `findings` into new/unchanged by fingerprint and set `Finding.baseline_status`
    in place. Fingerprints in the baseline that no finding carries any more are `gone`.

    With `accepted` (`{fingerprint: reason}`), every finding whose fingerprint has a reason
    gets `Finding.accepted_reason`, and the diff's `accepted` list carries one entry per
    such finding (rule/file from `index` when the baseline names them, else from the
    finding). `index` also names the gone fingerprints in `no_longer_reported`. `kind` is
    passed through to the diff (`BaselineDocument.kind`).
    """
    reasons = dict(accepted or {})
    named = index or {}
    result = BaselineDiff(file=str(file).replace("\\", "/"), generated_at=generated_at, kind=kind)
    seen: set[str] = set()
    listed: set[str] = set()
    for finding in findings:
        seen.add(finding.fingerprint)
        if finding.fingerprint in baseline:
            finding.baseline_status = "unchanged"
            result.unchanged.append(finding)
        else:
            finding.baseline_status = "new"
            result.new.append(finding)
        reason = reasons.get(finding.fingerprint)
        if reason is None:
            continue
        finding.accepted_reason = reason
        if finding.fingerprint in listed:
            continue
        listed.add(finding.fingerprint)
        entry = named.get(finding.fingerprint) or {}
        result.accepted.append(
            {
                "fingerprint": finding.fingerprint,
                "rule": entry.get("rule") or finding.display_id,
                "file": entry.get("file") or _location_of(finding),
                "reason": reason,
            }
        )
    result.gone = sorted(baseline - seen)
    result.no_longer_reported = [_named(fingerprint, named) for fingerprint in result.gone]
    return result
