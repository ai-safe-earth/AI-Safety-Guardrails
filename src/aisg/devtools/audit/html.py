"""aisg/devtools/audit/html.py
--------------------------
The html renderer for `aisg audit`: one standalone page, no script, no external
resource, ASCII only. Document 1 (no baseline) is the survey: the system map drawn
from the inventory, one section per subsystem with the findings placed on it, and
the plan. Document 2 (`--baseline`) adds what changed, what is left and what is still
UNKNOWN.

Every sentence the page emits is a fixed string in `TEMPLATES`; `report.check_templates`
scans them with the terminal's. Nothing user-controlled reaches the page unescaped, and
every non-ASCII character becomes a numeric entity, so the file is ASCII whatever the
audited tree contained. Line 1 is the audit's own ignore marker: a page written into the
audited tree is skipped by the next walk instead of re-reporting every snippet on it.

Rules that hold here and nowhere weaker:

- No severity colour. The map has neutral borders; `--warn` is the UNKNOWN box and
  nothing else, and no `--good` token exists.
- Every box and every section prints its UNKNOWN count and `[UNMEASURED]`, at zero
  findings too; "no surface found" is a fact about the inventory, "reported 0" a fact
  about the rules, and the page says both.
- "no longer reported", never a verdict: a fingerprint absent from this run is exactly
  that, and a rename produces it as readily as a change.
- Fixed coordinates, no layout solver: identical input, identical bytes.
"""

from __future__ import annotations

import html as _html
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from aisg.devtools.audit.model import Finding, Report, Severity, UnknownItem, redact
from aisg.devtools.audit.patterns import LANG_BY_EXT, OWN_HTML_MARKER_LINE, is_protected_path
from aisg.devtools.audit.report import (
    _T_BASELINE,
    _T_DASH,
    _T_EXIT,
    _T_FIX,
    _T_NO,
    _T_NONE,
    _T_NOTE,
    _T_REPORTED,
    _T_REPORTED_UNKNOWN,
    _T_UNKNOWN,
    _T_UNMEASURED,
    _T_YES,
    DISTRIBUTION,
    SCHEMA_VERSION,
    _as_dict,
    _external_row,
    _inventory_lines,
    _plural,
    _summary_line,
    _summary_of,
    _tags,
    _unknown_detail_lines,
    _unknown_head,
    tool_version,
)
from aisg.devtools.audit.rules import NOT_ATTRIBUTED, SUBSYSTEMS, Subsystem, subsystem_of
from aisg.devtools.audit.walk import ROOT_UNIT_ID

__all__ = ["TEMPLATES", "render_html"]

# Caps. Beyond them the page says "+N more in the JSON"; it never drops silently.
MAX_FACTS = 8
MAX_FINDINGS_PER_SECTION = 12
# Characters of 9px monospace that fit a 176px box with its padding.
_BOX_FACT_WIDTH = 30

# ---------------------------------------------------------------------------
# Templates: every fixed string this renderer emits. `report.check_templates` scans
# them (through `report.all_templates`) and nothing else.
# ---------------------------------------------------------------------------

_T_MARKER = OWN_HTML_MARKER_LINE  # "<!-- # aisg-audit: ignore-file -->", shared with walk
_T_PAGE_TITLE = "aisg audit: {target}"
_T_H1 = "AI safety audit: {target}"
_T_DOC1 = (
    "Document 1 of 2: the first survey. A later run with --baseline produces document 2, "
    "the comparison."
)
_T_DOC2 = "Document 2 of 2: compared against a baseline."
_T_HEAD_FACTS = "commit {sha} -- uncommitted changes: {dirty} -- generated {generated_at} -- {tool}"
_T_UNKNOWN_WORD = "unknown"
_T_COMPARED_NONE = "Compared against: none -- this is the first survey"
_T_COMPARED = "Compared against: {file}, {age}"
_T_AGE = "written {n} {unit} ago"
_T_AGE_UNKNOWN = "age unknown"
_T_UNIT_DAY = "day"
_T_UNIT_HOUR = "hour"
_T_UNIT_MINUTE = "minute"
_T_REASONS = "operator-recorded reasons: {n}"
_T_REASONS_NONE = "operator-recorded reasons: none"
_T_REASONS_REPORT = (
    "operator-recorded reasons: none: the baseline was a report, not a baseline file"
)
_T_RESOLVED_FAIL_ON = "fail-on: {fail_on}"
_T_RESOLVED_EXCLUDE = "exclude: {items}"
_T_READ_FIRST = "Read this first"
_T_ABSENCE = "Absence of a finding is not evidence of safety."
_T_UNKNOWN_COUNT = (
    "UNKNOWN: {n} item{s} the audit could not establish (listed in section {section})"
)
_T_BANNER_NO_RULES = (
    "Rules did not run. This page holds the inventory and the map only: there is no finding "
    "because nothing was checked, and there is no plan."
)
_T_SINCE = "Since the baseline"
_T_WHAT_CHANGED = "What changed"
_T_WHAT_LEFT = "What is left"
_T_WHAT_UNKNOWN = "What we still do not know"
_T_NO_LONGER = "No longer reported: {n}"
_T_NO_LONGER_NOTE = "no longer reported at this fingerprint; a rename or a move also produces this"
_T_NO_LONGER_ROW = "{rule} {title} -- {file}"
_T_NO_LONGER_UNNAMED = "{fingerprint} -- not in this run (the baseline did not record rule or file)"
_T_NEW_SINCE = "New since the baseline: {n}"
_T_FINDING_ROW = "{id} {title} -- {file}"
_T_LEFT = "{n} open row{s} in the plan; see section {section}, Remaining actions"
_T_STILL_UNKNOWN = "UNKNOWN: {n} item{s}; see section {section}"
_T_MAP = "System map"
_T_FIG_TITLE = "Fig. 1: system map of {target}"
_T_FIG_CAPTION = (
    "Fig. 1 -- drawn from the inventory, not traced at runtime. {k} of {total} rules ran. "
    "Deliberately omitted: data flow between tools, third-party services, anything the "
    "walk skipped."
)
_T_ROW_FLOW = "flow, left to right"
_T_ROW_FOUNDATIONS = "foundations"
_T_ROW_REST = "everything else"
_T_BOX_STATUS = "reported {n} | UNKNOWN {m}"
_T_BOX_RULES = "rules ran {k}/{total}"
_T_BOX_NOT_ATTRIBUTED = "Not attributed / UNKNOWN"
_T_BOX_NOT_ATTRIBUTED_LINE = (
    "UNKNOWN not attributed to a rule: {m} | reported {n} | rules ran {k}/{total}"
)
_T_BOX_FACT = "{n} {key}: {labels}"
_T_BOX_FACT_ONE = "{key}: {label}"
# The one inventory key whose fact name is not its own name with `_` as a space.
_T_KEY_MCP = "mcp servers"
_T_MORE_SHORT = "+{n}"
_T_NO_SURFACE = "no surface found"
_T_INV_NOT_INCLUDED = "(inventory not included)"
_T_SUBSYSTEMS = "Subsystems"
_T_SECTION_STATUS = "reported {n} | UNKNOWN {m} | rules ran {k}/{total}"
_T_NOT_ATTRIBUTED_TITLE = "Not attributed"
_T_FACTS = "From the inventory"
_T_FACT = "{key}: {label}"
_T_FACT_FILE = "{key}: {label} -- {file}"
_T_FACT_AT = "{key}: {label} -- {file}:{line}"
_T_MORE = "+{n} more in the JSON"
_T_LBL_PINNED = "{model} (pinned)"
_T_LBL_UNPINNED = "{model} (unpinned)"
_T_LBL_LOOP_CAPPED = "loop (capped)"
_T_LBL_LOOP_UNCAPPED = "loop (no cap found)"
_T_LBL_HITS = "{literal} literal hit{s} in code, {config} in config"
_T_LBL_HITS_SHORT = "{literal} literal, {config} config"
_T_LBL_CARD = "{file} (risk_tier: {tier})"
_T_LBL_CI = "{file} ({n} unsafe step{s})"
_T_FINDINGS_HEAD = "Findings placed here"
_T_UNKNOWN_HERE = "UNKNOWN items counted on this box: {n}; see section {section}"
_T_FINDING_HEAD = "{id} {title} -- {severity} {tags}"
_T_EVIDENCE_HTML = "[{role}] {file}:{line}"
_T_PKG_SAME = (
    "aisg: {symbols} -- implements the control this rule asks for. Leaves open: {leaves_open}"
)
_T_PKG_OTHER = (
    "aisg: {symbols} -- a different control ({mechanism}), in addition to, not instead of: "
    "{leaves_open}"
)
_T_PKG_NONE = "outside the package: {summary}"
_T_PKG_PYTHON_ONLY = (
    "aisg controls are Python-only; the control still applies, this symbol does not."
)
_T_PKG_PROTECTED = "this edit needs your approval of the specific diff"
_T_ACCEPTED = "Operator-recorded reason: {reason}"
_T_ACCEPTED_MOVED = "recorded at {old}, now reported at {new}"
_T_PLAN = "Plan"
_T_PLAN_HEADERS: tuple[str, ...] = (
    "#",
    "id",
    "severity",
    "subsystem",
    "control",
    "tier",
    "aisg",
    "who",
    "status",
)
_T_AISG_SAME = "same control"
_T_AISG_OTHER = "other control"
_T_AISG_NONE = "none"
_T_AISG_CELL = "{symbols} ({kind})"
_T_WHO_PACKAGE = "package"
_T_WHO_APPROVAL = "you, approval needed"
_T_WHO_YOU = "you"
_T_STATUS_ACCEPTED = "accepted"
_T_PLAN_ROWS = "Rows the package can implement (walk the table top-down; do not skip a row above)"
_T_PLAN_ROW = "#{n} {id} {title} -- {symbols}. Leaves open: {leaves_open}"
_T_PLAN_WIRING = (
    "Wiring a control is not evidence the finding is gone: re-run the audit and read document 2."
)
_T_REMAINING = "Remaining actions"
_T_GROUP_OUTSIDE = "Outside the package"
_T_GROUP_PACKAGE = "Package control wired or available, but leaves open"
_T_GROUP_PACKAGE_ROW = "{id} {title} -- {symbols}; leaves open: {leaves_open}"
_T_GROUP_ACCEPTED = "Accepted with a recorded reason"
_T_GROUP_ACCEPTED_ROW = "{id} {title} -- the operator wrote: {reason}"
_T_GROUP_UNKNOWN = "Still UNKNOWN"
_T_EXTERNAL_SECTION = "External tools and reports read"
_T_EXTERNAL_HEADERS: tuple[str, ...] = ("name", "status", "network", "version", "argv")
_T_REPORTS_READ = "Reports read from disk"
_T_REPORT_READ = "{source} -- {kind} {tag}"
_T_INVENTORY_HEAD = "Inventory counts"
_T_FOOTER_GENERATED = "generated by {tool}; the JSON report is authoritative"

# Page chrome. Tokens on `:root`, one dark override; `--warn` is the UNKNOWN box's
# border and nothing else. There is deliberately no `--good`, and no length is a
# percentage: the page prints no percentage anywhere, its stylesheet included.
_CSS = """
:root{--bg:#f7f6f2;--panel:#ffffff;--fg:#1d1d1b;--muted:#5a5955;--rule:#d9d6cd;
--code-bg:#f0eee7;--code-fg:#2a2a27;--infra:#5b6470;--warn:#b7791f;--accent:#2f5d8a;
color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--panel:#1f1f1d;--fg:#e8e6df;
--muted:#a7a49b;--rule:#3a3935;--code-bg:#262523;--code-fg:#e0ddd4;--infra:#9aa3ad;
--warn:#e0a63a;--accent:#8ab4e8}}
html{background:var(--bg);color:var(--fg)}
body{margin:0;font:15px/1.5 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 20px 48px}
h1{font-size:1.5em;margin:.4em 0}
h2{font-size:1.2em;margin:1.6em 0 .5em;border-bottom:1px solid var(--rule);padding-bottom:.2em}
h3{font-size:1.05em;margin:1.2em 0 .4em}
h4{font-size:1em;margin:.8em 0 .3em}
p{margin:.35em 0}
ul,ol{margin:.3em 0 .6em;padding-left:1.4em}
a{color:var(--accent)}
.sub{color:var(--muted);margin:.15em 0}
.take{border-left:4px solid var(--accent);background:var(--panel);padding:10px 14px;margin:1em 0}
.banner{border:1px dashed var(--warn);padding:10px 14px;margin:1em 0}
.fig{background:var(--panel);border:1px solid var(--rule);border-radius:8px;padding:8px;
overflow-x:auto}
.fig svg{display:block;max-width:calc(100vw - 80px);height:auto}
.figcap{color:var(--muted);font-size:.9em}
table{border-collapse:collapse;font-size:.9em;margin:.5em 0}
th,td{border:1px solid var(--rule);padding:4px 8px;text-align:left;vertical-align:top}
code{background:var(--code-bg);color:var(--code-fg);padding:1px 4px;border-radius:3px;
font:.92em ui-monospace,Menlo,Consolas,monospace}
.finding{border:1px solid var(--rule);border-radius:6px;padding:6px 12px;margin:.6em 0;
background:var(--panel)}
.finding h4{margin:.2em 0 .4em}
.status{font:.9em ui-monospace,Menlo,Consolas,monospace;color:var(--muted)}
.svgt{font:600 11.5px -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:var(--fg)}
.svgs{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--muted)}
.svgf{font:9px ui-monospace,Menlo,Consolas,monospace;fill:var(--muted)}
.svgm{font:10px ui-monospace,Menlo,Consolas,monospace;fill:var(--fg)}
.svgl{font:11px -apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:var(--muted)}
footer{margin-top:2em;border-top:1px solid var(--rule);padding-top:1em;color:var(--muted);
font-size:.9em}
""".strip()

TEMPLATES: tuple[str, ...] = (
    _T_MARKER,
    _T_PAGE_TITLE,
    _T_H1,
    _T_DOC1,
    _T_DOC2,
    _T_HEAD_FACTS,
    _T_UNKNOWN_WORD,
    _T_COMPARED_NONE,
    _T_COMPARED,
    _T_AGE,
    _T_AGE_UNKNOWN,
    _T_UNIT_DAY,
    _T_UNIT_HOUR,
    _T_UNIT_MINUTE,
    _T_REASONS,
    _T_REASONS_NONE,
    _T_REASONS_REPORT,
    _T_RESOLVED_FAIL_ON,
    _T_RESOLVED_EXCLUDE,
    _T_READ_FIRST,
    _T_ABSENCE,
    _T_UNKNOWN_COUNT,
    _T_BANNER_NO_RULES,
    _T_SINCE,
    _T_WHAT_CHANGED,
    _T_WHAT_LEFT,
    _T_WHAT_UNKNOWN,
    _T_NO_LONGER,
    _T_NO_LONGER_NOTE,
    _T_NO_LONGER_ROW,
    _T_NO_LONGER_UNNAMED,
    _T_NEW_SINCE,
    _T_FINDING_ROW,
    _T_LEFT,
    _T_STILL_UNKNOWN,
    _T_MAP,
    _T_FIG_TITLE,
    _T_FIG_CAPTION,
    _T_ROW_FLOW,
    _T_ROW_FOUNDATIONS,
    _T_ROW_REST,
    _T_BOX_STATUS,
    _T_BOX_RULES,
    _T_BOX_NOT_ATTRIBUTED,
    _T_BOX_NOT_ATTRIBUTED_LINE,
    _T_BOX_FACT,
    _T_BOX_FACT_ONE,
    _T_KEY_MCP,
    _T_MORE_SHORT,
    _T_NO_SURFACE,
    _T_INV_NOT_INCLUDED,
    _T_SUBSYSTEMS,
    _T_SECTION_STATUS,
    _T_NOT_ATTRIBUTED_TITLE,
    _T_FACTS,
    _T_FACT,
    _T_FACT_FILE,
    _T_FACT_AT,
    _T_MORE,
    _T_LBL_PINNED,
    _T_LBL_UNPINNED,
    _T_LBL_LOOP_CAPPED,
    _T_LBL_LOOP_UNCAPPED,
    _T_LBL_HITS,
    _T_LBL_HITS_SHORT,
    _T_LBL_CARD,
    _T_LBL_CI,
    _T_FINDINGS_HEAD,
    _T_UNKNOWN_HERE,
    _T_FINDING_HEAD,
    _T_EVIDENCE_HTML,
    _T_PKG_SAME,
    _T_PKG_OTHER,
    _T_PKG_NONE,
    _T_PKG_PYTHON_ONLY,
    _T_PKG_PROTECTED,
    _T_ACCEPTED,
    _T_ACCEPTED_MOVED,
    _T_PLAN,
    *_T_PLAN_HEADERS,
    _T_AISG_SAME,
    _T_AISG_OTHER,
    _T_AISG_NONE,
    _T_AISG_CELL,
    _T_WHO_PACKAGE,
    _T_WHO_APPROVAL,
    _T_WHO_YOU,
    _T_STATUS_ACCEPTED,
    _T_PLAN_ROWS,
    _T_PLAN_ROW,
    _T_PLAN_WIRING,
    _T_REMAINING,
    _T_GROUP_OUTSIDE,
    _T_GROUP_PACKAGE,
    _T_GROUP_PACKAGE_ROW,
    _T_GROUP_ACCEPTED,
    _T_GROUP_ACCEPTED_ROW,
    _T_GROUP_UNKNOWN,
    _T_EXTERNAL_SECTION,
    *_T_EXTERNAL_HEADERS,
    _T_REPORTS_READ,
    _T_REPORT_READ,
    _T_INVENTORY_HEAD,
    _T_FOOTER_GENERATED,
    _CSS,
)

# ---------------------------------------------------------------------------
# Escaping, clipping, dates
# ---------------------------------------------------------------------------


def _esc(value: Any) -> str:
    """HTML-escape (quotes included), then encode every non-ASCII character as an entity."""
    return _asciify(_html.escape(str(value), quote=True))


def _asciify(text: str) -> str:
    if text.isascii():
        return text
    return "".join(ch if ord(ch) < 128 else f"&#x{ord(ch):x};" for ch in text)


def _cell_width(ch: str) -> int:
    """Two cells for a wide or fullwidth character: a CJK name takes twice the box."""
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def _width(text: str) -> int:
    return sum(_cell_width(ch) for ch in text)


def _clip(text: str, width: int) -> str:
    """
    Shorten to `width` cells for a fixed-width SVG box; a page section is never clipped.
    Measured on the text before `_esc`: the entity a wide character becomes is eight
    ASCII characters on the wire and still one glyph two cells wide on the screen.
    """
    if _width(text) <= width:
        return text
    kept, used, budget = [], 0, max(width - 3, 1)
    for ch in text:
        used += _cell_width(ch)
        if used > budget:
            break
        kept.append(ch)
    return "".join(kept) + "..."


_ISO_Z = "%Y-%m-%dT%H:%M:%SZ"


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        return datetime.strptime(text, _ISO_Z).replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    # 3.10's fromisoformat rejects a trailing Z; the audit's own stamps carry one.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _age_text(older: Any, newer: Any) -> str:
    """`written N days ago` from two ISO stamps; `age unknown` when either is missing or odd."""
    start, end = _parse_iso(older), _parse_iso(newer)
    if start is None or end is None:
        return _T_AGE_UNKNOWN
    seconds = max(int((end - start).total_seconds()), 0)
    days, hours, minutes = seconds // 86400, seconds // 3600, seconds // 60
    if days >= 1:
        return _T_AGE.format(n=days, unit=_T_UNIT_DAY + _plural(days))
    if hours >= 1:
        return _T_AGE.format(n=hours, unit=_T_UNIT_HOUR + _plural(hours))
    return _T_AGE.format(n=minutes, unit=_T_UNIT_MINUTE + _plural(minutes))


# ---------------------------------------------------------------------------
# Placement: findings, UNKNOWN items and rules onto subsystems
# ---------------------------------------------------------------------------


@dataclass
class _Box:
    key: str
    title: str
    findings: list[Finding] = field(default_factory=list)
    unknown: int = 0
    ran: int = 0
    total: int = 0


def _place(report: Report) -> dict[str, _Box]:
    """One `_Box` per subsystem plus `NOT_ATTRIBUTED`, always present, counts at zero included."""
    boxes = {sub.key: _Box(sub.key, sub.title) for sub in SUBSYSTEMS}
    boxes[NOT_ATTRIBUTED] = _Box(NOT_ATTRIBUTED, _T_NOT_ATTRIBUTED_TITLE)
    for finding in report.findings:
        boxes[subsystem_of(finding.display_id or finding.id)].findings.append(finding)
    for item in report.unknown:
        rule_ids = tuple(getattr(item, "rule_ids", ()) or ())
        keys = {subsystem_of(str(rule_id)) for rule_id in rule_ids} or {NOT_ATTRIBUTED}
        for key in keys:
            boxes[key].unknown += 1
    for row in report.rules or ():
        entry = row if isinstance(row, dict) else {}
        box = boxes[subsystem_of(str(entry.get("id") or ""))]
        box.total += 1
        if entry.get("ran"):
            box.ran += 1
    return boxes


def _rules_ran(report: Report) -> tuple[int, int]:
    rows = [row for row in (report.rules or ()) if isinstance(row, dict)]
    return sum(1 for row in rows if row.get("ran")), len(rows)


# ---------------------------------------------------------------------------
# Inventory facts per subsystem
# ---------------------------------------------------------------------------

_LABEL_FIELDS = ("name", "host", "model", "lib", "tool", "symbol", "sdk", "kind", "file")


def _entries(inv: dict[str, Any], key: str) -> list[Any]:
    """The inventory rows behind one `Subsystem.inventory_keys` entry, whatever its shape."""
    value = inv.get(key)
    if key == "mcp":
        return list(value.get("servers") or []) if isinstance(value, dict) else []
    if key == "secrets":
        if not isinstance(value, dict):
            return []
        hits = _int(value.get("literal_hits")) + _int(value.get("config_hits"))
        return [value] if hits else []
    if key == "system_card":
        return [value] if isinstance(value, dict) and value else []
    if isinstance(value, list):
        return list(value)
    return []


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _gone_entries(block: Mapping[str, Any]) -> list[Any]:
    """The baseline block's `no_longer_reported` list; the block carries no separate count."""
    gone = block.get("no_longer_reported")
    return list(gone) if isinstance(gone, list) else []


def _label(key: str, entry: Any) -> str:
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return str(entry)
    if key == "models":
        model = str(entry.get("model") or entry.get("id") or _T_DASH)
        pinned = entry.get("pinned")
        if pinned is True:
            return _T_LBL_PINNED.format(model=model)
        if pinned is False:
            return _T_LBL_UNPINNED.format(model=model)
        return model
    if key == "loops":
        return _T_LBL_LOOP_CAPPED if entry.get("capped") else _T_LBL_LOOP_UNCAPPED
    if key == "secrets":
        literal = _int(entry.get("literal_hits"))
        return _T_LBL_HITS.format(
            literal=literal, s=_plural(literal), config=_int(entry.get("config_hits"))
        )
    if key == "system_card":
        return _T_LBL_CARD.format(
            file=entry.get("file") or _T_DASH, tier=entry.get("risk_tier") or _T_UNKNOWN_WORD
        )
    if key == "ci":
        steps = entry.get("unsafe_steps")
        n = len(steps) if isinstance(steps, list) else 0
        return _T_LBL_CI.format(file=entry.get("file") or _T_DASH, n=n, s=_plural(n))
    for name in _LABEL_FIELDS:
        value = entry.get(name)
        if value:
            return str(value)
    return _T_DASH


def _key_name(key: str) -> str:
    """
    The fact's name for one `Subsystem.inventory_keys` entry. Every other key is its own
    name with `_` as a space, derived from the fixed `SUBSYSTEMS` tuple and nothing the
    audited tree wrote; a test pins that every name so produced is ASCII and carries none
    of `report.BANNED_PHRASES`.
    """
    return _T_KEY_MCP if key == "mcp" else key.replace("_", " ")


def _box_label(key: str, entry: Any) -> str:
    """The section label, except where a box-width form exists."""
    if key == "secrets" and isinstance(entry, dict):
        return _T_LBL_HITS_SHORT.format(
            literal=_int(entry.get("literal_hits")), config=_int(entry.get("config_hits"))
        )
    return _label(key, entry)


def _box_fact(key: str, entries: Sequence[Any]) -> str:
    """
    One box line: `3 tools: send_email, +2`. A single entry drops the count; a line that
    does not fit drops its second label before it is clipped, so a name survives whole
    where it can. The section under the map carries every entry unclipped.
    """
    name = _key_name(key)
    if len(entries) == 1:
        return _clip(
            _T_BOX_FACT_ONE.format(key=name, label=_box_label(key, entries[0])), _BOX_FACT_WIDTH
        )
    labels = [_box_label(key, e) for e in entries[:2]]

    def line(shown: list[str]) -> str:
        parts = list(shown)
        if len(entries) > len(shown):
            parts.append(_T_MORE_SHORT.format(n=len(entries) - len(shown)))
        return _T_BOX_FACT.format(n=len(entries), key=name, labels=", ".join(parts))

    text = line(labels)
    if _width(text) > _BOX_FACT_WIDTH:
        text = line(labels[:1])
    return _clip(text, _BOX_FACT_WIDTH)


def _box_facts(sub: Subsystem, inv: dict[str, Any] | None) -> list[str]:
    """Up to two lines for the map box, the first two inventory keys with any entry."""
    if inv is None:
        return [_T_INV_NOT_INCLUDED]
    lines: list[str] = []
    for key in sub.inventory_keys:
        entries = _entries(inv, key)
        if not entries:
            continue
        lines.append(_box_fact(key, entries))
        if len(lines) == 2:
            break
    return lines or [_T_NO_SURFACE]


def _section_facts(sub: Subsystem, inv: dict[str, Any] | None) -> list[str]:
    """Every inventory row for the section, one per line with its file:line, capped at MAX_FACTS."""
    if inv is None:
        return [_T_INV_NOT_INCLUDED]
    facts: list[str] = []
    for key in sub.inventory_keys:
        for entry in _entries(inv, key):
            label = _label(key, entry)
            name = _key_name(key)
            file = entry.get("file") if isinstance(entry, dict) else None
            line = entry.get("line") if isinstance(entry, dict) else None
            if file and key != "system_card" and key != "ci" and line:
                facts.append(_T_FACT_AT.format(key=name, label=label, file=file, line=line))
            elif file and key != "system_card" and key != "ci":
                facts.append(_T_FACT_FILE.format(key=name, label=label, file=file))
            else:
                facts.append(_T_FACT.format(key=name, label=label))
    if not facts:
        return [_T_NO_SURFACE]
    if len(facts) > MAX_FACTS:
        rest = len(facts) - MAX_FACTS
        facts = facts[:MAX_FACTS] + [_T_MORE.format(n=rest)]
    return facts


# ---------------------------------------------------------------------------
# Per-finding: language, protection, the package line, the plan's `who`
# ---------------------------------------------------------------------------


def _unit_languages(inv: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for unit in (inv or {}).get("units") or []:
        entry = _as_dict(unit)
        if isinstance(entry, dict) and entry.get("id"):
            out[str(entry["id"])] = str(entry.get("language") or _T_UNKNOWN_WORD)
    return out


def _language_of(finding: Finding, languages: dict[str, str]) -> str:
    """
    The file's extension first, then the unit's language from the inventory, then the
    root unit's for a repo-scoped finding. The extension wins because the idiom is offered
    for the file, not the unit: a `.ts` file inside a Python-rooted unit must not be told
    `package`, and a `.py` file under a `package.json` can still import aisg.

    The table is the walker's `patterns.LANG_BY_EXT`, not a copy: a copy that stopped at
    Go called a `.java`, `.kt`, `.rs`, `.rb` or `.cs` file Python whenever its unit was.
    The walker's `config` pseudo-language says nothing about what the file can import,
    so a config-typed extension falls through to the unit exactly as no extension does.
    """
    file, _ = finding.location
    suffix = PurePosixPath(file).suffix
    by_ext = LANG_BY_EXT.get(suffix) or LANG_BY_EXT.get(suffix.lower())
    if by_ext and by_ext != "config":
        return by_ext
    unit = finding.scope.unit
    if unit and unit in languages:
        return languages[unit]
    if finding.scope.kind == "repo":
        return languages.get(ROOT_UNIT_ID, _T_UNKNOWN_WORD)
    return _T_UNKNOWN_WORD


def _is_protected(finding: Finding) -> bool:
    file, _ = finding.location
    return bool(file) and is_protected_path(file)


def _who(finding: Finding, language: str, protected: bool) -> str:
    package = finding.recommendation.package
    if protected:
        return _T_WHO_APPROVAL
    if package.symbols and package.same_control and language == "python":
        return _T_WHO_PACKAGE
    return _T_WHO_YOU


def _aisg_cell(finding: Finding) -> str:
    package = finding.recommendation.package
    if not package.symbols:
        return _T_AISG_NONE
    kind = _T_AISG_SAME if package.same_control else _T_AISG_OTHER
    return _T_AISG_CELL.format(symbols=", ".join(package.symbols), kind=kind)


def _package_lines(finding: Finding, language: str, protected: bool) -> list[str]:
    package = finding.recommendation.package
    symbols = ", ".join(package.symbols)
    if package.symbols and package.same_control:
        lines = [_T_PKG_SAME.format(symbols=symbols, leaves_open=package.leaves_open)]
    elif package.symbols:
        lines = [
            _T_PKG_OTHER.format(
                symbols=symbols, mechanism=package.mechanism, leaves_open=package.leaves_open
            )
        ]
    else:
        lines = [_T_PKG_NONE.format(summary=finding.recommendation.summary)]
    if package.symbols and language not in ("python", _T_UNKNOWN_WORD):
        lines.append(_T_PKG_PYTHON_ONLY)
    if protected:
        lines.append(_T_PKG_PROTECTED)
    return lines


def _html_tags(finding: Finding) -> str:
    """The terminal's tag string with the bucket in capitals: `ASSERTED [UNMEASURED] ...`."""
    bucket, _, rest = _tags(finding).partition(" ")
    return f"{bucket.upper()} {rest}".rstrip()


def _path_part(location: str) -> str:
    """`a/b.py` from a baseline's `a/b.py:12`; a bare path stays as it is."""
    head, sep, tail = location.rpartition(":")
    return head if sep and tail.isdigit() else location


def _finding_block(
    finding: Finding, languages: dict[str, str], accepted_index: dict[str, dict[str, Any]]
) -> list[str]:
    language = _language_of(finding, languages)
    protected = _is_protected(finding)
    rec = finding.recommendation
    out = [f'<article class="finding" id="f-{_esc(finding.fingerprint)}">']
    head = _T_FINDING_HEAD.format(
        id=finding.display_id,
        title=finding.title,
        severity=Severity(finding.severity).value,
        tags=_html_tags(finding),
    )
    out.append(f"<h4>{_esc(head)}</h4>")
    if finding.evidence:
        out.append('<ul class="evidence">')
        for evidence in finding.evidence:
            where = _T_EVIDENCE_HTML.format(
                role=evidence.role, file=evidence.file, line=evidence.line
            )
            snippet = redact(str(evidence.snippet))
            out.append(f"<li>{_esc(where)} <code>{_esc(snippet)}</code></li>")
        out.append("</ul>")
    out.append(f"<p>{_esc(_T_FIX.format(tier=rec.tier.value, summary=rec.summary))}</p>")
    for line in _package_lines(finding, language, protected):
        out.append(f'<p class="pkg">{_esc(line)}</p>')
    if finding.notes:
        out.append(f'<p class="note">{_esc(_T_NOTE.format(text=finding.notes))}</p>')
    if finding.accepted_reason is not None:
        out.append(
            f'<p class="accepted">{_esc(_T_ACCEPTED.format(reason=finding.accepted_reason))}</p>'
        )
        entry = accepted_index.get(finding.fingerprint) or {}
        old = str(entry.get("file") or "")
        file, line = finding.location
        if old and file and _path_part(old) != file:
            moved = _T_ACCEPTED_MOVED.format(old=old, new=f"{file}:{line}")
            out.append(f'<p class="accepted">{_esc(moved)}</p>')
    out.append("</article>")
    return out


# ---------------------------------------------------------------------------
# The map
# ---------------------------------------------------------------------------

_SVG_W = 960
_BOX_W = 176
_BOX_H = 118
_GAP = 14
_X0 = 12
_ROW1_Y = 34
_ROW2_Y = 190
_ROW3_Y = 346
_ROW3_H = 62
_SVG_H = _ROW3_Y + _ROW3_H + 14
_XS = tuple(_X0 + i * (_BOX_W + _GAP) for i in range(5))
_ROW_ATTRS = 'fill="var(--panel)" stroke="var(--infra)" stroke-width="1.2"'
_UNKNOWN_ATTRS = (
    'fill="var(--panel)" stroke="var(--warn)" stroke-width="1.4" stroke-dasharray="7 5"'
)


def _svg_text(x: int, y: int, cls: str, text: str) -> str:
    return f'<text x="{x}" y="{y}" class="{cls}">{_esc(text)}</text>'


def _svg_box(x: int, y: int, box: _Box, facts: Sequence[str]) -> list[str]:
    out = [f'<rect x="{x}" y="{y}" width="{_BOX_W}" height="{_BOX_H}" rx="10" {_ROW_ATTRS}/>']
    out.append(_svg_text(x + 8, y + 20, "svgt", box.title))
    lines = list(facts)[:2]
    for i, line in enumerate(lines):
        out.append(_svg_text(x + 8, y + 38 + 16 * i, "svgf", line))
    out.append(
        _svg_text(x + 8, y + 76, "svgm", _T_BOX_STATUS.format(n=len(box.findings), m=box.unknown))
    )
    out.append(_svg_text(x + 8, y + 92, "svgm", _T_BOX_RULES.format(k=box.ran, total=box.total)))
    out.append(_svg_text(x + 8, y + 108, "svgs", _T_UNMEASURED))
    return out


def _svg(report: Report, boxes: dict[str, _Box], inv: dict[str, Any] | None) -> list[str]:
    target = (report.target or {}).get("path") or _T_DASH
    out = [
        f'<svg viewBox="0 0 {_SVG_W} {_SVG_H}" width="940" height="{_SVG_H * 940 // _SVG_W}" '
        f'role="img" aria-labelledby="fig1-title">',
        f'<title id="fig1-title">{_esc(_T_FIG_TITLE.format(target=target))}</title>',
        '<defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
        'markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="var(--infra)"/>'
        "</marker></defs>",
        _svg_text(_X0, _ROW1_Y - 10, "svgl", _T_ROW_FLOW),
        _svg_text(_X0, _ROW2_Y - 10, "svgl", _T_ROW_FOUNDATIONS),
        _svg_text(_X0, _ROW3_Y - 10, "svgl", _T_ROW_REST),
    ]
    for i, sub in enumerate(SUBSYSTEMS[:5]):
        out.extend(_svg_box(_XS[i], _ROW1_Y, boxes[sub.key], _box_facts(sub, inv)))
        if i < 4:
            x1, x2 = _XS[i] + _BOX_W, _XS[i + 1]
            y = _ROW1_Y + _BOX_H // 2
            out.append(
                f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="var(--infra)" '
                'stroke-width="1.2" marker-end="url(#ar)"/>'
            )
    for i, sub in enumerate(SUBSYSTEMS[5:10]):
        out.extend(_svg_box(_XS[i], _ROW2_Y, boxes[sub.key], _box_facts(sub, inv)))
    rest = boxes[NOT_ATTRIBUTED]
    out.append(
        f'<rect x="{_X0}" y="{_ROW3_Y}" width="{_SVG_W - 2 * _X0}" height="{_ROW3_H}" rx="10" '
        f"{_UNKNOWN_ATTRS}/>"
    )
    out.append(_svg_text(_X0 + 8, _ROW3_Y + 22, "svgt", _T_BOX_NOT_ATTRIBUTED))
    line = _T_BOX_NOT_ATTRIBUTED_LINE.format(
        m=rest.unknown, n=len(rest.findings), k=rest.ran, total=rest.total
    )
    out.append(_svg_text(_X0 + 8, _ROW3_Y + 44, "svgm", f"{line} {_T_UNMEASURED}"))
    out.append("</svg>")
    return out


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------


def _numbering(doc2: bool, ran_any: bool) -> dict[str, int]:
    keys: list[str] = []
    if doc2:
        keys.append("since")
    keys += ["map", "subsystems"]
    if ran_any:
        keys.append("plan")
    if doc2:
        keys.append("remaining")
    keys += ["unknown", "external"]
    return {key: i for i, key in enumerate(keys, 1)}


def _h2(number: int, title: str, anchor: str) -> str:
    return f'<h2 id="{anchor}">{number}. {_esc(title)}</h2>'


def _header(report: Report, doc2: bool, tool_label: str) -> list[str]:
    target = (report.target or {}).get("path") or _T_DASH
    dirty = (report.target or {}).get("dirty")
    dirty_text = _T_UNKNOWN_WORD if dirty is None else (_T_YES if dirty else _T_NO)
    summary = _summary_of(report)
    out = [
        '<header class="doc">',
        f"<h1>{_esc(_T_H1.format(target=target))}</h1>",
        f'<p class="sub">{_esc(_T_DOC2 if doc2 else _T_DOC1)}</p>',
        '<p class="sub">'
        + _esc(
            _T_HEAD_FACTS.format(
                sha=(report.target or {}).get("git_sha") or _T_DASH,
                dirty=dirty_text,
                generated_at=report.generated_at,
                tool=tool_label,
            )
        )
        + "</p>",
    ]
    if not doc2:
        out.append(f'<p class="sub">{_esc(_T_COMPARED_NONE)}</p>')
    else:
        block = report.baseline or {}
        age = _age_text(block.get("generated_at"), report.generated_at)
        compared = _T_COMPARED.format(file=block.get("file") or _T_DASH, age=age)
        accepted = block.get("accepted")
        n = len(accepted) if isinstance(accepted, list) else 0
        if n:
            reasons = _T_REASONS.format(n=n)
        elif block.get("kind") == "audit":
            reasons = _T_REASONS_REPORT
        else:
            reasons = _T_REASONS_NONE
        out.append(f'<p class="sub">{_esc(compared)}; {_esc(reasons)}</p>')
    resolved = [_T_RESOLVED_FAIL_ON.format(fail_on=summary.get("fail_on", "low"))]
    exclude = (report.target or {}).get("exclude")
    if isinstance(exclude, (list, tuple)) and exclude:
        resolved.append(_T_RESOLVED_EXCLUDE.format(items=", ".join(str(x) for x in exclude)))
    out.append(f'<p class="sub">{_esc("; ".join(resolved))}</p>')
    out.append("</header>")
    return out


def _read_first(report: Report, numbers: dict[str, int], ran_any: bool) -> list[str]:
    n = len(report.unknown)
    out = [
        '<div class="take">',
        f"<h4>{_esc(_T_READ_FIRST)}</h4>",
        f"<p>{_esc(report.disclaimer)}</p>",
        f"<p><strong>{_esc(_T_ABSENCE)}</strong></p>",
        "<p>"
        + _esc(_T_UNKNOWN_COUNT.format(n=n, s=_plural(n), section=numbers["unknown"]))
        + "</p>",
        "</div>",
    ]
    if not ran_any:
        out.append(f'<div class="banner">{_esc(_T_BANNER_NO_RULES)}</div>')
    return out


def _since(report: Report, numbers: dict[str, int], open_rows: int) -> list[str]:
    block = report.baseline or {}
    out = [_h2(numbers["since"], _T_SINCE, "since"), f"<h3>{_esc(_T_WHAT_CHANGED)}</h3>"]
    # The block carries no count: `no_longer_reported` is the list, one entry per gone
    # fingerprint, and its length is the number.
    gone = _gone_entries(block)
    out.append(f"<p>{_esc(_T_NO_LONGER.format(n=len(gone)))}</p>")
    if gone:
        out.append("<ul>")
        for entry in gone:
            item = entry if isinstance(entry, dict) else {"fingerprint": entry}
            if item.get("rule"):
                text = _T_NO_LONGER_ROW.format(
                    rule=item.get("rule"),
                    title=item.get("title") or _T_DASH,
                    file=item.get("file") or _T_DASH,
                )
            else:
                text = _T_NO_LONGER_UNNAMED.format(fingerprint=item.get("fingerprint") or _T_DASH)
            out.append(f"<li>{_esc(text)}</li>")
        out.append("</ul>")
        out.append(f'<p class="sub">{_esc(_T_NO_LONGER_NOTE)}</p>')
    new = [f for f in report.findings if f.baseline_status == "new"]
    out.append(f"<p>{_esc(_T_NEW_SINCE.format(n=len(new)))}</p>")
    if new:
        out.append("<ul>")
        for finding in new:
            file, line = finding.location
            where = f"{file}:{line}" if file else finding.scope.name or _T_DASH
            row = _T_FINDING_ROW.format(id=finding.display_id, title=finding.title, file=where)
            out.append(f'<li><a href="#f-{_esc(finding.fingerprint)}">{_esc(row)}</a></li>')
        out.append("</ul>")
    out.append(f"<h3>{_esc(_T_WHAT_LEFT)}</h3>")
    section = numbers.get("remaining", numbers.get("plan", 0))
    out.append(f"<p>{_esc(_T_LEFT.format(n=open_rows, s=_plural(open_rows), section=section))}</p>")
    out.append(f"<h3>{_esc(_T_WHAT_UNKNOWN)}</h3>")
    k = len(report.unknown)
    out.append(
        f"<p>{_esc(_T_STILL_UNKNOWN.format(n=k, s=_plural(k), section=numbers['unknown']))}</p>"
    )
    return out


def _map(report: Report, numbers: dict[str, int], boxes: dict[str, _Box], inv: dict | None):
    ran, total = _rules_ran(report)
    out = [_h2(numbers["map"], _T_MAP, "map"), '<div class="fig">']
    out.extend(_svg(report, boxes, inv))
    out.append("</div>")
    out.append(f'<p class="figcap">{_esc(_T_FIG_CAPTION.format(k=ran, total=total))}</p>')
    return out


def _subsystem_section(
    index: str,
    box: _Box,
    facts: Sequence[str] | None,
    numbers: dict[str, int],
    languages: dict[str, str],
    accepted_index: dict[str, dict[str, Any]],
) -> list[str]:
    status = _T_SECTION_STATUS.format(
        n=len(box.findings), m=box.unknown, k=box.ran, total=box.total
    )
    out = [
        f'<h3 id="sec-{_esc(box.key)}">{index} {_esc(box.title)} '
        f'<span class="status">-- {_esc(status)} {_esc(_T_UNMEASURED)}</span></h3>'
    ]
    if facts is not None:
        out.append(f"<p>{_esc(_T_FACTS)}</p>")
        out.append("<ul>")
        out.extend(f"<li>{_esc(fact)}</li>" for fact in facts)
        out.append("</ul>")
    if box.unknown:
        out.append(
            f'<p class="sub">{_esc(_T_UNKNOWN_HERE.format(n=box.unknown, section=numbers["unknown"]))}</p>'
        )
    out.append(f"<p>{_esc(_T_FINDINGS_HEAD)}</p>")
    if not box.findings:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    for finding in box.findings[:MAX_FINDINGS_PER_SECTION]:
        out.extend(_finding_block(finding, languages, accepted_index))
    if len(box.findings) > MAX_FINDINGS_PER_SECTION:
        rest = len(box.findings) - MAX_FINDINGS_PER_SECTION
        out.append(f"<p>{_esc(_T_MORE.format(n=rest))}</p>")
    return out


def _subsystems(
    numbers: dict[str, int],
    boxes: dict[str, _Box],
    inv: dict[str, Any] | None,
    languages: dict[str, str],
    accepted_index: dict[str, dict[str, Any]],
) -> list[str]:
    number = numbers["subsystems"]
    out = [_h2(number, _T_SUBSYSTEMS, "subsystems")]
    for i, sub in enumerate(SUBSYSTEMS, 1):
        out.extend(
            _subsystem_section(
                f"{number}.{i}",
                boxes[sub.key],
                _section_facts(sub, inv),
                numbers,
                languages,
                accepted_index,
            )
        )
    rest = boxes[NOT_ATTRIBUTED]
    if rest.findings or rest.unknown:
        out.extend(
            _subsystem_section(
                f"{number}.{len(SUBSYSTEMS) + 1}", rest, None, numbers, languages, accepted_index
            )
        )
    return out


def _plan_rows(report: Report, languages: dict[str, str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for n, finding in enumerate(report.findings, 1):
        language = _language_of(finding, languages)
        protected = _is_protected(finding)
        who = _who(finding, language, protected)
        if finding.accepted_reason is not None:
            status = _T_STATUS_ACCEPTED
        else:
            status = finding.baseline_status or _T_DASH
        box = subsystem_of(finding.display_id or finding.id)
        title = next((s.title for s in SUBSYSTEMS if s.key == box), _T_NOT_ATTRIBUTED_TITLE)
        rows.append(
            {
                "n": n,
                "finding": finding,
                "subsystem": title,
                "aisg": _aisg_cell(finding),
                "who": who,
                "status": status,
            }
        )
    return rows


def _is_open(row: Mapping[str, Any]) -> bool:
    """An accepted row is not work: neither the package's list nor the open count holds it."""
    return row["status"] != _T_STATUS_ACCEPTED


def _plan(numbers: dict[str, int], rows: Sequence[dict[str, Any]]) -> list[str]:
    out = [_h2(numbers["plan"], _T_PLAN, "plan")]
    if not rows:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<table>")
        out.append("<tr>" + "".join(f"<th>{_esc(h)}</th>" for h in _T_PLAN_HEADERS) + "</tr>")
        for row in rows:
            finding: Finding = row["finding"]
            rec = finding.recommendation
            cells = [
                str(row["n"]),
                f'<a href="#f-{_esc(finding.fingerprint)}">{_esc(finding.display_id)}</a>',
                _esc(Severity(finding.severity).value),
                _esc(row["subsystem"]),
                _esc(rec.summary),
                _esc(rec.tier.value),
                _esc(row["aisg"]),
                _esc(row["who"]),
                _esc(row["status"]),
            ]
            out.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
        out.append("</table>")
    out.append(f"<h3>{_esc(_T_PLAN_ROWS)}</h3>")
    package_rows = [r for r in rows if r["who"] == _T_WHO_PACKAGE and _is_open(r)]
    if not package_rows:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<ol>")
        for row in package_rows:
            finding = row["finding"]
            package = finding.recommendation.package
            text = _T_PLAN_ROW.format(
                n=row["n"],
                id=finding.display_id,
                title=finding.title,
                symbols=", ".join(package.symbols),
                leaves_open=package.leaves_open,
            )
            out.append(f"<li>{_esc(text)}</li>")
        out.append("</ol>")
    out.append(f"<p><strong>{_esc(_T_PLAN_WIRING)}</strong></p>")
    return out


def _remaining(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["remaining"], _T_REMAINING, "remaining")]
    accepted = [f for f in report.findings if f.accepted_reason is not None]
    open_findings = [f for f in report.findings if f.accepted_reason is None]
    outside = [f for f in open_findings if not f.recommendation.package.symbols]
    with_package = [f for f in open_findings if f.recommendation.package.symbols]

    def group(title: str, items: list[str]) -> None:
        out.append(f"<h3>{_esc(title)}</h3>")
        if not items:
            out.append(f"<p>{_esc(_T_NONE)}</p>")
            return
        out.append("<ul>")
        out.extend(items)
        out.append("</ul>")

    def link(finding: Finding, text: str) -> str:
        return f'<li><a href="#f-{_esc(finding.fingerprint)}">{_esc(text)}</a></li>'

    group(
        _T_GROUP_OUTSIDE,
        [
            link(
                f,
                _T_FINDING_ROW.format(
                    id=f.display_id, title=f.title, file=f.location[0] or f.scope.name or _T_DASH
                ),
            )
            for f in outside
        ],
    )
    group(
        _T_GROUP_PACKAGE,
        [
            link(
                f,
                _T_GROUP_PACKAGE_ROW.format(
                    id=f.display_id,
                    title=f.title,
                    symbols=", ".join(f.recommendation.package.symbols),
                    leaves_open=f.recommendation.package.leaves_open,
                ),
            )
            for f in with_package
        ],
    )
    group(
        _T_GROUP_ACCEPTED,
        [
            link(
                f,
                _T_GROUP_ACCEPTED_ROW.format(
                    id=f.display_id, title=f.title, reason=f.accepted_reason
                ),
            )
            for f in accepted
        ],
    )
    k = len(report.unknown)
    out.append(f"<h3>{_esc(_T_GROUP_UNKNOWN)}</h3>")
    out.append(
        f"<p>{_esc(_T_STILL_UNKNOWN.format(n=k, s=_plural(k), section=numbers['unknown']))}</p>"
    )
    return out


def _unknown_section(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["unknown"], _T_UNKNOWN, "unknown")]
    items: Sequence[UnknownItem] = report.unknown
    if not items:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
        return out
    out.append("<ol>")
    for item in items:
        out.append(f"<li>{_esc(_unknown_head(item))}")
        details = _unknown_detail_lines(item)
        if details:
            out.append("<ul>" + "".join(f"<li>{_esc(d)}</li>" for d in details) + "</ul>")
        out.append("</li>")
    out.append("</ol>")
    return out


def _external_section(report: Report, numbers: dict[str, int]) -> list[str]:
    out = [_h2(numbers["external"], _T_EXTERNAL_SECTION, "external")]
    if not report.external_tools:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<table>")
        out.append("<tr>" + "".join(f"<th>{_esc(h)}</th>" for h in _T_EXTERNAL_HEADERS) + "</tr>")
        for result in report.external_tools:
            cells = "".join(f"<td>{_esc(c)}</td>" for c in _external_row(result))
            out.append(f"<tr>{cells}</tr>")
        out.append("</table>")
    out.append(f"<h3>{_esc(_T_REPORTS_READ)}</h3>")
    reports = [r for r in (report.reports or ()) if isinstance(r, dict)]
    if not reports:
        out.append(f"<p>{_esc(_T_NONE)}</p>")
    else:
        out.append("<ul>")
        for entry in reports:
            age = entry.get("age_days")
            if age is None:
                tag = _T_REPORTED_UNKNOWN
            else:
                tag = _T_REPORTED.format(age=age, source=entry.get("age_source") or _T_UNKNOWN_WORD)
            text = _T_REPORT_READ.format(
                source=entry.get("source") or _T_DASH, kind=entry.get("kind") or _T_DASH, tag=tag
            )
            out.append(f"<li>{_esc(text)}</li>")
        out.append("</ul>")
    out.append(f"<h3>{_esc(_T_INVENTORY_HEAD)}</h3>")
    out.append(
        "<ul>"
        + "".join(f"<li>{_esc(ln)}</li>" for ln in _inventory_lines(report.inventory))
        + "</ul>"
    )
    return out


def _footer(report: Report, tool_label: str) -> list[str]:
    summary = _summary_of(report)
    out = ["<footer>", f"<p>{_esc(_summary_line(summary))}</p>"]
    block = report.baseline
    if block:
        line = _T_BASELINE.format(
            new=_int(block.get("new")),
            unchanged=_int(block.get("unchanged")),
            gone=len(_gone_entries(block)),
            file=block.get("file") or _T_DASH,
        )
        out.append(f"<p>{_esc(line)}</p>")
    out.append(f"<p>{_esc(_T_EXIT.format(code=summary.get('exit_code')))}</p>")
    out.append(f"<p><strong>{_esc(_T_ABSENCE)}</strong></p>")
    out.append(f"<p>{_esc(_T_FOOTER_GENERATED.format(tool=tool_label))}</p>")
    out.append("</footer>")
    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def render_html(report: Report, quiet: bool = False) -> str:
    """
    The page. `quiet` is accepted so `render()` can pass it through unconditionally and
    ignored: a page is read, not tailed, and every section is always present.
    """
    del quiet
    doc2 = report.baseline is not None
    ran_any = any(isinstance(r, dict) and r.get("ran") for r in (report.rules or ()))
    numbers = _numbering(doc2, ran_any)
    inv = _as_dict(report.inventory)
    inv = inv if isinstance(inv, dict) and inv else None
    boxes = _place(report)
    languages = _unit_languages(inv)
    block = report.baseline or {}
    accepted_entries = block.get("accepted") if isinstance(block.get("accepted"), list) else []
    accepted_index = {str(e.get("fingerprint")): e for e in accepted_entries if isinstance(e, dict)}
    version = (report.tool or {}).get("version") or tool_version()
    tool_label = f"{DISTRIBUTION} {version}"
    target = (report.target or {}).get("path") or _T_DASH
    rows = _plan_rows(report, languages) if ran_any else []
    open_rows = sum(1 for r in rows if _is_open(r))

    out = [
        _T_MARKER,
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(_T_PAGE_TITLE.format(target=target))}</title>",
        f'<meta name="aisg-schema" content="{_esc(SCHEMA_VERSION)}">',
        f'<meta name="aisg-tool" content="{_esc(tool_label)}">',
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
    ]
    out.extend(_header(report, doc2, tool_label))
    out.extend(_read_first(report, numbers, ran_any))
    if doc2:
        out.extend(_since(report, numbers, open_rows))
    out.extend(_map(report, numbers, boxes, inv))
    out.extend(_subsystems(numbers, boxes, inv, languages, accepted_index))
    if ran_any:
        out.extend(_plan(numbers, rows))
    if doc2:
        out.extend(_remaining(report, numbers))
    out.extend(_unknown_section(report, numbers))
    out.extend(_external_section(report, numbers))
    out.extend(_footer(report, tool_label))
    out += ["</main>", "</body>", "</html>"]
    # Last line of defence: a stray non-ASCII character in any fixed string becomes an
    # entity too, so the page is ASCII whatever it was built from.
    return _asciify("\n".join(out)) + "\n"
