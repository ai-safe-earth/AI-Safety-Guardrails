"""scripts/controls_md.py
----------------------
Regenerate the registry-derived parts of the skill's `references/controls.md` in place.

The skill ships one section per audit rule. Three things in each section are copies of
what the rule class says, and a copy drifts: the severity word in the heading, the
`- Mapping:` bullet (the rule's `controls` tuple) and the "Leaves open:" text (the rule's
`recommendation.package.leaves_open`). This tool rewrites those three from
`aisg.devtools.audit.rules.ALL_RULES` and leaves every other word alone.

    python scripts/controls_md.py          # rewrite the canonical controls.md
    python scripts/controls_md.py --check  # list the drift, exit 1 if any, write nothing

Run from the repo root, then `python scripts/sync_skill.py` so the mirrors follow.
Not shipped.
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONTROLS_MD = REPO / "src" / "aisg" / "skills" / "ai-safety-audit" / "references" / "controls.md"

# The file's own wrap width; longer lines are only the table and one heading.
WIDTH = 92

SEVERITY_WORDS = ("critical", "high", "medium", "low", "info")

HEADING_RE = re.compile(r"^### (AUD-\d+) (.+?) \(([^()]*)\)\s*$")
# The heading's parenthetical starts with the rule severity; what follows (sub-finding
# severities, a REPORTED tag) is the author's and survives a rewrite.
PAREN_RE = re.compile(r"^(" + "|".join(SEVERITY_WORDS) + r")\b(.*)$")
LEAVES_OPEN = "Leaves open:"


def _collapse(text: str) -> str:
    return " ".join(text.split())


def _wrap(text: str) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def _bullets(lines: list[str], start: int, end: int) -> list[tuple[int, int]]:
    """(first, last) line index of every `- ` bullet between `start` and `end`."""
    spans: list[tuple[int, int]] = []
    first: int | None = None
    for index in range(start, end):
        line = lines[index]
        if line.startswith("- "):
            if first is not None:
                spans.append((first, index - 1))
            first = index
        elif first is not None and not line.startswith("  "):
            spans.append((first, index - 1))
            first = None
    if first is not None:
        spans.append((first, end - 1))
    return spans


def _bullet_text(lines: list[str], span: tuple[int, int]) -> str:
    """The bullet's words on one line, without the `- ` marker."""
    first, last = span
    return _collapse(" ".join(lines[first : last + 1]))[2:]


def _find_bullet(lines: list[str], spans: list[tuple[int, int]], prefix: str):
    for span in spans:
        if _bullet_text(lines, span).startswith(prefix):
            return span
    return None


def _sections(lines: list[str]) -> list[tuple[str, int, int]]:
    """(rule id, heading index, end index) for every `### AUD-` section."""
    heads = [(HEADING_RE.match(line), index) for index, line in enumerate(lines)]
    heads = [(m.group(1), index) for m, index in heads if m]
    out: list[tuple[str, int, int]] = []
    for position, (rule_id, index) in enumerate(heads):
        end = len(lines)
        for candidate in range(index + 1, len(lines)):
            if lines[candidate].startswith("#"):
                end = candidate
                break
        if position + 1 < len(heads):
            end = min(end, heads[position + 1][1])
        out.append((rule_id, index, end))
    return out


def _heading(line: str, severity: str) -> str:
    match = HEADING_RE.match(line)
    assert match is not None
    rule_id, title, paren = match.groups()
    m = PAREN_RE.match(paren.strip())
    rest = m.group(2) if m else "; " + paren.strip()
    return f"### {rule_id} {title} ({severity}{rest})"


def _mapping(controls: tuple[str, ...]) -> list[str]:
    return _wrap("- Mapping: " + ", ".join(controls) + ".")


def _package(existing: str, leaves_open: str) -> list[str]:
    head, sep, _tail = existing.partition(LEAVES_OPEN)
    if not leaves_open:
        return _wrap("- " + head.rstrip())
    prefix = head.rstrip() if sep else existing.rstrip()
    return _wrap(f"- {prefix} {LEAVES_OPEN} {leaves_open}")


def regenerate(text: str, rules) -> tuple[str, list[str]]:
    """The rewritten file and one drift line per part that differed."""
    by_id = {rule.id: rule for rule in rules}
    lines = text.split("\n")
    drift: list[str] = []
    # Bottom-up so an earlier section's line count change does not move a later one.
    sections = _sections(lines)
    seen = {rule_id for rule_id, _, _ in sections}
    for rule_id in sorted(set(by_id) - seen):
        drift.append(f"{rule_id}: no section in controls.md")
    for rule_id, head, end in reversed(sections):
        rule = by_id.get(rule_id)
        if rule is None:
            drift.append(f"{rule_id}: section has no rule in the registry")
            continue
        spans = _bullets(lines, head + 1, end)
        mapping = _find_bullet(lines, spans, "Mapping:")
        package = _find_bullet(lines, spans, "Package:")
        edits: list[tuple[tuple[int, int], list[str], str]] = []
        if package is None:
            drift.append(f"{rule_id}: no Package bullet")
        else:
            new = _package(_bullet_text(lines, package), rule.recommendation.package.leaves_open)
            edits.append((package, new, "leaves open"))
        if mapping is None:
            drift.append(f"{rule_id}: no Mapping bullet")
            after = spans[-1][1] + 1 if spans else head + 1
            edits.append(((after, after - 1), _mapping(rule.controls), "mapping"))
        else:
            edits.append((mapping, _mapping(rule.controls), "mapping"))
        new_heading = _heading(lines[head], rule.severity.value)
        edits.append(((head, head), [new_heading], "severity"))
        for (first, last), new, what in sorted(edits, key=lambda e: e[0], reverse=True):
            old = lines[first : last + 1]
            if old != new:
                drift.append(f"{rule_id}: {what}")
                lines[first : last + 1] = new
    return "\n".join(lines), sorted(drift)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="controls_md.py",
        description="Rewrite the severity, mapping and leaves-open text in controls.md "
        "from the audit rule registry.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="List the drift and exit 1 if there is any; write nothing.",
    )
    args = parser.parse_args(argv)

    sys.path.insert(0, str(REPO / "src"))
    from aisg.devtools.audit.rules import ALL_RULES

    if not CONTROLS_MD.is_file():
        print(f"not found: {CONTROLS_MD}", file=sys.stderr)
        return 2
    original = CONTROLS_MD.read_text(encoding="ascii")
    rewritten, drift = regenerate(original, ALL_RULES)
    for line in drift:
        print(("differs: " if args.check else "rewrote: ") + line)
    if args.check:
        if drift:
            print(f"{len(drift)} difference(s); run without --check to fix", file=sys.stderr)
            return 1
        print(f"in sync: {len(ALL_RULES)} rules")
        return 0
    if rewritten != original:
        CONTROLS_MD.write_bytes(rewritten.encode("ascii"))  # bytes: keep LF on Windows
    print(f"controls.md: {len(drift)} part(s) rewritten from {len(ALL_RULES)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
