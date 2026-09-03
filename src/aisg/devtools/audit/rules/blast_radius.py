# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/blast_radius.py
------------------------------------------
P1 rules AUD-101..AUD-108: what the agent can do at all. Host permission grants,
loops with no iteration cap, fetch and exec tools with no allowlist or sandbox,
missing per-session tool budgets, broad credentials in agent scope, no kill switch,
and hooks or CI steps that pipe the network into a shell.

Every rule reads discovery output only: `ctx.config_facts` (structured parsers),
`ctx.inventory` / `ctx.hits` (grep tier) and `ctx.pyfacts` (Python AST tier). When
the AST tier covers a Python file its evidence wins over the grep hit at the same
location; nothing is emitted twice for one line.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from aisg.devtools.audit import patterns, vocab
from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Evidence,
    EvidenceKind,
    Finding,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
    Unit,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in, unit_of

__all__ = [
    "RULES",
    "BroadCredentials",
    "ExecNoSandbox",
    "FetchNoAllowlist",
    "HostOverGrant",
    "NoKillSwitch",
    "NoToolBudget",
    "ToolRef",
    "UncappedLoop",
    "UnsafeHooksCi",
    "deep_covers",
    "iter_tools",
    "line_text",
    "tool_spans",
    "unit_by_id",
    "unit_id_of",
    "unit_scope",
    "window_text",
]

_DOC_SUFFIXES = (".md", ".rst", ".txt")
_LOOP_WINDOW = 40
_BROAD_CRED_NAMES: frozenset[str] = frozenset(key for key, _rx in patterns.BROAD_CRED_NAMES)


# ---------------------------------------------------------------------------
# Shared helpers (also used by rules/irreversible.py)
# ---------------------------------------------------------------------------


def line_text(ctx: AuditContext, relpath: str, line: int) -> str | None:
    """The stripped source line at 1-based `line`, or None when unreadable."""
    text = file_text(ctx, relpath)
    if text is None or line < 1:
        return None
    lines = text.splitlines()
    if line > len(lines):
        return None
    return lines[line - 1].strip()


def window_text(ctx: AuditContext, relpath: str, start: int, count: int) -> str:
    """`count` source lines starting at 1-based `start` (inclusive), joined; "" if unreadable."""
    text = file_text(ctx, relpath)
    if text is None:
        return ""
    lines = text.splitlines()
    first = max(start - 1, 0)
    return "\n".join(lines[first : first + max(count, 0)])


def deep_covers(ctx: AuditContext, relpath: str) -> bool:
    """True when the AST tier ran and `relpath` is a Python file it would have analysed."""
    if ctx.pyfacts is None:
        return False
    key = relpath.replace("\\", "/")
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            return getattr(record, "lang", None) == "python"
    return key.endswith((".py", ".pyi"))


def unit_by_id(ctx: AuditContext, unit_id: str | None) -> Unit | None:
    if unit_id is None:
        return None
    for unit in ctx.inventory.units:
        if unit.id == unit_id:
            return unit
    return None


def unit_id_of(ctx: AuditContext, relpath: str, fallback: str | None = None) -> str | None:
    """Unit id owning `relpath` through the walk records, else `fallback`."""
    unit = unit_of(ctx, relpath)
    return unit.id if unit is not None else fallback


def unit_scope(ctx: AuditContext, unit_id: str | None, relpath: str) -> Scope:
    """A unit-kind scope named after the unit root (falling back to the file's own unit)."""
    resolved = unit_id if unit_id is not None else unit_id_of(ctx, relpath)
    unit = unit_by_id(ctx, resolved)
    if unit is None:
        return Scope(kind="file", unit=resolved, name=relpath)
    return Scope(kind="unit", unit=unit.id, name=unit.root)


def _lang_of(ctx: AuditContext, relpath: str) -> str | None:
    key = relpath.replace("\\", "/")
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            return getattr(record, "lang", None)
    return None


def _any_ai_surface(ctx: AuditContext) -> bool:
    return any(unit.ai_surface for unit in ctx.inventory.units)


def _severity_from(value: Any, default: Severity) -> Severity:
    try:
        return Severity(str(value).lower())
    except ValueError:
        return default


@dataclass(frozen=True)
class ToolRef:
    """One tool definition, normalised across the AST tier and the grep tier."""

    name: str
    file: str
    line: int
    unit: str | None
    kind: str
    capabilities: frozenset[str]
    gated: bool | None  # grep tier: APPROVAL_SYMBOLS within the window; None on the AST tier
    body_symbols: tuple[str, ...]
    risk_tier: str
    deep: bool
    # AST tier only: (file, first line, last line) of each function the tool body lives in.
    spans: tuple[tuple[str, int, int], ...] = ()

    @property
    def match_kind(self) -> MatchKind:
        return MatchKind.AST if self.deep else MatchKind.GREP

    def snippet(self, ctx: AuditContext) -> str:
        source = line_text(ctx, self.file, self.line)
        if not source:
            return f"{self.name} ({self.kind})"
        if self.name in source:
            return source
        return f"{self.name}: {source}"

    def evidence(self, ctx: AuditContext) -> list[Evidence]:
        """The match leg at the definition line plus one `definition` leg per function span."""
        legs = [Evidence(role="match", file=self.file, line=self.line, snippet=self.snippet(ctx))]
        for file, line, _end in self.spans:
            if (file, line) == (self.file, self.line):
                continue
            legs.append(
                Evidence(
                    role="definition",
                    file=file,
                    line=line,
                    snippet=line_text(ctx, file, line) or f"def {self.name}",
                )
            )
        return legs


def tool_spans(ctx: AuditContext, name: str) -> tuple[tuple[str, int, int], ...]:
    """Function spans behind a tool name, from `pyfacts.tool_funcs` and `pyfacts.functions`."""
    pyfacts = ctx.pyfacts
    if pyfacts is None:
        return ()
    functions = getattr(pyfacts, "functions", None) or {}
    keys = (getattr(pyfacts, "tool_funcs", None) or {}).get(name, ())
    spans: list[tuple[str, int, int]] = []
    for key in keys:
        info = functions.get(key)
        if info is None:
            continue
        file = str(getattr(info, "file", "") or "").replace("\\", "/")
        line = int(getattr(info, "line", 0) or 0)
        end = int(getattr(info, "end_line", 0) or line)
        if file and line and (file, line, end) not in spans:
            spans.append((file, line, end))
    return tuple(spans)


def iter_tools(ctx: AuditContext) -> list[ToolRef]:
    """
    Tools from `pyfacts.tools` (AST) and `inventory.tools` (grep), sorted by (file, line, name).

    A grep entry is dropped when the AST tier already defines the same tool name in the
    same file, or anything at the same (file, line): deep evidence wins, never both.
    """
    out: list[ToolRef] = []
    covered_names: set[tuple[str, str]] = set()
    covered_lines: set[tuple[str, int]] = set()
    grep_units: dict[tuple[str, str], str | None] = {}
    for entry in ctx.inventory.tools or []:
        if isinstance(entry, dict):
            grep_units[(str(entry.get("file", "")), str(entry.get("name", "")))] = entry.get("unit")
    if ctx.pyfacts is not None:
        for tool in getattr(ctx.pyfacts, "tools", None) or []:
            file = str(getattr(tool, "file", "") or "").replace("\\", "/")
            name = str(getattr(tool, "name", "") or "")
            line = int(getattr(tool, "line", 0) or 0)
            out.append(
                ToolRef(
                    name=name,
                    file=file,
                    line=line,
                    unit=unit_id_of(ctx, file, grep_units.get((file, name))),
                    kind=str(getattr(tool, "kind", "") or "ast"),
                    capabilities=frozenset(getattr(tool, "capabilities", ()) or ()),
                    gated=None,
                    body_symbols=tuple(getattr(tool, "body_symbols", ()) or ()),
                    risk_tier=str(getattr(tool, "risk_tier", "") or ""),
                    deep=True,
                    spans=tool_spans(ctx, name),
                )
            )
            covered_names.add((file, name))
            covered_lines.add((file, line))
    for entry in ctx.inventory.tools or []:
        if not isinstance(entry, dict):
            continue
        file = str(entry.get("file", "") or "").replace("\\", "/")
        name = str(entry.get("name", "") or "")
        line = int(entry.get("line", 0) or 0)
        if (file, name) in covered_names or (file, line) in covered_lines:
            continue
        out.append(
            ToolRef(
                name=name,
                file=file,
                line=line,
                unit=entry.get("unit") or unit_id_of(ctx, file),
                kind=str(entry.get("kind", "") or "grep"),
                capabilities=frozenset(str(c) for c in entry.get("capabilities") or ()),
                gated=bool(entry.get("gated", False)),
                body_symbols=(),
                risk_tier=str(entry.get("risk_tier", "") or ""),
                deep=False,
            )
        )
    out.sort(key=lambda t: (t.file, t.line, t.name))
    return out


def _symbol_present(hits: list[Any], symbols: tuple[str, ...], body: Iterable[str]) -> bool:
    """A grep hit from the table exists, or a vocabulary symbol names one of the tool's own body symbols."""
    if hits:
        return True
    lowered = tuple(s.lower() for s in symbols)
    for item in body:
        item_l = str(item).lower()
        if any(sym in item_l for sym in lowered):
            return True
    return False


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.location[0], f.location[1], f.sub or ""))


# ---------------------------------------------------------------------------
# AUD-101 Host permission over-grant
# ---------------------------------------------------------------------------


class HostOverGrant(AuditRule):
    id = "AUD-101"
    title = "Host permission over-grant"
    priority = 1
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI03", "ASI05", "LLM06", "EU:Art.14", "NIST:GOVERN-1.7")
    related_lint_rules = ("EU-AIA-014a", "ALIGN-003")
    known_failure_modes = (
        "Host-global settings (~/.claude, ~/.codex, ~/.cursor, ~/.gemini) are not read unless "
        "--include-home is passed; a grant that lives there is invisible.",
        "A grant in a file the walk skipped (SKIP_DIRS, --exclude, the ignore marker) is not seen.",
        "A doc literal inside a quoted span or next to a discussion cue is reported as a mention "
        "at low; a fenced shell block with no cue stays low too, because a doc cannot grant "
        "anything even when it is copied into a script later.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Replace the wildcard grant with the narrowest command list the workflow needs and "
            "keep permission prompts on."
        ),
        alternatives=(
            "Claude Code: list explicit `Bash(git status)`-style entries in permissions.allow; "
            "drop `Bash(*)`, `WebFetch` without a domain and defaultMode bypassPermissions.",
            "Codex: set approval_policy to on-request and sandbox_mode to workspace-write.",
            "Cursor / Gemini: turn off yolo, autoRun, allowAllCommands and autoAccept; "
            "keep the sandbox on.",
            "Run the host inside a throwaway container or VM when a broad grant is unavoidable, "
            "so the blast radius is the container.",
            "aisg: put a ToolPolicyGuard with an approval_callback in front of the tool layer so "
            "the host grant is not the only gate.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        structured_lines: set[tuple[str, int]] = set()
        seen: set[tuple[str, int, str, str]] = set()
        facts = ctx.config_facts
        if facts is not None:
            for record in getattr(facts, "host_records", None) or []:
                file = str(getattr(record, "file", "") or "")
                for grant in getattr(record, "over_grants", None) or []:
                    self._structured(findings, seen, structured_lines, file, grant)
            for item in getattr(facts, "over_grant_literals", None) or []:
                try:
                    relpath, grant = item
                except (TypeError, ValueError):
                    continue
                self._structured(findings, seen, structured_lines, str(relpath), grant)
        hit_seen: set[tuple[str, int]] = set()
        for hit in hits_in(ctx, "overgrant_literal"):
            key = (hit.file, hit.line)
            if key in structured_lines or key in hit_seen:
                continue
            hit_seen.add(key)
            is_doc = hit.file.lower().endswith(_DOC_SUFFIXES)
            where = (
                "a doc; a doc cannot grant anything, capped at low"
                if is_doc
                else "a script or config file"
            )
            findings.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    severity=Severity.LOW if is_doc else None,
                    sub="docs" if is_doc else None,
                    match_kind=MatchKind.GREP,
                    notes=f"over-grant literal in {where}",
                )
            )
        return _sorted(findings)

    def _structured(
        self,
        findings: list[Finding],
        seen: set[tuple[str, int, str, str]],
        structured_lines: set[tuple[str, int]],
        file: str,
        grant: Any,
    ) -> None:
        key = str(getattr(grant, "key", "") or "")
        value = str(getattr(grant, "value", "") or "")
        line = int(getattr(grant, "line", 0) or 0)
        dedupe = (file, line, key, value)
        if dedupe in seen:
            return
        seen.add(dedupe)
        structured_lines.add((file, line))
        mention = bool(getattr(grant, "mention", False))
        sub = getattr(grant, "sub", None)
        severity = _severity_from(getattr(grant, "severity", None), self.severity)
        notes = None
        if mention:
            sub = sub or "docs"
            severity = Severity.LOW
            notes = "mention, not a use: quoted span or discussion cue nearby; capped at low"
        elif sub == "docs":
            severity = Severity.LOW
            notes = "literal in a doc; a doc cannot grant anything, capped at low"
        findings.append(
            self.finding(
                file=file,
                line=line,
                snippet=f"{key}: {value}",
                severity=severity,
                sub=sub,
                notes=notes,
            )
        )


# ---------------------------------------------------------------------------
# AUD-102 Agent loop without an iteration cap
# ---------------------------------------------------------------------------


class UncappedLoop(AuditRule):
    id = "AUD-102"
    title = "Agent loop without an iteration cap"
    priority = 1
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T2
    controls = ("ASI08", "LLM10", "EU:Art.15", "NIST:MANAGE-2.3")
    related_lint_rules = ("EU-AIA-015a",)
    known_failure_modes = (
        "Misses a cap expressed as a counter variable compared inside the loop body unless the "
        "comparison sits next to a break (Python AST tier); the grep tier only looks 40 lines "
        "after the loop for a LOOP_CAP_SYMBOLS name.",
        "The grep tier reports a loop when an LLM call sits anywhere in the same file, not "
        "necessarily inside the loop.",
        "A cap enforced by the framework (recursion_limit passed at graph compile time in "
        "another file) is not seen.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary="Bound the loop with a turn cap and a wall-clock deadline that the loop checks.",
        alternatives=(
            "Add `max_turns` / `max_iterations` to the loop and break when it is reached; log "
            "the exhaustion so it is visible.",
            "LangGraph: pass `recursion_limit` in the run config; OpenAI Agents SDK: set "
            "`max_turns` on Runner.run.",
            "Wrap the loop in an asyncio timeout or a deadline check so a stuck model cannot "
            "spend unbounded tokens.",
            "aisg: add a RateLimiter guard on the pipeline context so repeated calls in one "
            "session hit a budget.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        deep_lines: set[tuple[str, int]] = set()
        pyfacts = ctx.pyfacts
        if pyfacts is not None:
            calls = getattr(pyfacts, "llm_calls", None) or []
            for loop in getattr(pyfacts, "loops", None) or []:
                if not getattr(loop, "contains_llm_call", False):
                    continue
                if getattr(loop, "cap_symbol", None):
                    continue
                file = str(getattr(loop, "file", "") or "").replace("\\", "/")
                line = int(getattr(loop, "line", 0) or 0)
                deep_lines.add((file, line))
                function = getattr(loop, "function", None)
                kind = str(getattr(loop, "kind", "") or "loop")
                snippet = line_text(ctx, file, line) or f"{kind} loop"
                evidence = [Evidence(role="match", file=file, line=line, snippet=snippet)]
                for call in calls:
                    if (
                        getattr(call, "file", None) == file
                        and getattr(call, "loop_line", None) == line
                    ):
                        call_line = int(getattr(call, "line", 0) or 0)
                        call_snip = line_text(ctx, file, call_line) or str(
                            getattr(call, "provider", "llm")
                        )
                        evidence.append(
                            Evidence(role="llm_call", file=file, line=call_line, snippet=call_snip)
                        )
                scope = (
                    Scope(kind="function", unit=unit_id_of(ctx, file), name=f"{file}::{function}")
                    if function
                    else None
                )
                findings.append(
                    self.finding(
                        file=file,
                        line=line,
                        snippet=snippet,
                        evidence=evidence,
                        scope=scope,
                        notes=f"{kind} enclosing an LLM call; no LOOP_CAP_SYMBOLS name in the "
                        f"enclosing function",
                    )
                )
        for entry in ctx.inventory.loops or []:
            if not isinstance(entry, dict) or entry.get("capped", False):
                continue
            file = str(entry.get("file", "") or "").replace("\\", "/")
            line = int(entry.get("line", 0) or 0)
            if (file, line) in deep_lines or deep_covers(ctx, file):
                continue
            if not hits_in(ctx, "llm_call", file=file):
                continue
            snippet = line_text(ctx, file, line) or "loop"
            findings.append(
                self.finding(
                    file=file,
                    line=line,
                    snippet=snippet,
                    scope=Scope(kind="file", unit=entry.get("unit"), name=file),
                    match_kind=MatchKind.GREP,
                    notes="cap not resolved, co-located: an LLM call is in the same file and no "
                    f"LOOP_CAP_SYMBOLS name within {_LOOP_WINDOW} lines of the loop",
                )
            )
        return _sorted(findings)


# ---------------------------------------------------------------------------
# AUD-103 / AUD-104 / AUD-105: tool-shaped rules
# ---------------------------------------------------------------------------


class FetchNoAllowlist(AuditRule):
    id = "AUD-103"
    title = "Fetch/browse tool without a URL allowlist"
    priority = 1
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T2
    controls = ("ASI01", "ASI02", "LLM01", "NIST:MAP-5.1")
    related_lint_rules = ("EU-AIA-015b",)
    known_failure_modes = (
        "False negative when the allowlist lives in another unit (a shared package) or is "
        "enforced by an egress proxy the code never names.",
        "Any ALLOWLIST_SYMBOLS name anywhere in the unit satisfies the rule, even one that "
        "guards a different tool.",
        "Capability is inferred from the tool name and its first 30 body lines; a fetch behind "
        "a wrapper called `do_thing()` is missed.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary="Check every fetched URL against a host allowlist before the request is made.",
        alternatives=(
            "Add an `is_allowed_url(url)` check on scheme and host at the top of the tool and "
            "refuse anything else; block private ranges and loopback.",
            "Route tool traffic through an egress proxy that only resolves the allowed hosts.",
            "Use the provider's hosted web tool with its domain filter instead of raw requests.",
            "aisg: register the tool with a ToolPolicyGuard policy that carries the domain list.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in iter_tools(ctx):
            if "fetch" not in tool.capabilities:
                continue
            hits = hits_in(ctx, "allowlist", unit=tool.unit)
            if _symbol_present(hits, vocab.ALLOWLIST_SYMBOLS, tool.body_symbols):
                continue
            findings.append(
                self.finding(
                    file=tool.file,
                    line=tool.line,
                    snippet=tool.snippet(ctx),
                    evidence=tool.evidence(ctx),
                    scope=unit_scope(ctx, tool.unit, tool.file),
                    match_kind=tool.match_kind,
                    notes=f"tool {tool.name} ({tool.kind}) has fetch capability; no "
                    "ALLOWLIST_SYMBOLS name in its unit",
                )
            )
        return _sorted(findings)


class ExecNoSandbox(AuditRule):
    id = "AUD-104"
    title = "Exec tool without a sandbox"
    priority = 1
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T2
    controls = ("ASI05", "ASI02", "LLM06", "EU:Art.15", "NIST:MANAGE-2.3")
    related_lint_rules = ("EU-AIA-015b", "ALIGN-001")
    known_failure_modes = (
        "False negative when the sandbox lives in another unit or is the deployment itself "
        "(the whole service runs in a locked-down container the code never mentions).",
        "Any SANDBOX_SYMBOLS name in the unit satisfies the rule, including `docker` in an "
        "unrelated helper.",
        "Capability is inferred from the tool name and its first 30 body lines; exec behind a "
        "wrapper called `do_thing()` is missed.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary="Run model-chosen commands in an isolated sandbox with no host credentials.",
        alternatives=(
            "Execute inside a container or microVM per call (docker run --rm with a read-only "
            "root, gVisor / runsc, firecracker) and pass only the working directory in.",
            "Use a hosted code sandbox (e2b, modal) so the host never runs the command.",
            "Allowlist the exact binaries and argument shapes; refuse shell=True and any "
            "interpreter.",
            "aisg: gate the tool with ToolPolicyGuard and keep `shell_command` on the "
            "high_risk_fail_closed list so a judge outage blocks rather than allows.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in iter_tools(ctx):
            if "exec" not in tool.capabilities:
                continue
            hits = hits_in(ctx, "sandbox", unit=tool.unit)
            if _symbol_present(hits, vocab.SANDBOX_SYMBOLS, tool.body_symbols):
                continue
            findings.append(
                self.finding(
                    file=tool.file,
                    line=tool.line,
                    snippet=tool.snippet(ctx),
                    evidence=tool.evidence(ctx),
                    scope=unit_scope(ctx, tool.unit, tool.file),
                    match_kind=tool.match_kind,
                    notes=f"tool {tool.name} ({tool.kind}) has exec capability; no "
                    "SANDBOX_SYMBOLS name in its unit",
                )
            )
        return _sorted(findings)


class NoToolBudget(AuditRule):
    id = "AUD-105"
    title = "No per-session tool budget"
    priority = 1
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("ASI08", "LLM10", "NIST:MANAGE-2.3")
    related_lint_rules = ("EU-AIA-015a",)
    known_failure_modes = (
        "Fires on registries built for tests or demos that never run in production.",
        "A budget enforced by the framework or the provider (max_turns on a Runner, a gateway "
        "rate limit) is not seen when the code never names it.",
        "Any BUDGET_SYMBOLS name in the unit satisfies the rule, including a `rate_limit` on an "
        "unrelated HTTP endpoint.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary="Cap the number of tool calls a single session may make and stop when it is hit.",
        alternatives=(
            "Count tool calls per session in the loop and refuse further calls past "
            "`max_tool_calls`; surface the refusal to the model and the log.",
            "OpenAI Agents SDK / LangGraph: set `max_turns` or `recursion_limit` per run.",
            "Put a token or cost budget on the session at the gateway (a per-key rate limit) so "
            "the cap holds even when the loop is bypassed.",
            "aisg: enable the tool session budget (`_tool_session_counters` on the shared "
            "context) via ToolPolicyGuard.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        by_unit: dict[str | None, list[ToolRef]] = {}
        for tool in iter_tools(ctx):
            by_unit.setdefault(tool.unit, []).append(tool)
        for unit_id, tools in sorted(by_unit.items(), key=lambda kv: kv[0] or ""):
            names = sorted({t.name for t in tools})
            if len(names) < 3:
                continue
            if hits_in(ctx, "budget", unit=unit_id):
                continue
            first = tools[0]
            snippet = f"{len(names)} tools registered: {', '.join(names)}"
            evidence = [Evidence(role="match", file=first.file, line=first.line, snippet=snippet)]
            for tool in tools:
                evidence.append(
                    Evidence(role="tool", file=tool.file, line=tool.line, snippet=tool.name)
                )
            findings.append(
                self.finding(
                    file=first.file,
                    line=first.line,
                    snippet=snippet,
                    evidence=evidence,
                    scope=unit_scope(ctx, unit_id, first.file),
                    match_kind=first.match_kind,
                    notes="no BUDGET_SYMBOLS name in the unit",
                )
            )
        return _sorted(findings)


# ---------------------------------------------------------------------------
# AUD-106 Broad credentials in agent scope
# ---------------------------------------------------------------------------


class BroadCredentials(AuditRule):
    id = "AUD-106"
    title = "Broad credentials in agent scope"
    priority = 1
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    tier = Tier.T1
    controls = ("ASI03", "LLM02", "LLM06", "NIST:GOVERN-6.1")
    related_lint_rules = ("ALIGN-007",)
    known_failure_modes = (
        "Assumes co-location equals reachability: a credential in the same unit as an LLM call "
        "is reported even when the process that reads it never touches the model.",
        "Only the names in BROAD_CRED_NAMES are recognised; a broad credential under a custom "
        "name is missed, and a narrowly scoped token under a listed name is reported.",
        "Values are never read, so a placeholder and a live credential look the same here; "
        "the secrets rules cover the value.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Give the agent process its own least-privilege credential and keep the broad one "
            "out of its environment."
        ),
        alternatives=(
            "Mint a scoped token for the agent (a fine-grained GitHub token, an IAM role with "
            "one policy, a restricted Stripe key) and rotate the broad one.",
            "Move the credential to a secret manager and inject it only into the service that "
            "needs it, not the compose-wide or job-wide environment.",
            "Split the agent into its own compose service / CI job with a minimal env block.",
            "aisg: run the PIIDetector and secret guards on tool output so a leaked value is "
            "redacted before it reaches the model.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        gitignored = {
            getattr(record, "relpath", None): bool(getattr(record, "gitignored", False))
            for record in ctx.files
        }
        any_surface = _any_ai_surface(ctx)
        facts = ctx.config_facts
        bindings = (getattr(facts, "env", None) or []) if facts is not None else []
        for binding in bindings:
            name = str(getattr(binding, "name", "") or "")
            if name not in _BROAD_CRED_NAMES:
                continue
            file = str(getattr(binding, "file", "") or "").replace("\\", "/")
            line = int(getattr(binding, "line", 0) or 0)
            if not self._reachable(ctx, file, any_surface):
                continue
            if (file, line) in seen:
                continue
            seen.add((file, line))
            literal = bool(getattr(binding, "literal", False))
            findings.append(self._emit(ctx, file, line, name, literal, gitignored))
        for hit in hits_in(ctx, "broad_cred"):
            if (hit.file, hit.line) in seen:
                continue
            if not self._reachable(ctx, hit.file, any_surface):
                continue
            seen.add((hit.file, hit.line))
            findings.append(
                self._emit(ctx, hit.file, hit.line, hit.key, None, gitignored, grep=True)
            )
        return _sorted(findings)

    @staticmethod
    def _reachable(ctx: AuditContext, file: str, any_surface: bool) -> bool:
        unit = unit_of(ctx, file)
        if unit is None:
            return any_surface
        if unit.ai_surface:
            return True
        return unit.root in ("", ".") and any_surface

    def _emit(
        self,
        ctx: AuditContext,
        file: str,
        line: int,
        name: str,
        literal: bool | None,
        gitignored: dict[Any, bool],
        grep: bool = False,
    ) -> Finding:
        if literal is None:
            notes = "name referenced in a code or config file; the value is not read"
        elif literal:
            notes = "bound to a literal value in the file; the value is not read"
        else:
            notes = "bound to a reference or placeholder; the value is not read"
        finding = self.finding(
            file=file,
            line=line,
            snippet=name,
            scope=unit_scope(ctx, None, file),
            match_kind=MatchKind.GREP if grep else None,
            notes=notes,
        )
        if gitignored.get(file):
            finding.gitignored = True
        return finding


# ---------------------------------------------------------------------------
# AUD-107 No kill switch
# ---------------------------------------------------------------------------


class NoKillSwitch(AuditRule):
    id = "AUD-107"
    title = "No kill switch"
    priority = 1
    severity = Severity.MEDIUM
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("ASI10", "ASI08", "EU:Art.14", "NIST:MANAGE-2.4")
    related_lint_rules = ("EU-AIA-014a", "ALIGN-003")
    known_failure_modes = (
        "Cannot tell a kill switch that is read but never acted on from a working one; "
        "`aisg measure` and a runtime drill are what verify it.",
        "A switch implemented outside the code (a load balancer rule, a feature flag service "
        "under a name not in KILL_SWITCH_SYMBOLS) is not seen.",
        "`halt` and `feature_flag` are deliberately not recognised; a project using only those "
        "names is reported.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Read an explicit kill-switch flag at the top of every request and refuse to call "
            "the model or any tool while it is set."
        ),
        alternatives=(
            'Check `os.environ.get("AGENT_DISABLED")` (or `settings.agent_disabled`) before '
            "the LLM call and before each tool dispatch; return a fixed refusal when set.",
            "Wire a feature-flag client (LaunchDarkly, Unleash, a database row) under a "
            "`kill_switch` / `circuit_breaker` name that the request path reads live.",
            "Put the switch at the edge: a gateway rule that returns 503 for the agent route so "
            "the process itself need not be trusted to stop.",
            "aisg: gate the pipeline on a kill-switch guard rather than GUARDRAILS_DISABLE_ALL, "
            "which this package declares but does not read.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for unit in sorted(ctx.inventory.units, key=lambda u: (u.root, u.id)):
            if not unit.ai_surface:
                continue
            reads = hits_in(ctx, "kill_switch_read", unit=unit.id)
            if not reads:
                why = (
                    f"no kill-switch read (KILL_SWITCH_ENV_READS / KILL_SWITCH_SYMBOLS) in unit "
                    f"{unit.id} ({unit.root})"
                )
                finding = self.absence_finding(unit=unit, why=why)
                for hit in sorted(
                    hits_in(ctx, "kill_switch_symbol", unit=unit.id),
                    key=lambda h: (h.file, h.line),
                ):
                    finding.evidence.append(
                        Evidence(role="declared", file=hit.file, line=hit.line, snippet=hit.snippet)
                    )
                if len(finding.evidence) > 1:
                    finding.notes = "a kill-switch name is declared but never read"
                findings.append(finding)
            seen: set[tuple[str, int]] = set()
            for hit in sorted(
                hits_in(ctx, "inert_kill_switch", unit=unit.id), key=lambda h: (h.file, h.line)
            ):
                if (hit.file, hit.line) in seen:
                    continue
                seen.add((hit.file, hit.line))
                findings.append(
                    self.finding(
                        file=hit.file,
                        line=hit.line,
                        snippet=hit.snippet,
                        sub="inert",
                        scope=Scope(kind="unit", unit=unit.id, name=unit.root),
                        evidence_kind=EvidenceKind.CONFIG
                        if _lang_of(ctx, hit.file) == "config"
                        else EvidenceKind.CODE,
                        notes=f"{hit.key} declared but this package does not honour it: nothing "
                        "in aisg core or modules reads it",
                    )
                )
        return _sorted(findings)


# ---------------------------------------------------------------------------
# AUD-108 Unsafe hooks / CI supply
# ---------------------------------------------------------------------------


class UnsafeHooksCi(AuditRule):
    id = "AUD-108"
    title = "Unsafe hook or CI step"
    priority = 1
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI04", "LLM03", "NIST:GOVERN-6.1")
    related_lint_rules = ("EU-AIA-015b",)
    known_failure_modes = (
        "Only the UNSAFE_HOOK_PATTERNS shapes are recognised (curl or wget piped to a shell, "
        "npx -y, pip install over http://, --trusted-host); a script the hook downloads and "
        "then runs in a second step is missed.",
        "Host-global hooks (~/.claude/settings.json) are not read unless --include-home is passed.",
        "A workflow file the parser could not load as a mapping yields an UNKNOWN item, not a "
        "finding.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Pin what a hook or CI step runs: fetch a versioned artifact, verify it, then "
            "execute it in a separate step."
        ),
        alternatives=(
            "Vendor the script into the repo and run it from disk; review it like code.",
            "Pin the package (`npx package@1.2.3`, a pip requirement with `==` and a hash) and "
            "drop -y / --trusted-host / http://.",
            "Replace `curl | sh` with a checksum-verified download in one step and an execute "
            "in the next, so the transcript shows what ran.",
            "aisg: keep the hook, but run `aisg audit` in CI so a change to the hook command "
            "shows up as a new finding.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        facts = ctx.config_facts
        if facts is not None:
            for record in getattr(facts, "host_records", None) or []:
                file = str(getattr(record, "file", "") or "")
                for hook in getattr(record, "hooks", None) or []:
                    key = getattr(hook, "unsafe_key", None)
                    if not key:
                        continue
                    command = str(getattr(hook, "command", "") or "")
                    line = int(getattr(hook, "line", 0) or 0)
                    if (file, line, command) in seen:
                        continue
                    seen.add((file, line, command))
                    event = getattr(hook, "event", None) or "hook"
                    findings.append(
                        self.finding(
                            file=file,
                            line=line,
                            snippet=command,
                            notes=f"{event} hook matches {key}",
                        )
                    )
            for record in getattr(facts, "ci", None) or []:
                file = str(getattr(record, "file", "") or "")
                for step in getattr(record, "unsafe_steps", None) or []:
                    self._ci_step(findings, seen, file, step)
        for entry in ctx.inventory.ci or []:
            if not isinstance(entry, dict):
                continue
            file = str(entry.get("file", "") or "")
            for step in entry.get("unsafe_steps") or []:
                self._ci_step(findings, seen, file, step)
        return _sorted(findings)

    def _ci_step(
        self, findings: list[Finding], seen: set[tuple[str, int, str]], file: str, step: Any
    ) -> None:
        if isinstance(step, dict):
            line, key, snippet = step.get("line"), step.get("key"), step.get("snippet")
        else:
            try:
                line, key, snippet = step
            except (TypeError, ValueError):
                return
        line = int(line or 0)
        snippet = str(snippet or "")
        if not snippet or (file, line, snippet) in seen:
            return
        seen.add((file, line, snippet))
        findings.append(
            self.finding(file=file, line=line, snippet=snippet, notes=f"CI step matches {key}")
        )


RULES = [
    HostOverGrant,
    UncappedLoop,
    FetchNoAllowlist,
    ExecNoSandbox,
    NoToolBudget,
    BroadCredentials,
    NoKillSwitch,
    UnsafeHooksCi,
]
