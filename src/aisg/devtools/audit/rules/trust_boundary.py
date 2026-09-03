"""aisg/devtools/audit/rules/trust_boundary.py
--------------------------------------------
P3 trust-boundary rules for `aisg audit`: AUD-301 (lethal trifecta), AUD-302
(untrusted content concatenated into a prompt), AUD-303 (system prompt built
from request data).

Two tiers. When `--deep python` ran, `ctx.pyfacts` carries AST facts and the
finding is `match_kind: ast`; otherwise the rules fall back to inventory legs
(AUD-301, `structured`) or the discovery layer's `ingress_to_prompt` co-location
hits (AUD-302/303, `grep`). Deep evidence wins wherever it covers a file: a
grep hit is never emitted next to an AST verdict on the same file.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from aisg.devtools.audit.model import (
    TRIFECTA_RULE_ID,
    AuditContext,
    Basis,
    Evidence,
    EvidenceKind,
    Finding,
    Hit,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownItem,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in, unit_of

__all__ = [
    "LEGS",
    "LethalTrifecta",
    "SystemPromptFromRequest",
    "UntrustedIntoPrompt",
    "RULES",
    "trifecta_scopes",
]

# Leg roles in report order; the inventory section each is read from at the unit tier.
LEGS: tuple[str, ...] = ("private", "untrusted", "external_action")
_LEG_SECTIONS: tuple[tuple[str, str], ...] = (
    ("private", "data_sources"),
    ("untrusted", "ingress"),
    ("external_action", "external_actions"),
)
_REACH_DEPTH = 3  # mirrors pydeep.PyFacts._reach
_INGRESS_WINDOW = 40  # mirrors discover._INGRESS_WINDOW
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{3,}\b")
_IDENT_STOP = frozenset(
    {
        "self",
        "await",
        "async",
        "return",
        "none",
        "true",
        "false",
        "const",
        "function",
        "import",
        "from",
        "this",
        "null",
        "undefined",
        "else",
        "elif",
        "while",
        "with",
        "lambda",
        "yield",
        "print",
        "class",
        "pass",
        "break",
        "continue",
        "string",
        "export",
        "default",
    }
)
_UNIT_NOTE = "legs co-located in one unit; data flow not verified"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _idents(line: str) -> set[str]:
    return {tok for tok in _IDENT_RE.findall(line or "") if tok.lower() not in _IDENT_STOP}


def _posix(path: Any) -> str:
    return str(path or "").replace("\\", "/")


def _line_text(ctx: AuditContext, relpath: str, line: int, fallback: str) -> str:
    """The source line, when the walk enumerated the file; else `fallback`."""
    text = file_text(ctx, relpath) if relpath else None
    if text is None or line < 1:
        return fallback
    lines = text.splitlines()
    if line > len(lines):
        return fallback
    stripped = lines[line - 1].strip()
    return stripped or fallback


def _functions(pyfacts: Any) -> dict[str, Any]:
    functions = getattr(pyfacts, "functions", None)
    return dict(functions) if isinstance(functions, dict) else {}


def _deep_files(pyfacts: Any) -> set[str]:
    """Relpaths the AST layer parsed. A file with a syntax error is absent and keeps grep."""
    out: set[str] = set()
    for info in _functions(pyfacts).values():
        file = getattr(info, "file", None)
        if file:
            out.add(_posix(file))
    return out


def _unit_by_id(ctx: AuditContext, unit_id: str | None) -> Unit | None:
    if unit_id is None:
        return None
    for unit in ctx.inventory.units:
        if unit.id == unit_id:
            return unit
    return None


def _unit_for_path(ctx: AuditContext, relpath: str) -> Unit | None:
    """`unit_of` through the walk records, else the unit whose root is the longest prefix."""
    unit = unit_of(ctx, relpath)
    if unit is not None:
        return unit
    key = _posix(relpath)
    best: Unit | None = None
    best_len = -1
    for candidate in ctx.inventory.units:
        root = _posix(candidate.root or ".")
        if root in (".", ""):
            depth = 0
        elif key == root or key.startswith(root.rstrip("/") + "/"):
            depth = len(root)
        else:
            continue
        if depth > best_len:
            best, best_len = candidate, depth
    return best


def _ev_fields(item: Any) -> tuple[str, int, str] | None:
    """(file, line, snippet) from an Evidence or a dict-shaped leg entry; None when unusable."""
    if isinstance(item, dict):
        file, line, snippet = item.get("file"), item.get("line"), item.get("snippet")
        if snippet is None:
            snippet = item.get("symbol")
    else:
        file = getattr(item, "file", None)
        line = getattr(item, "line", None)
        snippet = getattr(item, "snippet", None)
    if not file:
        return None
    try:
        number = int(line or 0)
    except (TypeError, ValueError):
        number = 0
    return _posix(file), number, str(snippet or "")


def _sanitiser_hits(ctx: AuditContext, relpath: str) -> list[Hit]:
    return sorted(hits_in(ctx, "sanitiser", file=relpath), key=lambda h: (h.line, h.key))


def _sanitiser_note(hits: list[Hit]) -> str:
    names = sorted({h.key for h in hits})
    lines = ", ".join(str(h.line) for h in hits[:3])
    return (
        f"sanitiser symbol(s) {', '.join(names)} present in this file (line {lines}) but not on "
        "the assembly's binding path; verify it covers this prompt (a decorator is not followed)"
    )


def _sorted(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.location[0], f.location[1], f.sub or ""))


# ---------------------------------------------------------------------------
# AUD-301  Lethal trifecta
# ---------------------------------------------------------------------------


def _reach(functions: dict[str, Any], root: str, by_name: dict[str, list[str]]) -> list[str]:
    """Keys reachable from `root` through bare-name calls, depth-bounded, root first."""
    seen, queue, order = {root}, deque([(root, 0)]), []
    while queue:
        cur, depth = queue.popleft()
        order.append(cur)
        info = functions.get(cur)
        if info is None or depth >= _REACH_DEPTH:
            continue
        for callee in getattr(info, "calls", ()) or ():
            for key in by_name.get(str(callee).rsplit(".", 1)[-1], ()):
                if key not in seen:
                    seen.add(key)
                    queue.append((key, depth + 1))
    return order


def _by_name(functions: dict[str, Any]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for key, info in functions.items():
        name = getattr(info, "name", None)
        if name:
            index.setdefault(str(name).rsplit(".", 1)[-1], []).append(key)
    return index


def _scope_keys(pyfacts: Any, scope: Scope) -> list[str]:
    """Function keys whose legs back `scope`, in call-graph (BFS) order."""
    functions = _functions(pyfacts)
    if scope.kind == "function":
        roots = [
            key
            for key, info in functions.items()
            if getattr(info, "name", None)
            and f"{_posix(getattr(info, 'file', ''))}::{info.name}" == scope.name
        ]
        by_name = _by_name(functions)
        keys: list[str] = []
        for root in roots:
            for key in _reach(functions, root, by_name):
                if key not in keys:
                    keys.append(key)
        return keys
    if scope.kind == "file":
        return [
            key
            for key, info in functions.items()
            if _posix(getattr(info, "file", "")) == scope.name
        ]
    return [key for key, info in functions.items() if getattr(info, "unit", None) == scope.unit]


def _deep_legs(pyfacts: Any, scope: Scope) -> dict[str, Evidence]:
    """One Evidence per leg role for a pydeep trifecta scope; missing roles are absent."""
    legs = getattr(pyfacts, "legs", None)
    legs = legs if isinstance(legs, dict) else {}
    out: dict[str, Evidence] = {}
    for key in _scope_keys(pyfacts, scope):
        by_role = legs.get(key) or {}
        for role in LEGS:
            if role in out:
                continue
            for item in by_role.get(role) or []:
                fields = _ev_fields(item)
                if fields is not None:
                    out[role] = Evidence(
                        role=role, file=fields[0], line=fields[1], snippet=fields[2]
                    )
                    break
    return out


def _scope_anchor(pyfacts: Any, scope: Scope) -> tuple[str, int]:
    """(file, line) the scope starts at: the def line for a function, 1 for a file."""
    if scope.kind == "function":
        for info in _functions(pyfacts).values():
            name = getattr(info, "name", None)
            file = _posix(getattr(info, "file", ""))
            if name and f"{file}::{name}" == scope.name:
                return file, int(getattr(info, "line", 0) or 0)
        return str(scope.name or "").split("::", 1)[0], 0
    return _posix(scope.name or "."), 1 if scope.kind == "file" else 0


@dataclass
class _UnitLegs:
    """Unit-tier legs: inventory entries per role, plus MCP-implied ones kept apart."""

    code: dict[str, list[Evidence]] = field(default_factory=lambda: {r: [] for r in LEGS})
    mcp: dict[str, list[tuple[Evidence, str]]] = field(
        default_factory=lambda: {r: [] for r in LEGS}
    )
    code_files: set[str] = field(default_factory=set)

    def roles(self, *, with_mcp: bool) -> set[str]:
        out = {r for r in LEGS if self.code[r]}
        if with_mcp:
            out |= {r for r in LEGS if self.mcp[r]}
        return out


def _inventory_legs(ctx: AuditContext, unit: Unit) -> _UnitLegs:
    legs = _UnitLegs()
    for role, section in _LEG_SECTIONS:
        entries = getattr(ctx.inventory, section, None) or []
        rows: list[tuple[str, int, str]] = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("unit") != unit.id:
                continue
            fields = _ev_fields(entry)
            if fields is None:
                continue
            file, line, symbol = fields
            rows.append((file, line, symbol))
        for file, line, symbol in sorted(rows):
            snippet = _line_text(ctx, file, line, symbol)
            legs.code[role].append(Evidence(role=role, file=file, line=line, snippet=snippet))
            legs.code_files.add(file)
    servers = (
        (ctx.inventory.mcp or {}).get("servers") if isinstance(ctx.inventory.mcp, dict) else []
    )
    for server in servers or []:
        if not isinstance(server, dict):
            continue
        file = _posix(server.get("file") or "")
        if not file:
            continue
        owner = _unit_for_path(ctx, file)
        if owner is None or owner.id != unit.id:
            continue
        implied = [str(leg) for leg in server.get("implied_legs") or [] if str(leg) in LEGS]
        # A remote host the operator listed in --trusted-mcp-hosts is not untrusted ingress
        # by transport. Package-name legs stay: trusting the host does not vet its content.
        if server.get("trusted") is True and server.get("url"):
            implied = [leg for leg in implied if leg != "untrusted"]
        name = str(server.get("name") or "?")
        target = server.get("url") or " ".join(
            [str(server.get("command") or "")] + [str(a) for a in server.get("args") or []]
        )
        snippet = f"mcp server {name}: {target.strip()}"
        try:
            line = int(server.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        for role in implied:
            legs.mcp[role].append(
                (Evidence(role=role, file=file, line=line, snippet=snippet), name)
            )
    return legs


class LethalTrifecta(AuditRule):
    id = TRIFECTA_RULE_ID
    title = "LETHAL TRIFECTA: private data + untrusted content + external action in one scope"
    priority = 3
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    measured_precision = None
    known_failure_modes = (
        "unit-level scope over-approximates in monorepos",
        "MCP legs implied by package name",
        "call-graph reach is depth-3 and by bare name; dynamic dispatch is not followed",
    )
    controls = (
        "ASI01",
        "ASI02",
        "ASI06",
        "LLM01",
        "LLM02",
        "LLM06",
        "EU:Art.9",
        "EU:Art.15",
        "NIST:MAP-5.1",
        "NIST:MANAGE-2.2",
    )
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Split the loop so no single agent turn holds private data, untrusted content and "
            "an external action: route untrusted content through a read-only agent, and gate "
            "every external action behind a human approval or a separate, data-free worker."
        ),
        alternatives=(
            "aisg ToolPolicyGuard (approval on external-action tools) + PIIDetector on ingress",
            "Dual-LLM / CaMeL pattern: a quarantined model reads untrusted content, a "
            "privileged model with no tool access to it decides actions",
            "NeMo Guardrails flows that forbid tool calls in turns that ingested external text",
            "Guardrails AI validators on tool inputs plus an allowlist of action targets",
            "Per-turn capability tokens: drop the write/send capability once untrusted content "
            "enters the context",
        ),
    )
    tier = Tier.T3
    related_lint_rules = ("EU-AIA-012a", "EU-AIA-014a", "ALIGN-003")

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        pyfacts = ctx.pyfacts
        deep_files = _deep_files(pyfacts)
        deep_hit_units: set[str | None] = set()

        if pyfacts is not None:
            for scope in self._deep_scopes(pyfacts):
                unit = _unit_by_id(ctx, scope.unit)
                if unit is not None and not unit.ai_surface:
                    continue
                legs = _deep_legs(pyfacts, scope)
                missing = [role for role in LEGS if role not in legs]
                if missing:
                    self.unknown.append(
                        UnknownItem(
                            category="deep",
                            what=f"AUD-301 scope {scope.name}",
                            why=f"deep analysis reported the scope but no evidence for {missing}",
                            how_to_resolve="re-run with --deep python; report the scope",
                            file=_scope_anchor(pyfacts, scope)[0],
                            rule_ids=(self.id,),
                        )
                    )
                    continue
                file, line = _scope_anchor(pyfacts, scope)
                findings.append(
                    self.finding(
                        file=file,
                        line=line,
                        snippet=str(scope.name or file),
                        evidence=[legs[role] for role in LEGS],
                        scope=scope,
                        match_kind=MatchKind.AST,
                    )
                )
                deep_hit_units.add(scope.unit)

        for unit in ctx.inventory.units:
            if not unit.ai_surface or unit.id in deep_hit_units:
                continue
            legs = _inventory_legs(ctx, unit)
            covered = bool(deep_files) and bool(legs.code_files) and legs.code_files <= deep_files
            if covered and pyfacts is not None:
                # Deep parsed every file holding a code leg and found no connected scope:
                # only a leg the AST layer cannot see (an MCP server) may complete the set.
                if not (legs.roles(with_mcp=True) - legs.roles(with_mcp=False)):
                    continue
            if legs.roles(with_mcp=True) != set(LEGS):
                continue
            evidence: list[Evidence] = []
            mcp_notes: list[str] = []
            for role in LEGS:
                if legs.code[role]:
                    evidence.append(legs.code[role][0])
                    continue
                ev, name = legs.mcp[role][0]
                evidence.append(ev)
                mcp_notes.append(f"{role} leg implied by MCP server '{name}' ({ev.file})")
            root = _posix(unit.root or ".")
            findings.append(
                self.finding(
                    file=root,
                    line=0,
                    snippet=f"unit {root}",
                    evidence=evidence,
                    scope=Scope(kind="unit", unit=unit.id, name=root),
                    match_kind=MatchKind.STRUCTURED,
                    notes="; ".join([_UNIT_NOTE] + mcp_notes),
                )
            )
        return _sorted(findings)

    def _deep_scopes(self, pyfacts: Any) -> list[Scope]:
        method = getattr(pyfacts, "trifecta_scopes", None)
        if not callable(method):
            return []
        try:
            scopes = list(method())
        except Exception as exc:  # a broken deep layer degrades to the unit tier, visibly
            self.unknown.append(
                UnknownItem(
                    category="deep",
                    what="AUD-301 trifecta scopes",
                    why=f"{type(exc).__name__}: {exc}",
                    how_to_resolve="re-run with --deep python; report the traceback",
                    rule_ids=(self.id,),
                )
            )
            return []
        out = [s for s in scopes if isinstance(s, Scope)]
        return sorted(out, key=lambda s: (s.kind, str(s.unit or ""), str(s.name or "")))


def trifecta_scopes(ctx: AuditContext) -> list[Scope]:
    """Scopes AUD-301 would report on `ctx`: function or file scopes when deep ran, else units."""
    return [finding.scope for finding in LethalTrifecta().evaluate(ctx)]


# ---------------------------------------------------------------------------
# AUD-302 / AUD-303  Untrusted content into a prompt
# ---------------------------------------------------------------------------


@dataclass
class _PromptSite:
    """A grep-tier prompt line that shares an identifier with an ingress line above it."""

    file: str
    line: int
    snippet: str
    unit: str | None
    idents: list[str] = field(default_factory=list)
    sources: list[Hit] = field(default_factory=list)
    system_hit: Hit | None = None


def _prompt_sites(ctx: AuditContext) -> list[_PromptSite]:
    by_key: dict[tuple[str, int], _PromptSite] = {}
    for hit in sorted(hits_in(ctx, "ingress_to_prompt"), key=lambda h: (h.file, h.line, h.key)):
        site = by_key.setdefault(
            (hit.file, hit.line),
            _PromptSite(file=hit.file, line=hit.line, snippet=hit.snippet, unit=hit.unit),
        )
        if hit.key and hit.key not in site.idents:
            site.idents.append(hit.key)
    for site in by_key.values():
        wanted = set(site.idents)
        for ingress in sorted(hits_in(ctx, "ingress", file=site.file), key=lambda h: h.line):
            if not (ingress.line < site.line <= ingress.line + _INGRESS_WINDOW):
                continue
            if wanted & _idents(ingress.snippet):
                site.sources.append(ingress)
        prompt_idents = _idents(site.snippet)
        for hit in sorted(hits_in(ctx, "prompt_assembly", file=site.file), key=lambda h: h.line):
            if hit.key != "system_role":
                continue
            if hit.line == site.line:
                site.system_hit = hit
                break
            if site.line < hit.line <= site.line + _INGRESS_WINDOW and (
                prompt_idents & _idents(hit.snippet)
            ):
                site.system_hit = hit
                break
    return sorted(by_key.values(), key=lambda s: (s.file, s.line))


def _untrusted_sources(ctx: AuditContext, relpath: str, line: int) -> list[Evidence]:
    """The nearest untrusted-ingress line above `line` in the same file, as `source`."""
    rows: list[tuple[int, str]] = []
    legs = getattr(ctx.pyfacts, "legs", None)
    for by_role in (legs or {}).values() if isinstance(legs, dict) else []:
        for item in (by_role or {}).get("untrusted") or []:
            fields = _ev_fields(item)
            if fields is not None and fields[0] == relpath and fields[1] <= line:
                rows.append((fields[1], _line_text(ctx, relpath, fields[1], fields[2])))
    if not rows:
        for entry in ctx.inventory.ingress or []:
            fields = _ev_fields(entry)
            if fields is not None and fields[0] == relpath and fields[1] <= line:
                rows.append((fields[1], _line_text(ctx, relpath, fields[1], fields[2])))
    if not rows:
        return []
    src_line, snippet = max(rows)
    return [Evidence(role="source", file=relpath, line=src_line, snippet=snippet)]


class _PromptRule(AuditRule):
    """Shared evaluate for AUD-302/303; `system` selects which assemblies belong to the rule."""

    system: bool = False
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    requires_ai_surface = True
    measured_precision = None

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        pyfacts = ctx.pyfacts
        deep_files = _deep_files(pyfacts)

        assemblies = getattr(pyfacts, "prompt_assemblies", None) if pyfacts is not None else None
        for assembly in sorted(
            list(assemblies or []),
            key=lambda a: (_posix(getattr(a, "file", "")), int(getattr(a, "line", 0) or 0)),
        ):
            names = tuple(getattr(assembly, "untrusted_names", ()) or ())
            if not names or bool(getattr(assembly, "is_system", False)) is not self.system:
                continue
            file = _posix(getattr(assembly, "file", ""))
            line = int(getattr(assembly, "line", 0) or 0)
            if not file or (file, line) in seen:
                continue
            seen.add((file, line))
            findings.append(self._deep_finding(ctx, assembly, file, line, names))

        for site in _prompt_sites(ctx):
            if site.file in deep_files or (site.file, site.line) in seen:
                continue
            if (site.system_hit is not None) is not self.system:
                continue
            seen.add((site.file, site.line))
            findings.append(self._grep_finding(ctx, site))
        return _sorted(findings)

    def _deep_finding(
        self, ctx: AuditContext, assembly: Any, file: str, line: int, names: tuple[str, ...]
    ) -> Finding:
        kind = str(getattr(assembly, "kind", "") or "assembly")
        fallback = f"{kind} prompt built from {', '.join(names)}"
        evidence = [
            Evidence(
                role="assembly", file=file, line=line, snippet=_line_text(ctx, file, line, fallback)
            )
        ]
        evidence.extend(_untrusted_sources(ctx, file, line))
        what = "system prompt" if self.system else "prompt"
        notes = f"untrusted name(s) {', '.join(names)} bound from ingress reach this {kind} {what}"
        severity: Severity | None = None
        sanitisers = _sanitiser_hits(ctx, file)
        if sanitisers:
            severity = Severity.LOW
            notes = f"{notes}; {_sanitiser_note(sanitisers)}"
        unit = unit_of(ctx, file)
        return self.finding(
            file=file,
            line=line,
            snippet=evidence[0].snippet,
            evidence=evidence,
            scope=Scope(kind="file", unit=unit.id if unit is not None else None, name=file),
            severity=severity,
            match_kind=MatchKind.AST,
            notes=notes,
        )

    def _grep_finding(self, ctx: AuditContext, site: _PromptSite) -> Finding:
        evidence = [Evidence(role="assembly", file=site.file, line=site.line, snippet=site.snippet)]
        if site.system_hit is not None and site.system_hit.line != site.line:
            evidence.append(
                Evidence(
                    role="system_role",
                    file=site.file,
                    line=site.system_hit.line,
                    snippet=site.system_hit.snippet,
                )
            )
        seen_lines: set[int] = set()
        for source in site.sources:
            if source.line in seen_lines or len(seen_lines) >= 3:
                continue
            seen_lines.add(source.line)
            evidence.append(
                Evidence(role="source", file=site.file, line=source.line, snippet=source.snippet)
            )
        notes = (
            f"co-located, unverified: identifier(s) {', '.join(site.idents)} shared with an "
            f"ingress line within {_INGRESS_WINDOW} lines; data flow not verified"
        )
        severity: Severity | None = None
        sanitisers = _sanitiser_hits(ctx, site.file)
        if sanitisers:
            severity = Severity.LOW
            notes = f"{notes}; {_sanitiser_note(sanitisers)}"
        return self.finding(
            file=site.file,
            line=site.line,
            snippet=site.snippet,
            evidence=evidence,
            scope=Scope(kind="file", unit=site.unit, name=site.file),
            severity=severity,
            match_kind=MatchKind.GREP,
            notes=notes,
        )


class UntrustedIntoPrompt(_PromptRule):
    id = "AUD-302"
    title = "Untrusted content concatenated into a prompt"
    priority = 3
    severity = Severity.HIGH
    system = False
    known_failure_modes = (
        "misses sanitisation done in a decorator",
        "grep tier co-locates by shared identifier and is noisy by design",
    )
    controls = ("ASI01", "ASI06", "LLM01", "EU:Art.15", "NIST:MAP-5.1", "NIST:MEASURE-2.7")
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Delimit and label untrusted text before it enters the prompt, keep it in the user "
            "turn (never the system prompt), and run an injection detector on the ingress path."
        ),
        alternatives=(
            "aisg PromptInjectionGuard on the input stage, with the mention/use distinction on",
            "Spotlighting: wrap untrusted text in explicit delimiters or datamarking and tell "
            "the model the span is data, not instructions",
            "LLM Guard PromptInjection scanner or Lakera Guard on the ingress path",
            "Rebuff or a NeMo Guardrails input rail before assembly",
        ),
    )
    tier = Tier.T2
    related_lint_rules = ("EU-AIA-015a",)


class SystemPromptFromRequest(_PromptRule):
    id = "AUD-303"
    title = "System prompt built from request data"
    priority = 3
    severity = Severity.HIGH
    system = True
    known_failure_modes = (
        "misses sanitisation done in a decorator",
        "grep tier binds a `system=` line to an assembly by shared identifier only",
    )
    controls = ("ASI01", "LLM01", "LLM07", "EU:Art.15", "NIST:MAP-5.1", "NIST:MEASURE-2.7")
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Keep the system prompt static: move every request-derived value into the user "
            "turn or a structured tool result, and template only from trusted configuration."
        ),
        alternatives=(
            "aisg PromptInjectionGuard on the request field before any prompt is built",
            "Static system prompt file plus a typed context object passed in the user message",
            "NeMo Guardrails or Guardrails AI input validation that rejects instruction-like text",
            "Provider-side prompt caching of a fixed system prompt, which makes per-request "
            "system text a visible cache miss",
        ),
    )
    tier = Tier.T3
    related_lint_rules = ("EU-AIA-015a",)


RULES = [LethalTrifecta, UntrustedIntoPrompt, SystemPromptFromRequest]
