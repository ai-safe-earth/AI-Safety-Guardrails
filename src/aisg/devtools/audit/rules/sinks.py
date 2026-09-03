# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/sinks.py
------------------------------------
P4 sink rules for `aisg audit`: AUD-401..AUD-406, one per sink kind. Each reports
model output reaching a dangerous call without a sanitiser on the way.

Deep tier (`--deep python`): `pyfacts.taint_paths` with `sanitised` False, evidence
roles `source` (the response accessor) and `sink`, `match_kind: ast`. Grep tier:
a `sink` hit within 60 lines after an `llm_call` or `response_accessor` hit in the
same file that shares an identifier of four or more characters. Co-location is
noisy by design and every grep finding says so in its notes. Deep wins per file:
when the AST layer parsed a file no grep finding is emitted for it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from aisg.devtools.audit.model import (
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
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in, unit_of

__all__ = [
    "SINK_RULE_BY_KIND",
    "ShellSink",
    "EvalSink",
    "SqlSink",
    "HtmlSink",
    "UrlSink",
    "FsSink",
    "RULES",
]

_WINDOW = 60  # lines a sink may follow an llm_call / response_accessor hit by
_SOURCE_TABLES = ("response_accessor", "llm_call")
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


def _idents(line: str) -> set[str]:
    return {tok for tok in _IDENT_RE.findall(line or "") if tok.lower() not in _IDENT_STOP}


def _posix(path: Any) -> str:
    return str(path or "").replace("\\", "/")


def _line_text(ctx: AuditContext, relpath: str, line: int, fallback: str) -> str:
    text = file_text(ctx, relpath) if relpath else None
    if text is None or line < 1:
        return fallback
    lines = text.splitlines()
    if line > len(lines):
        return fallback
    stripped = lines[line - 1].strip()
    return stripped or fallback


def _deep_files(pyfacts: Any) -> set[str]:
    """Relpaths the AST layer parsed; a file it could not parse keeps its grep tier."""
    functions = getattr(pyfacts, "functions", None)
    out: set[str] = set()
    for info in (functions or {}).values() if isinstance(functions, dict) else []:
        file = getattr(info, "file", None)
        if file:
            out.add(_posix(file))
    return out


def _sorted(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.location[0], f.location[1], f.sub or ""))


@dataclass(frozen=True)
class _Source:
    hit: Hit
    delta: int
    shared: tuple[str, ...]


def _nearest_source(ctx: AuditContext, sink: Hit) -> _Source | None:
    """
    The closest llm_call / response_accessor hit above `sink` sharing an identifier.

    A response accessor on the sink's own line counts (`exec(resp.choices[0]...)`);
    an llm_call must be strictly above it, so the call line's own URL sink does not
    pair with itself.
    """
    sink_idents = _idents(sink.snippet)
    if not sink_idents:
        return None
    best: _Source | None = None
    for table in _SOURCE_TABLES:
        for hit in hits_in(ctx, table, file=sink.file):
            delta = sink.line - hit.line
            if delta < 0 or delta > _WINDOW:
                continue
            if table == "llm_call" and delta == 0:
                continue
            shared = tuple(sorted(sink_idents & _idents(hit.snippet)))
            if not shared:
                continue
            candidate = _Source(hit=hit, delta=delta, shared=shared)
            if best is None or candidate.delta < best.delta:
                best = candidate
        if best is not None:
            return best  # a response accessor beats any llm_call
    return best


class _SinkRule(AuditRule):
    """Shared evaluate for the six sink rules; `kind` selects the sink family."""

    kind: str = ""
    priority = 4
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    requires_ai_surface = True
    measured_precision = None
    known_failure_modes = (
        "taint stops at data structures",
        "grep co-location is noisy by design and says so",
    )
    tier = Tier.T3
    related_lint_rules = ("EU-AIA-014b", "ALIGN-003")

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        pyfacts = ctx.pyfacts
        deep_files = _deep_files(pyfacts)

        paths = getattr(pyfacts, "taint_paths", None) if pyfacts is not None else None
        for path in sorted(
            list(paths or []),
            key=lambda p: (
                _posix(getattr(p, "file", "")),
                int(getattr(p, "sink_line", 0) or 0),
                int(getattr(p, "source_line", 0) or 0),
            ),
        ):
            if getattr(path, "sink_kind", None) != self.kind or bool(
                getattr(path, "sanitised", False)
            ):
                continue
            file = _posix(getattr(path, "file", ""))
            sink_line = int(getattr(path, "sink_line", 0) or 0)
            if not file or (file, sink_line) in seen:
                continue
            seen.add((file, sink_line))
            findings.append(self._deep_finding(ctx, path, file, sink_line))

        for hit in sorted(hits_in(ctx, "sink"), key=lambda h: (h.file, h.line, h.key)):
            if hit.key.split(":", 1)[0] != self.kind:
                continue
            if hit.file in deep_files or (hit.file, hit.line) in seen:
                continue
            source = _nearest_source(ctx, hit)
            if source is None:
                continue
            seen.add((hit.file, hit.line))
            findings.append(self._grep_finding(hit, source))
        return _sorted(findings)

    def _deep_finding(self, ctx: AuditContext, path: Any, file: str, sink_line: int) -> Finding:
        source_line = int(getattr(path, "source_line", 0) or 0)
        accessor = str(getattr(path, "source_accessor", "") or "model output")
        sink_call = str(getattr(path, "sink_call", "") or self.kind)
        evidence = [
            Evidence(
                role="source",
                file=file,
                line=source_line,
                snippet=_line_text(ctx, file, source_line, accessor),
            ),
            Evidence(
                role="sink",
                file=file,
                line=sink_line,
                snippet=_line_text(ctx, file, sink_line, sink_call),
            ),
        ]
        unit = unit_of(ctx, file)
        unit_id = unit.id if unit is not None else None
        function = getattr(path, "function", None)
        if function:
            scope = Scope(kind="function", unit=unit_id, name=f"{file}::{function}")
        else:
            scope = Scope(kind="file", unit=unit_id, name=file)
        notes = (
            f"model output ({accessor}, line {source_line}) reaches {sink_call} at line {sink_line}"
        )
        via = tuple(int(v) for v in (getattr(path, "via", ()) or ()) if v)
        if len(via) > 1:
            notes = f"{notes} via lines {', '.join(str(v) for v in via)}"
        return self.finding(
            file=file,
            line=sink_line,
            snippet=evidence[1].snippet,
            evidence=evidence,
            scope=scope,
            match_kind=MatchKind.AST,
            notes=notes,
        )

    def _grep_finding(self, sink: Hit, source: _Source) -> Finding:
        evidence = [
            Evidence(
                role="source", file=sink.file, line=source.hit.line, snippet=source.hit.snippet
            ),
            Evidence(role="sink", file=sink.file, line=sink.line, snippet=sink.snippet),
        ]
        notes = (
            f"co-located, unverified: identifier(s) {', '.join(source.shared)} shared with "
            f"{source.hit.table} at line {source.hit.line}; data flow not verified"
        )
        return self.finding(
            file=sink.file,
            line=sink.line,
            snippet=sink.snippet,
            evidence=evidence,
            scope=Scope(kind="file", unit=sink.unit, name=sink.file),
            match_kind=MatchKind.GREP,
            notes=notes,
        )


class ShellSink(_SinkRule):
    id = "AUD-401"
    kind = "shell"
    title = "Model output -> shell"
    severity = Severity.CRITICAL
    controls = (
        "ASI02",
        "ASI05",
        "LLM05",
        "LLM06",
        "EU:Art.15",
        "NIST:MANAGE-2.2",
        "NIST:MEASURE-2.7",
    )
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Never hand model text to a shell. Map the model's choice onto a fixed set of "
            "commands, pass arguments as an argv list, and run in a sandbox with an approval "
            "step for anything that writes or sends."
        ),
        alternatives=(
            "aisg ToolPolicyGuard with shell_command in the approval-required set",
            "Argv lists with shlex.quote and shell=False; no string interpolation into a command",
            "Run tool code in a container or gVisor/Firecracker sandbox with no network by default",
            "NeMo Guardrails output rail that refuses executable text",
        ),
    )


class EvalSink(_SinkRule):
    id = "AUD-402"
    kind = "eval"
    title = "Model output -> eval/exec"
    severity = Severity.CRITICAL
    controls = ("ASI02", "ASI05", "LLM05", "LLM06", "EU:Art.15", "NIST:MANAGE-2.2")
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Do not evaluate model-written code in the host process. Parse the output into a "
            "typed structure, or execute it in an isolated interpreter with a resource cap."
        ),
        alternatives=(
            "aisg ToolPolicyGuard approval on any code-execution tool",
            "ast.literal_eval or a JSON schema for structured output instead of eval",
            "A sandboxed interpreter (Pyodide, RestrictedPython, a subprocess with seccomp) with "
            "a timeout and no filesystem",
            "E2B / Modal style remote sandboxes for agent-written code",
        ),
    )


class SqlSink(_SinkRule):
    id = "AUD-403"
    kind = "sql"
    title = "Model output -> SQL"
    severity = Severity.CRITICAL
    controls = ("ASI02", "LLM05", "LLM06", "EU:Art.15", "NIST:MANAGE-2.2")
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Model text is never a query. Bind it as a parameter, or map it onto a fixed set "
            "of prepared statements, and run text-to-SQL against a read-only replica."
        ),
        alternatives=(
            "aisg ToolPolicyGuard with database_write in the high-risk fail-closed set",
            "Parameterised queries / prepared statements; model output only in bind values",
            "A read-only database role for any connection the agent can reach",
            "SQL allowlist or parser (sqlglot) that rejects DDL/DML before execution",
        ),
    )


class HtmlSink(_SinkRule):
    id = "AUD-404"
    kind = "html"
    title = "Model output -> HTML without escaping"
    severity = Severity.HIGH
    controls = ("LLM05", "LLM02", "EU:Art.15", "NIST:MEASURE-2.7")
    related_lint_rules = ("EU-AIA-014b",)
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Treat model output as untrusted markup. Render it as text, or through a sanitiser "
            "with an element allowlist, and ship a Content-Security-Policy."
        ),
        alternatives=(
            "aisg OutputSanitizer on the output stage before rendering",
            "textContent / autoescaping templates instead of innerHTML, Markup or mark_safe",
            "DOMPurify or bleach with an explicit tag allowlist",
            "A strict Content-Security-Policy so injected markup cannot run script",
        ),
    )


class UrlSink(_SinkRule):
    id = "AUD-405"
    kind = "url"
    title = "Model output -> outbound URL"
    severity = Severity.HIGH
    controls = ("ASI02", "LLM05", "LLM06", "EU:Art.15", "NIST:MANAGE-2.2")
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "A model-chosen URL is an SSRF and exfiltration path. Resolve it against a host "
            "allowlist, block private ranges, and never attach credentials to it."
        ),
        alternatives=(
            "aisg ToolPolicyGuard with an allowlist on fetch/browse tools",
            "Host allowlist plus a resolver check that rejects loopback, link-local and RFC1918",
            "An egress proxy that strips credentials and logs every outbound request",
            "Pre-registered URL templates the model fills with validated parameters only",
        ),
    )


class FsSink(_SinkRule):
    id = "AUD-406"
    kind = "fs"
    title = "Model output -> filesystem write"
    severity = Severity.HIGH
    controls = ("ASI02", "LLM05", "LLM06", "EU:Art.15", "NIST:MANAGE-2.2")
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Confine model-driven writes to a scratch directory: resolve the path, reject "
            "anything outside the allowed root, and keep the agent off dotfiles and code."
        ),
        alternatives=(
            "aisg ToolPolicyGuard approval on write/delete tools",
            "Path.resolve() + is_relative_to(allowed_root) before every open(..., 'w')",
            "Run the agent in a container with a single writable mount",
            "A versioned scratch store (git worktree, object store) so writes are reviewable",
        ),
    )


RULES = [ShellSink, EvalSink, SqlSink, HtmlSink, UrlSink, FsSink]

SINK_RULE_BY_KIND: dict[str, str] = {rule.kind: rule.id for rule in RULES}
