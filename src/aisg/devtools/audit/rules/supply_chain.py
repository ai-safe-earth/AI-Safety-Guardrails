"""aisg/devtools/audit/rules/supply_chain.py
-------------------------------------------
P6 rules, AUD-601..606: floating model ids, unpinned MCP servers and bootstrap
lines, remote or plaintext MCP transports, poisoned MCP tool descriptions,
unverified weights, and the dependency-vulnerability slot the external adapters
fill.

AUD-604 reads `McpServer.description` only (tool descriptions are already folded
into it by `configs`) and never applies `patterns.is_mention`: a description is
read by the model, not by a person, so "discussing" an attack phrase there is the
attack.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from aisg.devtools.audit import patterns
from aisg.devtools.audit.configs import is_loopback
from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    Evidence,
    EvidenceKind,
    Finding,
    MatchKind,
    Recommendation,
    Severity,
    Tier,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in

__all__ = [
    "RULES",
    "DependencyVulns",
    "McpDescriptionPoisoning",
    "RemoteMcp",
    "UnpinnedMcp",
    "UnpinnedModel",
    "UnpinnedWeights",
]

_PLAINTEXT_SCHEMES = frozenset({"http", "ws"})
_MAX_POISON_LEGS = 6


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.evidence[0].file if f.evidence else "",
            f.evidence[0].line if f.evidence else 0,
            f.sub or "",
        ),
    )


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _line_text(ctx: AuditContext, relpath: str, line: int) -> str | None:
    text = file_text(ctx, relpath)
    if text is None or line < 1:
        return None
    lines = text.split("\n")
    if line > len(lines):
        return None
    return lines[line - 1].rstrip("\r")


def _servers(ctx: AuditContext) -> list[Any]:
    """`ConfigFacts.servers` when present, else the inventory's projected entries.

    The inventory shape is a dict with the section 2 keys; attribute access is
    normalised through `_field` so both work in the rules below.
    """
    facts = getattr(ctx.config_facts, "servers", None)
    if facts:
        return list(facts)
    mcp = ctx.inventory.mcp if isinstance(ctx.inventory.mcp, dict) else {}
    return [s for s in mcp.get("servers", []) or [] if isinstance(s, dict)]


def _field(server: Any, name: str, default: Any = None) -> Any:
    if isinstance(server, dict):
        return server.get(name, default)
    return getattr(server, name, default)


def _launch(server: Any) -> str:
    command = _field(server, "command") or ""
    args = " ".join(str(a) for a in (_field(server, "args") or ()))
    return f"{command} {args}".strip() or (_field(server, "url") or "")


def _trusted_hosts(ctx: AuditContext) -> set[str]:
    raw = getattr(ctx.options, "trusted_mcp_hosts", ()) or ()
    if isinstance(raw, str):
        raw = raw.split(",")
    return {str(h).strip().lower() for h in raw if str(h).strip()}


def _server_remote(server: Any) -> tuple[bool, str | None]:
    """(remote, host) for a config-facts or inventory server entry."""
    remote = _field(server, "remote")
    url = _field(server, "url")
    host = _field(server, "remote_host")
    if host is None and url:
        try:
            host = urlparse(str(url)).hostname
        except ValueError:
            host = None
    if remote is None:
        remote = bool(url) and not is_loopback(host)
    return bool(remote), (host.lower() if isinstance(host, str) else None)


def _is_trusted(server: Any, host: str | None, trusted: set[str]) -> bool:
    if not trusted:
        return False
    candidates: set[str] = set()
    if host:
        candidates.add(host)
    url = _field(server, "url")
    if url:
        try:
            netloc = urlparse(str(url)).netloc.lower()
        except ValueError:
            netloc = ""
        if netloc:
            candidates.add(netloc)
    return bool(candidates & trusted)


def _scheme(url: Any) -> str:
    try:
        return urlparse(str(url)).scheme.lower() if url else ""
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# AUD-601
# ---------------------------------------------------------------------------


class UnpinnedModel(AuditRule):
    """A model id that resolves to a floating alias.

    Reads `inventory.models[]`; `pinned is False` is the signal. `None` (unknown
    provider, Hugging Face id) is not a finding: pinning cannot be told from the id.
    """

    id = "AUD-601"
    title = "Unpinned model id"
    priority = 6
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI04", "LLM03", "EU:Art.9", "EU:Art.15", "NIST:MANAGE-3.1", "NIST:GOVERN-6.1")
    related_lint_rules = ()
    known_failure_modes = (
        "provider alias tables go stale as vendors rename snapshots",
        "a model id read from an environment variable is only seen when the .env is committed",
        "an id built at runtime (f-string, config lookup) is not seen",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Pin the dated snapshot (claude-*-YYYYMMDD, gpt-4o-YYYY-MM-DD, gemini-*-NNN) "
            "and bump it deliberately with an eval run."
        ),
        alternatives=(
            "aisg measure with the pinned id recorded in measure-report.json",
            "promptfoo evals gating the model bump in CI",
            "a config-level model registry with one id per environment",
            "vendor model-version aliases resolved once at deploy time and logged",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for entry in ctx.inventory.models or []:
            if not isinstance(entry, dict) or entry.get("pinned") is not False:
                continue
            relpath = _posix(entry.get("file", ""))
            line = int(entry.get("line") or 0)
            model = str(entry.get("model", ""))
            provider = str(entry.get("provider", ""))
            stamp = (relpath, line, model)
            if stamp in seen:
                continue
            seen.add(stamp)
            snippet = _line_text(ctx, relpath, line) or f"{provider}: {model}"
            out.append(
                self.finding(
                    file=relpath,
                    line=line,
                    snippet=snippet,
                    sub=provider or None,
                    notes=(
                        f"{provider} id {model} is a floating alias "
                        f"(source: {entry.get('source', 'unknown')})"
                    ),
                    evidence_kind=(
                        EvidenceKind.CONFIG
                        if entry.get("source") in ("env", "config")
                        else EvidenceKind.CODE
                    ),
                )
            )
        return _sorted(out)


# ---------------------------------------------------------------------------
# AUD-602
# ---------------------------------------------------------------------------


class UnpinnedMcp(AuditRule):
    """An MCP server launched without a version, or an unpinned bootstrap line.

    Structured tier: `McpServer.pinned is False` (npx / uvx / pip / docker launch
    with no version, or a floating tag). Grep tier: the `bootstrap` table, which
    discovery fills only for BOOTSTRAP_FILE_GLOBS paths (Dockerfiles, CI workflows),
    never for docs.
    """

    id = "AUD-602"
    title = "Unpinned MCP server / bootstrap"
    priority = 6
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI04", "LLM03", "EU:Art.15", "NIST:GOVERN-6.1", "NIST:MANAGE-3.1")
    related_lint_rules = ()
    known_failure_modes = (
        "a version pin is not an integrity pin: `pkg@1.2.3` can still be republished",
        "a launcher wrapped in a shell script (`command: ./run.sh`) is not assessable (None)",
        "bootstrap lines inside a heredoc or a multi-line RUN are seen line by line",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Pin the package (`pkg@1.2.3`, `pkg==1.2.3`, `image@sha256:...`) and keep a "
            "lockfile so the server that ran in review is the one that runs in production."
        ),
        alternatives=(
            "a lockfile (package-lock.json / uv.lock) checked in next to the MCP config",
            "Docker digests (`@sha256:`) for MCP images and CI base images",
            "aisg audit in CI with --fail-on high",
            "Renovate / Dependabot to bump the pins under review",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for server in _servers(ctx):
            if _field(server, "pinned") is not False:
                continue
            relpath = _posix(_field(server, "file", ""))
            line = int(_field(server, "line") or 0)
            name = str(_field(server, "name", ""))
            stamp = (relpath, line, name)
            if stamp in seen:
                continue
            seen.add(stamp)
            out.append(
                self.finding(
                    file=relpath,
                    line=line,
                    snippet=f'"{name}": {_launch(server)}',
                    sub="mcp",
                    notes=f"MCP server {name} launches without a version pin",
                )
            )
        for hit in hits_in(ctx, "bootstrap"):
            stamp = (hit.file, hit.line, hit.key)
            if stamp in seen:
                continue
            seen.add(stamp)
            kind = hit.key.split(":", 1)[0]
            out.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    sub=kind,
                    notes=f"unpinned bootstrap: {hit.key}",
                    match_kind=MatchKind.GREP,
                )
            )
        return _sorted(out)


# ---------------------------------------------------------------------------
# AUD-603
# ---------------------------------------------------------------------------


class RemoteMcp(AuditRule):
    """A remote MCP transport to a host outside `--trusted-mcp-hosts`, or a
    plaintext one.

    `remote` and `remote_host` come from `ConfigFacts.servers`; the inventory
    projection is the fallback. Loopback URLs are not remote. A trusted host over
    `http://` / `ws://` is still reported, as `plaintext`.
    """

    id = "AUD-603"
    title = "Remote or plaintext MCP transport"
    priority = 6
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI04", "ASI07", "LLM03", "EU:Art.15", "NIST:MEASURE-2.7", "NIST:MAP-5.1")
    related_lint_rules = ()
    known_failure_modes = (
        "a hostname is never resolved: a DNS name for 127.0.0.1 counts as remote",
        "a URL read from an environment variable is not seen",
        "trust is a flag the operator passes, not something the audit verifies",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Run the server locally over stdio, or pin the remote host, require TLS and "
            "pass it with --trusted-mcp-hosts once it has been reviewed."
        ),
        alternatives=(
            "stdio transport to a locally installed, version-pinned server",
            "an MCP gateway / proxy that terminates TLS and enforces an allowlist",
            "aisg audit --trusted-mcp-hosts <host> after a documented review",
            "network policy (egress allowlist) around the host process",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        trusted = _trusted_hosts(ctx)
        for server in _servers(ctx):
            remote, host = _server_remote(server)
            if not remote:
                continue
            url = _field(server, "url")
            plaintext = _scheme(url) in _PLAINTEXT_SCHEMES
            is_trusted = _is_trusted(server, host, trusted)
            if is_trusted and not plaintext:
                continue
            relpath = _posix(_field(server, "file", ""))
            line = int(_field(server, "line") or 0)
            name = str(_field(server, "name", ""))
            stamp = (relpath, line, name)
            if stamp in seen:
                continue
            seen.add(stamp)
            transport = _field(server, "transport", "unknown")
            if plaintext:
                sub = "plaintext"
                note = f"MCP server {name}: {transport} over {_scheme(url)}:// to {host}"
                if not is_trusted:
                    note += " (host not in --trusted-mcp-hosts)"
            else:
                sub = "untrusted"
                note = f"MCP server {name}: {transport} to {host}, not in --trusted-mcp-hosts"
            out.append(
                self.finding(
                    file=relpath,
                    line=line,
                    snippet=f'"{name}": {url}',
                    sub=sub,
                    notes=note,
                )
            )
        return _sorted(out)


# ---------------------------------------------------------------------------
# AUD-604
# ---------------------------------------------------------------------------


class McpDescriptionPoisoning(AuditRule):
    """Injection phrasing, poisoning phrases or invisible characters in an MCP
    server / tool description.

    Input is `McpServer.description` from `ConfigFacts.servers` (own description
    plus one `<tool>: <text>` line per tool). Three pattern sets run over it:
    MCP_POISON_PHRASES, MCP_DESCRIPTION_INJECTION (the shipped guard's
    INJECTION_PATTERNS) and INVISIBLE_CHAR_RE. One finding per server; every
    matched pattern name is recorded as an evidence leg. `is_mention` is never
    applied here.
    """

    id = "AUD-604"
    title = "MCP tool-description poisoning"
    priority = 6
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI01", "ASI04", "ASI06", "LLM01", "LLM03", "EU:Art.15", "NIST:MEASURE-2.7")
    related_lint_rules = ("EU-AIA-015a", "ALIGN-005", "ALIGN-006")
    known_failure_modes = (
        "descriptions served at runtime by a live server are not in any file; only manifests are read",
        "tool descriptions in Python / TypeScript decorators are not scanned here",
        "regex phrases: a paraphrased instruction with none of the seed phrases is missed",
        "no mcp-scan corroboration in-process: bucket stays asserted",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Remove the server, pin a reviewed version, and gate tool descriptions through "
            "a scanner before the host loads them."
        ),
        alternatives=(
            "mcp-scan --local-only in CI on every MCP config",
            "aisg PromptInjectionGuard over tool descriptions at registration time",
            "a host-side tool allowlist with pinned description hashes",
            "Invariant Labs / Lakera tool-description scanning",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        servers = getattr(ctx.config_facts, "servers", None) or []
        for server in servers:
            description = getattr(server, "description", None)
            if not description:
                continue
            legs = _poison_legs(description)
            if not legs:
                continue
            relpath = _posix(getattr(server, "file", ""))
            line = int(getattr(server, "line", None) or 0)
            names = [name for name, _excerpt in legs]
            evidence = [
                Evidence(role="match", file=relpath, line=line, snippet=_excerpt_for(legs[0][1]))
            ]
            for name, excerpt in legs[:_MAX_POISON_LEGS]:
                evidence.append(
                    Evidence(role=f"pattern:{name}", file=relpath, line=line, snippet=excerpt)
                )
            out.append(
                self.finding(
                    file=relpath,
                    line=line,
                    snippet=_excerpt_for(legs[0][1]),
                    evidence=evidence,
                    sub="description",
                    notes=(
                        f"MCP server {getattr(server, 'name', '')}: seed_pattern "
                        + ", ".join(names)
                    ),
                )
            )
        return _sorted(out)


def _excerpt_for(excerpt: str) -> str:
    return excerpt if excerpt else "(empty)"


def _poison_legs(description: str) -> list[tuple[str, str]]:
    """(pattern name, excerpt) per matched pattern, poison phrases first."""
    legs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, rx in list(patterns.MCP_POISON_PHRASES) + list(patterns.MCP_DESCRIPTION_INJECTION):
        match = rx.search(description)
        if match is None or name in seen:
            continue
        seen.add(name)
        legs.append((name, _window(description, match.start(), match.end())))
    invisible = patterns.INVISIBLE_CHAR_RE.search(description)
    if invisible is not None:
        code = ord(invisible.group(0))
        count = len(patterns.INVISIBLE_CHAR_RE.findall(description))
        legs.append(("invisible_char", f"U+{code:04X} x{count} at offset {invisible.start()}"))
    return legs


def _window(text: str, start: int, end: int, pad: int = 40) -> str:
    lo, hi = max(0, start - pad), min(len(text), end + pad)
    excerpt = patterns.INVISIBLE_CHAR_RE.sub("", text[lo:hi])
    return (("..." if lo > 0 else "") + excerpt + ("..." if hi < len(text) else "")).strip()


# ---------------------------------------------------------------------------
# AUD-605
# ---------------------------------------------------------------------------


class UnpinnedWeights(AuditRule):
    """Weights or code pulled without a revision, or deserialised unsafely.

    Reads the `weights` table: `from_pretrained` / `hf_hub_download` without
    `revision=`, `trust_remote_code=True`, `torch.load` without `weights_only=True`,
    an unpickle of a model file. Code files only, by construction of the table.
    """

    id = "AUD-605"
    title = "Unpinned weights / trust_remote_code"
    priority = 6
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    tier = Tier.T1
    controls = ("ASI04", "ASI05", "LLM03", "LLM04", "EU:Art.15", "NIST:GOVERN-6.1")
    related_lint_rules = ("EU-AIA-015b",)
    known_failure_modes = (
        "single-line regex: `revision=` on the next line of a call still fires",
        "a revision passed through a variable is not recognised as a pin",
        "`torch.load` on a trusted local artefact is reported like a downloaded one",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Pin `revision=<commit>` on every hub call, drop `trust_remote_code`, load with "
            "`weights_only=True` or safetensors, and never unpickle a downloaded file."
        ),
        alternatives=(
            "safetensors format with `use_safetensors=True`",
            "a private model registry (MLflow / internal hub) with content hashes",
            "aisg audit in CI with --fail-on high",
            "picklescan / modelscan over artefacts before they are loaded",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for hit in hits_in(ctx, "weights"):
            stamp = (hit.file, hit.line, hit.key)
            if stamp in seen:
                continue
            seen.add(stamp)
            out.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    sub=hit.key,
                    notes=f"pattern: {hit.key}",
                )
            )
        return _sorted(out)


# ---------------------------------------------------------------------------
# AUD-606
# ---------------------------------------------------------------------------


class DependencyVulns(AuditRule):
    """Known-vulnerable dependencies. MEASURED only.

    `evaluate` never produces a finding: the rows come from the pip-audit /
    npm-audit / osv-scanner adapters, which build them through `tool_finding` so
    the metadata below is the single source. Without an adapter the audit reports
    an UNKNOWN item, not an absence of vulnerabilities.
    """

    id = "AUD-606"
    title = "Dependency vulnerabilities"
    priority = 6
    severity = Severity.HIGH
    basis = Basis.MEASURED
    evidence_kind = EvidenceKind.TOOL_OUTPUT
    match_kind = MatchKind.EXTERNAL
    tier = Tier.T1
    controls = ("ASI04", "LLM03", "EU:Art.15", "NIST:GOVERN-6.1", "NIST:MANAGE-3.1")
    related_lint_rules = ()
    known_failure_modes = (
        "no adapter on PATH means no rows: the result is UNKNOWN, never zero findings",
        "advisory databases lag disclosure; a fresh CVE is not in them yet",
        "severity is the tool's; tools disagree on the same advisory",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Upgrade to the fixed version named by the advisory, or record a reviewed "
            "exception with an expiry; run the scanner in CI."
        ),
        alternatives=(
            "pip-audit / npm audit / osv-scanner in CI on every lockfile change",
            "Dependabot or Renovate security updates",
            "aisg audit in CI, which folds those scanners in when present",
            "an SBOM (CycloneDX) matched against OSV on a schedule",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        return []

    def tool_finding(
        self,
        *,
        file: str,
        line: int,
        snippet: str,
        severity: Severity | None = None,
        tool: str,
        notes: str | None = None,
    ) -> Finding:
        """A MEASURED row for one advisory, as the adapters should emit it."""
        return self.finding(
            file=file,
            line=line,
            snippet=snippet,
            severity=severity,
            sub=tool,
            bucket=Bucket.MEASURED,
            notes=notes,
        )


RULES = [
    UnpinnedModel,
    UnpinnedMcp,
    RemoteMcp,
    McpDescriptionPoisoning,
    UnpinnedWeights,
    DependencyVulns,
]
