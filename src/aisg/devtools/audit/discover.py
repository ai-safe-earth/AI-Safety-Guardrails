"""aisg/devtools/audit/discover.py
---
Grep-level discovery: every enumerated file becomes a list of `Hit`s, and the
hits become the `Inventory` the rules read. No LLM, no subprocess, no network;
the only I/O is reading the files `walk` already enumerated (plus the host-global
configs when `include_home` is set, and never otherwise).

Three file classes get three different table sets. Code (python, typescript, go
and every other source language) gets everything. Config-language files (yaml,
json, toml, ini, .env, shell, Dockerfile) get the tables that make sense for
configuration: model ids, secrets, PII, broad credentials, eval tools, kill-switch
names, aisg presets, fail-open flags, unpinned bootstrap lines and host over-grant
literals. Docs (.md/.rst/.txt) get over-grant literals and Annex III keywords only:
a README that says `pip install foo` is not a supply-chain finding.

Hit keys follow the pattern tables, with three tables carrying a captured token
after a colon so the inventory builders never re-run a regex: `tool_def` keys are
`<kind>:<name>`, `model_id` keys are `<provider>:<id>` and `keyword_filter` keys
are `list_literal:<name>`. Every snippet is redacted before it is stored anywhere.

Honesty rules that hold here: a report read from disk is ASSERTED with an age,
never MEASURED; the audit never infers a model or a digest a report does not
carry; UNKNOWN is recorded, never silently dropped.
"""

from __future__ import annotations

import json
import re
import time
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlparse

import yaml

from aisg.devtools.audit import configs, patterns, vocab, walk
from aisg.devtools.audit.configs import CiRecord, EnvBinding, HostRecord, McpServer, OverGrant
from aisg.devtools.audit.model import (
    SCHEMA_VERSION,
    Hit,
    Inventory,
    ReportRecord,
    Unit,
    UnknownCategory,
    UnknownItem,
    redact,
    truncate_snippet,
)
from aisg.devtools.audit.walk import FileRecord

# The literal prefilter (below) leans on the stdlib's private regex parser. It is only
# an optimisation: if a future Python moves or removes it, discovery runs unfiltered.
_sre_parser: Any
try:
    from re import _parser as _sre_parser  # Python 3.11+
except ImportError:  # pragma: no cover - Python 3.10
    try:
        import sre_parse as _sre_parser  # type: ignore[no-redef]
    except ImportError:
        _sre_parser = None

__all__ = [
    "ConfigFacts",
    "DiscoverOptions",
    "ai_surface_units",
    "config_facts",
    "discover",
    "grep_file",
    "read_measure_report",
    "read_probe_report",
    "read_report",
    "read_system_card",
    "unit_ai_surface",
]

# ---------------------------------------------------------------------------
# Options and rich config facts
# ---------------------------------------------------------------------------


@dataclass
class DiscoverOptions:
    """Duck-typed: `discover()` reads these names off whatever object it is given."""

    include_home: bool = False
    trusted_mcp_hosts: tuple[str, ...] = ()
    max_size: int | None = None


@dataclass
class ConfigFacts:
    """The structured config records behind `Inventory.hosts` / `.mcp` / `.ci`.

    The inventory carries exactly the section 2 shapes; rules that need the
    over-grant severity, the hook command text, the mention flag, an MCP server's
    description / transport host / `remote` flag, or an agent's `tools:` list read
    these records instead.
    """

    host_records: list[HostRecord] = field(default_factory=list)
    servers: list[McpServer] = field(default_factory=list)
    ci: list[CiRecord] = field(default_factory=list)
    env: list[EnvBinding] = field(default_factory=list)
    over_grant_literals: list[tuple[str, OverGrant]] = field(default_factory=list)


def _opt(options: object, name: str, default: Any) -> Any:
    value = getattr(options, name, None) if options is not None else None
    return default if value is None else value


# ---------------------------------------------------------------------------
# Compiled tables (once, at import)
# ---------------------------------------------------------------------------

Table = list[tuple[str, "re.Pattern[str]"]]

_DOC_EXTS = frozenset({".md", ".markdown", ".mdx", ".rst", ".txt"})
_CONFIG_DATA_EXTS = frozenset({".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"})
_YAML_EXTS = frozenset({".yaml", ".yml"})
_STRUCTURED_EXTS = frozenset({".json", ".toml", ".yaml", ".yml"})
_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")


def _word_rows(symbols: Iterable[str]) -> Table:
    return [(sym, re.compile(r"\b" + re.escape(sym) + r"\b", re.I)) for sym in symbols]


def _alternation(symbols: Iterable[str]) -> str:
    return "(?:" + "|".join(re.escape(sym) for sym in symbols) + ")"


_SANDBOX_ROWS = _word_rows(vocab.SANDBOX_SYMBOLS)
_ALLOWLIST_ROWS = _word_rows(vocab.ALLOWLIST_SYMBOLS)
_SANITISER_ROWS = _word_rows(vocab.SANITISER_SYMBOLS)
_BUDGET_ROWS = _word_rows(vocab.BUDGET_SYMBOLS)
_LOOP_CAP_ROWS = _word_rows(vocab.LOOP_CAP_SYMBOLS)
_INERT_KILL_SWITCH_ROWS = _word_rows(vocab.INERT_KILL_SWITCH)
# `kill_switch_symbol`: the name appears at all (a declaration counts). `kill_switch_read`:
# an env read of a kill-switch name, or the symbol called, indexed, attribute-accessed or
# tested (`if x` / `not x`). A bare assignment is a declaration, not a read; the AUD-107
# rule wants the second table and reports the first as "declared but never read".
_KILL_SWITCH_SYMBOL_ROWS = _word_rows(vocab.KILL_SWITCH_SYMBOLS)
_KILL_SWITCH_READ_ROWS: Table = list(
    zip(
        ("os_environ", "getenv", "process_env", "os_getenv", "settings_attr"),
        vocab.KILL_SWITCH_ENV_READS,
    )
) + [
    (
        sym,
        re.compile(
            r"(?:\b(?:if|not|while|and|or|return|assert)\s+" + re.escape(sym) + r"\b"
            r"|\b" + re.escape(sym) + r"\s*[(.\[])",
            re.I,
        ),
    )
    for sym in vocab.KILL_SWITCH_SYMBOLS
]
_APPROVAL_ROWS: Table = [("approval", vocab.APPROVAL_SYMBOLS)]
_GATE_BYPASS_ROWS: Table = [("gate_bypass", vocab.GATE_BYPASS)]
_LOOP_CAP_RE = re.compile(r"\b" + _alternation(vocab.LOOP_CAP_SYMBOLS) + r"\b", re.I)

_OLLAMA_CALL_RE = re.compile(r"\bollama\.(?:chat|generate)\(|localhost:11434")

# Config-file model keys: MODEL, LLM_MODEL, OPENAI_MODEL, model, model_name ... = value.
_CONFIG_MODEL_RE = re.compile(
    r"""(?i)^\s*["']?(?:[A-Z_]*MODEL|model(?:_name|_id)?)["']?\s*[:=]\s*["']?([A-Za-z0-9][^"'\s,]{1,80})"""
)

# Name-based secret assignment: `<name> = "<literal of 16+ chars>"`.
_SECRET_ASSIGN_RE = re.compile(
    r"""(?<![A-Za-z0-9])([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*["']([^"'\n]{16,})["']"""
)

_DICT_REGISTRY_RE = re.compile(
    r"(?i)^\s*(?:[A-Za-z_]*tools?|tool_registry|tool_map|tool_handlers)\s*(?::\s*[^=\n]+)?=\s*(?:dict\()?\{"
)
_DICT_KEY_RE = re.compile(r"""^\s*["'](\w+)["']\s*:""")
_LIST_NAME_RES = (
    re.compile(r"""\bname\s*=\s*["'](\w+)["']"""),
    re.compile(r"""["']name["']\s*:\s*["'](\w+)["']"""),
)
_REGISTRY_WINDOW = 40

_DESCRIPTION_RES = (
    re.compile(r"""^\s*[rRuU]?["']{3}\s*(.+?)\s*(?:["']{3})?\s*$"""),
    re.compile(r"""["']?description["']?\s*[:=]\s*["'](.+?)["']"""),
)

_AISG_SECTION_RE = re.compile(r"^(?:input|processing|output|policy):\s*$", re.M)
_AISG_GUARD_RE = re.compile(
    r"^\s+(?:pii_detector|pii_restorer|prompt_injection|rate_limiter|tool_policy|llm_input_filter"
    r"|llm_tool_filter|llm_output_filter|toxicity_output|eu_ai_act|nist_ai_rmf|nemo_rails):\s*$",
    re.M,
)

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
_INGRESS_WINDOW = 40
_TOOL_BODY_LINES = 30
_GATE_WINDOW = 60
_LOOP_WINDOW = 40
_REPORT_HEAD = 2048
_REPORT_NAME_RE = re.compile(r"^(?:measure|probe)[-_]?report.*\.json$", re.I)
# Any aisg schema marks a report candidate: a version other than aisg/1 must surface
# as UNKNOWN (reports), not vanish because the file looked unfamiliar.
_REPORT_SCHEMA_RE = re.compile(r'"schema"\s*:\s*"aisg/[0-9]+"')
_BENIGN_RE = re.compile(r"\bbenign\b", re.I)

_CI_GLOBS: Table = patterns._globs(
    [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".gitlab-ci.yml",
        ".pre-commit-config.yaml",
        "Jenkinsfile",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
    ]
)
_COMPOSE_GLOBS: Table = patterns._globs(
    ["docker-compose*.yml", "docker-compose*.yaml", "compose.yml", "compose.yaml"]
)


def _glob_hit(table: Table, relpath: str) -> bool:
    return any(rx.search(relpath) for _key, rx in table)


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    """A `Hit` plus the redacted matched text (the inventory's `api` / `symbol`)."""

    hit: Hit
    text: str


@dataclass
class _FileCtx:
    record: FileRecord
    text: str
    lines: list[str]
    line_starts: list[int]
    folded: str
    folded_starts: list[int]
    out: list[_Match]
    seen: set[tuple[str, str, int]]

    def line_of(self, offset: int) -> int:
        return bisect_right(self.line_starts, offset)

    def add(self, table: str, key: str, line: int, col: int, snippet: str, text: str) -> bool:
        stamp = (table, key, line)
        if stamp in self.seen:
            return False
        self.seen.add(stamp)
        hit = Hit(
            file=self.record.relpath,
            line=line,
            col=col,
            snippet=truncate_snippet(snippet.strip()),
            table=table,
            key=key,
            unit=self.record.unit,
            lang=self.record.lang,
        )
        self.out.append(_Match(hit=hit, text=redact(text)))
        return True


def _newline_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _ctx(record: FileRecord, text: str) -> _FileCtx:
    lines = [line.rstrip("\r") for line in text.split("\n")]
    # Case folding never adds or removes a newline, so line numbers computed on the
    # folded text are the line numbers of the original.
    folded = text.casefold()
    return _FileCtx(
        record, text, lines, _newline_starts(text), folded, _newline_starts(folded), [], set()
    )


def _file_class(record: FileRecord) -> str:
    ext = PurePosixPath(record.relpath).suffix.lower()
    if ext in _DOC_EXTS:
        return "doc"
    if record.lang == "config":
        return "config"
    return "code"


# --- literal prefilter -------------------------------------------------------
# Three hundred `\bword\b` rows against every file is the whole cost of discovery, and
# a word-boundary prefix defeats the regex engine's literal fast path. Each row is
# parsed once into a set of literal strings of which every match must contain at least
# one (a contiguous literal run, or one alternative of a required group); a file whose
# case-folded text contains none of them cannot match the row and is never regex-scanned
# for it. Anything the parser cannot reduce to such a set gets no prefilter and the plain
# regex, so the filter only ever removes impossible matches.

_ZERO_WIDTH_OPS = frozenset({"AT", "ASSERT", "ASSERT_NOT"})
_REPEAT_OPS = frozenset({"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"})


def _filter_score(lits: set[str]) -> tuple[int, int]:
    """Longer required text and fewer alternatives make a more selective filter."""
    return (min(len(lit) for lit in lits), -len(lits))


def _better(current: set[str] | None, candidate: set[str] | None) -> set[str] | None:
    if not candidate or any(not lit for lit in candidate):
        return current
    if current is None or _filter_score(candidate) > _filter_score(current):
        return candidate
    return current


def _seq_literals(seq: Any) -> set[str] | None:
    """The most selective literal set that every match of a parsed sequence must contain."""
    best: set[str] | None = None
    buf = ""
    for op, av in seq:
        name = getattr(op, "name", "")
        if name == "LITERAL":
            buf += chr(av)
            continue
        if name in _ZERO_WIDTH_OPS:
            continue  # consumes nothing, so a literal run stays contiguous across it
        if buf:
            best = _better(best, {buf})
            buf = ""
        inner: set[str] | None = None
        if name == "SUBPATTERN":
            inner = _seq_literals(av[-1])
        elif name == "BRANCH":
            inner = _branch_literals(av[1])
        elif name in _REPEAT_OPS and av[0] >= 1:
            inner = _seq_literals(av[2])
        elif name == "ATOMIC_GROUP":
            inner = _seq_literals(av)
        best = _better(best, inner)
    if buf:
        best = _better(best, {buf})
    return best


def _branch_literals(branches: Any) -> set[str] | None:
    out: set[str] = set()
    for branch in branches:
        lits = _seq_literals(branch)
        if not lits:
            return None
        out |= lits
    return out


@lru_cache(maxsize=None)
def _literal_filter(rx: re.Pattern[str]) -> tuple[str, ...] | None:
    if _sre_parser is None:
        return None
    try:
        parsed = _sre_parser.parse(rx.pattern, rx.flags & ~re.DEBUG)
        lits = _seq_literals(parsed)
    except Exception:  # an unparsable oddity simply goes unfiltered
        return None
    if not lits or any(not lit for lit in lits):
        return None
    return tuple(sorted(lit.casefold() for lit in lits))


def _possible(ctx: _FileCtx, rx: re.Pattern[str]) -> bool:
    lits = _literal_filter(rx)
    if lits is None:
        return True
    return any(lit in ctx.folded for lit in lits)


def _candidate_lines(ctx: _FileCtx, rx: re.Pattern[str]) -> Iterable[int]:
    """Line numbers that can hold a match of `rx`: a superset, never a subset."""
    lits = _literal_filter(rx)
    if lits is None:
        if rx.search(ctx.text) is None:
            return ()
        return range(1, len(ctx.lines) + 1)
    found: set[int] = set()
    folded, starts = ctx.folded, ctx.folded_starts
    for lit in lits:
        pos = folded.find(lit)
        while pos != -1:
            found.add(bisect_right(starts, pos))
            pos = folded.find(lit, pos + 1)
    return sorted(found)


def _scan_rows(ctx: _FileCtx, table: str, rows: Table, key_fn: Any = None) -> None:
    """Per-line search for each row, on the lines the literal prefilter lets through."""
    for key, rx in rows:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None:
                continue
            final_key = key if key_fn is None else key_fn(key, match)
            if final_key is None:
                continue
            ctx.add(table, final_key, number, match.start() + 1, line, match.group(0))


def _scan_whole(ctx: _FileCtx, table: str, rows: Table, key_fn: Any = None) -> None:
    """Whole-text search for rows that legitimately span lines (tool schemas, decorators)."""
    for key, rx in rows:
        if not _possible(ctx, rx):
            continue
        for match in rx.finditer(ctx.text):
            final_key = key if key_fn is None else key_fn(key, match)
            if final_key is None:
                continue
            anchor = match.start(1) if match.lastindex else match.start()
            number = ctx.line_of(anchor)
            line = ctx.lines[number - 1] if number - 1 < len(ctx.lines) else ""
            col = anchor - ctx.line_starts[number - 1] + 1
            ctx.add(table, final_key, number, col, line, match.group(0))


def _excluded_secret_file(relpath: str) -> bool:
    name = PurePosixPath(relpath).name.lower()
    if name.endswith(_EXAMPLE_SUFFIXES):
        return True
    return relpath.startswith("tests/fixtures/") or "/tests/fixtures/" in relpath


def _is_placeholder(value: str) -> bool:
    return any(rx.search(value) for _key, rx in patterns.SECRET_PLACEHOLDERS)


def _mask_value(prefix: str, value: str) -> str:
    return f"<redacted:{prefix}...{value[-4:]}>"


def _scan_secrets(ctx: _FileCtx) -> None:
    if _excluded_secret_file(ctx.record.relpath):
        return
    for key, rx in patterns.SECRET_PATTERNS:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None:
                continue
            if match.lastindex:
                value, start, end = match.group(1), match.start(1), match.end(1)
                if _is_placeholder(value):
                    continue
                prefix = ""
            else:
                value, start, end = match.group(0), match.start(), match.end()
                prefix = value[: min(8, len(value) - 4)]
            masked = line[:start] + _mask_value(prefix, value) + line[end:]
            ctx.add("secret", key, number, match.start() + 1, masked, masked[start : start + 40])
    # A secret_var hit needs a name that matches SECRET_VAR_NAMES, so its literals bound
    # the candidate lines far more tightly than the assignment shape does.
    for number in _candidate_lines(ctx, patterns.SECRET_VAR_NAMES):
        line = ctx.lines[number - 1]
        for match in _SECRET_ASSIGN_RE.finditer(line):
            name, value = match.group(1), match.group(2)
            if not patterns.SECRET_VAR_NAMES.search(name):
                continue
            if patterns.SECRET_VAR_EXCLUDE.search(name) or _is_placeholder(value):
                continue
            masked = line[: match.start(2)] + _mask_value("", value) + line[match.end(2) :]
            ctx.add("secret_var", name, number, match.start() + 1, masked, name)


def _scan_pii(ctx: _FileCtx) -> None:
    for entity, rx in patterns.PII_TABLE:
        for number in _candidate_lines(ctx, rx):
            line = ctx.lines[number - 1]
            match = rx.search(line)
            if match is None or _is_placeholder(match.group(0)):
                continue
            masked = line[: match.start()] + f"<pii:{entity}>" + line[match.end() :]
            ctx.add("pii", entity, number, match.start() + 1, masked, f"<pii:{entity}>")


def _model_key(provider: str, ident: str) -> str:
    return f"{provider}:{ident.strip()}"


def _scan_model_ids(ctx: _FileCtx, config: bool) -> None:
    ollama_ok = bool(_OLLAMA_CALL_RE.search(ctx.text))
    provider_rows = [(k, rx) for k, rx in patterns.MODEL_ID_PATTERNS if k != "other"]
    other_rows: Table = (
        [("other", _CONFIG_MODEL_RE)]
        if config
        else [(k, rx) for k, rx in patterns.MODEL_ID_PATTERNS if k == "other"]
    )
    active = [(k, rx) for k, rx in provider_rows if _possible(ctx, rx)]
    active_other = [(k, rx) for k, rx in other_rows if _possible(ctx, rx)]
    if not active and not active_other:
        return
    numbers: set[int] = set()
    for _key, rx in active + active_other:
        numbers.update(_candidate_lines(ctx, rx))
    for number in sorted(numbers):
        line = ctx.lines[number - 1]
        spans: list[tuple[int, int]] = []
        for key, rx in active:
            if key == "ollama" and not ollama_ok:
                continue
            for match in rx.finditer(line):
                ident = match.group(1) if match.lastindex else match.group(0)
                span = (match.start(), match.end())
                if any(s < span[1] and span[0] < e for s, e in spans):
                    continue
                spans.append(span)
                ctx.add("model_id", _model_key(key, ident), number, span[0] + 1, line, ident)
        for key, rx in active_other:
            match = rx.search(line)
            if match is None:
                continue
            span = (match.start(1), match.end(1))
            if any(s < span[1] and span[0] < e for s, e in spans):
                continue
            ident = match.group(1)
            if config and any(rx2.search(ident) for _k, rx2 in patterns.SECRET_PLACEHOLDERS):
                continue
            ctx.add("model_id", _model_key(key, ident), number, span[0] + 1, line, ident)


def _registry_names(ctx: _FileCtx, start_line: int, dict_form: bool) -> list[tuple[int, str]]:
    names: list[tuple[int, str]] = []
    window = ctx.lines[start_line : start_line + _REGISTRY_WINDOW]
    for offset, line in enumerate(window, 1):
        stripped = line.strip()
        if stripped.startswith(("}", "]")):
            break
        if dict_form:
            match = _DICT_KEY_RE.match(line)
            if match:
                names.append((start_line + offset, match.group(1)))
            continue
        for rx in _LIST_NAME_RES:
            for match in rx.finditer(line):
                names.append((start_line + offset, match.group(1)))
    if not dict_form and not names:
        head = ctx.lines[start_line - 1]
        inline = re.search(r"\[([^\]]*)\]", head)
        if inline:
            for ident in re.findall(r"\b[A-Za-z_]\w*\b", inline.group(1)):
                names.append((start_line, ident))
    return names


def _scan_tools(ctx: _FileCtx) -> None:
    rows = patterns.table_for(ctx.record.lang, patterns.TOOL_DEF_PATTERNS)
    named = [(k, rx) for k, rx in rows if k != "registry_list"]
    _scan_whole(ctx, "tool_def", named, key_fn=lambda key, m: f"{key}:{m.group(1)}")
    list_rows = [(k, rx) for k, rx in rows if k == "registry_list"]
    for _key, rx in list_rows:
        for number in _candidate_lines(ctx, rx):
            match = rx.search(ctx.lines[number - 1])
            if match is None:
                continue
            for name_line, name in _registry_names(ctx, number, dict_form=False):
                text = ctx.lines[name_line - 1]
                ctx.add("tool_def", f"registry_list:{name}", name_line, 1, text, name)
    for number, line in enumerate(ctx.lines, 1):
        if _DICT_REGISTRY_RE.match(line) is None:
            continue
        for name_line, name in _registry_names(ctx, number, dict_form=True):
            text = ctx.lines[name_line - 1]
            ctx.add("tool_def", f"registry:{name}", name_line, 1, text, name)


def _scan_aisg_preset(ctx: _FileCtx) -> None:
    if PurePosixPath(ctx.record.relpath).suffix.lower() not in _YAML_EXTS:
        return
    if not _AISG_SECTION_RE.search(ctx.text):
        return
    match = _AISG_GUARD_RE.search(ctx.text)
    if match is None:
        return
    number = ctx.line_of(match.start())
    ctx.add("guardrail", "aisg_preset", number, 1, ctx.lines[number - 1], match.group(0))


def _scan_ingress_to_prompt(ctx: _FileCtx) -> None:
    ingress = [m for m in ctx.out if m.hit.table == "ingress"]
    prompts = [m for m in ctx.out if m.hit.table == "prompt_assembly"]
    if not ingress or not prompts:
        return

    def idents(number: int) -> set[str]:
        raw = ctx.lines[number - 1] if number - 1 < len(ctx.lines) else ""
        return {tok for tok in _IDENT_RE.findall(raw) if tok.lower() not in _IDENT_STOP}

    ingress_idents = {m.hit.line: idents(m.hit.line) for m in ingress}
    for prompt in prompts:
        p_line = prompt.hit.line
        p_idents = idents(p_line)
        if not p_idents:
            continue
        for i_line, i_idents in ingress_idents.items():
            if not (i_line < p_line <= i_line + _INGRESS_WINDOW):
                continue
            for shared in sorted(p_idents & i_idents):
                ctx.add(
                    "ingress_to_prompt",
                    shared,
                    p_line,
                    prompt.hit.col,
                    ctx.lines[p_line - 1],
                    shared,
                )


def _scan_code(ctx: _FileCtx) -> None:
    lang = ctx.record.lang
    table_for = patterns.table_for
    _scan_rows(ctx, "llm_call", table_for(lang, patterns.LLM_CALL_PATTERNS))
    _scan_model_ids(ctx, config=False)
    _scan_rows(ctx, "framework", table_for(lang, patterns.FRAMEWORK_PATTERNS))
    _scan_tools(ctx)
    _scan_rows(ctx, "data_source", table_for(lang, patterns.PRIVATE_DATA_SOURCES))
    _scan_rows(ctx, "ingress", table_for(lang, patterns.UNTRUSTED_INGRESS))
    _scan_rows(ctx, "external_action", table_for(lang, patterns.EXTERNAL_ACTION))
    _scan_rows(ctx, "sink", table_for(lang, patterns.SINK_PATTERNS))
    _scan_rows(ctx, "response_accessor", patterns.LLM_RESPONSE_ACCESSORS)
    _scan_rows(ctx, "guardrail", patterns.GUARDRAIL_LIBS)
    _scan_rows(ctx, "llm_observability", patterns.LLM_OBSERVABILITY_SYMBOLS)
    _scan_rows(ctx, "apm", patterns.GENERIC_APM_SYMBOLS)
    _scan_rows(ctx, "audit_log", patterns.AUDIT_LOG_SYMBOLS)
    _scan_rows(ctx, "weights", patterns.WEIGHTS_PATTERNS)
    _scan_rows(ctx, "loop", table_for(lang, patterns.LOOP_PATTERNS))
    _scan_rows(ctx, "prompt_assembly", table_for(lang, patterns.PROMPT_ASSEMBLY_PATTERNS))
    _scan_rows(
        ctx,
        "keyword_filter",
        table_for(lang, patterns.KEYWORD_FILTER_PATTERNS),
        key_fn=lambda key, m: f"{key}:{m.group(1)}",
    )
    _scan_rows(ctx, "kill_switch_read", _KILL_SWITCH_READ_ROWS)
    _scan_rows(ctx, "kill_switch_symbol", _KILL_SWITCH_SYMBOL_ROWS)
    _scan_rows(ctx, "sandbox", _SANDBOX_ROWS)
    _scan_rows(ctx, "allowlist", _ALLOWLIST_ROWS)
    _scan_rows(ctx, "sanitiser", _SANITISER_ROWS)
    _scan_rows(ctx, "budget", _BUDGET_ROWS)
    _scan_rows(ctx, "approval", _APPROVAL_ROWS)
    _scan_rows(ctx, "gate_bypass", _GATE_BYPASS_ROWS)
    _scan_rows(ctx, "loop_cap", _LOOP_CAP_ROWS)
    _scan_ingress_to_prompt(ctx)


def _matches(record: FileRecord, text: str) -> list[_Match]:
    ctx = _ctx(record, text)
    relpath = record.relpath
    klass = _file_class(record)
    literal_rows = patterns.HOST_OVERGRANT["*"]
    if klass == "doc":
        # A mention is still a hit (the key stays "literal"); the mention flag lives on
        # ConfigFacts.over_grant_literals, where parse_literals records it.
        _scan_rows(ctx, "overgrant_literal", literal_rows)
        if _glob_hit(patterns.ANNEX_III_FILE_GLOBS, relpath):
            _scan_rows(ctx, "annex_iii", patterns.ANNEX_III_KEYWORDS)
        return ctx.out
    _scan_secrets(ctx)
    if _glob_hit(patterns.PII_FILE_GLOBS, relpath):
        _scan_pii(ctx)
    _scan_rows(ctx, "broad_cred", patterns.BROAD_CRED_NAMES)
    _scan_rows(ctx, "eval_tool", patterns.EVAL_TOOLS)
    _scan_rows(ctx, "fail_open", patterns.FAIL_OPEN_PATTERNS)
    _scan_rows(ctx, "overgrant_literal", literal_rows)
    _scan_rows(ctx, "inert_kill_switch", _INERT_KILL_SWITCH_ROWS)
    if _glob_hit(patterns.BOOTSTRAP_FILE_GLOBS, relpath):
        _scan_rows(
            ctx,
            "bootstrap",
            patterns.UNPINNED_BOOTSTRAP_PATTERNS,
            key_fn=lambda key, m: f"{key}:{m.group(1)}",
        )
    if _glob_hit(patterns.ANNEX_III_FILE_GLOBS, relpath):
        _scan_rows(ctx, "annex_iii", patterns.ANNEX_III_KEYWORDS)
    if klass == "config":
        _scan_model_ids(ctx, config=True)
        _scan_rows(ctx, "kill_switch_symbol", _KILL_SWITCH_SYMBOL_ROWS)
        _scan_aisg_preset(ctx)
        return ctx.out
    _scan_code(ctx)
    return ctx.out


def grep_file(record: FileRecord, text: str | None) -> list[Hit]:
    """Every grep hit in one file. Snippets are redacted before the Hit exists.

    `text` is what `walk.read_text` returned; None (binary, oversized, unreadable) is
    an empty result, never an error.
    """
    if text is None:
        return []
    return [m.hit for m in _matches(record, text)]


# ---------------------------------------------------------------------------
# Config facts (structured parsing via configs.py)
# ---------------------------------------------------------------------------


def _is_structured(relpath: str) -> bool:
    return PurePosixPath(relpath).suffix.lower() in _STRUCTURED_EXTS


def _parse_failure(relpath: str, message: str) -> UnknownItem:
    return UnknownItem(
        category=UnknownCategory.RUNTIME,
        what=f"config {relpath}",
        why=message,
        how_to_resolve="Fix the file so it parses; an unparsable host config was not audited.",
        file=relpath,
    )


def _trusted(server: McpServer, trusted_hosts: Iterable[str]) -> bool:
    if not server.remote:
        return server.pinned is not False
    wanted = {str(h).strip().lower() for h in trusted_hosts if str(h).strip()}
    if not wanted:
        return False
    candidates: set[str] = set()
    if server.remote_host:
        candidates.add(server.remote_host.lower())
    if server.url:
        try:
            netloc = urlparse(server.url).netloc.lower()
        except ValueError:
            netloc = ""
        if netloc:
            candidates.add(netloc)
    return bool(candidates & wanted)


def _server_entry(server: McpServer, trusted_hosts: Iterable[str]) -> dict[str, Any]:
    """Section 2 `mcp.servers[]` shape, projected from the richer `McpServer` record.

    The host, transport host, `remote` flag, env key names and the description stay
    on `ConfigFacts.servers` for the rules (AUD-603/604 read them there); the inventory
    carries only the section 2 keys.
    """
    return {
        "name": server.name,
        "file": server.file,
        "line": server.line,
        "transport": server.transport,
        "command": server.command,
        "args": list(server.args),
        "url": server.url,
        "pinned": server.pinned,
        "trusted": _trusted(server, trusted_hosts),
        "implied_legs": list(server.implied_legs),
        "env_secret_literals": len(server.env_literal_keys),
    }


def _host_entry(record: HostRecord) -> dict[str, Any]:
    """Section 2 `hosts[]` shape: codex carries its two policy knobs, every other host
    the permission grants. Agent frontmatter `tools:` and the over-grant severities
    stay on `ConfigFacts.host_records`."""
    if record.host == "codex":
        return {
            "host": record.host,
            "file": record.file,
            "approval_policy": record.approval_policy,
            "sandbox_mode": record.sandbox_mode,
        }
    return {
        "host": record.host,
        "file": record.file,
        "over_grants": [grant.value for grant in record.over_grants],
        "default_mode": record.default_mode,
        "hooks": len(record.hooks),
    }


def _dispatch_config(
    label: str,
    text: str,
    host: str,
    table: str,
    facts: ConfigFacts,
    unknown: list[UnknownItem],
    mcp_files: list[dict[str, Any]],
) -> None:
    name = PurePosixPath(label).name
    ext = PurePosixPath(label).suffix.lower()
    if _is_structured(label):
        error = configs.parse_error(label, text, host)
        if error is not None:
            unknown.append(_parse_failure(label, error))
            return
    if table == "host":
        if host == "claude":
            if ext == ".json":
                facts.host_records.append(configs.parse_claude_settings(label, text))
            elif "/.claude/agents/" in "/" + label or label.startswith(".claude/agents/"):
                front = configs.parse_agent_frontmatter(label, text)
                tools = tuple(str(t) for t in (front.get("tools") or []))
                facts.host_records.append(HostRecord(host="claude", file=label, tools=tools))
                for grant in configs.parse_literals(label, text, is_doc=True):
                    facts.over_grant_literals.append((label, grant))
            else:  # CLAUDE.md / AGENTS.md
                for grant in configs.parse_literals(label, text, is_doc=True):
                    facts.over_grant_literals.append((label, grant))
            return
        if host == "codex":
            record, servers = configs.parse_codex_config(label, text)
            facts.host_records.append(record)
            if servers:
                facts.servers.extend(servers)
                mcp_files.append({"file": label, "host": host})
            return
        if host == "gemini":
            record, servers = configs.parse_gemini(label, text)
            facts.host_records.append(record)
            if servers:
                facts.servers.extend(servers)
                mcp_files.append({"file": label, "host": host})
            return
        if host == "cursor":
            facts.host_records.append(configs.parse_cursor(label, text))
            return
        return
    # MCP config (any host)
    del name
    facts.servers.extend(configs.parse_mcp_config(label, text, host))
    mcp_files.append({"file": label, "host": host})


def _home_label(path: Path, home: Path) -> str:
    try:
        rel = path.resolve().relative_to(home.resolve())
    except (ValueError, OSError):
        return path.as_posix()
    return "~/" + rel.as_posix()


def _read_home(
    max_size: int | None,
    facts: ConfigFacts,
    unknown: list[UnknownItem],
    mcp_files: list[dict[str, Any]],
) -> None:
    """Host-global configs. Only ever reached when `include_home` is set.

    `configs.home_config_paths()` is the only way the home directory is reached: its
    first entry is always `<home>/.claude/settings.json`, so the home used for the
    `~/` label is that entry's grandparent rather than a second lookup here.
    """
    paths = configs.home_config_paths()
    if not paths:
        return
    home = paths[0].parent.parent
    for path in paths:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        text = walk.read_text(path, max_size)
        if text is None:
            continue
        label = _home_label(path, home)
        name = path.name.lower()
        if name == "settings.json":
            _dispatch_config(label, text, "claude", "host", facts, unknown, mcp_files)
        elif name == "config.toml":
            _dispatch_config(label, text, "codex", "host", facts, unknown, mcp_files)
        elif name == "claude_desktop_config.json":
            _dispatch_config(label, text, "claude_desktop", "mcp", facts, unknown, mcp_files)


def config_facts(
    root: Path,
    files: list[FileRecord],
    options: object = None,
    texts: dict[str, str] | None = None,
) -> tuple[ConfigFacts, list[UnknownItem]]:
    """Structured host / MCP / CI / env facts. `texts` avoids a second read of each file."""
    del root  # relpaths are already relative; kept for signature symmetry with discover()
    max_size = _opt(options, "max_size", None)
    facts = ConfigFacts()
    unknown: list[UnknownItem] = []
    mcp_files: list[dict[str, Any]] = []
    for record in files:
        relpath = record.relpath
        if texts is not None and relpath in texts:
            text = texts[relpath]
        else:
            text = walk.read_text(record.path, max_size)
        if text is None:
            continue
        try:
            kind = configs.config_kind(relpath)
            if kind is not None:
                _dispatch_config(relpath, text, kind[0], kind[1], facts, unknown, mcp_files)
                continue
            basename = PurePosixPath(relpath).name
            if _glob_hit(_CI_GLOBS, relpath):
                facts.ci.append(configs.parse_ci_workflow(relpath, text))
            elif patterns.ENV_FILE_RE.match(basename) or _glob_hit(_COMPOSE_GLOBS, relpath):
                facts.env.extend(configs.parse_compose_env(relpath, text))
            if record.lang in ("config", "other"):
                is_doc = _file_class(record) == "doc"
                for grant in configs.parse_literals(relpath, text, is_doc=is_doc):
                    facts.over_grant_literals.append((relpath, grant))
        except Exception as exc:  # never let one file take the audit down
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what=f"config {relpath}",
                    why=f"{type(exc).__name__}: {truncate_snippet(str(exc), 200)}",
                    file=relpath,
                )
            )
    if _opt(options, "include_home", False):
        _read_home(max_size, facts, unknown, mcp_files)
    facts.host_records.sort(key=lambda r: (r.file, r.host))
    facts.servers.sort(key=lambda s: (s.file, s.line or 0, s.name))
    facts.ci.sort(key=lambda c: c.file)
    facts.env.sort(key=lambda e: (e.file, e.line or 0, e.name))
    facts.over_grant_literals.sort(key=lambda item: (item[0], item[1].line or 0, item[1].key))
    # The configs list rides on facts through this private attribute: it is inventory
    # data, not a config record, and discover() lifts it into Inventory.mcp.
    facts._mcp_files = sorted(mcp_files, key=lambda d: (d["file"], d["host"]))  # type: ignore[attr-defined]
    return facts, unknown


# ---------------------------------------------------------------------------
# Reports and the system card
# ---------------------------------------------------------------------------


def _relpath(path: Path, root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def _load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    text = walk.read_text(path)
    if text is None:
        return None, "unreadable, binary or oversized"
    try:
        body = json.loads(text)
    except ValueError as exc:
        return None, f"invalid JSON: {truncate_snippet(str(exc), 120)}"
    if not isinstance(body, dict):
        return None, f"top-level value is {type(body).__name__}, expected an object"
    return body, None


def _report_kind(body: dict[str, Any]) -> str | None:
    if isinstance(body.get("guards"), (list, dict)):
        return "measure"
    summary = body.get("summary")
    if "cases" in body or (isinstance(summary, dict) and "sent" in summary):
        return "probe"
    return None


def _build_report(kind: str, path: Path, root: Path, body: dict[str, Any]) -> ReportRecord:
    relpath = _relpath(path, root)
    raw_ts = body.get("generated_at")
    generated_at = raw_ts if isinstance(raw_ts, str) else None
    parsed = _parse_timestamp(raw_ts)
    now = datetime.now(timezone.utc)
    if parsed is not None:
        age_source, age_days = "generated_at", (now - parsed).days
    else:
        when, source = walk.file_age(path, root)
        if when is not None:
            age_source, age_days = source, (now - when).days
        else:
            age_source, age_days = "unknown", None
    target = body.get("target")
    raw_models = body.get("models") or (target.get("models") if isinstance(target, dict) else None)
    models = [str(m) for m in raw_models] if isinstance(raw_models, (list, tuple)) else []
    digest = body.get("config_digest")
    return ReportRecord(
        kind=kind,
        file=relpath,
        schema=body.get("schema"),
        generated_at=generated_at,
        age_source=age_source,
        age_days=age_days,
        models=models,
        config_digest=digest if isinstance(digest, str) else None,
        body=body,
    )


def read_report(path: Path, root: Path) -> tuple[ReportRecord | None, UnknownItem | None]:
    """Read an `aisg measure` / `aisg probe` JSON report; refuse any schema but aisg/1."""
    path = Path(path)
    relpath = _relpath(path, root)
    body, error = _load_json(path)
    if body is None:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS, what=relpath, why=error or "unreadable", file=relpath
        )
    schema = body.get("schema")
    if schema != SCHEMA_VERSION:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS,
            what=relpath,
            why=f"schema {schema} is not {SCHEMA_VERSION}",
            how_to_resolve=f"Regenerate the report with a version of aisg that writes {SCHEMA_VERSION}.",
            file=relpath,
        )
    kind = _report_kind(body)
    if kind is None:
        return None, UnknownItem(
            category=UnknownCategory.REPORTS,
            what=relpath,
            why="neither a measure report (guards) nor a probe report (cases/summary.sent)",
            file=relpath,
        )
    return _build_report(kind, path, root, body), None


def read_measure_report(path: Path, root: Path) -> ReportRecord | None:
    """A measure report, or None when the file is not an aisg/1 measure report."""
    body, _error = _load_json(Path(path))
    if body is None or body.get("schema") != SCHEMA_VERSION or _report_kind(body) != "measure":
        return None
    return _build_report("measure", Path(path), root, body)


def read_probe_report(path: Path, root: Path) -> ReportRecord | None:
    """A probe report, or None when the file is not an aisg/1 probe report."""
    body, _error = _load_json(Path(path))
    if body is None or body.get("schema") != SCHEMA_VERSION or _report_kind(body) != "probe":
        return None
    return _build_report("probe", Path(path), root, body)


def read_system_card(path: Path) -> dict[str, Any] | None:
    """The system card mapping (YAML file, or the YAML frontmatter of a model card)."""
    path = Path(path)
    text = walk.read_text(path)
    if text is None:
        return None
    if path.suffix.lower() in _YAML_EXTS:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
    else:
        data = configs.parse_agent_frontmatter(path.as_posix(), text)
    return data if isinstance(data, dict) else None


def _looks_like_report(record: FileRecord) -> bool:
    if PurePosixPath(record.relpath).suffix.lower() != ".json":
        return False
    if _REPORT_NAME_RE.match(PurePosixPath(record.relpath).name):
        return True
    try:
        with open(record.path, "rb") as fh:
            head = fh.read(_REPORT_HEAD)
    except OSError:
        return False
    return _REPORT_SCHEMA_RE.search(head.decode("utf-8", errors="replace")) is not None


def _card_value(card: dict[str, Any], key: str) -> Any:
    value = card.get(key)
    if isinstance(value, (str, int, float)) or value is None:
        return value
    return str(value)


def _risk_tier(value: Any) -> str:
    text = "" if value is None else str(value).strip().lower()
    if not text or text.startswith("todo"):
        return "unknown"
    return text


def _incident_contact(card: dict[str, Any]) -> Any:
    for key in ("incident_contact", "contact", "security_contact"):
        if key in card:
            return _card_value(card, key)
    incident = card.get("incident")
    if isinstance(incident, dict):
        return _card_value(incident, "contact")
    return None


# ---------------------------------------------------------------------------
# Inventory builders
# ---------------------------------------------------------------------------


def _sort_key(entry: dict[str, Any]) -> tuple[str, int, str]:
    name = entry.get("name") or entry.get("model") or entry.get("lib") or entry.get("tool")
    name = name or entry.get("kind") or entry.get("symbol") or ""
    return (str(entry.get("file", "")), int(entry.get("line") or 0), str(name))


def _sorted(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(entries, key=_sort_key)


def _split_key(key: str) -> tuple[str, str]:
    head, sep, tail = key.partition(":")
    return (head, tail) if sep else (key, key)


def _by_table(matches: list[_Match]) -> dict[str, list[_Match]]:
    out: dict[str, list[_Match]] = {}
    for match in matches:
        out.setdefault(match.hit.table, []).append(match)
    return out


def _model_source(relpath: str) -> str:
    name = PurePosixPath(relpath).name
    if patterns.ENV_FILE_RE.match(name):
        return "env"
    if PurePosixPath(relpath).suffix.lower() in _CONFIG_DATA_EXTS:
        return "config"
    return "literal"


def _build_models(matches: list[_Match]) -> list[dict[str, Any]]:
    """Section 2 `models[]`: exactly {id, file, line, provider, model, pinned, source}.

    The unit is deliberately not part of the entry; `ai_surface_units()` and
    `_model_ref()` recover it from the file through the walk's unit map.
    """
    seen: set[tuple[str, int, str]] = set()
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        provider, ident = _split_key(hit.key)
        stamp = (hit.file, hit.line, ident)
        if stamp in seen:
            continue
        seen.add(stamp)
        pinned = None if provider == "other" else patterns.classify_model(provider, ident)
        out.append(
            {
                "id": "",
                "file": hit.file,
                "line": hit.line,
                "provider": provider,
                "model": ident,
                "pinned": pinned,
                "source": _model_source(hit.file),
            }
        )
    out = _sorted(out)
    for index, entry in enumerate(out, 1):
        entry["id"] = f"m{index}"
    return out


def _model_ref(
    models: list[dict[str, Any]],
    file: str,
    line: int,
    unit: str | None,
    unit_by_file: dict[str, str | None],
) -> str | None:
    """Closest preceding model id in the same file, else any in the file, else the unit."""
    best: dict[str, Any] | None = None
    for entry in models:
        if entry["file"] != file or entry["line"] > line:
            continue
        if best is None or entry["line"] > best["line"]:
            best = entry
    if best is None:
        same_file = [m for m in models if m["file"] == file]
        if same_file:
            best = same_file[0]
    if best is None and unit is not None:
        same_unit = [m for m in models if unit_by_file.get(m["file"]) == unit]
        if same_unit:
            best = same_unit[0]
    return None if best is None else best["id"]


def _build_llm_calls(
    matches: list[_Match],
    models: list[dict[str, Any]],
    unit_by_file: dict[str, str | None],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "provider": patterns.LLM_PROVIDER_BY_KEY.get(hit.key, "unknown"),
                "sdk": hit.key,
                "api": match.text,
                "unit": hit.unit,
                "model_ref": _model_ref(models, hit.file, hit.line, hit.unit, unit_by_file),
            }
        )
    return _sorted(out)


def _build_frameworks(matches: list[_Match]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for match in sorted(matches, key=lambda m: (m.hit.file, m.hit.line, m.hit.key)):
        hit = match.hit
        if (hit.file, hit.key) in seen:
            continue
        seen.add((hit.file, hit.key))
        out.append({"name": hit.key, "file": hit.file, "line": hit.line, "unit": hit.unit})
    return _sorted(out)


def _description_after(lines: list[str], line: int) -> str:
    for text in lines[line - 1 : line + 5]:
        for rx in _DESCRIPTION_RES:
            match = rx.search(text)
            if match and match.group(1).strip():
                return truncate_snippet(match.group(1))
    return ""


def _build_tools(
    matches: list[_Match], lines_by_file: dict[str, list[str]]
) -> list[dict[str, Any]]:
    seen: set[tuple[str | None, str]] = set()
    out: list[dict[str, Any]] = []
    ordered = sorted(matches, key=lambda m: (m.hit.file, m.hit.line, m.hit.key))
    # The capability body stops at the next tool definition in the same file, so a
    # schema list does not lend `run_shell`'s exec label to the `send_email` before it.
    def_lines: dict[str, list[int]] = {}
    for match in ordered:
        def_lines.setdefault(match.hit.file, []).append(match.hit.line)
    for match in ordered:
        hit = match.hit
        kind, name = _split_key(hit.key)
        if not name or (hit.unit, name) in seen:
            continue
        seen.add((hit.unit, name))
        lines = lines_by_file.get(hit.file, [])
        body_end = hit.line + _TOOL_BODY_LINES
        for other in def_lines.get(hit.file, []):
            if hit.line < other < body_end:
                body_end = other - 1
        body = "\n".join(lines[hit.line : body_end])
        window = "\n".join(lines[hit.line - 1 : hit.line + _GATE_WINDOW])
        gate_symbols = sorted(
            {m.group(0).rstrip("(").strip() for m in vocab.APPROVAL_SYMBOLS.finditer(window)}
        )
        out.append(
            {
                "id": "",
                "name": name,
                "file": hit.file,
                "line": hit.line,
                "unit": hit.unit,
                "kind": kind,
                "capabilities": sorted(vocab.classify_tool(name, body)),
                "gated": bool(gate_symbols),
                "gate_symbols": gate_symbols,
                "risk_tier": vocab.risk_tier_for(name),
                "description_snippet": _description_after(lines, hit.line),
            }
        )
    out = _sorted(out)
    for index, entry in enumerate(out, 1):
        entry["id"] = f"t{index}"
    return out


def _build_legs(matches: list[_Match]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        kind, _symbol = _split_key(hit.key)
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "kind": kind,
                "symbol": match.text,
                "unit": hit.unit,
            }
        )
    return _sorted(out)


def _build_guardrails(matches: list[_Match], fail_open_files: set[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for match in sorted(matches, key=lambda m: (m.hit.file, m.hit.line, m.hit.key)):
        hit = match.hit
        if (hit.file, hit.key) in seen:
            continue
        seen.add((hit.file, hit.key))
        out.append(
            {
                "lib": hit.key,
                "file": hit.file,
                "line": hit.line,
                "fail_open": True if hit.file in fail_open_files else None,
            }
        )
    return _sorted(out)


def _build_observability(llm: list[_Match], apm: list[_Match]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    # Generic APM is not LLM observability; it is kept, prefixed, so a rule can tell them apart.
    labelled = [(m, m.hit.key) for m in llm] + [(m, f"apm:{m.hit.key}") for m in apm]
    for match, lib in sorted(
        labelled, key=lambda item: (item[0].hit.file, item[0].hit.line, item[1])
    ):
        if (match.hit.file, lib) in seen:
            continue
        seen.add((match.hit.file, lib))
        out.append({"lib": lib, "file": match.hit.file, "line": match.hit.line})
    return _sorted(out)


def _build_evals(matches: list[_Match], texts: dict[str, str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        if (hit.file, hit.key) in seen:
            continue
        seen.add((hit.file, hit.key))
        out.append(
            {
                "tool": hit.key,
                "file": hit.file,
                "in_ci": _glob_hit(_CI_GLOBS, hit.file),
                "has_benign": _BENIGN_RE.search(texts.get(hit.file, "")) is not None,
            }
        )
    return _sorted(out)


def _build_loops(
    matches: list[_Match], lines_by_file: dict[str, list[str]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for match in matches:
        hit = match.hit
        lines = lines_by_file.get(hit.file, [])
        window = "\n".join(lines[hit.line : hit.line + _LOOP_WINDOW])
        cap = _LOOP_CAP_RE.search(window)
        out.append(
            {
                "file": hit.file,
                "line": hit.line,
                "capped": cap is not None,
                "cap_symbol": cap.group(0) if cap else None,
                "unit": hit.unit,
            }
        )
    return _sorted(out)


def _build_ci(facts: ConfigFacts, texts: dict[str, str]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for record in facts.ci:
        text = texts.get(record.file, "")
        out.append(
            {
                "file": record.file,
                "runs_evals": any(rx.search(text) for _key, rx in patterns.EVAL_TOOLS),
                "unsafe_steps": [
                    {"line": line, "key": key, "snippet": truncate_snippet(snippet)}
                    for line, key, snippet in record.unsafe_steps
                ],
            }
        )
    return sorted(out, key=lambda d: d["file"])


def _secret_counts(matches: list[_Match], facts: ConfigFacts) -> dict[str, Any]:
    code: set[tuple[str, int]] = set()
    config: set[tuple[str, int]] = set()
    for match in matches:
        hit = match.hit
        stamp = (hit.file, hit.line)
        if hit.lang == "config":
            config.add(stamp)
        else:
            code.add(stamp)
    for binding in facts.env:
        if not binding.literal or _excluded_secret_file(binding.file):
            continue
        if patterns.SECRET_VAR_NAMES.search(
            binding.name
        ) and not patterns.SECRET_VAR_EXCLUDE.search(binding.name):
            config.add((binding.file, binding.line or 0))
    return {"literal_hits": len(code), "config_hits": len(config), "scanner": "regex-only"}


def _build_system_card(
    files: list[FileRecord],
) -> tuple[dict[str, Any] | None, UnknownItem | None]:
    for record in files:  # files are sorted by relpath, so the first match is deterministic
        if not _glob_hit(patterns.SYSTEM_CARD_GLOBS, record.relpath):
            continue
        card = read_system_card(record.path)
        if card is None:
            return None, UnknownItem(
                category=UnknownCategory.RUNTIME,
                what=f"system card {record.relpath}",
                why="not a readable YAML mapping",
                file=record.relpath,
            )
        return {
            "file": record.relpath,
            "risk_tier": _risk_tier(card.get("risk_tier")),
            "annex_iii_category": _card_value(card, "annex_iii_category"),
            "incident_contact": _incident_contact(card),
        }, None
    return None, None


# ---------------------------------------------------------------------------
# AI surface
# ---------------------------------------------------------------------------


def _unit_of_file(inventory: Inventory, relpath: str) -> str:
    return walk.unit_of(relpath, inventory.units)


def ai_surface_units(inventory: Inventory) -> set[str]:
    """Units with at least one LLM call, framework, model id or MCP config."""
    units: set[str] = set()
    for section in (inventory.llm_calls, inventory.frameworks, inventory.models):
        for entry in section:
            unit = entry.get("unit")
            if unit is None and entry.get("file"):
                unit = _unit_of_file(inventory, entry["file"])
            if unit:
                units.add(unit)
    for entry in inventory.mcp.get("configs", []):
        file = entry.get("file", "")
        if file and not file.startswith("~/") and not PurePosixPath(file).is_absolute():
            units.add(_unit_of_file(inventory, file))
    return units


def unit_ai_surface(inventory: Inventory, unit_id: str) -> bool:
    return unit_id in ai_surface_units(inventory)


# ---------------------------------------------------------------------------
# discover()
# ---------------------------------------------------------------------------


def _languages(scanned: list[FileRecord]) -> dict[str, int]:
    counts: dict[str, int] = {"python": 0, "typescript": 0, "go": 0, "other": 0}
    for record in scanned:
        lang = record.lang if record.lang not in ("config", "other") else "other"
        counts[lang] = counts.get(lang, 0) + 1
    return counts


def discover(
    root: Path,
    files: list[FileRecord],
    units: list[Unit],
    options: object = None,
) -> tuple[Inventory, list[Hit], ConfigFacts]:
    """Grep every file, parse every config, and assemble the inventory.

    Returns the inventory, the raw hits (sorted by file, line, column, table, key) and
    the structured config facts. Never raises on a bad file: each failure becomes an
    `UnknownItem` in `inventory.unknown`.
    """
    started = time.perf_counter()
    root = Path(root)
    max_size = _opt(options, "max_size", None)
    trusted_hosts = tuple(_opt(options, "trusted_mcp_hosts", ()))
    inventory = Inventory(units=list(units))
    unknown: list[UnknownItem] = []
    matches: list[_Match] = []
    texts: dict[str, str] = {}
    lines_by_file: dict[str, list[str]] = {}
    scanned: list[FileRecord] = []
    skipped = 0
    total_bytes = 0

    for record in sorted(files, key=lambda r: r.relpath):
        text = walk.read_text(record.path, max_size)
        if text is None:
            skipped += 1
            continue
        scanned.append(record)
        total_bytes += record.size
        texts[record.relpath] = text
        try:
            file_matches = _matches(record, text)
        except Exception as exc:  # a pathological file must not stop the audit
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.RUNTIME,
                    what=f"discover {record.relpath}",
                    why=f"{type(exc).__name__}: {truncate_snippet(str(exc), 200)}",
                    file=record.relpath,
                )
            )
            continue
        matches.extend(file_matches)
        lines_by_file[record.relpath] = [line.rstrip("\r") for line in text.split("\n")]

    facts, config_unknown = config_facts(root, scanned, options, texts)
    unknown.extend(config_unknown)

    matches.sort(key=lambda m: (m.hit.file, m.hit.line, m.hit.col, m.hit.table, m.hit.key))
    tables = _by_table(matches)

    unit_by_file = {record.relpath: record.unit for record in scanned}
    inventory.models = _build_models(tables.get("model_id", []))
    inventory.llm_calls = _build_llm_calls(
        tables.get("llm_call", []), inventory.models, unit_by_file
    )
    inventory.frameworks = _build_frameworks(tables.get("framework", []))
    inventory.tools = _build_tools(tables.get("tool_def", []), lines_by_file)
    inventory.data_sources = _build_legs(tables.get("data_source", []))
    inventory.ingress = _build_legs(tables.get("ingress", []))
    inventory.external_actions = _build_legs(tables.get("external_action", []))
    inventory.sinks = _build_legs(tables.get("sink", []))
    fail_open_files = {m.hit.file for m in tables.get("fail_open", [])}
    inventory.guardrails = _build_guardrails(tables.get("guardrail", []), fail_open_files)
    inventory.observability = _build_observability(
        tables.get("llm_observability", []), tables.get("apm", [])
    )
    inventory.evals = _build_evals(tables.get("eval_tool", []), texts)
    inventory.loops = _build_loops(tables.get("loop", []), lines_by_file)
    inventory.secrets = _secret_counts(
        tables.get("secret", []) + tables.get("secret_var", []), facts
    )

    inventory.mcp = {
        "configs": list(getattr(facts, "_mcp_files", [])),
        "servers": [_server_entry(server, trusted_hosts) for server in facts.servers],
    }
    inventory.hosts = [_host_entry(record) for record in facts.host_records]
    inventory.ci = _build_ci(facts, texts)

    reports: list[ReportRecord] = []
    for record in scanned:
        if not _looks_like_report(record):
            continue
        report, item = read_report(record.path, root)
        if item is not None:
            unknown.append(item)
            continue
        if report is None:
            continue
        reports.append(report)
        if report.age_source == "unknown":
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what=f"report age {record.relpath}",
                    why="no generated_at, mtime and git both unavailable",
                    how_to_resolve="Regenerate the report; a report of unknown age is not evidence.",
                    file=record.relpath,
                )
            )
    inventory.reports = sorted(reports, key=lambda r: r.file)

    card, card_item = _build_system_card(scanned)
    inventory.system_card = card
    if card_item is not None:
        unknown.append(card_item)
    inventory.incident_path = sorted(
        r.relpath for r in scanned if _glob_hit(patterns.INCIDENT_PATH_GLOBS, r.relpath)
    )

    surface = ai_surface_units(inventory)
    for unit in inventory.units:
        unit.ai_surface = unit.id in surface
        if unit.ai_surface and unit.language != "python":
            language = unit.language if unit.language != "unknown" else "unknown-language"
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.DEEP,
                    what=f"{language} deep analysis",
                    why="not available in this version; grep-level findings only",
                    how_to_resolve="Review the grep-level findings for this unit by hand.",
                    file=unit.root,
                )
            )

    inventory.languages = _languages(scanned)
    sha, dirty = walk.git_meta(root)
    inventory.target = {
        "path": root.resolve().as_posix(),
        "git_sha": sha,
        "dirty": dirty,
        "scanned_files": len(scanned),
        "skipped_files": skipped,
        "bytes": total_bytes,
        "duration_ms": int((time.perf_counter() - started) * 1000),
    }
    inventory.unknown = unknown
    return inventory, [m.hit for m in matches], facts
