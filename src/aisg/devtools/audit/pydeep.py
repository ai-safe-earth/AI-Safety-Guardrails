"""aisg/devtools/audit/pydeep.py
----------------------------
Python AST layer (section 5): LLM call sites, loop caps, tool graph and gate
join, prompt assembly, output taint, trifecta legs and guard fail-open.

Everything here is heuristic and UNMEASURED. Only ``ast`` is used; one walk per
file collects raw facts, small pure functions derive the joins. A file that
fails to parse or to analyse becomes an ``UnknownItem`` (category ``deep``) and
never an exception: ``analyse_unit`` never raises.

Guard fail-open sites live in ``PyFacts.fail_open`` -- a separate list of
``GateSite`` with ``symbol="fail_open"`` and ``inert_reason="exception
swallowed"`` -- not in ``gates``: they are the opposite of a gate and must never
satisfy a tool-gate join.
"""

from __future__ import annotations

import ast
import re
from collections import deque
from dataclasses import dataclass, field, replace
from typing import Any

from aisg.devtools.audit import vocab
from aisg.devtools.audit.model import Evidence, Scope, UnknownCategory, UnknownItem, redact
from aisg.devtools.audit.patterns import (
    EXTERNAL_ACTION,
    GUARDRAIL_LIBS,
    LLM_RESPONSE_ACCESSORS,
    PRIVATE_DATA_SOURCES,
    UNTRUSTED_INGRESS,
)

# --------------------------------------------------------------------------- #
# Public tables
# --------------------------------------------------------------------------- #

# Dotted callee suffixes that name an LLM call. The bare ones (run/invoke/...) only
# count when the receiver resolves to an object built from an SDK module.
LLM_CALL_ATTRS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("messages", "create"),
        ("chat", "completions", "create"),
        ("responses", "create"),
        ("generate_content",),
        ("invoke",),
        ("ainvoke",),
        ("run",),
        ("arun",),
        ("completion",),
        ("acompletion",),
        ("converse",),
        ("invoke_model",),
    }
)

# Sink kind -> qualified dotted-name suffixes (imports are resolved first, so
# `from os import system; system(x)` is `os.system`). Per-kind argument rules live
# in `_sink_taint`.
SINK_ATTRS: dict[str, tuple[tuple[str, ...], ...]] = {
    "shell": (
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "Popen"),
        ("os", "system"),
        ("os", "popen"),
    ),
    "eval": (
        ("eval",),
        ("exec",),
        ("compile",),
        ("__import__",),
        ("importlib", "import_module"),
        ("pickle", "loads"),
        ("yaml", "load"),
    ),
    "sql": (("execute",), ("executemany",), ("text",), ("raw",)),
    "html": (
        ("Markup",),
        ("render_template_string",),
        ("HttpResponse",),
        ("mark_safe",),
        ("write",),
    ),
    "url": (
        ("requests", "get"),
        ("requests", "post"),
        ("requests", "put"),
        ("requests", "delete"),
        ("requests", "patch"),
        ("requests", "head"),
        ("requests", "request"),
        ("httpx", "get"),
        ("httpx", "post"),
        ("httpx", "put"),
        ("httpx", "delete"),
        ("httpx", "patch"),
        ("httpx", "request"),
        ("urllib", "request", "urlopen"),
        ("session", "get"),
        ("session", "post"),
    ),
    "fs": (
        ("open",),
        ("write_text",),
        ("write_bytes",),
        ("shutil", "rmtree"),
        ("shutil", "move"),
        ("os", "remove"),
        ("os", "unlink"),
    ),
}

# --------------------------------------------------------------------------- #
# Private tables
# --------------------------------------------------------------------------- #

# Last segment -> (kind, suffix): one dict probe per call instead of ~45 slice compares.
_SINK_BY_LAST: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {}
for _kind, _suffixes in SINK_ATTRS.items():
    for _suffix in _suffixes:
        _SINK_BY_LAST[_suffix[-1]] = (*_SINK_BY_LAST.get(_suffix[-1], ()), (_kind, _suffix))
# Builtins count only when called bare: `re.compile` and `zipfile.open` are not sinks.
_BUILTIN_SINKS = frozenset({"eval", "exec", "compile", "__import__", "open"})

_SDK_MODULES: tuple[tuple[str, str], ...] = (
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("google.generativeai", "google"),
    ("google.genai", "google"),
    ("boto3", "bedrock"),
    ("litellm", "litellm"),
    ("langchain", "langchain"),
    ("langgraph", "langchain"),
    ("mistralai", "mistral"),
    ("cohere", "cohere"),
    ("ollama", "ollama"),
)
# Multi-segment suffixes are specific enough to count when any SDK is imported.
_SUFFIX_PROVIDER: dict[tuple[str, ...], str] = {
    ("messages", "create"): "anthropic",
    ("chat", "completions", "create"): "openai",
    ("responses", "create"): "openai",
    ("generate_content",): "google",
    ("converse",): "bedrock",
    ("invoke_model",): "bedrock",
}
_ACCESSOR_ATTRS = frozenset(
    {"text", "content", "output_text", "tool_calls", "candidates", "choices"}
)
_ACCESSOR_KEYS = frozenset({"output", "content", "text"})
_TOOL_DECORATORS = frozenset({"tool", "tool_plain", "function_tool", "kernel_function"})
_TEMPLATE_CTORS = frozenset(
    {
        "PromptTemplate",
        "ChatPromptTemplate",
        "from_messages",
        "from_template",
        "SystemMessage",
        "HumanMessage",
        "SystemMessagePromptTemplate",
        "substitute",
        "safe_substitute",
    }
)
_SYSTEM_CTORS = frozenset({"SystemMessage", "SystemMessagePromptTemplate"})
_PROMPT_KWARGS = frozenset(
    {
        "system",
        "content",
        "prompt",
        "instructions",
        "system_prompt",
        "system_instruction",
        "messages",
        "template",
        "human",
        "user",
    }
)
_SYSTEM_KWARGS = frozenset({"system", "system_prompt", "system_instruction"})
_PROMPT_DICT_KEYS = frozenset(
    {"content", "prompt", "system", "instructions", "input", "question", "query"}
)
_PROMPT_NAME_RE = re.compile(r"(?i)prompt|system|instruction|message|template|persona|context")
_SYSTEM_NAME_RE = re.compile(r"(?i)system_?(?:prompt|message|msg|instruction|template)")
_ALLOW_NAME_RE = re.compile(r"(?i)allow|whitelist|permitted|valid")
_HTML_WRITER_RE = re.compile(r"(?i)resp|wfile|http|handler|stream")
_KILL_CALLS: frozenset[tuple[str, ...]] = frozenset(
    {
        ("shlex", "quote"),
        ("int",),
        ("float",),
        ("re", "fullmatch"),
        ("html", "escape"),
        ("markupsafe", "escape"),
        ("urllib", "parse", "quote"),
        ("urllib", "parse", "quote_plus"),
    }
)
_MUTATORS = frozenset({"append", "extend", "insert", "add", "update", "put", "setdefault"})
_LOOP_CAPS = frozenset(vocab.LOOP_CAP_SYMBOLS)
_SANITISERS = tuple(vocab.SANITISER_SYMBOLS)
_LEGS = ("private", "untrusted", "external_action")
_LEG_TABLES = (
    ("private", PRIVATE_DATA_SOURCES["python"]),
    ("untrusted", UNTRUSTED_INGRESS["python"]),
    ("external_action", EXTERNAL_ACTION["python"]),
)
_UNTRUSTED_PY = UNTRUSTED_INGRESS["python"]
_ROUTE_RE = dict(_UNTRUSTED_PY)["http:route_decorator"]
_LEG_NODES = (ast.Call, ast.Attribute, ast.Await, ast.Import, ast.ImportFrom, ast.Subscript)
_PARSE_ERRORS = (SyntaxError, RecursionError, MemoryError, ValueError)

# --------------------------------------------------------------------------- #
# Public product
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CallSite:
    file: str
    line: int
    provider: str
    function: str | None
    loop_line: int | None
    capped: bool | None


@dataclass(frozen=True)
class ToolDef:
    name: str
    file: str
    line: int
    kind: str  # decorator | from_function | basetool | schema_dict | registry
    capabilities: frozenset[str]
    body_symbols: tuple[str, ...]
    calls: tuple[str, ...]
    risk_tier: str


@dataclass(frozen=True)
class GateSite:
    symbol: str
    file: str
    line: int
    function: str | None
    inert_reason: str | None


@dataclass(frozen=True)
class LoopSite:
    file: str
    line: int
    kind: str  # while_true | for_count | for_range_huge
    cap_symbol: str | None
    contains_llm_call: bool
    function: str | None


@dataclass(frozen=True)
class Assembly:
    file: str
    line: int
    kind: str  # fstring | concat | format | template
    source_names: tuple[str, ...]
    is_system: bool
    untrusted_names: tuple[str, ...]


@dataclass(frozen=True)
class TaintPath:
    file: str
    source_line: int
    source_accessor: str
    sink_kind: str  # shell | eval | sql | html | url | fs
    sink_line: int
    sink_call: str
    sanitised: bool
    via: tuple[int, ...]
    function: str | None = None  # enclosing function of the sink


@dataclass(frozen=True)
class _FuncInfo:
    """Call-graph node: a function (or a module's top level) and the bare names it calls."""

    key: str
    file: str
    unit: str | None
    name: str | None
    line: int
    end_line: int
    calls: tuple[str, ...]


@dataclass
class PyFacts:
    llm_calls: list[CallSite] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)
    gates: list[GateSite] = field(default_factory=list)
    tool_gate_join: dict[str, GateSite | None] = field(default_factory=dict)
    loops: list[LoopSite] = field(default_factory=list)
    prompt_assemblies: list[Assembly] = field(default_factory=list)
    taint_paths: list[TaintPath] = field(default_factory=list)
    legs: dict[str, dict[str, list[Evidence]]] = field(default_factory=dict)
    fail_open: list[GateSite] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)
    # Call graph behind the joins: "func:<relpath>::<name>" / "module:<relpath>" -> node.
    functions: dict[str, _FuncInfo] = field(default_factory=dict)
    # Tool name -> function keys its body lives in (BFS roots for the gate join).
    tool_funcs: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def merge(self, other: PyFacts) -> None:
        """Fold another file's facts in. Tools are unique by name; first definition wins."""
        seen = {t.name for t in self.tools}
        self.tools.extend(t for t in other.tools if t.name not in seen and not seen.add(t.name))
        for attr in (
            "llm_calls",
            "gates",
            "loops",
            "prompt_assemblies",
            "taint_paths",
            "fail_open",
            "unknown",
        ):
            getattr(self, attr).extend(getattr(other, attr))
        self.legs.update(other.legs)
        self.functions.update(other.functions)
        for name, keys in other.tool_funcs.items():
            self.tool_funcs.setdefault(name, keys)
        self.tool_gate_join.update(other.tool_gate_join)

    def _by_name(self) -> dict[str, list[str]]:
        """Bare function name -> keys defining it; an index for one join pass."""
        by_name: dict[str, list[str]] = {}
        for k, info in self.functions.items():
            if info.name is not None:
                by_name.setdefault(info.name.rsplit(".", 1)[-1], []).append(k)
        return by_name

    def _reach(self, key: str, by_name: dict[str, list[str]], depth: int = 3) -> list[str]:
        """Keys reachable from `key` through same-unit calls, `key` first, depth-bounded."""
        seen, queue, order = {key}, deque([(key, 0)]), []
        while queue:
            cur, d = queue.popleft()
            order.append(cur)
            info = self.functions.get(cur)
            if info is None or d >= depth:
                continue
            for callee in info.calls:
                for k in by_name.get(callee, ()):
                    if k not in seen:
                        seen.add(k)
                        queue.append((k, d + 1))
        return order

    def _leg_set(self, key: str) -> set[str]:
        return {leg for leg in _LEGS if self.legs.get(key, {}).get(leg)}

    def trifecta_scopes(self) -> list[Scope]:
        """Narrowest scopes covering all three legs: functions, else files, else none."""
        out: list[Scope] = []
        by_name = self._by_name()
        for key, info in self.functions.items():
            if info.name is None:
                continue
            covered: set[str] = set()
            for reached in self._reach(key, by_name):
                covered |= self._leg_set(reached)
            if covered == set(_LEGS):
                out.append(Scope(kind="function", unit=info.unit, name=f"{info.file}::{info.name}"))
        if out:
            return out
        per_file: dict[str, set[str]] = {}
        units: dict[str, str | None] = {}
        for key, info in self.functions.items():
            per_file.setdefault(info.file, set()).update(self._leg_set(key))
            units.setdefault(info.file, info.unit)
        return [
            Scope(kind="file", unit=units[f], name=f)
            for f, legs in per_file.items()
            if legs == set(_LEGS)
        ]

    def join_gates(self) -> None:
        """Recompute `tool_gate_join`: first live gate on any depth-3 call path, else an inert one."""
        by_name = self._by_name()
        for tool in self.tools:
            found: GateSite | None = None
            keys: list[str] = []
            for root in self.tool_funcs.get(tool.name, ()):
                keys.extend(k for k in self._reach(root, by_name) if k not in keys)
            for key in keys:
                info = self.functions.get(key)
                if info is None:
                    continue
                for gate in self.gates:
                    if gate.file == info.file and info.line <= gate.line <= info.end_line:
                        if gate.inert_reason is None:
                            found = gate
                            break
                        found = found or gate
                if found is not None and found.inert_reason is None:
                    break
            self.tool_gate_join[tool.name] = found


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #


def _unparse(node: ast.AST | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:  # exotic nodes must never kill the audit
        return ""


def _chain(node: ast.AST) -> list[str]:
    """Dotted chain of a callee/receiver, looking through calls, subscripts and awaits."""
    parts: list[str] = []
    cur = node
    while True:
        if isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        elif isinstance(cur, ast.Call):
            cur = cur.func
        elif isinstance(cur, (ast.Subscript, ast.Await)):
            cur = cur.value
        elif isinstance(cur, ast.Name):
            parts.append(cur.id)
            break
        else:
            break
    return parts[::-1]


def _base(node: ast.AST) -> ast.AST:
    """The Call or Name an attribute/subscript chain hangs off."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Await)):
        node = node.value
    return node


def _match(table: Any, text: str) -> tuple[str, str] | None:
    for key, pattern in table:
        m = pattern.search(text)
        if m:
            return key, m.group(0)
    return None


_ANCHORS: dict[int, tuple[re.Pattern, tuple[str, ...] | None]] = {}
_META = set("\\.^$*+?{}[]()|")


def _scan(src: str):
    """Yield (index, char, depth) per unescaped char of a pattern; an escape yields a `\\`.

    `depth` is the nesting outside the char: 0 for anything not inside a group or
    character class. Brackets themselves report the outer depth. Class contents
    never reach depth 0, so a `)` or `|` inside `[...]` cannot fool the caller.
    """
    depth = 0
    in_class = False
    i = 0
    while i < len(src):
        ch = src[i]
        if ch == "\\":
            yield i, "\\", depth
            i += 2
            continue
        if in_class:
            if ch == "]" and src[i - 1] != "[" and src[i - 2 : i] != "[^":
                in_class = False
                depth -= 1
                yield i, ch, depth
            else:
                yield i, ch, depth
        elif ch in "([{":
            in_class = ch == "["
            yield i, ch, depth
            depth += 1
        elif ch in ")}":
            depth -= 1
            yield i, ch, depth
        else:
            yield i, ch, depth
        i += 1


def _branches(src: str) -> list[str]:
    """Top-level alternation branches of a pattern source (one outer `(?:...)` unwrapped)."""
    parts: list[str] = []
    start = 0
    closed_at = None
    for i, ch, depth in _scan(src):
        if depth != 0:
            continue
        if ch == "|":
            parts.append(src[start:i])
            start = i + 1
        elif ch == ")" and closed_at is None:
            closed_at = i
    if not parts and closed_at == len(src) - 1 and src.startswith("(?:"):
        return _branches(src[3:-1])
    parts.append(src[start:])
    return parts


def _literal(branch: str) -> str:
    """Longest literal run every match of an alternation-free branch must contain."""
    runs: list[str] = []
    run = ""
    for _i, ch, depth in _scan(branch):
        if depth == 0 and ch not in _META:
            run += ch
            continue
        if run and depth == 0 and ch in "?*{":
            run = run[:-1]  # the char before a `?`, `*` or `{m,n}` is optional
        runs.append(run)
        run = ""
    runs.append(run)
    return max(runs, key=len)


def _anchors(pattern: re.Pattern) -> tuple[str, ...] | None:
    """Literals of which every match of `pattern` contains at least one; None if unknowable.

    One literal per top-level branch. Conservative by construction: a mistake here
    can only ever yield a shorter literal or None, never a literal a match lacks.
    """
    entry = _ANCHORS.get(id(pattern))
    if entry is not None and entry[0] is pattern:
        return entry[1]
    anchors: list[str] | None = []
    if pattern.flags & re.VERBOSE:
        anchors = None
    else:
        for branch in _branches(pattern.pattern):
            lit = _literal(branch)
            if not lit:
                anchors = None
                break
            anchors.append(lit.lower() if pattern.flags & re.IGNORECASE else lit)
    result = tuple(anchors) if anchors else None
    _ANCHORS[id(pattern)] = (pattern, result)
    return result


def _may_hit(pattern: re.Pattern, text: str, lower: str) -> bool:
    """Cheap file-level prefilter: False only when no match of `pattern` can exist in `text`."""
    anchors = _anchors(pattern)
    if anchors is None:
        return pattern.search(text) is not None
    haystack = lower if pattern.flags & re.IGNORECASE else text
    return any(a in haystack for a in anchors)


def _active(table: Any, text: str, lower: str) -> list[tuple[str, re.Pattern]]:
    """The patterns that may hit somewhere in a file: node-level matching only needs those."""
    return [(key, pattern) for key, pattern in table if _may_hit(pattern, text, lower)]


def _names_in(node: ast.AST) -> tuple[str, ...]:
    """Name ids read inside an expression, callee names excluded, first-seen order."""
    callees = {id(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)}
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and id(n) not in callees and n.id not in out:
            out.append(n.id)
    return tuple(out)


def _target_names(target: ast.AST) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _target_names(elt)]
    root = _base(target)
    return [root.id] if isinstance(root, ast.Name) else []


def _shallow(call: ast.Call) -> str:
    """Call rendered with nested calls collapsed, so a gate literal is seen by one call only."""

    def arg(n: ast.AST) -> str:
        return ".".join(_chain(n.func)) + "(...)" if isinstance(n, ast.Call) else _unparse(n)

    parts = [arg(a) for a in call.args]
    parts += [f"{k.arg or '**'}={arg(k.value)}" for k in call.keywords]
    return f"{_unparse(call.func)}({', '.join(parts)})"


def _kwarg(call: ast.Call, name: str) -> ast.AST | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _sanitiser_name(chain: list[str]) -> bool:
    last = chain[-1].lower() if chain else ""
    return any(tok in last for tok in _SANITISERS)


# --------------------------------------------------------------------------- #
# Per-module context
# --------------------------------------------------------------------------- #


@dataclass
class _Scope:
    key: str
    name: str | None
    node: ast.AST
    parent: _Scope | None
    assigns: list[tuple[str, ast.AST, int]] = field(default_factory=list)
    params: dict[str, ast.AST | None] = field(default_factory=dict)
    route: bool = False

    def lookup(self, name: str, line: int) -> tuple[str, ast.AST | None] | None:
        """Nearest preceding binding of `name`: own assigns, params, then enclosing scopes."""
        found = None
        for n, value, ln in self.assigns:
            if n == name and ln < line:
                found = value
        if found is not None:
            return ("assign", found)
        if name in self.params:
            return ("param", self.params[name])
        if self.parent is not None:
            return self.parent.lookup(name, line)
        for n, value, _ln in self.assigns:  # module level: a def may precede its globals
            if n == name:
                found = value
        return ("assign", found) if found is not None else None


class _Module:
    def __init__(self, relpath: str, unit: str | None, tree: ast.Module, text: str) -> None:
        self.relpath = relpath
        self.unit = unit
        self.tree = tree
        self.text = text
        self.lines = text.splitlines()
        # File-level prefilters: a pattern that misses the raw source misses every node.
        lower = text.lower()
        self.active_legs = [(leg, _active(table, text, lower)) for leg, table in _LEG_TABLES]
        self.active_legs = [(leg, table) for leg, table in self.active_legs if table]
        self.has_gate_text = _may_hit(vocab.APPROVAL_SYMBOLS, text, lower) or _may_hit(
            vocab.GATE_BYPASS, text, lower
        )
        self.parent_of: dict[ast.AST, ast.AST] = {}
        self.scope_of: dict[ast.AST, _Scope] = {}
        self.def_scope: dict[ast.AST, _Scope] = {}
        self.module_scope = _Scope(f"module:{relpath}", None, tree, None)
        self.alias: dict[str, str] = {}
        self.guard_names: set[str] = set()
        self.any_sdk = False
        self.llm_nodes: set[int] = set()
        self.call_results: set[str] = set()
        self.loop_sites: dict[ast.AST, LoopSite] = {}
        self._scopes(tree, self.module_scope, "")
        self.any_sdk = any(self.provider(v.split(".")) for v in self.alias.values())

    # -- construction ------------------------------------------------------
    def _import(self, node: ast.Import | ast.ImportFrom) -> None:
        if isinstance(node, ast.Import):
            for a in node.names:
                self.alias[a.asname or a.name.split(".")[0]] = (
                    a.name if a.asname else a.name.split(".")[0]
                )
        else:
            mod = "." * node.level + (node.module or "")
            for a in node.names:
                self.alias[a.asname or a.name] = f"{mod}.{a.name}"
        if _match(GUARDRAIL_LIBS, _unparse(node)):
            self.guard_names.update(a.asname or a.name.split(".")[0] for a in node.names)

    def _scopes(self, node: ast.AST, scope: _Scope, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            self.parent_of[child] = node
            self.scope_of[child] = scope
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                self._import(child)
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = prefix + child.name
                inner = _Scope(f"func:{self.relpath}::{qual}", qual, child, scope)
                a = child.args
                positional = a.posonlyargs + a.args
                defaults = [None] * (len(positional) - len(a.defaults)) + list(a.defaults)
                for arg, default in zip(positional, defaults):
                    inner.params[arg.arg] = arg.annotation or default
                for arg, default in zip(a.kwonlyargs, a.kw_defaults):
                    inner.params[arg.arg] = arg.annotation or default
                for arg in (a.vararg, a.kwarg):
                    if arg is not None:
                        inner.params[arg.arg] = arg.annotation
                inner.route = any(_ROUTE_RE.search("@" + _unparse(d)) for d in child.decorator_list)
                self.def_scope[child] = inner
                self._scopes(child, inner, qual + ".")
                continue
            if isinstance(child, ast.ClassDef):
                self._scopes(child, scope, prefix + child.name + ".")
                continue
            if isinstance(child, ast.Assign):
                for t in child.targets:
                    for n in _target_names(t):
                        scope.assigns.append((n, child.value, child.lineno))
            elif isinstance(child, ast.AnnAssign) and child.value is not None:
                for n in _target_names(child.target):
                    scope.assigns.append((n, child.value, child.lineno))
            elif isinstance(child, ast.withitem) and child.optional_vars is not None:
                for n in _target_names(child.optional_vars):
                    scope.assigns.append((n, child.context_expr, child.context_expr.lineno))
            elif isinstance(child, (ast.For, ast.AsyncFor)):
                for n in _target_names(child.target):
                    scope.assigns.append((n, child.iter, child.lineno))
            elif isinstance(child, ast.NamedExpr):
                scope.assigns.append((child.target.id, child.value, child.lineno))
            self._scopes(child, scope, prefix)

    # -- resolution --------------------------------------------------------
    def qualify(self, chain: list[str]) -> list[str]:
        if chain and chain[0] in self.alias:
            return self.alias[chain[0]].split(".") + chain[1:]
        return chain

    @staticmethod
    def provider(qchain: list[str]) -> str | None:
        dotted = ".".join(qchain)
        for prefix, provider in _SDK_MODULES:
            if dotted == prefix or dotted.startswith((prefix + ".", prefix + "_")):
                return provider
        return None

    def origin(self, expr: ast.AST, scope: _Scope, depth: int = 0) -> list[str]:
        """Qualified chain of the import an expression's root was built from."""
        if depth > 6:
            return []
        while isinstance(expr, ast.Await):
            expr = expr.value
        if isinstance(expr, ast.BinOp):
            return self.origin(expr.left, scope, depth + 1) or self.origin(
                expr.right, scope, depth + 1
            )
        chain = _chain(expr)
        if not chain:
            return []
        if chain[0] in self.alias:
            return self.qualify(chain)
        bound = scope.lookup(chain[0], getattr(expr, "lineno", 1 << 30))
        if bound is None or bound[1] is None or bound[1] is expr:
            return chain
        return self.origin(bound[1], scope, depth + 1) or chain

    def scope(self, node: ast.AST) -> _Scope:
        return self.scope_of.get(node, self.module_scope)

    def source(self, node: ast.AST) -> str:
        end = getattr(node, "end_lineno", node.lineno) or node.lineno
        return "\n".join(self.lines[node.lineno - 1 : end])

    def ancestors(self, node: ast.AST):
        cur = self.parent_of.get(node)
        while cur is not None:
            yield cur
            cur = self.parent_of.get(cur)

    def is_untrusted(self, name: str, scope: _Scope, line: int, depth: int = 0) -> bool:
        """Does `name`'s binding chain reach UNTRUSTED_INGRESS without a sanitiser?"""
        if depth > 5:
            return False
        bound = scope.lookup(name, line)
        if bound is None:
            return False
        kind, value = bound
        if kind == "param":
            if scope.route:
                return True
            return value is not None and _match(_UNTRUSTED_PY, _unparse(value)) is not None
        if value is None or (isinstance(value, ast.Call) and _sanitiser_name(_chain(value.func))):
            return False
        if _match(_UNTRUSTED_PY, _unparse(value)):
            return True
        return any(
            self.is_untrusted(n, scope, value.lineno, depth + 1)
            for n in _names_in(value)
            if n != name
        )

    def is_guard_call(self, call: ast.Call, scope: _Scope) -> bool:
        if _match(GUARDRAIL_LIBS, _unparse(call)):
            return True
        chain = _chain(call.func)
        if chain and chain[0] in self.guard_names:
            return True
        origin = self.origin(call.func, scope)
        return bool(origin) and (
            origin[0] in self.guard_names
            or _match(GUARDRAIL_LIBS, "import " + ".".join(origin)) is not None
        )


class _UnitIndex:
    """Function definitions across the unit, by bare name."""

    def __init__(self, modules: list[_Module]) -> None:
        self.by_name: dict[str, list[tuple[_Module, ast.AST]]] = {}
        for mod in modules:
            for node in mod.def_scope:
                self.by_name.setdefault(node.name, []).append((mod, node))  # type: ignore[attr-defined]

    def lookup(self, name: str, prefer: _Module) -> tuple[_Module, ast.AST] | None:
        candidates = self.by_name.get(name, [])
        for mod, node in candidates:
            if mod is prefer:
                return mod, node
        return candidates[0] if candidates else None


# --------------------------------------------------------------------------- #
# Taint
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Taint:
    line: int
    accessor: str
    via: tuple[int, ...]
    sanitised: bool


def _pick(*taints: _Taint | None) -> _Taint | None:
    live = [t for t in taints if t is not None]
    for t in live:
        if not t.sanitised:
            return t
    return live[0] if live else None


def _exprs(stmt: ast.stmt):
    """Expression nodes of one statement, not descending into nested statements."""
    stack = [c for c in ast.iter_child_nodes(stmt) if not isinstance(c, ast.stmt)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(c for c in ast.iter_child_nodes(node) if not isinstance(c, ast.stmt))


class _Tainter:
    def __init__(self, index: _UnitIndex, out: list[TaintPath]) -> None:
        self.index = index
        self.out = out
        self._exec_scopes: dict[int, bool] = {}

    def run(
        self, mod: _Module, scope: _Scope, body: list[ast.stmt], env: dict[str, _Taint], depth: int
    ) -> None:
        for stmt in body:
            self.stmt(mod, scope, stmt, env, depth)

    def stmt(
        self, mod: _Module, scope: _Scope, stmt: ast.stmt, env: dict[str, _Taint], depth: int
    ) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        for node in _exprs(stmt):
            if isinstance(node, ast.Call):
                self.sink(mod, scope, node, env, depth)
        line = stmt.lineno
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and stmt.value is not None:
            t = self.of(mod, scope, stmt.value, env, depth)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for name in (n for tg in targets for n in _target_names(tg)):
                if isinstance(stmt, ast.AugAssign):
                    t = _pick(t, env.get(name))
                if t is not None:
                    env[name] = replace(t, via=(*t.via, line)[-8:])
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            t = self.of(mod, scope, stmt.iter, env, depth)
            if t is not None:
                for name in _target_names(stmt.target):
                    env[name] = replace(t, via=(*t.via, line)[-8:])
        elif isinstance(stmt, (ast.Expr, ast.Return)) and stmt.value is not None:
            self.of(mod, scope, stmt.value, env, depth)
        elif isinstance(stmt, (ast.If, ast.While)):
            self.of(mod, scope, stmt.test, env, depth)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.of(mod, scope, item.context_expr, env, depth)
        for attr in ("body", "orelse", "finalbody"):
            for child in getattr(stmt, attr, []) or []:
                if isinstance(child, ast.stmt):
                    self.stmt(mod, scope, child, env, depth)
        for handler in getattr(stmt, "handlers", []) or []:
            self.run(mod, scope, handler.body, env, depth)

    def seed(self, mod: _Module, expr: ast.AST) -> _Taint | None:
        base = _base(expr)
        if isinstance(base, ast.Call):
            rooted = id(base) in mod.llm_nodes
        else:
            rooted = isinstance(base, ast.Name) and base.id in mod.call_results
        if not rooted:
            return None
        src = _unparse(expr)
        hit = _match(LLM_RESPONSE_ACCESSORS, src)
        if hit:
            return _Taint(expr.lineno, hit[0], (), False)
        cur = expr
        while isinstance(cur, (ast.Attribute, ast.Subscript)):
            if isinstance(cur, ast.Attribute) and cur.attr in _ACCESSOR_ATTRS:
                return _Taint(expr.lineno, cur.attr, (), False)
            if isinstance(cur, ast.Subscript) and isinstance(cur.slice, ast.Constant):
                if cur.slice.value in _ACCESSOR_KEYS:
                    return _Taint(expr.lineno, str(cur.slice.value), (), False)
            cur = cur.value
        return None

    def of(
        self, mod: _Module, scope: _Scope, expr: ast.AST, env: dict[str, _Taint], depth: int
    ) -> _Taint | None:
        """Taint carried by an expression, applying kills and same-unit propagation."""
        if isinstance(expr, ast.Name):
            return env.get(expr.id)
        if isinstance(expr, ast.Await):
            return self.of(mod, scope, expr.value, env, depth)
        if isinstance(expr, (ast.Attribute, ast.Subscript)):
            return self.seed(mod, expr) or self.of(mod, scope, expr.value, env, depth)
        if isinstance(expr, ast.Call):
            return self.call(mod, scope, expr, env, depth)
        if isinstance(expr, ast.Compare):
            left = self.of(mod, scope, expr.left, env, depth)
            if (
                left is not None
                and isinstance(expr.left, ast.Name)
                and any(
                    isinstance(op, ast.In) and _ALLOW_NAME_RE.search(_unparse(c))
                    for op, c in zip(expr.ops, expr.comparators)
                )
            ):
                env[expr.left.id] = replace(left, sanitised=True)
            for c in expr.comparators:
                self.of(mod, scope, c, env, depth)
            return None
        if isinstance(expr, ast.NamedExpr):
            t = self.of(mod, scope, expr.value, env, depth)
            if t is not None:
                env[expr.target.id] = t
            return t
        if isinstance(expr, ast.Lambda):
            return None
        parts = [c for c in ast.iter_child_nodes(expr) if not isinstance(c, ast.stmt)]
        return _pick(*(self.of(mod, scope, c, env, depth) for c in parts))

    def call(
        self, mod: _Module, scope: _Scope, call: ast.Call, env: dict[str, _Taint], depth: int
    ) -> _Taint | None:
        if id(call) in mod.llm_nodes and _match(LLM_RESPONSE_ACCESSORS, _unparse(call)):
            return _Taint(call.lineno, "agent_invoke", (), False)
        chain = _chain(call.func)
        qchain = mod.qualify(chain)
        receiver = self.of(mod, scope, call.func, env, depth) if chain and len(chain) > 1 else None
        args = [self.of(mod, scope, a, env, depth) for a in call.args]
        kws = [self.of(mod, scope, k.value, env, depth) for k in call.keywords]
        inner = _pick(receiver, *args, *kws)
        if inner is None:
            return None
        if tuple(qchain) in _KILL_CALLS or _sanitiser_name(chain):
            if qchain[-2:] == ["re", "fullmatch"]:
                for a in call.args:
                    if isinstance(a, ast.Name) and a.id in env:
                        env[a.id] = replace(env[a.id], sanitised=True)
            return replace(inner, sanitised=True)
        if chain and chain[-1] == "resolve" and ".is_relative_to(" in mod.source(scope.node):
            return replace(inner, sanitised=True)
        if chain and chain[-1] in _MUTATORS and receiver is None and len(chain) > 1:
            root = _base(call.func)
            if isinstance(root, ast.Name):
                env[root.id] = inner
        if depth == 0 and len(chain) == 1:
            target = self.index.lookup(chain[0], mod)
            if target is not None:
                self.follow(target, call, args, kws, env, inner)
        return inner

    def follow(
        self,
        target: tuple[_Module, ast.AST],
        call: ast.Call,
        args: list,
        kws: list,
        env: dict[str, _Taint],
        inner: _Taint,
    ) -> None:
        """Depth-1 propagation into a same-unit callee's parameters."""
        cmod, fn = target
        cscope = cmod.def_scope[fn]
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]  # type: ignore[attr-defined]
        env2: dict[str, _Taint] = {}
        for i, t in enumerate(args):
            if t is not None and i < len(params):
                env2[params[i]] = replace(t, via=(*t.via, call.lineno)[-8:])
        for kw, t in zip(call.keywords, kws):
            if t is not None and kw.arg is not None:
                env2[kw.arg] = replace(t, via=(*t.via, call.lineno)[-8:])
        if env2:
            self.run(cmod, cscope, fn.body, env2, 1)  # type: ignore[attr-defined]

    def sink(
        self, mod: _Module, scope: _Scope, call: ast.Call, env: dict[str, _Taint], depth: int
    ) -> None:
        chain = _chain(call.func)
        if not chain:
            return
        qchain = mod.qualify(chain)
        kind = next(
            (
                k
                for k, suffix in _SINK_BY_LAST.get(qchain[-1], ())
                if qchain[-len(suffix) :] == list(suffix)
                and (qchain[-1] not in _BUILTIN_SINKS or len(qchain) == 1)
            ),
            None,
        )
        if kind is None:
            return
        t = self._sink_taint(mod, scope, call, chain, qchain, kind, env, depth)
        if t is None:
            return
        path = TaintPath(
            mod.relpath,
            t.line,
            t.accessor,
            kind,
            call.lineno,
            ".".join(chain),
            t.sanitised,
            t.via,
            scope.name,
        )
        if path not in self.out:
            self.out.append(path)

    def _sink_taint(self, mod, scope, call, chain, qchain, kind, env, depth) -> _Taint | None:
        def of(node: ast.AST | None) -> _Taint | None:
            return None if node is None else self.of(mod, scope, node, env, depth)

        args = call.args
        first = args[0] if args else None
        last = chain[-1] if chain else ""
        if kind == "shell":
            if qchain[0] != "os":
                if not _is_true(_kwarg(call, "shell")) and isinstance(first, (ast.List, ast.Tuple)):
                    return None
                return of(first if first is not None else _kwarg(call, "args"))
            return _pick(*(of(a) for a in args))
        if kind == "eval":
            if last == "load" and "Safe" in _unparse(_kwarg(call, "Loader")):
                return None
            if last == "compile" and not self._has_exec(scope):
                return None
            return _pick(*(of(a) for a in args))
        if kind == "sql":
            return of(first)
        if kind == "html":
            if last == "write" and not _HTML_WRITER_RE.search(".".join(chain[:-1])):
                return None
            return _pick(*(of(a) for a in args))
        if kind == "url":
            return of(first if first is not None else _kwarg(call, "url"))
        if last == "open":
            mode = args[1] if len(args) > 1 else _kwarg(call, "mode")
            if not (isinstance(mode, ast.Constant) and str(mode.value)[:1] in ("w", "a", "x")):
                return None
            return of(first)
        if last in ("write_text", "write_bytes"):
            return of(call.func.value) if isinstance(call.func, ast.Attribute) else None
        return _pick(*(of(a) for a in args))

    def _has_exec(self, scope: _Scope) -> bool:
        """`compile()` only matters where its result can reach `exec`/`eval` (cached per scope)."""
        key = id(scope.node)
        if key not in self._exec_scopes:
            self._exec_scopes[key] = any(
                isinstance(n, ast.Call) and _chain(n.func) in (["exec"], ["eval"])
                for n in ast.walk(scope.node)
            )
        return self._exec_scopes[key]


# --------------------------------------------------------------------------- #
# Per-module analysis
# --------------------------------------------------------------------------- #


class _Analyser:
    def __init__(self, mod: _Module, index: _UnitIndex) -> None:
        self.mod = mod
        self.index = index
        self.facts = PyFacts()
        self.legs: dict[str, dict[str, dict[str, tuple[int, int, str]]]] = {}
        self.recorded: set[int] = set()
        self.system_uses: set[str] = set()
        self.calls_by_scope: dict[str, list[str]] = {}
        # (index into prompt_assemblies, names it was assigned to): resolved once every
        # `system=` / SystemMessage / role-system use in the module has been seen.
        self.pending_system: list[tuple[int, tuple[str, ...]]] = []

    # -- entry -------------------------------------------------------------
    def run(self) -> PyFacts:
        mod, facts = self.mod, self.facts
        for node in ast.walk(mod.tree):
            scope = mod.scope(node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(node)
            elif isinstance(node, ast.ClassDef):
                self._class(node)
            elif isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
                self._loop(node, scope)
            elif isinstance(node, ast.Call):
                self._system_use(node)
                self._call(node, scope)
                chain = _chain(node.func)
                if chain:
                    self.calls_by_scope.setdefault(scope.key, []).append(chain[-1])
            elif isinstance(node, ast.Dict):
                self._system_use_dict(node)
                self._schema_dict(node)
            elif isinstance(node, ast.Assign):
                self._assign(node, scope)
            elif isinstance(node, ast.Try):
                self._try(node, scope)
            if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call)):
                self._assembly(node, scope)
            if mod.active_legs and isinstance(node, _LEG_NODES) and self._leg_worthy(node):
                self._leg(node, scope, _unparse(node))
        self._finish_loops()
        self._finish_assemblies()
        self._taint()
        facts.functions[mod.module_scope.key] = self._func_info(mod.module_scope, mod.tree)
        for fn, scope in mod.def_scope.items():
            facts.functions[scope.key] = self._func_info(scope, fn)
        for key, legs in self.legs.items():
            facts.legs[key] = {
                leg: [
                    Evidence(leg, mod.relpath, ln, redact(src))
                    for ln, _n, src in sorted(legs.get(leg, {}).values())
                ]
                for leg in _LEGS
            }
        for attr in (
            "llm_calls",
            "gates",
            "loops",
            "prompt_assemblies",
            "taint_paths",
            "fail_open",
        ):
            getattr(facts, attr).sort(key=lambda x: x.line if hasattr(x, "line") else x.sink_line)
        facts.tools.sort(key=lambda t: t.line)
        return facts

    def _func_info(self, scope: _Scope, node: ast.AST) -> _FuncInfo:
        calls = tuple(dict.fromkeys(self.calls_by_scope.get(scope.key, ())))
        end = getattr(node, "end_lineno", None) or len(self.mod.lines)
        line = getattr(node, "lineno", 1)
        return _FuncInfo(scope.key, self.mod.relpath, self.mod.unit, scope.name, line, end, calls)

    # -- legs --------------------------------------------------------------
    def _leg_worthy(self, node: ast.AST) -> bool:
        """Skip chain pieces an enclosing node renders anyway (`a.b` inside `a.b.c(...)`)."""
        parent = self.mod.parent_of.get(node)
        if isinstance(node, ast.Attribute):
            return not (
                isinstance(parent, ast.Attribute)
                or (isinstance(parent, ast.Call) and parent.func is node)
            )
        if isinstance(node, ast.Subscript):
            return not isinstance(parent, ast.Subscript)
        return True

    def _leg(self, node: ast.AST, scope: _Scope, src: str) -> None:
        if not src:
            return
        for leg, table in self.mod.active_legs:
            hit = _match(table, src)
            if hit is None:
                continue
            bucket = self.legs.setdefault(scope.key, {}).setdefault(leg, {})
            prev = bucket.get(hit[0])
            if prev is None or len(src) < prev[1]:
                bucket[hit[0]] = (node.lineno, len(src), src)

    # -- functions, classes, tools ----------------------------------------
    def _function(self, node: ast.AST) -> None:
        mod = self.mod
        scope = mod.def_scope[node]
        for dec in node.decorator_list:  # type: ignore[attr-defined]
            self._leg(dec, scope, "@" + _unparse(dec))
            chain = _chain(dec)
            if chain and chain[-1] in _TOOL_DECORATORS:
                name = node.name  # type: ignore[attr-defined]
                if isinstance(dec, ast.Call):
                    named = _kwarg(dec, "name")
                    if named is None and dec.args and isinstance(dec.args[0], ast.Constant):
                        named = dec.args[0]
                    if isinstance(named, ast.Constant) and isinstance(named.value, str):
                        name = named.value
                self._tool(name, node.lineno, "decorator", [node], "")

    def _class(self, node: ast.ClassDef) -> None:
        if not any(_chain(b)[-1:] == ["BaseTool"] for b in node.bases):
            return
        name = node.name
        for stmt in node.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if _target_names(targets[0]) == ["name"] and isinstance(stmt.value, ast.Constant):
                    name = str(stmt.value.value)
        runs = [
            s
            for s in node.body
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
            and s.name in ("_run", "_arun")
        ]
        self._tool(name, node.lineno, "basetool", runs or [node], "")

    def _schema_dict(self, node: ast.Dict) -> None:
        keys = {
            k.value: v
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        name = keys.get("name")
        if not isinstance(name, ast.Constant) or not isinstance(name.value, str):
            return
        if "parameters" not in keys and "input_schema" not in keys:
            return
        desc = keys.get("description")
        body = desc.value if isinstance(desc, ast.Constant) and isinstance(desc.value, str) else ""
        self._tool(name.value, node.lineno, "schema_dict", self._fn_nodes(name.value), body)

    def _assign(self, node: ast.Assign, scope: _Scope) -> None:
        if self.mod.has_gate_text:
            self._gate_text(_unparse(node), node, scope, None)
        target = node.targets[0] if len(node.targets) == 1 else None
        if not (isinstance(target, ast.Name) and "tool" in target.id.lower()):
            return
        if not isinstance(node.value, ast.Dict) or not node.value.keys:
            return
        for k, v in zip(node.value.keys, node.value.values):
            if not (isinstance(k, ast.Constant) and isinstance(k.value, str)):
                return
            if not isinstance(v, (ast.Name, ast.Attribute, ast.Lambda)):
                return
        for k, v in zip(node.value.keys, node.value.values):
            fn = v.id if isinstance(v, ast.Name) else k.value  # type: ignore[union-attr]
            self._tool(k.value, node.lineno, "registry", self._fn_nodes(fn), "")  # type: ignore

    def _fn_nodes(self, name: str) -> list[tuple[_Module, ast.AST]]:
        found = self.index.lookup(name, self.mod)
        return [found] if found else []

    def _tool(self, name: str, line: int, kind: str, bodies: list, fallback: str) -> None:
        if any(t.name == name for t in self.facts.tools):
            return
        nodes: list[tuple[_Module, ast.AST]] = [
            b if isinstance(b, tuple) else (self.mod, b) for b in bodies
        ]
        source = "\n".join(m.source(n) for m, n in nodes) or fallback
        calls: list[str] = []
        symbols: set[str] = set()
        keys: list[str] = []
        for m, n in nodes:
            for sub in ast.walk(n):
                if isinstance(sub, ast.Call):
                    dotted = ".".join(_chain(sub.func))
                    if dotted and dotted not in calls:
                        calls.append(dotted)
                elif isinstance(sub, ast.Attribute):
                    symbols.add(".".join(_chain(sub)))
            if n in m.def_scope:
                keys.append(m.def_scope[n].key)
            elif isinstance(n, ast.ClassDef):
                keys.extend(m.def_scope[s].key for s in n.body if s in m.def_scope)
        symbols.update(calls)
        self.facts.tools.append(
            ToolDef(
                name,
                self.mod.relpath,
                line,
                kind,
                frozenset(vocab.classify_tool(name, source)),
                tuple(sorted(symbols))[:64],
                tuple(calls),
                vocab.risk_tier_for(name),
            )
        )
        self.facts.tool_funcs[name] = tuple(keys)

    # -- calls: LLM sites, from_function tools, gates ---------------------
    def _call(self, node: ast.Call, scope: _Scope) -> None:
        mod = self.mod
        chain = _chain(node.func)
        for suffix in LLM_CALL_ATTRS:
            if chain[-len(suffix) :] == list(suffix):
                provider = mod.provider(mod.origin(node.func, scope))
                if provider is None and mod.any_sdk:
                    provider = _SUFFIX_PROVIDER.get(suffix)
                if provider is not None:
                    self._llm_site(node, scope, provider)
                break
        if chain and (chain[-1] == "from_function" or chain[-1] in ("Tool", "StructuredTool")):
            fn = _kwarg(node, "func") or (node.args[0] if node.args else None)
            if isinstance(fn, ast.Name) and (chain[-1] == "from_function" or _kwarg(node, "func")):
                named = _kwarg(node, "name")
                name = named.value if isinstance(named, ast.Constant) else fn.id
                self._tool(str(name), node.lineno, "from_function", self._fn_nodes(fn.id), "")
        if mod.has_gate_text:
            self._gate_text(_shallow(node), node, scope, node)

    def _llm_site(self, node: ast.Call, scope: _Scope, provider: str) -> None:
        mod = self.mod
        mod.llm_nodes.add(id(node))
        loop = next((mod.loop_sites[a] for a in mod.ancestors(node) if a in mod.loop_sites), None)
        self.facts.llm_calls.append(
            CallSite(
                mod.relpath,
                node.lineno,
                provider,
                scope.name,
                loop.line if loop else None,
                (loop.cap_symbol is not None) if loop else None,
            )
        )
        parent = mod.parent_of.get(node)
        while isinstance(parent, ast.Await):
            parent = mod.parent_of.get(parent)
        if isinstance(parent, (ast.Assign, ast.AnnAssign)):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            mod.call_results.update(n for t in targets for n in _target_names(t))

    def _gate_text(self, src: str, node: ast.AST, scope: _Scope, call: ast.Call | None) -> None:
        approval = vocab.APPROVAL_SYMBOLS.search(src)
        bypass = vocab.GATE_BYPASS.search(src)
        if approval is None and bypass is None:
            return
        hit = (approval or bypass).group(0).strip()  # type: ignore[union-attr]
        symbol = re.split(r"[\s(=:]", hit, maxsplit=1)[0]
        reason: str | None = None
        if bypass is not None:
            reason = "bypass: " + bypass.group(0).strip()
        elif call is not None:
            if (
                _is_true(_kwarg(call, "require_approval"))
                and _kwarg(call, "approval_callback") is None
            ):
                reason = "require_approval=True without approval_callback"
            elif (
                symbol in ("interrupt_before", "interrupt_after")
                and _kwarg(call, "checkpointer") is None
            ):
                reason = f"{symbol} without checkpointer"
        gate = GateSite(symbol, self.mod.relpath, node.lineno, scope.name, reason)
        if gate not in self.facts.gates:
            self.facts.gates.append(gate)

    # -- loops -------------------------------------------------------------
    def _loop(self, node: ast.AST, scope: _Scope) -> None:
        kind = self._loop_kind(node)
        if kind is None:
            return
        container = scope.node if scope.name is not None else node
        site = LoopSite(
            self.mod.relpath, node.lineno, kind, self._cap(container, node), False, scope.name
        )
        self.mod.loop_sites[node] = site

    def _loop_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.While):
            t = node.test
            if isinstance(t, ast.Constant) and isinstance(t.value, (bool, int)) and t.value:
                return "while_true"
            return None
        it = node.iter  # type: ignore[attr-defined]
        if not isinstance(it, ast.Call):
            return None
        chain = self.mod.qualify(_chain(it.func))
        if chain[-2:] == ["itertools", "count"]:
            return "for_count"
        if chain == ["range"] and it.args:
            stop = it.args[0] if len(it.args) == 1 else it.args[1]
            if isinstance(stop, ast.BinOp) and isinstance(stop.op, ast.Pow):
                if (
                    isinstance(stop.left, ast.Constant)
                    and stop.left.value == 10
                    and isinstance(stop.right, ast.Constant)
                    and isinstance(stop.right.value, int)
                    and stop.right.value >= 6
                ):
                    return "for_range_huge"
            if (
                isinstance(stop, ast.Constant)
                and isinstance(stop.value, int)
                and stop.value >= 10**6
            ):
                return "for_range_huge"
        return None

    @staticmethod
    def _cap(container: ast.AST, loop: ast.AST) -> str | None:
        counters: set[str] = set()
        for n in ast.walk(container):
            ident = None
            if isinstance(n, ast.Name):
                ident = n.id
            elif isinstance(n, ast.Attribute):
                ident = n.attr
            elif isinstance(n, (ast.arg, ast.keyword)):
                ident = n.arg
            if ident and ident.lower() in _LOOP_CAPS:
                return ident
            if isinstance(n, (ast.AugAssign, ast.Assign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                counters.update(x for t in targets for x in _target_names(t))
        for n in ast.walk(loop):
            if not isinstance(n, ast.If) or not any(
                isinstance(s, (ast.Break, ast.Return)) for s in n.body
            ):
                continue
            for c in ast.walk(n.test):
                if isinstance(c, ast.Compare):
                    for operand in (c.left, *c.comparators):
                        if isinstance(operand, ast.Name) and operand.id in counters:
                            return operand.id
        return None

    def _finish_loops(self) -> None:
        lines = {c.line for c in self.facts.llm_calls}
        for node, site in self.mod.loop_sites.items():
            end = getattr(node, "end_lineno", None) or site.line
            inside = any(site.line <= ln <= end for ln in lines)
            self.facts.loops.append(replace(site, contains_llm_call=inside))

    # -- prompt assembly ---------------------------------------------------
    def _system_use(self, call: ast.Call) -> None:
        chain = _chain(call.func)
        if chain and chain[-1] in _SYSTEM_CTORS:
            for a in call.args:
                self.system_uses.update(_names_in(a))
        value = _kwarg(call, "system")
        if value is not None:
            self.system_uses.update(_names_in(value))

    def _system_use_dict(self, node: ast.Dict) -> None:
        keys = {
            k.value: v
            for k, v in zip(node.keys, node.values)
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        role = keys.get("role")
        if isinstance(role, ast.Constant) and role.value == "system" and "content" in keys:
            self.system_uses.update(_names_in(keys["content"]))

    def _assembly_kind(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.JoinedStr):
            return "fstring"
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if any(
                isinstance(s, ast.JoinedStr)
                or (isinstance(s, ast.Constant) and isinstance(s.value, str))
                for s in (node.left, node.right)
            ):
                return "concat"
            return None
        if isinstance(node, ast.Call):
            chain = _chain(node.func)
            if not chain:
                return None
            if chain[-1] == "format" and isinstance(node.func, ast.Attribute):
                return "format"
            if chain[-1] in _TEMPLATE_CTORS:
                return "template"
        return None

    def _assembly(self, node: ast.AST, scope: _Scope) -> None:
        kind = self._assembly_kind(node)
        if kind is None or any(id(a) in self.recorded for a in self.mod.ancestors(node)):
            return
        targets: tuple[str, ...] = ()
        if kind == "template":
            prompt_like, is_system = True, _chain(node.func)[-1] in _SYSTEM_CTORS  # type: ignore
            inner = [
                n
                for n in ast.walk(node)
                if n is not node and self._assembly_kind(n) in ("fstring", "concat", "format")
            ]
            if inner:
                return  # the inner assemblies carry the precise context
        else:
            prompt_like, is_system, targets = self._context(node, scope)
        if not prompt_like:
            return
        self.recorded.add(id(node))
        names = _names_in(node)
        untrusted = tuple(n for n in names if self.mod.is_untrusted(n, scope, node.lineno))
        if targets and not is_system:
            self.pending_system.append((len(self.facts.prompt_assemblies), targets))
        self.facts.prompt_assemblies.append(
            Assembly(self.mod.relpath, node.lineno, kind, names, is_system, untrusted)
        )

    def _finish_assemblies(self) -> None:
        """A prompt assigned to a name that is later passed as `system=` is a system prompt."""
        for index, targets in self.pending_system:
            if any(n in self.system_uses for n in targets):
                current = self.facts.prompt_assemblies[index]
                self.facts.prompt_assemblies[index] = replace(current, is_system=True)

    def _context(self, node: ast.AST, scope: _Scope) -> tuple[bool, bool, tuple[str, ...]]:
        """(prompt_like, is_system, assigned names) from where the built string flows."""
        cur = node
        system = False
        for parent in self.mod.ancestors(node):
            if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                names = tuple(n for t in targets for n in _target_names(t))
                if any(_PROMPT_NAME_RE.search(n) for n in names):
                    return True, system or any(_SYSTEM_NAME_RE.search(n) for n in names), names
                return False, False, ()
            if isinstance(parent, ast.keyword):
                if parent.arg in _PROMPT_KWARGS:
                    return True, system or parent.arg in _SYSTEM_KWARGS, ()
                return False, False, ()
            if isinstance(parent, ast.Call):
                last = _chain(parent.func)[-1:]
                if last and last[0] in _SYSTEM_CTORS:
                    return True, True, ()
                if id(parent) in self.mod.llm_nodes or (last and last[0] in _TEMPLATE_CTORS):
                    return True, system, ()
                return False, False, ()
            if isinstance(parent, ast.Dict):
                key = next((k for k, v in zip(parent.keys, parent.values) if v is cur), None)
                role = next(
                    (
                        v
                        for k, v in zip(parent.keys, parent.values)
                        if isinstance(k, ast.Constant) and k.value == "role"
                    ),
                    None,
                )
                if isinstance(key, ast.Constant) and key.value in _PROMPT_DICT_KEYS:
                    return True, isinstance(role, ast.Constant) and role.value == "system", ()
                return False, False, ()
            if isinstance(parent, ast.Return):
                return bool(scope.name and _PROMPT_NAME_RE.search(scope.name)), False, ()
            if (
                isinstance(parent, ast.Tuple)
                and parent.elts
                and isinstance(parent.elts[0], ast.Constant)
            ):
                system = system or parent.elts[0].value == "system"
            if not isinstance(
                parent,
                (ast.List, ast.Tuple, ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Await),
            ):
                return False, False, ()
            cur = parent
        return False, False, ()

    # -- fail-open ---------------------------------------------------------
    def _try(self, node: ast.Try, scope: _Scope) -> None:
        def swallows(body: list[ast.stmt]) -> bool:
            if len(body) != 1:
                return False
            stmt = body[0]
            return isinstance(stmt, ast.Pass) or (
                isinstance(stmt, ast.Return) and _is_true(stmt.value)
            )

        if not any(swallows(h.body) for h in node.handlers):
            return
        for stmt in node.body:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Call) and self.mod.is_guard_call(sub, scope):
                    self.facts.fail_open.append(
                        GateSite(
                            "fail_open",
                            self.mod.relpath,
                            node.lineno,
                            scope.name,
                            "exception swallowed",
                        )
                    )
                    return

    # -- taint -------------------------------------------------------------
    def _taint(self) -> None:
        if not self.mod.llm_nodes:
            return  # every seed is a model-output accessor on a call site in this module
        tainter = _Tainter(self.index, self.facts.taint_paths)
        tainter.run(self.mod, self.mod.module_scope, list(self.mod.tree.body), {}, 0)
        for fn, scope in self.mod.def_scope.items():
            tainter.run(self.mod, scope, fn.body, {}, 0)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def _unknown(relpath: str, exc: BaseException) -> UnknownItem:
    return UnknownItem(
        category=UnknownCategory.DEEP,
        what="deep analysis",
        why=f"{type(exc).__name__}: {exc}",
        how_to_resolve="fix the parse error; grep-level findings for this file still apply",
        file=relpath,
    )


def _parse(relpath: str, unit: str | None, text: str, facts: PyFacts) -> _Module | None:
    try:
        return _Module(relpath, unit, ast.parse(text, filename=relpath), text)
    except _PARSE_ERRORS as exc:
        facts.unknown.append(_unknown(relpath, exc))
        return None


def _analyse(modules: list[_Module], facts: PyFacts) -> PyFacts:
    index = _UnitIndex(modules)
    for mod in modules:
        try:
            facts.merge(_Analyser(mod, index).run())
        except Exception as exc:  # an analyser bug must surface as UNKNOWN, never as a crash
            facts.unknown.append(_unknown(mod.relpath, exc))
    facts.join_gates()
    return facts


def analyse_file(record: Any, text: str) -> PyFacts:
    """Facts for one file. `record` needs `.relpath` (posix str) and optionally `.unit`."""
    facts = PyFacts()
    relpath = str(record.relpath).replace("\\", "/")
    mod = _parse(relpath, getattr(record, "unit", None), text, facts)
    return _analyse([mod], facts) if mod is not None else facts


def analyse_unit(files: list[Any], inventory: Any = None) -> PyFacts:
    """Facts for every Python file of a unit; joins are resolved across the unit's files.

    `files` are walker records (`.path`, `.relpath`, `.lang`, `.unit`); non-Python
    records are skipped. `inventory` is accepted for the contract and unused here:
    MCP-implied legs are the trust-boundary rule's business. Never raises.
    """
    facts = PyFacts()
    modules: list[_Module] = []
    for record in files:
        lang = getattr(record, "lang", None)
        relpath = str(record.relpath).replace("\\", "/")
        if lang != "python" and not relpath.endswith((".py", ".pyi")):
            continue
        try:
            text = record.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            facts.unknown.append(_unknown(relpath, exc))
            continue
        mod = _parse(relpath, getattr(record, "unit", None), text, facts)
        if mod is not None:
            modules.append(mod)
    return _analyse(modules, facts)
