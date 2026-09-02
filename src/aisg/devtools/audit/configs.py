"""aisg/devtools/audit/configs.py
----------------------------
Structured parsers for MCP, host, CI and env configs used by `aisg audit`.

Every file here is parsed with json / tomllib / yaml.safe_load, never by regex over the
body. The only regexes applied are the tables from `patterns.py`, and only to individual
string values (an allow-list entry, a mode string, a hook command, a CI step) or to plain
text files through `parse_literals`.

Error handling: a parser given invalid input returns an empty result (an empty list, or a
record with nothing in it) and never raises. The caller obtains the message for its
`UnknownItem` by calling `parse_error(path, text)` on the same input.

Secret values never enter a returned object: env bindings and MCP `env` maps are reduced
to their names plus a boolean saying whether the value was a literal.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

import yaml

from aisg.devtools.audit.model import truncate_snippet
from aisg.devtools.audit.patterns import (
    ENV_FILE_RE,
    HOST_CONFIG_FILES,
    HOST_OVERGRANT,
    HOST_OVERGRANT_INTERPRETER,
    MCP_CONFIG_FILES,
    SECRET_PLACEHOLDERS,
    UNSAFE_HOOK_PATTERNS,
    is_mention,
)
from aisg.devtools.audit.vocab import MCP_IMPLIED_LEGS

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

__all__ = [
    "McpServer",
    "OverGrant",
    "HookCommand",
    "HostRecord",
    "CiRecord",
    "EnvBinding",
    "parse_error",
    "parse_mcp_config",
    "parse_claude_settings",
    "parse_codex_config",
    "parse_cursor",
    "parse_gemini",
    "parse_literals",
    "parse_ci_workflow",
    "parse_compose_env",
    "parse_agent_frontmatter",
    "home_config_paths",
    "config_kind",
    "mcp_pinned",
    "is_loopback",
    "url_host",
]

# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class McpServer:
    """One MCP server entry from a host or registry config. Never carries env values.

    `description` is the AUD-604 input: the server's own description, followed by one
    `<tool>: <description>` line per tool when the manifest lists tools (server.json,
    smithery.yaml). `env_literal_keys` are the `env` entries whose value is a literal
    rather than a `${...}` / `<...>` reference or a placeholder -- names only.
    """

    name: str
    file: str
    host: str
    transport: str = "unknown"
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    env_keys: tuple[str, ...] = ()
    env_literal_keys: tuple[str, ...] = ()
    pinned: bool | None = None
    remote: bool = False
    remote_host: str | None = None
    implied_legs: tuple[str, ...] = ()
    description: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        # `trusted` is None for a remote server until the caller applies
        # --trusted-mcp-hosts; a local stdio server has no transport host to distrust.
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "host": self.host,
            "transport": self.transport,
            "command": self.command,
            "args": list(self.args),
            "url": self.url,
            "pinned": self.pinned,
            "remote": self.remote,
            "remote_host": self.remote_host,
            "trusted": None if self.remote else True,
            "implied_legs": list(self.implied_legs),
            "env_keys": list(self.env_keys),
            "env_secret_literals": len(self.env_literal_keys),
            "description": truncate_snippet(self.description) if self.description else None,
        }


@dataclass(frozen=True)
class OverGrant:
    key: str
    value: str
    severity: str
    sub: str | None = None
    line: int | None = None
    mention: bool = False


@dataclass(frozen=True)
class HookCommand:
    event: str
    command: str
    line: int | None = None
    unsafe_key: str | None = None


@dataclass
class HostRecord:
    host: str
    file: str
    over_grants: list[OverGrant] = field(default_factory=list)
    default_mode: str | None = None
    hooks: list[HookCommand] = field(default_factory=list)
    approval_policy: str | None = None
    sandbox_mode: str | None = None
    tools: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "file": self.file,
            "over_grants": [grant.value for grant in self.over_grants],
            "default_mode": self.default_mode,
            "hooks": len(self.hooks),
            "approval_policy": self.approval_policy,
            "sandbox_mode": self.sandbox_mode,
            "tools": list(self.tools),
        }


@dataclass
class CiRecord:
    """Unsafe CI / hook steps as (line, UNSAFE_HOOK_PATTERNS key, snippet) triples."""

    file: str
    unsafe_steps: list[tuple[int | None, str, str]] = field(default_factory=list)


@dataclass(frozen=True)
class EnvBinding:
    """An environment variable name bound in a config file. The value is never kept."""

    file: str
    name: str
    line: int | None
    literal: bool


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_FORMAT_BY_EXT = {".json": "json", ".toml": "toml", ".yaml": "yaml", ".yml": "yaml"}


def _posix(path: str) -> str:
    return str(path).replace("\\", "/")


def _basename(path: str) -> str:
    return PurePosixPath(_posix(path)).name


def _format_for(path: str) -> str | None:
    return _FORMAT_BY_EXT.get(PurePosixPath(_posix(path)).suffix.lower())


def _load(path: str, text: str) -> tuple[Any, str | None]:
    """Parse `text` by the file's extension. Returns (data, error); data is None on error."""
    fmt = _format_for(path)
    try:
        if fmt == "json":
            return json.loads(text), None
        if fmt == "toml":
            if tomllib is None:
                return None, "tomllib unavailable on this interpreter (install tomli)"
            return tomllib.loads(text), None
        if fmt == "yaml":
            return yaml.safe_load(text), None
    except Exception as exc:  # json/toml/yaml raise their own hierarchies
        return None, f"{exc.__class__.__name__}: {truncate_snippet(str(exc), 200)}"
    return None, f"unsupported config format: {_basename(path)}"


def _load_mapping(path: str, text: str) -> dict[str, Any] | None:
    data, error = _load(path, text)
    if error is not None or not isinstance(data, dict):
        return None
    return data


def parse_error(path: str, text: str, host: str | None = None) -> str | None:
    """The reason a config could not be parsed, or None when it parses to a mapping.

    The parse_* functions return empty results on bad input; call this for the message
    to record in an UnknownItem. `host` is accepted for symmetry and unused.
    """
    data, error = _load(path, text)
    if error is not None:
        return error
    if not isinstance(data, dict):
        return f"top-level value is {type(data).__name__}, expected a mapping"
    return None


def _find_line(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def _find_line_any(text: str, needles: Sequence[str]) -> int | None:
    for needle in needles:
        found = _find_line(text, needle)
        if found is not None:
            return found
    return None


def _str_list(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value if item is not None)
    return ()


# ---------------------------------------------------------------------------
# URLs and pinning
# ---------------------------------------------------------------------------


def url_host(url: str | None) -> str | None:
    """Hostname of a URL (lowercase, no brackets, no port), or None."""
    if not url:
        return None
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host or None


def is_loopback(host: str | None) -> bool:
    """True only for `localhost`, 127.0.0.0/8 and ::1. Never resolves DNS.

    A hostname that is not a literal IP counts as remote even if it would resolve to
    loopback; `0.0.0.0` is not loopback.
    """
    if not host:
        return False
    bare = host.strip().strip("[]").lower()
    if bare == "localhost":
        return True
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return False


_NPM_LAUNCHERS = frozenset({"npx", "bunx", "pnpx"})
_PY_LAUNCHERS = frozenset({"uvx", "pipx"})
_SUBCOMMANDS = frozenset({"run", "tool", "install", "dlx", "exec"})
_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?$")
_UNPINNED_TAGS = frozenset({"", "latest", "next", "*", "canary", "main", "master"})
# `docker run` flags that consume the next token, so it is not the image.
_DOCKER_VALUE_FLAGS = frozenset(
    "-e --env --env-file -v --volume --mount --name -p --publish --network --entrypoint "
    "-w --workdir -u --user -l --label --platform --pull -m --memory --cpus --add-host "
    "--hostname -h --restart --log-driver --security-opt --cap-add --cap-drop --device "
    "--tmpfs --gpus".split()
)


def _launcher(command: str) -> str:
    name = PurePosixPath(_posix(command)).name.lower()
    for ext in (".exe", ".cmd", ".bat"):
        if name.endswith(ext):
            name = name[: -len(ext)]
    return name


def _looks_local(spec: str) -> bool:
    return (
        spec.startswith((".", "/", "~", "file:"))
        or "\\" in spec
        or ":" in spec.split("@")[0]
        or spec.endswith((".js", ".ts", ".mjs", ".cjs", ".py"))
    )


def _npm_spec_pinned(spec: str) -> bool | None:
    if _looks_local(spec) or spec.startswith(("github:", "git+", "http")):
        return None
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return False
    version = body.rsplit("@", 1)[1].strip()
    if version.lower() in _UNPINNED_TAGS:
        return False
    return bool(_EXACT_VERSION_RE.match(version))


def _py_spec_pinned(spec: str) -> bool | None:
    if _looks_local(spec) or "://" in spec or spec.startswith("git+"):
        return None
    for sep in ("===", "==", "@"):
        if sep in spec:
            version = spec.split(sep, 1)[1].strip()
            if version.lower() in _UNPINNED_TAGS:
                return False
            return bool(_EXACT_VERSION_RE.match(version))
    return False


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    tail = image.rsplit("/", 1)[-1]
    if ":" not in tail:
        return False
    return tail.rsplit(":", 1)[1].lower() not in _UNPINNED_TAGS


def _first_spec(args: Sequence[str], value_flags: frozenset[str]) -> str | None:
    """First positional argument, honouring flags that consume the next token."""
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in value_flags:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg in _SUBCOMMANDS:
            continue
        return arg
    return None


def _flag_value(args: Sequence[str], names: Sequence[str]) -> str | None:
    for index, arg in enumerate(args):
        for name in names:
            if arg == name and index + 1 < len(args):
                return args[index + 1]
            if arg.startswith(name + "="):
                return arg[len(name) + 1 :]
    return None


def mcp_pinned(command: str | None, args: Sequence[str]) -> bool | None:
    """Whether an MCP launch line pins its package. None when not assessable.

    npx/bunx/pnpx: `pkg@1.2.3` or `@scope/pkg@1.2.3` -> True; no version or a floating tag
    (`latest`, `next`, ranges) -> False. uvx/pipx (and `uv tool run`): `pkg==1.0` or
    `pkg@1.0` -> True, bare -> False, `--from pkg==1.0` -> True. `docker run image:tag` ->
    True unless the tag is `latest` or absent (`@sha256:` always pins). `pip install`
    follows the uvx rules. Interpreters, local paths and unknown launchers -> None.
    """
    if not command:
        return None
    launcher = _launcher(command)
    argv = [str(arg) for arg in args]
    if launcher in _NPM_LAUNCHERS or (launcher == "pnpm" and argv[:1] == ["dlx"]):
        spec = _flag_value(argv, ("--package", "-p")) or _first_spec(argv, frozenset())
        return None if spec is None else _npm_spec_pinned(spec)
    if launcher in _PY_LAUNCHERS or (launcher == "uv" and argv[:2] == ["tool", "run"]):
        spec = _flag_value(argv, ("--from",)) or _first_spec(argv, frozenset({"--with", "-p"}))
        return None if spec is None else _py_spec_pinned(spec)
    if launcher in ("pip", "pip3") and argv[:1] == ["install"]:
        if "-r" in argv or "--requirement" in argv or "-e" in argv:
            return None
        spec = _first_spec(argv, frozenset({"--index-url", "-i", "--extra-index-url"}))
        return None if spec is None else _py_spec_pinned(spec)
    if launcher == "docker" and argv[:1] == ["run"]:
        image = _first_spec(argv, _DOCKER_VALUE_FLAGS)
        return None if image is None else _image_pinned(image)
    return None


# ---------------------------------------------------------------------------
# MCP server entries
# ---------------------------------------------------------------------------

_ENV_REFERENCE_RE = re.compile(r"^\s*(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]*>|%[^%]+%)\s*$")
_TRANSPORT_ALIASES = {
    "stdio": "stdio",
    "sse": "sse",
    "http": "http",
    "streamable-http": "http",
    "streamable_http": "http",
    "streamablehttp": "http",
    "streamable": "http",
}


def _is_env_literal(value: Any) -> bool:
    """A non-empty string that is neither a reference nor a documented placeholder."""
    if not isinstance(value, str) or not value.strip():
        return False
    if _ENV_REFERENCE_RE.match(value):
        return False
    return not any(rx.search(value) for _key, rx in SECRET_PLACEHOLDERS)


def _env_split(env: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(env, dict):
        return (), ()
    keys = tuple(str(key) for key in env)
    literal = tuple(str(key) for key, value in env.items() if _is_env_literal(value))
    return keys, literal


def _transport(kind: Any, url: str | None, command: str | None) -> str:
    if isinstance(kind, str) and kind.strip().lower() in _TRANSPORT_ALIASES:
        return _TRANSPORT_ALIASES[kind.strip().lower()]
    if url:
        scheme = (urlparse(url).scheme or "").lower()
        if scheme in ("http", "https"):
            return "sse" if url.rstrip("/").lower().endswith("/sse") else "http"
        return "unknown"
    return "stdio" if command else "unknown"


def _implied_legs(*texts: str | None, remote: bool) -> tuple[str, ...]:
    """MCP_IMPLIED_LEGS by substring over the server name / package / command line.

    A server nothing matches is `("untrusted",)`: an unknown stdio server is untrusted
    input until someone reads it; a remote one is untrusted by transport.
    """
    haystack = " ".join(text for text in texts if text).lower()
    legs: list[str] = []
    matched = False
    for key, key_legs in MCP_IMPLIED_LEGS.items():
        if key in haystack:
            matched = True
            legs.extend(leg for leg in key_legs if leg not in legs)
    if remote and "untrusted" not in legs:
        legs.append("untrusted")
    if not matched and not legs:
        legs.append("untrusted")
    return tuple(legs)


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _description(entry: dict[str, Any]) -> str | None:
    """Server description plus one `<tool>: <description>` line per listed tool."""
    parts: list[str] = []
    own = _text_or_none(entry.get("description")) or _text_or_none(entry.get("instructions"))
    if own:
        parts.append(own)
    tools = entry.get("tools")
    for tool in tools if isinstance(tools, list) else []:
        if isinstance(tool, dict):
            text = _text_or_none(tool.get("description")) or _text_or_none(tool.get("instructions"))
            if text:
                parts.append(f"{tool.get('name', 'tool')}: {text}")
    return "\n".join(parts) or None


def _server(
    *,
    name: str,
    path: str,
    host: str,
    text: str,
    command: str | None = None,
    args: Sequence[str] = (),
    url: str | None = None,
    kind: Any = None,
    env: Any = None,
    description: str | None = None,
    line: int | None = None,
    pinned: bool | None = None,
    legs_text: str | None = None,
) -> McpServer:
    argv = tuple(str(arg) for arg in args)
    remote_host = url_host(url)
    remote = url is not None and not is_loopback(remote_host)
    env_keys, env_literal = _env_split(env)
    if pinned is None:
        pinned = mcp_pinned(command, argv)
    return McpServer(
        name=name,
        file=_posix(path),
        host=host,
        transport=_transport(kind, url, command),
        command=command,
        args=argv,
        url=url,
        env_keys=env_keys,
        env_literal_keys=env_literal,
        pinned=pinned,
        remote=remote,
        remote_host=remote_host if remote else None,
        implied_legs=_implied_legs(legs_text or name, command, *argv, remote=remote),
        description=description,
        line=line if line is not None else _find_line(text, f'"{name}"'),
    )


def _server_entries(data: dict[str, Any], host: str) -> Iterator[tuple[str, dict[str, Any]]]:
    if host == "codex":
        block = data.get("mcp_servers")
    else:
        block = data.get("mcpServers")
        if block is None:
            block = data.get("servers")
    if isinstance(block, dict):
        for name, entry in block.items():
            if isinstance(entry, dict):
                yield str(name), entry
    elif isinstance(block, list):
        for entry in block:
            if isinstance(entry, dict) and entry.get("name"):
                yield str(entry["name"]), entry


def _parse_host_servers(path: str, text: str, host: str, data: dict[str, Any]) -> list[McpServer]:
    servers: list[McpServer] = []
    for name, entry in _server_entries(data, host):
        url = _text_or_none(entry.get("url")) or _text_or_none(entry.get("httpUrl"))
        url = url or _text_or_none(entry.get("serverUrl"))
        line = _find_line(text, f"[mcp_servers.{name}]") if host == "codex" else None
        servers.append(
            _server(
                name=name,
                path=path,
                host=host,
                text=text,
                command=_text_or_none(entry.get("command")),
                args=_str_list(entry.get("args")),
                url=url,
                kind=entry.get("type") or entry.get("transport"),
                env=entry.get("env"),
                description=_description(entry),
                line=line,
            )
        )
    return servers


_REGISTRY_LAUNCHER = {"npm": "npx", "pypi": "uvx", "docker": "docker", "oci": "docker"}


def _registry_launch(package: dict[str, Any]) -> tuple[str | None, tuple[str, ...], bool | None]:
    """(command, args, pinned) equivalent to a registry `packages[]` entry."""
    registry = str(package.get("registry_name") or package.get("registry_type") or "").lower()
    name = _text_or_none(package.get("name") or package.get("identifier"))
    version = _text_or_none(package.get("version"))
    command = _text_or_none(package.get("runtime_hint")) or _REGISTRY_LAUNCHER.get(registry)
    if not name:
        return command, (), None
    pinned = bool(version) and version.lower() not in _UNPINNED_TAGS
    if registry in ("docker", "oci"):
        return command or "docker", ("run", f"{name}:{version}" if version else name), pinned
    if registry == "pypi":
        return command or "uvx", (f"{name}=={version}" if version else name,), pinned
    return command or "npx", (f"{name}@{version}" if version else name,), pinned


def _parse_registry(path: str, text: str, data: dict[str, Any]) -> list[McpServer]:
    """MCP registry `server.json`: one record per package and per remote.

    The description (server plus tools) rides on the first record only, so a poisoned
    description is reported once. Implied legs come from the package name and the last
    segment of the registry name -- `io.github.<org>/notes` must not read as "github".
    """
    name = str(data.get("name") or _basename(path))
    short = name.rsplit("/", 1)[-1]
    description = _description(data)
    line = _find_line(text, '"name"')
    launches: list[dict[str, Any]] = []
    for package in data.get("packages") or []:
        if isinstance(package, dict):
            command, args, pinned = _registry_launch(package)
            pkg = _text_or_none(package.get("name")) or ""
            launches.append(
                {"command": command, "args": args, "pinned": pinned, "legs_text": f"{short} {pkg}"}
            )
    for remote in data.get("remotes") or []:
        if isinstance(remote, dict):
            launches.append(
                {
                    "url": _text_or_none(remote.get("url")),
                    "kind": remote.get("transport_type") or remote.get("type"),
                    "legs_text": short,
                }
            )
    if not launches:
        launches.append({"legs_text": short})
    return [
        _server(
            name=name,
            path=path,
            host="registry",
            text=text,
            description=description if index == 0 else None,
            line=line,
            **launch,
        )
        for index, launch in enumerate(launches)
    ]


def _parse_smithery(path: str, text: str, data: dict[str, Any]) -> list[McpServer]:
    start = data.get("startCommand")
    start = start if isinstance(start, dict) else {}
    return [
        _server(
            name=str(data.get("name") or "smithery"),
            path=path,
            host="smithery",
            text=text,
            command=_text_or_none(start.get("command")),
            args=_str_list(start.get("args")),
            url=_text_or_none(start.get("url")),
            kind=start.get("type"),
            env=start.get("env"),
            description=_description(data),
            line=_find_line(text, "startCommand"),
        )
    ]


def parse_mcp_config(path: str, text: str, host: str) -> list[McpServer]:
    """MCP servers declared in a host, registry or smithery config; [] when unparsable.

    `host` is one of claude, cursor, vscode, gemini, codex, claude_desktop, registry,
    smithery (the keys of `MCP_CONFIG_FILES`). Registry manifests (`server.json`) yield
    one record per package and per remote; the description and tool descriptions are
    attached to the first so a description finding is reported once.
    """
    data = _load_mapping(path, text)
    if data is None:
        return []
    if host == "registry":
        return _parse_registry(path, text, data)
    if host == "smithery":
        return _parse_smithery(path, text, data)
    return _parse_host_servers(path, text, host, data)


# ---------------------------------------------------------------------------
# Host settings
# ---------------------------------------------------------------------------


def _table_rows(host: str, key: str) -> list[tuple[str, re.Pattern]]:
    return [(k, rx) for k, rx in HOST_OVERGRANT.get(host, []) if k == key]


def _unsafe_key(command: str) -> str | None:
    for key, rx in UNSAFE_HOOK_PATTERNS:
        if rx.search(command):
            return key
    return None


def _hook_commands(hooks: Any, text: str) -> list[HookCommand]:
    out: list[HookCommand] = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            entries: list[Any] = [group]
            nested = group.get("hooks")
            if isinstance(nested, list):
                entries.extend(item for item in nested if isinstance(item, dict))
            for entry in entries:
                command = entry.get("command")
                if not isinstance(command, str) or not command.strip():
                    continue
                line = _find_line_any(text, (json.dumps(command)[1:-1], command))
                out.append(HookCommand(str(event), command, line, _unsafe_key(command)))
    return out


def parse_claude_settings(path: str, text: str) -> HostRecord:
    """`.claude/settings*.json`: permission over-grants, defaultMode and hook commands."""
    record = HostRecord(host="claude", file=_posix(path))
    data = _load_mapping(path, text)
    if data is None:
        return record
    permissions = data.get("permissions")
    permissions = permissions if isinstance(permissions, dict) else {}
    critical_rows = _table_rows("claude", "permissions.allow")
    for entry in _str_list(permissions.get("allow")):
        line = _find_line(text, json.dumps(entry))
        if any(rx.search(entry) for _key, rx in critical_rows):
            record.over_grants.append(OverGrant("permissions.allow", entry, "critical", None, line))
        elif any(rx.search(entry) for _key, rx in HOST_OVERGRANT_INTERPRETER):
            record.over_grants.append(
                OverGrant("permissions.allow", entry, "medium", "interpreter", line)
            )
    mode = permissions.get("defaultMode")
    if isinstance(mode, str):
        record.default_mode = mode
        if any(rx.search(mode) for _key, rx in _table_rows("claude", "permissions.defaultMode")):
            line = _find_line(text, json.dumps(mode))
            record.over_grants.append(
                OverGrant("permissions.defaultMode", mode, "critical", None, line)
            )
    record.hooks = _hook_commands(data.get("hooks"), text)
    return record


def _codex_grants(prefix: str, block: dict[str, Any], text: str) -> list[OverGrant]:
    out: list[OverGrant] = []
    for key, rx in HOST_OVERGRANT["codex"]:
        value = block.get(key)
        if isinstance(value, str) and rx.search(value):
            line = _find_line_any(text, (f'{key} = "{value}"', f"{key} = '{value}'", key))
            out.append(OverGrant(prefix + key, value, "critical", None, line))
    return out


def parse_codex_config(path: str, text: str) -> tuple[HostRecord, list[McpServer]]:
    """`.codex/config.toml`: approval_policy, sandbox_mode (top level and per profile)."""
    record = HostRecord(host="codex", file=_posix(path))
    data = _load_mapping(path, text)
    if data is None:
        return record, []
    policy = data.get("approval_policy")
    sandbox = data.get("sandbox_mode")
    record.approval_policy = policy if isinstance(policy, str) else None
    record.sandbox_mode = sandbox if isinstance(sandbox, str) else None
    record.over_grants.extend(_codex_grants("", data, text))
    profiles = data.get("profiles")
    if isinstance(profiles, dict):
        for name, profile in profiles.items():
            if isinstance(profile, dict):
                record.over_grants.extend(_codex_grants(f"profiles.{name}.", profile, text))
    return record, _parse_host_servers(path, text, "codex", data)


def _walk_flags(data: Any, host: str, text: str, prefix: str = "") -> list[OverGrant]:
    """Match every (nested) key of `data` against the host's boolean over-grant rows."""
    out: list[OverGrant] = []
    if not isinstance(data, dict):
        return out
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            out.extend(_walk_flags(value, host, text, dotted + "."))
            continue
        if isinstance(value, (bool, str)):
            rendered = str(value).lower() if isinstance(value, bool) else value
            for row_key, rx in HOST_OVERGRANT.get(host, []):
                if row_key == key and rx.search(rendered):
                    line = _find_line_any(text, (f'"{key}"', f"{key}:"))
                    out.append(OverGrant(dotted, rendered, "critical", None, line))
    return out


def parse_cursor(path: str, text: str) -> HostRecord:
    """`.cursor/settings.json` flags, or the literal table over `.cursor/rules/*.mdc`."""
    record = HostRecord(host="cursor", file=_posix(path))
    if _format_for(path) == "json":
        data = _load_mapping(path, text)
        if data is not None:
            record.over_grants = _walk_flags(data, "cursor", text)
        return record
    record.over_grants = parse_literals(path, text, is_doc=True)
    return record


def parse_gemini(path: str, text: str) -> tuple[HostRecord, list[McpServer]]:
    """`.gemini/settings.json`: autoAccept / sandbox flags plus `mcpServers`."""
    record = HostRecord(host="gemini", file=_posix(path))
    data = _load_mapping(path, text)
    if data is None:
        return record, []
    record.over_grants = _walk_flags(data, "gemini", text)
    return record, _parse_host_servers(path, text, "gemini", data)


def parse_literals(path: str, text: str, is_doc: bool) -> list[OverGrant]:
    """The `HOST_OVERGRANT["*"]` literals over any text file.

    Scripts, CI, Dockerfiles and hooks: critical. Docs (`is_doc=True`): low with
    `sub="docs"`, and `is_mention` sets `mention` per hit -- a mention is still returned,
    never dropped, because the finding stays observable.
    """
    out: list[OverGrant] = []
    rows = HOST_OVERGRANT["*"]
    for number, line in enumerate(text.splitlines(), 1):
        for key, rx in rows:
            for match in rx.finditer(line):
                mention = is_doc and is_mention(line, match.start(), match.end())
                out.append(
                    OverGrant(
                        key=key,
                        value=match.group(0),
                        severity="low" if is_doc else "critical",
                        sub="docs" if is_doc else None,
                        line=number,
                        mention=mention,
                    )
                )
    return out


# ---------------------------------------------------------------------------
# CI workflows
# ---------------------------------------------------------------------------

_GITLAB_SCRIPT_KEYS = ("script", "before_script", "after_script")


def _flatten_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten_strings(item)


def _ci_strings(path: str, data: dict[str, Any]) -> Iterator[str]:
    name = _basename(path).lower()
    if name == ".pre-commit-config.yaml" or "repos" in data:
        for repo in data.get("repos") or []:
            if not isinstance(repo, dict) or str(repo.get("repo", "")).lower() != "local":
                continue
            for hook in repo.get("hooks") or []:
                if isinstance(hook, dict):
                    parts = [str(hook.get("entry", ""))] + list(_flatten_strings(hook.get("args")))
                    yield " ".join(part for part in parts if part)
        return
    jobs = data.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if isinstance(step, dict):
                    yield from _flatten_strings(step.get("run"))
        return
    for key, job in data.items():
        if not isinstance(job, dict):
            continue
        for script_key in _GITLAB_SCRIPT_KEYS:
            yield from _flatten_strings(job.get(script_key))


def parse_ci_workflow(path: str, text: str) -> CiRecord:
    """Unsafe commands in GitHub workflow `run:` blocks, GitLab scripts, local pre-commit hooks.

    Each string is matched against `UNSAFE_HOOK_PATTERNS`; the recorded line is the line
    of the matching text within the file, found by searching the raw text for it. One
    step per (line, snippet): the first matching pattern key wins, as for hooks.
    """
    record = CiRecord(file=_posix(path))
    data = _load_mapping(path, text)
    if data is None:
        return record
    seen: set[tuple[int | None, str]] = set()
    for block in _ci_strings(path, data):
        for key, rx in UNSAFE_HOOK_PATTERNS:
            for match in rx.finditer(block):
                snippet_line = block[: match.start()].rsplit("\n", 1)[-1]
                snippet_line += block[match.start() :].split("\n", 1)[0]
                snippet = snippet_line.strip()
                line = _find_line(text, snippet)
                if line is None:
                    line = _find_line(text, match.group(0))
                if (line, snippet) not in seen:
                    seen.add((line, snippet))
                    record.unsafe_steps.append((line, key, snippet))
    return record


# ---------------------------------------------------------------------------
# Env bindings
# ---------------------------------------------------------------------------

_DOTENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=(.*)$")


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_dotenv(path: str, text: str) -> list[EnvBinding]:
    out: list[EnvBinding] = []
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DOTENV_LINE_RE.match(raw)
        if not match:
            continue
        name, value = match.group(1), match.group(2)
        if " #" in value and not value.strip().startswith(("'", '"')):
            value = value.split(" #", 1)[0]
        out.append(EnvBinding(_posix(path), name, number, _is_env_literal(_unquote(value))))
    return out


def _env_line(text: str, name: str) -> int | None:
    pattern = re.compile(r"^\s*(?:-\s*)?['\"]?" + re.escape(name) + r"['\"]?\s*(?:[=:]|$)")
    for number, line in enumerate(text.splitlines(), 1):
        if pattern.match(line):
            return number
    return None


def _compose_bindings(path: str, text: str, environment: Any) -> Iterator[EnvBinding]:
    if isinstance(environment, dict):
        for name, value in environment.items():
            rendered = "" if value is None else str(value)
            yield EnvBinding(
                _posix(path), str(name), _env_line(text, str(name)), _is_env_literal(rendered)
            )
    elif isinstance(environment, list):
        for item in environment:
            if not isinstance(item, str):
                continue
            name, sep, value = item.partition("=")
            name = name.strip()
            if not name:
                continue
            literal = bool(sep) and _is_env_literal(_unquote(value))
            yield EnvBinding(_posix(path), name, _env_line(text, name), literal)


def parse_compose_env(path: str, text: str) -> list[EnvBinding]:
    """Env var names bound in a `.env*` file or a docker-compose `environment:` block.

    `literal` is True when the value is non-empty, not a `${...}`/`$VAR`/`<...>`
    reference and not a `SECRET_PLACEHOLDERS` match. Values are never returned.
    """
    if ENV_FILE_RE.match(_basename(path)):
        return _parse_dotenv(path, text)
    data = _load_mapping(path, text)
    if data is None:
        return []
    out: list[EnvBinding] = []
    services = data.get("services")
    blocks = list(services.values()) if isinstance(services, dict) else [data]
    for block in blocks:
        if isinstance(block, dict):
            out.extend(_compose_bindings(path, text, block.get("environment")))
    return out


# ---------------------------------------------------------------------------
# Agent frontmatter
# ---------------------------------------------------------------------------


def parse_agent_frontmatter(path: str, text: str) -> dict[str, Any]:
    """YAML frontmatter of a `.claude/agents/*.md` file; {} when absent or invalid.

    `tools` is normalised to a list of str (a comma-separated string is split).
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = next((i for i, line in enumerate(lines[1:], 1) if line.strip() in ("---", "...")), None)
    if end is None:
        return {}
    try:
        data = yaml.safe_load("\n".join(lines[1:end]))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out = dict(data)
    if "tools" in out:
        tools = out["tools"]
        if isinstance(tools, str):
            out["tools"] = [part.strip() for part in tools.split(",") if part.strip()]
        elif isinstance(tools, (list, tuple)):
            out["tools"] = [str(item).strip() for item in tools if item is not None]
        else:
            out["tools"] = []
    return out


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


def home_config_paths(home: Path | None = None, platform: str | None = None) -> list[Path]:
    """Host-global config locations. Pure computation: nothing is opened or stat'ed.

    Only read when `--include-home` is given; off by default so CI never sees a
    developer's global settings.
    """
    base = Path.home() if home is None else home
    system = sys.platform if platform is None else platform
    if system.startswith("win"):
        appdata = os.environ.get("APPDATA")
        desktop = Path(appdata) if appdata else base / "AppData" / "Roaming"
        desktop = desktop / "Claude"
    elif system == "darwin":
        desktop = base / "Library" / "Application Support" / "Claude"
    else:
        desktop = base / ".config" / "Claude"
    return [
        base / ".claude" / "settings.json",
        base / ".codex" / "config.toml",
        desktop / "claude_desktop_config.json",
    ]


def config_kind(relpath: str) -> tuple[str, str] | None:
    """(host, table) for a config path, table being "host" or "mcp"; None otherwise.

    `HOST_CONFIG_FILES` is checked first: `.codex/config.toml` and `.gemini/settings.json`
    appear in both tables and their host parsers return the MCP servers as well.
    """
    posix = _posix(relpath)
    for host, rx in HOST_CONFIG_FILES:
        if rx.search(posix):
            return host, "host"
    for host, rx in MCP_CONFIG_FILES:
        if rx.search(posix):
            return host, "mcp"
    return None
