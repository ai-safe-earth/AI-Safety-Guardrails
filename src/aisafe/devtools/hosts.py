"""aisafe/devtools/hosts.py
----------------------
The agent hosts this package knows: where each reads skills from (`aisafe skill install`)
and, for the hosts that run command hooks, where their hook configuration lives and which
events exist (`aisafe hook install`). One table, two consumers, so a host added here reaches
both.

Every `verified: True` row names the vendor page the location was read from; a row that
could not be verified keeps its URL and says so in `note`. `aisafe skill list` and
`aisafe hook list` print the flag, and `references/hosts.md` in the skill mirrors the table
(a test pins that every host and source URL appears there).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "ALWAYS_HOSTS",
    "HOOK_HOSTS",
    "HOSTS",
    "UNVERIFIED_NOTE",
    "Host",
    "HookSupport",
    "hook_hosts",
]

# Hosts `--host all` always installs the skill for; every other host only when its
# directory already exists (installing into `.cursor/` on a machine that never ran
# Cursor litters the repo).
ALWAYS_HOSTS = ("claude", "agents")

UNVERIFIED_NOTE = "location not verified against vendor documentation"


@dataclass(frozen=True)
class HookSupport:
    """
    How one host runs command hooks. `config_project` is the hook configuration file
    relative to the repository root, `config_global` the same relative to the home
    directory, both POSIX. `events` maps the adapter's own event kinds (`pre_tool`,
    `post_tool`, `session_start`, `prompt`, `stop`) to the host's event names; a kind the
    host has no event for is absent. `output` names the shape of what the host reads on
    stdout (see `aisafe.devtools.hook` for the exact envelopes). `ask` says whether the host
    has an "ask the user" primitive; without one the hook's `ask` falls back to the
    configured `ask-fallback`.
    """

    config_project: str
    config_global: str
    format: str  # json | toml
    events: dict[str, str]
    output: str  # claude | cursor | gemini | codex
    ask: bool
    verified: bool
    source: str
    note: str | None = None
    timeout_unit: str = "seconds"  # what the host's `timeout` field counts

    def __post_init__(self) -> None:
        if self.verified and not self.source:
            raise ValueError("hook support marked verified needs a source URL")


@dataclass(frozen=True)
class Host:
    """
    Where one agent host reads skills from. `project_dir` is relative to the
    target root, `global_dir` to the home directory, both POSIX. `source` is
    the vendor page the location was checked against; a `verified` host must
    carry one. `alias_of` marks a host that reads another host's project dir.
    `hooks` is None for a host that runs no command hooks (or whose hook surface
    this package does not speak).
    """

    name: str
    project_dir: str
    global_dir: str
    verified: bool
    source: str
    alias_of: str | None = None
    note: str | None = None
    hooks: HookSupport | None = None

    def __post_init__(self) -> None:
        if self.verified and not self.source:
            raise ValueError(f"host {self.name!r} is marked verified but has no source URL")

    def base_dir(self, global_: bool) -> str:
        return self.global_dir if global_ else self.project_dir


# Hook facts verified on 2026-10-19 against each `source` page. Claude Code: a
# `hooks` map of event -> [{matcher, hooks: [{type: command, command, timeout(s)}]}];
# PreToolUse answers with `hookSpecificOutput.permissionDecision` allow|deny|ask. Cursor:
# `.cursor/hooks.json` {"version": 1, "hooks": {event: [{command}]}}; permission hooks
# answer {"permission": allow|deny|ask}; exit 2 denies. Gemini CLI: `settings.json`
# `hooks` map of event -> [{matcher, hooks: [{type: command, command, timeout(ms)}]}];
# the answer is {"decision": allow|deny, "reason"}; there is no ask; exit 2 blocks with
# stderr as the reason, and stdout must be one JSON object or nothing. Codex: no vendor
# page documents command hooks for the CLI; the row is kept so `aisafe hook list` says so.
_CLAUDE_HOOKS = HookSupport(
    config_project=".claude/settings.json",
    config_global=".claude/settings.json",
    format="json",
    events={
        "pre_tool": "PreToolUse",
        "post_tool": "PostToolUse",
        "session_start": "SessionStart",
        "prompt": "UserPromptSubmit",
        "stop": "Stop",
    },
    output="claude",
    ask=True,
    verified=True,
    source="https://code.claude.com/docs/en/hooks",
)
_CURSOR_HOOKS = HookSupport(
    config_project=".cursor/hooks.json",
    config_global=".cursor/hooks.json",
    format="json",
    events={
        "pre_tool": "beforeShellExecution",
        "pre_mcp": "beforeMCPExecution",
        "post_tool": "afterFileEdit",
        "prompt": "beforeSubmitPrompt",
        "stop": "stop",
    },
    output="cursor",
    ask=True,
    verified=True,
    source="https://cursor.com/docs/agent/hooks",
    note=(
        "no pre-edit event: protected-path and secret-literal checks on file edits run "
        "after the edit and are advisory; shell and MCP gating is enforced"
    ),
)
_GEMINI_HOOKS = HookSupport(
    config_project=".gemini/settings.json",
    config_global=".gemini/settings.json",
    format="json",
    events={"pre_tool": "BeforeTool", "post_tool": "AfterTool", "session_start": "SessionStart"},
    output="gemini",
    ask=False,
    verified=True,
    source="https://geminicli.com/docs/hooks/reference/",
    note="no ask primitive: an `ask` decision follows [tool.aisafe-hook].ask-fallback",
    timeout_unit="milliseconds",
)
_CODEX_HOOKS = HookSupport(
    config_project=".codex/config.toml",
    config_global=".codex/config.toml",
    format="toml",
    events={},
    output="codex",
    ask=False,
    verified=False,
    source="https://developers.openai.com/codex/config-reference",
    note="command hooks are not documented for the Codex CLI; nothing is written",
)

# Verified at build time (2026-09-02, hooks 2026-10-19) by fetching each `source` page and
# reading the stated directories. Where a design-time URL now redirects permanently,
# `source` is the page that actually served the text. A `verified: False` row keeps its
# URL so `list` still shows where to look; `note` says what was found.
HOSTS: dict[str, Host] = {
    "claude": Host(
        name="claude",
        project_dir=".claude/skills",
        global_dir=".claude/skills",
        verified=True,
        source="https://code.claude.com/docs/en/skills",
        hooks=_CLAUDE_HOOKS,
    ),
    "agents": Host(
        name="agents",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=True,
        source="https://agentskills.io/client-implementation/adding-skills-support",
    ),
    "codex": Host(
        name="codex",
        project_dir=".agents/skills",
        global_dir=".codex/skills",
        verified=False,
        source="https://learn.chatgpt.com/docs/build-skills",
        alias_of="agents",
        note=(
            "could not be re-verified at build time: the vendor page "
            "(developers.openai.com/codex/skills redirects to it) names "
            ".agents/skills in the repo and $HOME/.agents/skills for user-level "
            "skills and does not mention ~/.codex/skills; check the printed "
            "destination against your Codex layout"
        ),
        hooks=_CODEX_HOOKS,
    ),
    "cursor": Host(
        name="cursor",
        project_dir=".cursor/skills",
        global_dir=".cursor/skills",
        verified=True,
        source="https://cursor.com/docs/context/skills",
        hooks=_CURSOR_HOOKS,
    ),
    "gemini": Host(
        name="gemini",
        project_dir=".gemini/skills",
        global_dir=".gemini/skills",
        verified=True,
        source="https://geminicli.com/docs/cli/skills/",
        hooks=_GEMINI_HOOKS,
    ),
    "antigravity": Host(
        name="antigravity",
        project_dir=".agents/skills",
        global_dir=".agents/skills",
        verified=False,
        source="",
        note=UNVERIFIED_NOTE,
    ),
}

# The hosts `aisafe hook` speaks, in the order `aisafe hook list` prints them.
HOOK_HOSTS: tuple[str, ...] = ("claude", "cursor", "gemini", "codex")


def hook_hosts() -> list[Host]:
    """Hosts that carry a `HookSupport`, in `HOOK_HOSTS` order."""
    return [HOSTS[name] for name in HOOK_HOSTS if HOSTS[name].hooks is not None]
