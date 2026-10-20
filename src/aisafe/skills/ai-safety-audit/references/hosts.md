# Where this skill lives on each host

`aisafe skill install` copies the packaged `ai-safety-audit/` folder into the directory an
agent host reads skills from. The table records what was found on each vendor page when the
package was built; `aisafe skill list` prints the current flag and URL for the installed
version.

| host | project dir | global dir | verified | source |
|---|---|---|---|---|
| `claude` | `.claude/skills/` | `~/.claude/skills/` | yes | https://code.claude.com/docs/en/skills |
| `agents` | `.agents/skills/` | `~/.agents/skills/` | yes | https://agentskills.io/client-implementation/adding-skills-support |
| `codex` | `.agents/skills/` (alias of `agents`) | `~/.codex/skills/` | no | https://learn.chatgpt.com/docs/build-skills |
| `cursor` | `.cursor/skills/` | `~/.cursor/skills/` | yes | https://cursor.com/docs/context/skills |
| `gemini` | `.gemini/skills/` | `~/.gemini/skills/` | yes | https://geminicli.com/docs/cli/skills/ |
| `antigravity` | `.agents/skills/` | `~/.agents/skills/` | no | (none) |

"verified" means: as recorded at build time, the `source` page stated that directory.
`aisafe skill list` shows the current flag. A host marked `no` prints a note on install
saying the location was not verified against vendor documentation; `codex` in particular
prints its resolved destination, because the vendor page (the design-time URL
`developers.openai.com/codex/skills` redirects to it) names `.agents/skills` for
repository skills and `~/.agents/skills` for user-level skills without mentioning
`~/.codex/skills`. Check the printed path against your own Codex layout.

## Hooks

`aisafe hook install --host <name>` writes this adapter's entries into the host's hook
configuration (it prints the diff and writes only with `--yes` or an interactive yes: those
files are protected paths) and copies the pinned bootstrap `scripts/hook.sh` / `hook.ps1`
next to it. `aisafe hook list` prints the table for the installed version. In the skill's
closing step the install is offered by name only: the host's hook file is a protected
path (rule 4), so the user runs the command, reads the diff and answers yes themselves;
the skill never writes it for them.

| host | hook config (project) | events wired | ask | verified | source |
|---|---|---|---|---|---|
| `claude` | `.claude/settings.json` | PreToolUse (edits, Bash), PostToolUse (edits), SessionStart, Stop; UserPromptSubmit with `--policies prompt_injection` | yes | yes | https://code.claude.com/docs/en/hooks |
| `cursor` | `.cursor/hooks.json` | beforeShellExecution, beforeMCPExecution, afterFileEdit, stop; beforeSubmitPrompt with the prompt policy | yes | yes | https://cursor.com/docs/agent/hooks |
| `gemini` | `.gemini/settings.json` | BeforeTool (`write_file`, `replace`, `run_shell_command`), AfterTool (`write_file`, `replace`), SessionStart | no | yes | https://geminicli.com/docs/hooks/reference/ |
| `codex` | `.codex/config.toml` | none: command hooks are not documented for the Codex CLI; `install` prints this and writes nothing | no | no | https://developers.openai.com/codex/config-reference |

What the hooks decide, on every host that has the event: a secret-shaped literal about to be
written is denied; an edit to a protected path (host permission file, CI workflow, `.env*`,
`.secrets*`, `.pre-commit-config.yaml`) asks; `curl ... | sh`, `wget -O- ... | sh` and
plain-http `pip install` are denied; `npx -y`, a permission-bypass flag and a shell write to
a protected path ask; after an edit, `aisafe audit --only <file>` runs against the baseline and
new findings on that file become context; at Stop, a full audit against the baseline blocks
once when a new finding at or above `fail-on` appears. Cursor has no pre-edit event, so its
file checks are advisory and run after the edit; shell and MCP gating is enforced. Gemini
has no "ask", so an `ask` follows `[tool.aisafe-hook].ask-fallback` (`allow`, recorded, or
`deny`). The adapter fails OPEN on its own errors, records them in
`.aisafe-audit/hook-state.json` and says so at the next session start; it never calls a model,
never installs anything and never opens a socket.

The Claude Code plugin (`claude plugin marketplace add ai-safe-earth/AnyAISafe`,
then `claude plugin install ai-safety-audit@ai-safe-earth`) carries the same hooks in
`hooks/hooks.json` and this skill as `skills/ai-safety-audit/`, so no settings file is
edited at all.

## The `all` rule

`--host all` installs into `claude` and `agents` always, and into any other host only when
that host's directory already exists (`.cursor/` in the repo, or `~/.gemini/` with
`--global`). Installing into `.cursor/` on a machine that has never run Cursor litters the
repo. `--host all --force-all` installs everywhere regardless.

## Install commands

Project-local (the default; writes under the current repository):

    aisafe skill install --host claude
    aisafe skill install --host agents
    aisafe skill install --host all

Global (writes under the home directory):

    aisafe skill install --host claude --global

Without `aisafe` on PATH, through a pinned bootstrap (`<version>` is the `AISAFE_VERSION`
pinned in `scripts/audit.sh`; never leave it off):

    uvx --from 'aisafe==<version>' aisafe skill install --host all
    pipx run --spec 'aisafe==<version>' aisafe skill install --host all

Other verbs: `aisafe skill path` prints the packaged directory; `aisafe skill list` prints the
host table; `aisafe skill diff --host <x>` compares the installed copy with the packaged one
and exits 1 when they differ. `install` refuses to overwrite a differing copy without
`--force`; `--dry-run` prints what it would write.

## Frontmatter rule

`SKILL.md` frontmatter carries exactly two keys, `name` and `description`, and nothing else.
That is the intersection of what the hosts above accept; host-specific metadata goes in
`agents/openai.yaml`, which hosts that do not read it ignore. A test pins the key set.

## Bootstrap scripts

`scripts/audit.sh`, `audit.ps1`, `verify.sh`, `verify.ps1`, `hook.sh`, `hook.ps1`,
`attest.sh` and `attest.ps1` resolve `aisafe` in this order:
`aisafe` on PATH, else `uvx --from 'aisafe==<version>'`, else
`pipx run --spec 'aisafe==<version>'`. `aisafe` is the distribution, the importable name
and the console script; on PyPI the unrelated `aisafeguard` also installs an `aisafe`
command, so `audit.sh` and `attest.sh` say which one ran and `hook.sh` fails open when
the one it found rejects `hook run`. The version is pinned to the package
that shipped the scripts and a test asserts it equals `pyproject.toml`; an unpinned bootstrap
is what AUD-602 flags in targets, and the skill does not get an exception. When none of the
three is available, `audit.sh` exits 2 with install hints, `verify.sh` prints
`measure skipped: aisafe not importable in target`, and `hook.sh` exits 0 with
`hook skipped` on stderr: a hook is a gate on someone else's editor and fails open.
`audit.sh` / `audit.ps1` and `attest.sh` / `attest.ps1` print one line on stderr before
running, `aisafe: <path> version <version> (pinned <version>)` (or `aisafe: uvx
aisafe==<version> ...`), so the conversation records which aisafe ran; when the version
differs from the pin, stop and say so before reading any result.
