# ai-safety-audit (Claude Code plugin)

The `ai-safety-audit` skill plus the hooks that keep an agent session inside the audit's
rules. The skill copy under `skills/` is a byte-identical mirror of the canonical skill in
`src/aisg/skills/ai-safety-audit/`, kept in sync by `scripts/sync_skill.py`.

Install:

    claude plugin marketplace add ai-safe-earth/AnyAISafe
    claude plugin install ai-safety-audit@ai-safe-earth

What the hooks do (every command goes through the pinned bootstrap `scripts/hook.sh`, which
resolves `aisg` on PATH, else `uvx --from "anyaisafe==<version>"`, else `pipx run`; a missing
`aisg` fails OPEN and says so on stderr):

| event | what runs | answer |
|---|---|---|
| PreToolUse on Edit/Write/MultiEdit/NotebookEdit | secret-shaped literal -> deny; protected path (host permission, CI, secret file) -> ask | `permissionDecision` |
| PreToolUse on Bash | `curl ... \| sh`, plain-http pip -> deny; `npx -y`, a permission-bypass flag, a write to a protected path -> ask | `permissionDecision` |
| PostToolUse on an edit | `aisg audit --only <file>` against the baseline; new findings on that file become context | `additionalContext` |
| SessionStart | the last audit report's posture, or "no report yet" | plain text |
| Stop | full audit against the baseline; a new finding at or above `fail-on` blocks once | `decision: block` |

Nothing here calls a model, installs anything or opens a socket; the hook writes only under
`.aisg-audit/`. Defaults live in `[tool.aisg-hook]` of the project's `pyproject.toml`
(`aisg hook list` prints the host table). Findings describe evidence; neither the audit nor
the hooks state a compliance verdict.
