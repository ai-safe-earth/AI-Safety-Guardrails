# Security policy

## Reporting a vulnerability

Report privately through GitHub's vulnerability reporting for this repository:
https://github.com/ai-safe-earth/AI-Safety-Guardrails/security/advisories/new

Do not open a public issue for a vulnerability. There is no separate e-mail
address and no published response-time commitment; the advisory thread is the
only channel, and it is where you will hear back.

## Scope

- The `aisguard` distribution, imported as `aisg` (`aisg.core`, `aisg.modules`,
  `aisg.integrations`, `aisg.config`).
- The `aisg` command line: `lint`, `misalign`, `measure`, `probe`, `init`,
  `audit`, `skill`, `decide`, `hook`, `attest`.
- The `ai-safety-audit` skill and its bootstrap scripts
  (`src/aisg/skills/ai-safety-audit/scripts/` and the mirrors under
  `.claude/skills/`, `.agents/skills/` and `plugins/ai-safety-audit/skills/`).
- The agent-host hooks (`aisg hook`, the bootstrap `hook.sh` / `hook.ps1`) and
  the Claude Code plugin (`.claude-plugin/`, `plugins/ai-safety-audit/`).
- The CI surface: `action.yml`, `.pre-commit-hooks.yaml` and the GitLab job
  template `.gitlab-ci-euaiact.yml`.

A guard that misses an attack is a detection gap, not a vulnerability; report
those as ordinary issues with the payload, or add a case to the probe corpus.

## What to include

- The affected version (`pip show aisguard`) or commit.
- The command, config or input that triggers the problem, minimised.
- What happens and what you expected; a stack trace or report excerpt if any.
- Which external scanners were on `PATH`, if `aisg audit` is involved.

## How releases are published

A `vX.Y.Z` tag runs `.github/workflows/release.yml`: the suite, the self-audit
and `scripts/bump_version.py --check` gate it, the wheel and sdist are built, and
PyPI publishing uses trusted publishing (OpenID Connect) behind a GitHub
environment with a required reviewer. No long-lived PyPI credential exists in the
repository or its secrets. A release you cannot trace to a tag, a workflow run
and that approval is not one of ours.

## What the tooling sends

`aisg audit`, `aisg lint`, `aisg misalign`, `aisg decide`, `aisg attest` and
`aisg hook` never send anything anywhere: no model calls, no telemetry, no
network sockets from their processes; the hook's only child process is `git`,
and it writes only under `.aisg-audit/`. The only network use is
by external scanners you already installed, and each one is listed with its
`network` flag in every report. `aisg probe` sends its fixed payload corpus to
the URL you name and nothing else; non-loopback targets need
`--i-have-authorization`.
