# Security policy

## Reporting a vulnerability

Report privately through GitHub's vulnerability reporting for this repository:
https://github.com/ai-safe-earth/AI-Safety-Guardrails/security/advisories/new

Do not open a public issue for a vulnerability. There is no separate e-mail
address and no published response-time commitment; the advisory thread is the
only channel, and it is where you will hear back.

## Scope

- The `ai-safety-guardrails` package (`aisg.core`, `aisg.modules`,
  `aisg.integrations`, `aisg.config`).
- The `aisg` command line: `lint`, `misalign`, `measure`, `probe`, `init`,
  `audit`, `skill`.
- The `ai-safety-audit` skill and its bootstrap scripts
  (`src/aisg/skills/ai-safety-audit/scripts/` and the mirrors under
  `.claude/skills/` and `.agents/skills/`).

A guard that misses an attack is a detection gap, not a vulnerability; report
those as ordinary issues with the payload, or add a case to the probe corpus.

## What to include

- The affected version (`pip show ai-safety-guardrails`) or commit.
- The command, config or input that triggers the problem, minimised.
- What happens and what you expected; a stack trace or report excerpt if any.
- Which external scanners were on `PATH`, if `aisg audit` is involved.

## What the tooling sends

`aisg audit` and `aisg lint` never send anything anywhere: no model calls, no
telemetry, no network sockets from the audit process. The only network use is
by external scanners you already installed, and each one is listed with its
`network` flag in every report. `aisg probe` sends its fixed payload corpus to
the URL you name and nothing else; non-loopback targets need
`--i-have-authorization`.
