# CLAUDE.md

## Mission

AnyAISafe exists to make any software that uses AI safe and ethical. Every change to
this repository should serve that goal. How you get there is up to you: these are
principles, not a procedure. When a rule below gets in the way of the mission, the
mission wins. Say so, and say why.

"Safe and ethical" is open to interpretation. We settle it two ways:

- **AI-safety principles.** Prevent harm before it happens. Keep humans in control of
  actions that are hard to undo. Be honest about what is known and what is not. Respect
  privacy. Build for the worst case, not the demo.
- **Human interest first.** When a choice trades the interest of the people affected (the
  end users, the people an AI system decides about, the developers using this tool)
  against convenience, speed or our own metrics, the people win.

## What the repository is

One Python package, `aisafe` (project name AnyAISafe, repo
`github.com/ai-safe-earth/AnyAISafe`, published on PyPI). It has two halves:

- **Runtime guardrails** (`aisafe.core`, `aisafe.modules`, `aisafe.integrations`): guards
  that check what goes into a model, what tools it may call, and what comes out.
- **Developer tools** (`aisafe.devtools`, one command, `aisafe`): `audit` finds safety gaps
  in a codebase, worst damage first. `measure` scores each guard. `decide` prices the
  proposed controls. `attest` checks a level that a named person signs. `hook`, `fleet`,
  `probe`, `lint` and `misalign` do the rest.

The agent skill `ai-safety-audit` ships inside the package
(`src/aisafe/skills/ai-safety-audit/`). The Claude Code plugin `aisafe`
(`.claude-plugin/`, `plugins/aisafe/`) carries a copy of it. The full user reference is
`docs/REFERENCE.md`; the contributor guide is `CONTRIBUTING.md`.

## Principles we already settled

They came from real mistakes. Keep them unless you have evidence they are wrong.

- **Evidence, not verdicts.** The tool never says a system is compliant or safe. It says
  what it found, what it measured, and what it could not check. An empty report is not
  proof of safety.
- **Unknown stays unknown.** A missing measurement is `None` and shows as UNMEASURED. It
  is never shown as good, and never filled in by hand.
- **A guard is a trade.** Score it on harmless traffic as well as attacks. A guard that
  blocks the people it protects gets switched off, and then protects no one.
- **Deterministic devtools.** The audit and its tools call no model, install nothing and
  open no network socket. Same code, same findings.
- **People approve what cannot be undone.** Irreversible tool calls, permission files, CI
  and secrets change only with a person's approval. Nothing here pushes, tags or
  publishes on its own.
- **Do not make safety annoying.** Hooks fail open on their own bugs and record the error;
  a broken gate teaches people to bypass gates. The one exception: a secret about to be
  written into code is still denied.
- **Accountability has a name.** An accepted risk carries a reason. A level carries a
  named owner. A fingerprint with no reason is a suppression, not an acceptance.

## Working here

Run from the repo root. No install is needed for tests (`tests/conftest.py` puts `src/`
on the path). Without an install, `PYTHONPATH=src python -m aisafe.cli <command>` is the
command. On Windows set `PYTHONIOENCODING=utf-8`.

Before calling a change done:

```bash
pytest                                     # all LLM calls are mocked; no keys needed
ruff check <changed files> && ruff format <changed files>
aisafe audit . --no-external --fail-on high --baseline audit-baseline.json   # must exit 0
python scripts/sync_skill.py --check       # plugin's skill copy matches the packaged one
python scripts/bump_version.py --check     # every version site agrees
```

Things that are easy to break:

- Format labels stay as they are: `"schema": "aisg/1"`, `aisg_schema`, the `AISG_*`
  canaries. They name a document format that readers match, not the product.
- YAML presets exist twice on purpose: `src/aisafe/config/` ships in the wheel and
  `config/` is the local copy. Edit both; a test pins them equal.
- Generated files are regenerated, never hand-edited: `controls.md`
  (`scripts/controls_md.py`), `levels.md` (`scripts/levels_md.py`), and the plugin's
  skill copy (`scripts/sync_skill.py`). Edit the source, then run the script.
- A baseline reason must describe the evidence without quoting the text that triggered
  the finding, or the baseline reports itself.
- `aisafe measure` writes a report the next audit reads as evidence. Point `-o` outside
  the tree.

Style: ruff format, line length 100, `from __future__ import annotations`, a
`"""path/to/module.py\n---\n"""` docstring header on every module.

Git: commit straight to `main`. Tagging `vX.Y.Z` publishes to PyPI, so it is the
owner's act, never done unasked.

## Final responses

Applies only to the final message of a task. Not to code, commit messages, or plan files.

Style
- Plain English. Short sentences. Bullet points.
- No preamble, no recap of my request, no praise.

Structure: use these headings in this order. Omit any that would be empty.
1. **Decide**: choices only I can make. For each, give your recommendation and a one-line reason.
2. **Changes**: grouped by feature, most important first. For each, give one line on what changed and why, then the files touched. Show a code snippet only when the exact line matters.
3. **Watch out**: risks, side effects, shortcuts taken, anything untested or failing.
4. **Next**: logical next steps.

Learning
- When a term, concept, or tool is likely new to me, add a one-line explanation in [brackets] right after it.
  Example: "added debouncing [waits until typing stops before running]".
