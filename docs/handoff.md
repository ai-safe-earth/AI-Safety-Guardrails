# Handoff — the end-to-end skill run on VaiVia (2026-09-15)

Pick this up cold: read `docs/STATUS.md` first for the repository as a whole,
then this file for the walkthrough that is half-finished.

`main` is at `bbe722d`, pushed, CI green. Working tree clean.

## What this is

The five-phase `ai-safety-audit` skill was run end to end against a real
application — **VaiVia** (`github.com/ai-safe-earth/VaiVia`, commit `9cdceed`),
348 files, Python backend plus TypeScript frontend and gateway. Phases 1 and 2
are done, phase 3 is two rows into a plan of eleven, phases 4 and 5 have not
started.

The run was done on a **throwaway clone**, never on the user's checkout.

## Where the work lives

| what | where |
| --- | --- |
| the walkthrough's changes to VaiVia | below, in this file — see "The two changes" |
| document 1, as rendered in phase 2 | `docs/handoff/audit-before.html` |
| the rule fixes the run produced | committed to this repository, see below |

**The clone itself is gone or going.** It was at
`…\Temp\claude\…\scratchpad\vaivia`, a session temp directory. To resume:

```bash
git clone https://github.com/ai-safe-earth/VaiVia.git /some/scratch/vaivia
cd /some/scratch/vaivia && git checkout 9cdceed
# then re-apply the two changes below by hand
```

Nothing was committed or pushed to VaiVia, and nothing should be without the
user saying so. The two changes are the user's decisions, not suggestions: they
approved both in so many words.

**Why the diff is inlined here and not kept as a `.patch`.** It was, for about
ten minutes, and the self-audit caught it: a diff file is read as source, and
both its `-` and `+` lines count. The removed
`DATABASE_URL=postgresql://…:…@…` line raised a real AUD-106 against *this*
repository, and the added `os.environ.get("AGENT_DISABLED")` line was read as a
kill-switch read for our own root unit, silencing our own AUD-107. One imported
file both added a finding and hid one. A `.md` is classified as a doc, and doc
files are not scanned for secrets or kill-switch reads, so the diff is safe
here; the rendered html is safe because line 1 is the ignore marker and `walk`
skips it as own output. Do not commit another project's patches into this tree.

## The two changes

**1. `backend/api/routes/chat.py`** — the kill switch, approved in phase 3 row 2:

```python
# in the imports
import os

# after _sse()
# Values that mean "stopped". Read live from the environment on every request:
# `get_settings()` is lru_cache'd, so a switch behind it would need a restart to
# flip, and a switch you must restart to use is not a kill switch.
_DISABLED_VALUES = frozenset({"1", "true", "yes", "on"})


async def _disabled_stream() -> AsyncIterator[str]:
    """One SSE error event: no model call, no tool dispatch, no orchestrator."""
    yield _sse(
        ChatEvent(
            "error",
            {
                "error": "agent_disabled",
                "message": "The assistant is temporarily disabled.",
            },
        )
    )


# first statement of the chat() handler, before `state = http_request.app.state`
    if os.environ.get("AGENT_DISABLED", "").strip().lower() in _DISABLED_VALUES:
        return StreamingResponse(
            _disabled_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
```

**2. `.env.example`** — the user's policy: no real URL, user, password, database
name or port in the template; all of it arrives through `.env`, local
development included. Fifteen values became angle-bracket placeholders, keyed
by variable name so the old values need not be repeated here:

`NEO4J_URI`, `NEO4J_USER`, `NEO4J_DATABASE`, `POSTGIS_PORT`, `POSTGIS_DB`,
`POSTGIS_USER`, `POSTGIS_PASSWORD`, `PIPELINE_DATABASE_URL`, `SUPABASE_URL`,
`SUPABASE_JWT_JWKS_URL`, `GATEWAY_PORT`, `ALLOWED_ORIGINS`, `BACKEND_URL`,
`DATABASE_URL`, `NEXT_PUBLIC_GATEWAY_URL`.

Connection strings took the shape
`postgresql://<user>:<password>@<host>:<port>/<database>`. Left alone:
`GATEWAY_HOST` (a bind address, not a destination — the user did not include
it), values that were already placeholders, and the commented hosted examples.
Costs the user accepted: the file is no longer copy-and-run for local
development, and the comment above the Supabase block that says
"`supabase status` prints these" now precedes placeholders.

## The numbers

VaiVia's report over the session. Every reduction was a defect in the audit or
a control actually built — nothing was suppressed, nothing accepted.

| stage | findings | criticals |
| --- | --- | --- |
| first run | 71 | 50 |
| four false-positive fixes (`bc40862`) | 15 | 0 |
| row 1, AUD-106 comment fix (`90c7192`) | 12 | 0 |
| row 2, AUD-107 (`bbe722d`) + the kill switch | 10 | 0 |

## Commits this run produced (all in this repository)

| commit | what the run found |
| --- | --- |
| `bc40862` | Four false positives: `ssn` matched inside `className` so every JSX attribute was a critical secret (48 of the 50); `env(VAR)` read as a literal; a header *name* read as a credential; a price table read as seven unpinned deployments |
| `90c7192` | AUD-106: a credential *name* in a comment is documentation; a *value* in a comment is still a leak |
| `76b5111` | AUD-106: `<user>:<password>@` is not a credential on a live line either |
| `bbe722d` | AUD-107: a unit with no model call, ingress or tool has no request to gate |

## Phase 3 — the plan, and where it stopped

Rows are walked top-down, one approval each. Decision source is
`recommendation.package` in the JSON report, never the html prose.

**Done:**

1. **AUD-106** *Broad credentials in agent scope* — closed as **open work**, no
   acceptance recorded. Three of its four sites were comments (rule fixed). The
   fourth, `.env.example:70`, is real and cannot be closed by editing a file:
   it is raised by the config-facts tier, which reports the credential *name*
   declared in the agent's environment — its own note says "the value is not
   read". The control is a least-privilege Postgres role for the backend, which
   is work in VaiVia's deployment. Separately, the user applied a policy to
   `.env.example`: no real URL, user, password, database name or port; all 15
   such values are placeholders now (in the patch).
2. **AUD-107** *No kill switch* — **closed**. Unit `.` cleared by the rule fix
   (no request path). Unit `backend` cleared by a real control: a live
   `os.environ.get("AGENT_DISABLED")` read in `backend/api/routes/chat.py`
   before the orchestrator, returning one SSE error event. Live env read and
   not `settings.agent_disabled` because `get_settings()` is `lru_cache`d, and
   a switch that needs a restart to flip is not a switch.

**Limits of that kill switch, for document 2 — do not write them up as a win:**

- FastAPI resolves `db` and `user_id` *before* the handler body, so a database
  connection and a user lookup still happen while the switch is on.
- It gates the chat route only; `routing.py` and the rest of the unit are
  ungated. One recognised read clears the finding for a whole unit — a weakness
  of the rule, not evidence the unit is covered.
- Flipping an env var still means a restart in most deployments.
- The user has gateway middleware (`onRequest` hook in `gateway/src/app.ts`,
  beside auth, rate-limit and quota plugins). The edge is the better place for
  a switch that also stops the dependencies; `process.env.AGENT_DISABLED` there
  is recognised by the same rule. That is a second diff, unproposed.

**Remaining rows, in order:**

| row | rule | site | note |
| --- | --- | --- | --- |
| 3 | `AUD-504/print` | `backend/scripts/dump_conversation.py:131` | prints model output verbatim |
| 4 | `AUD-601/openai` | `.env.example:31` | `INTENT_MODEL=gpt-4o-mini`; may be stale after the placeholder pass — a model name, not a credential, so it was left |
| 5 | `AUD-601/openai` | `backend/core/config.py:77` | grouped, 4 sites |
| 6 | `AUD-601/anthropic` | `backend/scripts/cost_by_commit.py:67` | a comparison against an id in a cost script |
| 7-8 | `AUD-701` | units `.` and `backend` | **`same_control: true`** — the package wires this |
| 9 | `AUD-703` | unit `.` | no incident path |
| 10 | `AUD-901` | unit `.` | **`same_control: true`** — evals in CI |
| 11 | `AUD-1001` | unit `.` | no system card |

Rows 7-8 and 10 are the only ones where `aisg` itself wires the control. They
exercise the last untested branch of phase 3 — the package idiom in
`references/apply/python.md`, keyed by the first symbol — and are worth doing
before declaring the flow tested.

## Two decisions still unanswered from phase 2

- Whether `.aisg-audit/` should be committed in VaiVia or ignored. The skill
  proposes the one-line `.gitignore` diff and never edits it unasked.
- Which rows to defer. Default was top-down, which is what was walked.

## Phases 4 and 5, not started

Document 2 is `--baseline .aisg-audit/audit-baseline.json` into a *new* file,
never overwriting document 1. Phase 5 (tests, `aisg measure`, `aisg probe`)
needs explicit approval first: those can call model providers and cost money.

## What the run taught about the tooling itself

Worth fixing before anyone else runs this:

1. **The skill's bootstrap runs whatever `aisg` is on PATH.** Here that was a
   stale pipx install at `~/.local/bin/aisg.exe` reporting version `0.1.0` —
   the same version string as the source it was several commits behind — whose
   first act was to fail on a bug fixed the day before. The flow should print
   which `aisg` it used and from where. Everything above was run with
   `PYTHONPATH=…/src python -m aisg.cli` instead.
2. **Two findings can share one fingerprint** (normalisation strips digits from
   identifiers). Seen live: `.env.example` lines 70 and 73 collided, so when
   line 73 stopped being reported the baseline diff said two disappearances
   where three lines went quiet. A row can go quiet without the record saying
   so. Higher priority than it looked on paper.
3. **`AUD-602`, `AUD-605` and `AUD-106` still report per occurrence** — the
   grouping helper in `rules/__init__.py` applies unchanged.
4. One unexplained CI-free flake: a full suite run reported 31 failed / 115
   errors, and an immediate re-run was clean (3628 passed). It happened while a
   second pytest and several audits ran concurrently on Windows; the signature
   (errors, not assertion failures) points at fixture/temp collisions rather
   than a defect. Not reproduced since. Do not run two suites at once.
5. **A diff file is read as source, in both directions.** Committing another
   project's `.patch` into this tree raised a credential finding from a removed
   line and silenced one of our own findings from an added line. The audit is
   not wrong -- a `.patch` is text and nothing marks it as history -- but a rule
   that reads `-` lines as live code is worth a look, and until then the
   practice is: no foreign patches in the tree.

## How to verify from a cold start

```bash
pytest                                    # ~3630 tests, ~5 min, no API keys
ruff check src tests scripts
aisg lint src examples --errors-only
aisg audit . --no-external --fail-on high --baseline audit-baseline.json
python scripts/sync_skill.py --check
python scripts/controls_md.py --check
gh run list --limit 4
```
