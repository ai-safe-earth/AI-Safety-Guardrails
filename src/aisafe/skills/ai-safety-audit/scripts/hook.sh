#!/bin/sh
# aisafe-audit: ignore-file
# ai-safety-audit hook bootstrap: run `aisafe hook` through a pinned install chain. The host's
# JSON payload on stdin passes through untouched; a missing aisafe fails OPEN (exit 0).
set -eu
AISAFE_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
HOOK_ARGS=" $* "; HOOK_VERB="${1:-}"
skip() {
  # A hook is a gate on someone else's editor: say why on stderr, let the action through.
  # Cursor reads an empty answer to a permission hook as a block, so give it an allow.
  echo "aisafe-hook: $1; hook skipped" >&2
  case "$HOOK_ARGS" in *" --host cursor "*) printf '%s\n' '{"permission":"allow"}' ;; esac
  exit 0
}
if command -v aisafe >/dev/null 2>&1; then
  launcher="$(command -v aisafe)"; origin="path:$launcher"; set -- aisafe hook "$@"
elif command -v uvx >/dev/null 2>&1; then
  launcher=uvx; origin=uvx; set -- uvx --from "aisafe==$AISAFE_VERSION" aisafe hook "$@"
elif command -v pipx >/dev/null 2>&1; then
  launcher=pipx; origin=pipx; set -- pipx run --spec "aisafe==$AISAFE_VERSION" aisafe hook "$@"
else
  skip "aisafe not found (install 'aisafe==$AISAFE_VERSION')"
fi
# `aisafe hook run` exits 0 on every path, its own errors included. Any other status means it
# never ran: the `aisafe` on PATH is not this project's (PyPI's `aisafeguard` installs one too,
# and its usage error exits 2, which Claude Code reads as a block), or uvx/pipx could not fetch
# the pinned release (offline, index down). Fail open and say which launcher failed.
rc=0; "$@" --origin "$origin" --expect-version "$AISAFE_VERSION" || rc=$?
if [ "$rc" -eq 0 ] || [ "$HOOK_VERB" != run ]; then exit "$rc"; fi
skip "$launcher exited $rc (not this project's aisafe, or the pinned release could not be fetched)"
