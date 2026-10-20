#!/bin/sh
# aisafe-audit: ignore-file
# ai-safety-audit hook bootstrap: run `aisafe hook` through a pinned install chain. The host's
# JSON payload on stdin passes through untouched; a missing aisafe fails OPEN (exit 0).
set -eu
AISAFE_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if command -v aisafe >/dev/null 2>&1; then
  # `aisafe hook run` exits 0 on every path, its own errors included. Any other status means
  # the `aisafe` on PATH is not this project's (PyPI's `aisafeguard` installs one too, and its
  # usage error exits 2, which Claude Code reads as a block): fail open and say which ran.
  rc=0; aisafe hook "$@" --origin "path:$(command -v aisafe)" --expect-version "$AISAFE_VERSION" || rc=$?
  if [ "$rc" -eq 0 ] || [ "${1:-}" != run ]; then exit "$rc"; fi
  echo "aisafe-hook: $(command -v aisafe) exited $rc (not this project's aisafe?); hook skipped" >&2
  case " $* " in *" --host cursor "*) printf '%s\n' '{"permission":"allow"}' ;; esac
  exit 0
elif command -v uvx >/dev/null 2>&1; then exec uvx --from "aisafe==$AISAFE_VERSION" aisafe hook "$@" --origin uvx --expect-version "$AISAFE_VERSION"
elif command -v pipx >/dev/null 2>&1; then exec pipx run --spec "aisafe==$AISAFE_VERSION" aisafe hook "$@" --origin pipx --expect-version "$AISAFE_VERSION"
else
  # A hook is a gate on someone else's editor: say so on stderr, let the action through.
  # Cursor reads an empty answer to a permission hook as a block, so give it an allow.
  echo "aisafe-hook: aisafe not found (install 'aisafe==$AISAFE_VERSION'); hook skipped" >&2
  case " $* " in *" --host cursor "*) printf '%s\n' '{"permission":"allow"}' ;; esac
  exit 0
fi
