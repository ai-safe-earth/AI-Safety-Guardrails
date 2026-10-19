#!/bin/sh
# aisg-audit: ignore-file
# ai-safety-audit hook bootstrap: run `aisg hook` through a pinned install chain. The host's
# JSON payload on stdin passes through untouched; a missing aisg fails OPEN (exit 0).
set -eu
AISG_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if command -v aisg >/dev/null 2>&1; then exec aisg hook "$@" --origin "path:$(command -v aisg)" --expect-version "$AISG_VERSION"
elif command -v uvx >/dev/null 2>&1; then exec uvx --from "anyaisafe==$AISG_VERSION" aisg hook "$@" --origin uvx --expect-version "$AISG_VERSION"
elif command -v pipx >/dev/null 2>&1; then exec pipx run --spec "anyaisafe==$AISG_VERSION" aisg hook "$@" --origin pipx --expect-version "$AISG_VERSION"
else
  # A hook is a gate on someone else's editor: say so on stderr, let the action through.
  # Cursor reads an empty answer to a permission hook as a block, so give it an allow.
  echo "aisg-hook: aisg not found (install 'anyaisafe==$AISG_VERSION'); hook skipped" >&2
  case " $* " in *" --host cursor "*) printf '%s\n' '{"permission":"allow"}' ;; esac
  exit 0
fi
