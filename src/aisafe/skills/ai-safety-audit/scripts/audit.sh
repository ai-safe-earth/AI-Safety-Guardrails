#!/bin/sh
# aisafe-audit: ignore-file
# ai-safety-audit bootstrap: run `aisafe audit` through a pinned install chain, and say on
# stderr which aisafe ran (path and version, against the pin) before it runs.
set -eu
AISAFE_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if command -v aisafe >/dev/null 2>&1; then
  v=$(aisafe --version 2>/dev/null | sed 's/^aisafe //' || true); [ -n "$v" ] || v=unknown
  echo "aisafe: $(command -v aisafe) version $v (pinned $AISAFE_VERSION)" >&2
  exec aisafe audit "$@"
elif command -v uvx >/dev/null 2>&1; then
  echo "aisafe: uvx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)" >&2
  exec uvx --from "aisafe==$AISAFE_VERSION" aisafe audit "$@"
elif command -v pipx >/dev/null 2>&1; then
  echo "aisafe: pipx aisafe==$AISAFE_VERSION (pinned $AISAFE_VERSION)" >&2
  exec pipx run --spec "aisafe==$AISAFE_VERSION" aisafe audit "$@"
else
  echo "aisafe not found. Install one of:" >&2
  echo "  uv tool install 'aisafe==$AISAFE_VERSION'   (uv works without a pre-installed Python)" >&2
  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    echo "  pipx install 'aisafe==$AISAFE_VERSION'" >&2
    echo "  pip install 'aisafe==$AISAFE_VERSION'" >&2
  else
    echo "  (no python3/python on PATH: install uv first, e.g. https://docs.astral.sh/uv/getting-started/installation/)" >&2
  fi
  exit 2
fi
