#!/bin/sh
# aisg-audit: ignore-file
# ai-safety-audit bootstrap: run `aisg audit` through a pinned install chain, and say on
# stderr which aisg ran (path and version, against the pin) before it runs.
set -eu
AISG_VERSION="0.1.0"   # pinned; test_skill_package.py asserts this equals pyproject.toml [project].version
if command -v aisg >/dev/null 2>&1; then
  v=$(aisg --version 2>/dev/null | sed 's/^aisg //' || true); [ -n "$v" ] || v=unknown
  echo "aisg: $(command -v aisg) version $v (pinned $AISG_VERSION)" >&2
  exec aisg audit "$@"
elif command -v uvx >/dev/null 2>&1; then
  echo "aisg: uvx aisguard==$AISG_VERSION (pinned $AISG_VERSION)" >&2
  exec uvx --from "aisguard==$AISG_VERSION" aisg audit "$@"
elif command -v pipx >/dev/null 2>&1; then
  echo "aisg: pipx aisguard==$AISG_VERSION (pinned $AISG_VERSION)" >&2
  exec pipx run --spec "aisguard==$AISG_VERSION" aisg audit "$@"
else
  echo "aisg not found. Install one of:" >&2
  echo "  uv tool install 'aisguard==$AISG_VERSION'   (uv works without a pre-installed Python)" >&2
  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    echo "  pipx install 'aisguard==$AISG_VERSION'" >&2
    echo "  pip install 'aisguard==$AISG_VERSION'" >&2
  else
    echo "  (no python3/python on PATH: install uv first, e.g. https://docs.astral.sh/uv/getting-started/installation/)" >&2
  fi
  exit 2
fi
