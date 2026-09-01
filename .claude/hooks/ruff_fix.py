"""
.claude/hooks/ruff_fix.py
-------------------------
PostToolUse hook: run `ruff format` then `ruff check --fix` on the Python file
Claude just wrote or edited. Touched files only -- the tree is not lint-clean
repo-wide, so a broader run would bury the real diff.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    response = payload.get("tool_response") or {}
    tool_input = payload.get("tool_input") or {}
    path = response.get("filePath") or tool_input.get("file_path") or ""

    if not path.endswith(".py") or not os.path.isfile(path):
        return 0

    # tests/fixtures/ holds deliberately broken code used as linter input.
    if "/tests/fixtures/" in path.replace(os.sep, "/"):
        return 0

    for cmd in (["ruff", "format", path], ["ruff", "check", "--fix", path]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=30)
        except Exception:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
