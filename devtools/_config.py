"""
devtools/_config.py
-------------------
Load CLI defaults from the ``[tool.euaiact-lint]`` and
``[tool.misalignment-check]`` sections of ``pyproject.toml``.

Values loaded here are *defaults*: they are applied via
``ArgumentParser.set_defaults()`` before ``parse_args()``, so an explicit
command-line flag always wins.

Caveat: the boolean options are ``store_true`` flags with no ``--no-*``
counterpart, so setting one to ``true`` in ``pyproject.toml`` cannot be
switched back off from the command line.

Degrades to ``{}`` (pure argparse defaults) when no ``pyproject.toml`` is
found, when it cannot be parsed, or on Python 3.10 without ``tomli``
installed -- ``tomllib`` is stdlib only from 3.11.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


# Options argparse stores as a comma-separated string, but which are more
# naturally written as a list in TOML.
_LIST_AS_CSV = frozenset({"exclude", "rules"})


def find_pyproject(start: Path | None = None) -> Path | None:
    """Walk upward from `start` (default: cwd) looking for pyproject.toml."""
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / "pyproject.toml"
        if candidate.is_file():
            return candidate
    return None


def load_tool_config(section: str, start: Path | None = None) -> dict[str, Any]:
    """Return the ``[tool.<section>]`` table as argparse-shaped defaults."""
    if tomllib is None:
        return {}

    path = find_pyproject(start)
    if path is None:
        return {}

    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, ValueError):
        return {}

    table = (data.get("tool") or {}).get(section)
    if not isinstance(table, dict):
        return {}

    resolved: dict[str, Any] = {}
    for key, value in table.items():
        dest = key.replace("-", "_")
        if dest in _LIST_AS_CSV and isinstance(value, list):
            value = ",".join(str(item) for item in value)
        resolved[dest] = value
    return resolved


def apply_tool_config(parser, section: str, start: Path | None = None) -> dict[str, Any]:
    """
    Apply ``[tool.<section>]`` defaults to `parser`, ignoring any key that is
    not an option on this parser. Returns what was actually applied.
    """
    config = load_tool_config(section, start)
    known = {action.dest for action in parser._actions}
    applied = {key: value for key, value in config.items() if key in known}
    if applied:
        parser.set_defaults(**applied)
    return applied
