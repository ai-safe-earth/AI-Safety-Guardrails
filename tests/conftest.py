"""
tests/conftest.py
-----------------
Put `src/` on sys.path so the suite runs against the working tree without
requiring an install. An editable install (`pip install -e .`) also works --
this simply makes the uninstalled case deterministic rather than relying on
whichever test module happened to import first.
"""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# ---------------------------------------------------------------------------
# `aisg audit` fixtures: tests/fixtures/audit/<name>
# ---------------------------------------------------------------------------

import shutil
from collections.abc import Callable

import pytest

AUDIT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "audit"


@pytest.fixture
def audit_fixture() -> Callable[[str], Path]:
    """Real, read-only path to `tests/fixtures/audit/<name>`."""
    return lambda name: AUDIT_FIXTURES / name


@pytest.fixture
def py_agent(tmp_path: Path) -> Path:
    """
    A scratch copy of the `py_agent` fixture with `secrets.py` added.

    The committed tree holds no secret-shaped literal; the two below are
    assembled at runtime so the repo never contains one.
    """
    target = tmp_path / "py_agent"
    shutil.copytree(AUDIT_FIXTURES / "py_agent", target)
    anthropic_key = "sk-ant-" + "api03-" + "x" * 40
    aws_key = "AKIA" + "Q" * 16
    (target / "secrets.py").write_text(
        f'ANTHROPIC_API_KEY = "{anthropic_key}"\nAWS_ACCESS_KEY_ID = "{aws_key}"\n',
        encoding="utf-8",
    )
    return target
