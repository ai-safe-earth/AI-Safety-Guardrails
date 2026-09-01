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
