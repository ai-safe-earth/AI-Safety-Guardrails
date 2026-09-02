"""tests/test_calc.py
------------------
Arithmetic helpers behave.
"""

from __future__ import annotations

import pytest
from pkg import add, divide, multiply


def test_add() -> None:
    assert add(2, 3) == 5


def test_multiply() -> None:
    assert multiply(4, 2.5) == 10


def test_divide_by_zero_raises() -> None:
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)
