"""pkg/calc.py
-----------
Arithmetic on floats with an explicit zero-division guard.
"""

from __future__ import annotations


def add(left: float, right: float) -> float:
    return left + right


def multiply(left: float, right: float) -> float:
    return left * right


def divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        raise ZeroDivisionError("denominator must be non-zero")
    return numerator / denominator
