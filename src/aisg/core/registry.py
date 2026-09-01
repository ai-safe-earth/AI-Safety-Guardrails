"""
core/registry.py
----------------
Global registry for guardrail classes, enabling config-driven loading.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Type

if TYPE_CHECKING:
    from aisg.core.base import GuardrailBase

REGISTRY: dict[str, Type["GuardrailBase"]] = {}


def register_guard(name: str) -> Callable:
    """Class decorator that registers a guardrail by name for config-driven loading."""

    def decorator(cls: Type["GuardrailBase"]) -> Type["GuardrailBase"]:
        REGISTRY[name] = cls
        return cls

    return decorator
