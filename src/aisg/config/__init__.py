"""
src/aisg/config/__init__.py
---------------------------
Packaged configuration presets.

The YAML presets ship as package data, so they are readable from an installed
wheel via importlib.resources -- not just from a source checkout. A copy is
also kept at the repo-root `config/` directory for local development; the two
are identical.

    from aisg.config import preset_path, load_preset

    GuardrailPipeline.from_config(preset_path("default.yaml"))
    text = load_preset("eu_high_risk.yaml")
"""

from __future__ import annotations

from contextlib import ExitStack
from importlib import resources
from pathlib import Path

__all__ = ["PRESETS", "preset_path", "load_preset"]

PRESETS = ("default.yaml", "eu_high_risk.yaml")

# Keeps extracted resources alive for the process lifetime. Needed when the
# package is loaded from a zip, where as_file() materialises a temp copy.
_FILES = ExitStack()


def preset_path(name: str) -> Path:
    """
    Filesystem path to a packaged preset (e.g. "default.yaml", or
    "nemo_rails/config.yml"). Works from a wheel as well as a checkout.
    """
    resource = resources.files(__package__)
    for part in name.split("/"):
        resource = resource / part
    if not resource.is_file():
        raise FileNotFoundError(f"No packaged config named {name!r}")
    return _FILES.enter_context(resources.as_file(resource))


def load_preset(name: str) -> str:
    """Read a packaged preset as text."""
    resource = resources.files(__package__)
    for part in name.split("/"):
        resource = resource / part
    return resource.read_text(encoding="utf-8")
