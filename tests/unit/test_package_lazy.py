"""tests/unit/test_package_lazy.py
--------------------------------
`import aisafe` must not pay for the OpenTelemetry SDK. The two observability classes
load on first attribute access (PEP 562); every other name in `__all__` stays eager
because the guards register themselves on import and the pipeline reads that registry.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

import aisafe

SRC = Path(aisafe.__file__).resolve().parents[1]


def _fresh_interpreter(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env
    )
    return result.stdout.strip()


def test_import_aisafe_leaves_observability_unimported() -> None:
    code = (
        "import sys, aisafe; "
        "print(sorted(m for m in sys.modules if m.startswith('aisafe.modules.observability')))"
    )
    assert _fresh_interpreter(code) == "[]"


def test_import_aisafe_still_registers_every_guard_the_presets_name() -> None:
    code = (
        "import aisafe; from aisafe.core.registry import REGISTRY; "
        "print(sorted(k for k in REGISTRY if k in "
        "{'pii_detector','prompt_injection','tool_policy','toxicity_output','eu_ai_act'}))"
    )
    assert _fresh_interpreter(code) == (
        "['eu_ai_act', 'pii_detector', 'prompt_injection', 'tool_policy', 'toxicity_output']"
    )


def test_lazy_attributes_resolve_to_the_real_classes_and_stick() -> None:
    from aisafe.modules.observability.audit_logger import AuditLogger
    from aisafe.modules.observability.otel import TelemetryProvider

    assert aisafe.TelemetryProvider is TelemetryProvider
    assert aisafe.AuditLogger is AuditLogger
    # Resolved once, then an ordinary module attribute.
    assert "TelemetryProvider" in vars(aisafe)


def test_lazy_names_stay_in_all_and_dir() -> None:
    assert {"TelemetryProvider", "AuditLogger"} <= set(aisafe.__all__)
    assert {"TelemetryProvider", "AuditLogger"} <= set(dir(aisafe))


def test_every_public_name_resolves() -> None:
    for name in aisafe.__all__:
        assert getattr(aisafe, name) is not None


def test_unknown_attribute_still_raises() -> None:
    with pytest.raises(AttributeError, match="NoSuchGuard"):
        aisafe.NoSuchGuard  # noqa: B018
