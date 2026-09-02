"""aisg/devtools/audit/__init__.py
-------------------------------
`aisg audit`: entry points re-exported lazily, so importing the package stays cheap.
"""

from __future__ import annotations

from typing import Any

__all__ = ["main", "build_parser", "run_audit"]


def __getattr__(name: str) -> Any:
    # PEP 562: `aisg.cli` lazy-imports one name from here, and nothing
    # argparse-heavy (parser, rules, adapters) loads until then. The submodule
    # is also called `main`, and importing it binds that name on this package
    # to the module object, so all three entry points are rebound explicitly
    # to keep every later access resolving to the functions.
    if name not in __all__:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    impl = import_module(f"{__name__}.main")
    for symbol in __all__:
        globals()[symbol] = getattr(impl, symbol)
    return globals()[name]
