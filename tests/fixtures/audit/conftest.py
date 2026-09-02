"""tests/fixtures/audit/conftest.py
--------------------------------
Everything below this directory is `aisg audit` input, not a test suite.
`clean_py/tests/test_calc.py` looks like a test module and imports a package
that is never installed, so keep pytest from collecting anything down here.
"""

from __future__ import annotations

collect_ignore_glob = ["*"]
