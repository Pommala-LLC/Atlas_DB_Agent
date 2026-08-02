"""Repository test bootstrap for the src-layout package."""
from __future__ import annotations

import os
import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
_existing = os.environ.get("PYTHONPATH")
os.environ["PYTHONPATH"] = str(_SRC) if not _existing else os.pathsep.join((str(_SRC), _existing))

# The production path fails closed if gherkin-official is missing. The build
# sandbox cannot download PyPI wheels, so source tests use the renderer's
# explicit canonical-subset test parser only when the official package is absent.
if importlib.util.find_spec("gherkin") is None:
    os.environ["OJAS_TEST_ALLOW_GHERKIN_FALLBACK"] = "1"
