"""Pytest bootstrap: make ``src/`` importable so ``import UPO`` finds the package.

``src`` is inserted at the FRONT of ``sys.path`` so the ``src/UPO`` package
always wins over any stray top-level ``UPO`` module. (The old root-level
``UPO.py`` shim was removed for exactly that reason.)
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"

while str(_SRC) in sys.path:
    sys.path.remove(str(_SRC))
sys.path.insert(0, str(_SRC))