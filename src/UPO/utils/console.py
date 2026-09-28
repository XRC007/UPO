"""Shared Rich console.

Previously a module-level global in ``UPO.py``. Importing it from one place
keeps panel/table styling identical across every package module and avoids the
duplicate-console interleaving that appears when several modules each build
their own ``Console()``.
"""

from __future__ import annotations

import sys

from rich.console import Console

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError with the
# box-drawing characters / emoji used in the Rich banner and Click help text.
if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

console: Console = Console()