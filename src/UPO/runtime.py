"""Process-wide runtime bootstrap for UPO.

This module owns the side effects that the original monolithic ``UPO.py``
performed at import time:

* Windows ``SelectorEventLoopPolicy`` selection (required by aiohttp; Playwright
  gets its own Proactor loop in ``UPO.collectors.crawl4ai_runner``).
* UTF-8 reconfiguration of stdout/stderr so Rich box-drawing characters and
  emoji survive the legacy cp1252 console.
* Resolution of the project root and the ``os.chdir`` anchor, so every relative
  path in ``config.yaml`` (``data/``, ``output/``, ``checked/``) resolves the
  same way whether the CLI is launched as ``python main.py``, ``python -m UPO``
  or via the VS Code Run button.
* ``.env`` loading, which must happen *before* ``UPO.config`` is imported
  because ``DEFAULT_CONFIG`` reads ``os.getenv`` for API keys.

Import this module before anything else in the package; ``UPO/__init__.py``
does that for you.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# src/UPO/runtime.py -> src/UPO -> src -> <project root>
PACKAGE_DIR: Path = Path(__file__).resolve().parent
SRC_DIR: Path = PACKAGE_DIR.parent
PROJECT_ROOT: Path = SRC_DIR.parent

# Playwright/crawl4ai runs in its own thread with a dedicated
# ProactorEventLoop (see UPO.collectors.crawl4ai_runner), so the MAIN loop
# is free to choose whatever the pipeline needs. Windows' select()-based
# SelectorEventLoop caps at FD_SETSIZE=512 sockets TOTAL — fine for the
# sequential phase pipeline (phases never overlap) but a hard crash for
# the pipelined lifecycle engine, whose stages run concurrently
# (500 TCP probes + 150 verifies + … can exceed 512 live sockets). The
# Proactor loop is IOCP-based: no FD limit, fully supported by aiohttp.
# Set UPO_SELECTOR_LOOP=1 to force the legacy Selector policy (e.g. to
# reproduce old serial-pipeline FD behavior).
if sys.platform == "win32":
    if os.environ.get("UPO_SELECTOR_LOOP") == "1":
        asyncio.set_event_loop_policy(
            asyncio.WindowsSelectorEventLoopPolicy())
    else:
        asyncio.set_event_loop_policy(
            asyncio.WindowsProactorEventLoopPolicy())

# Anchor relative config/data/output paths to the project root.
os.chdir(PROJECT_ROOT)

# Load API keys (.env) before UPO.config builds DEFAULT_CONFIG.
try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is optional
    load_dotenv = None  # type: ignore[assignment]

if load_dotenv is not None:
    for _candidate in (PROJECT_ROOT / ".env", Path.cwd() / ".env"):
        try:
            if _candidate.exists():
                load_dotenv(_candidate)
                break
        except Exception:
            continue


def reconfigure_streams() -> None:
    """Force UTF-8 on the console streams (idempotent, Windows only)."""
    if sys.platform != "win32":
        return
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass