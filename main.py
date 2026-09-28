"""UPO — Ultimate Proxy Operator.

Entry point. Keeps the legacy Windows/UTF-8 bootstrap (now in
``UPO.runtime``) and hands off to the Click CLI.

    python main.py --help
    python main.py --test-limit 100 --no-crawl4ai --rounds 1
    python -m UPO --help          (with src on PYTHONPATH)
"""

from __future__ import annotations

import os
import sys

# Allow running from a clean checkout without `pip install -e .`.
_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Importing the package triggers UPO.runtime: event-loop policy, UTF-8
# console, chdir to the project root and .env loading.
from UPO.cli.app import main  # noqa: E402
from UPO.runtime import reconfigure_streams  # noqa: E402


def _entry() -> None:
    reconfigure_streams()
    main()


if __name__ == "__main__":
    _entry()