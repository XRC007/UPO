"""UPO v5-fix2 — Ultimate Proxy Operator.

Public API. The package is a drop-in replacement for the old single-module
``UPO.py``, so ``from UPO import UPOEngine, Proxy, ...`` keeps working and no
import machinery or sys.path juggling is required from callers.

Runtime bootstrap (event loop policy, UTF-8 console, project-root chdir, .env)
lives in :mod:`UPO.runtime` and runs on package import, before anything reads
``DEFAULT_CONFIG``.

Sub-packages
------------
``UPO.config``        static config tree, source lists, ASN tables, regexes
``UPO.models``        ``Proxy`` dataclass and its enums
``UPO.core``          ``UPOEngine`` hub, ``IPFilter``, ``RateLimiter``
``UPO.db``            ``ProxyHistory``, ``VerifiedProxyDB``
``UPO.collectors``    source scrapers, crawl4ai runner
``UPO.checks``        verify / anonymity / protocol / speed / fingerprint / dns / ban / fraud
``UPO.export``        categorization, file export, stats report
``UPO.api``           optional FastAPI server
``UPO.cli``           Click CLI + sequential pipeline orchestrator
"""

from __future__ import annotations

# Bootstrap MUST come first: it sets the event-loop policy, chdirs to the
# project root and loads .env before DEFAULT_CONFIG reads API keys.
from . import runtime as runtime
from .runtime import PACKAGE_DIR, PROJECT_ROOT, SRC_DIR

from .config import (  # noqa: E402
    API_SOURCES,
    CDN_ASNS,
    CLOUDFLARE_IP_RANGES,
    CRAWL4AI_INSTALL_PATH,
    DATACENTER_ASNS,
    DEFAULT_CONFIG,
    GITHUB_HTTP_SOURCES,
    GITHUB_SOCKS4_SOURCES,
    GITHUB_SOCKS5_SOURCES,
    MOBILE_ASNS,
    PROXY_REGEX,
    RESIDENTIAL_ASNS,
    load_config,
    total_source_count,
)
from .models import (  # noqa: E402
    AnonymityLevel,
    Proxy,
    ProxyProtocol,
    ProxyType,
    SpeedTier,
)
from .core.filter import IPFilter  # noqa: E402
from .core.limiter import RateLimiter  # noqa: E402
from .db.history import ProxyHistory  # noqa: E402
from .db.verified import VerifiedProxyDB  # noqa: E402
from .utils.console import console  # noqa: E402

# UPOEngine pulls in every mixin, so import it last.
from .core.engine import UPOEngine  # noqa: E402

# ``main`` and ``pipeline`` are re-exported lazily in __getattr__ below so that
# importing the library does not eagerly import the CLI (and therefore click).

__version__ = "5.0.0"

__all__ = [
    # engine + pipeline
    "UPOEngine",
    "main",
    "pipeline",
    "start_api",
    "run_crawl4ai",
    # models
    "Proxy",
    "ProxyProtocol",
    "AnonymityLevel",
    "SpeedTier",
    "ProxyType",
    # utilities
    "IPFilter",
    "RateLimiter",
    "ProxyHistory",
    "VerifiedProxyDB",
    "console",
    # config
    "DEFAULT_CONFIG",
    "load_config",
    "PROXY_REGEX",
    "API_SOURCES",
    "CDN_ASNS",
    "CLOUDFLARE_IP_RANGES",
    "CRAWL4AI_INSTALL_PATH",
    "DATACENTER_ASNS",
    "GITHUB_HTTP_SOURCES",
    "GITHUB_SOCKS4_SOURCES",
    "GITHUB_SOCKS5_SOURCES",
    "MOBILE_ASNS",
    "RESIDENTIAL_ASNS",
    "total_source_count",
    # runtime
    "PROJECT_ROOT",
    "SRC_DIR",
    "PACKAGE_DIR",
    "runtime",
    "__version__",
]

_LAZY = {
    "main": ("UPO.cli.app", "main"),
    "pipeline": ("UPO.cli.app", "pipeline"),
    "start_api": ("UPO.api.server", "start_api"),
    "run_crawl4ai": ("UPO.collectors.crawl4ai_runner", "run_crawl4ai"),
}


def __getattr__(name: str):
    """Resolve CLI/API/crawl4ai names only when actually requested."""
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    module = importlib.import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))