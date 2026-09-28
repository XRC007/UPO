"""Verification and enrichment checks.

Each module contributes one mixin to ``UPO.core.engine.UPOEngine``:

* ``verify``      — judge testing, TCP prefilter, liveness verification
* ``anonymity``   — transparent / anonymous / elite classification
* ``protocol``    — which of http/https/socks4/socks5 actually work
* ``speed``       — download throughput and speed tier
* ``fingerprint`` — header/TCP fingerprint plus the stealth score
* ``dns``         — DNS leak detection
* ``ban``         — Google/Bing ban screening
* ``fraud``       — tiered paid-API fraud scoring
"""

from __future__ import annotations

from .anonymity import AnonymityMixin
from .ban import BanMixin
from .dns import DnsMixin
from .fingerprint import FingerprintMixin
from .fraud import FraudMixin
from .protocol import ProtocolMixin
from .speed import SpeedMixin
from .verify import VerifyMixin

__all__ = [
    "VerifyMixin",
    "AnonymityMixin",
    "ProtocolMixin",
    "SpeedMixin",
    "FingerprintMixin",
    "DnsMixin",
    "BanMixin",
    "FraudMixin",
]