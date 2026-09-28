"""SECTION 1 (part): enums used by the data model.

Split out of ``models/proxy.py`` so lightweight modules (filters, exporters)
can import the enums without dragging in the dataclass.
"""

from __future__ import annotations

from enum import Enum


class ProxyProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class AnonymityLevel(str, Enum):
    TRANSPARENT = "transparent"
    ANONYMOUS = "anonymous"
    ELITE = "elite"


class SpeedTier(str, Enum):
    FAST = "fast"
    MEDIUM = "medium"
    SLOW = "slow"


class ProxyType(str, Enum):
    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    MOBILE = "mobile"
    UNKNOWN = "unknown"


__all__ = ["ProxyProtocol", "AnonymityLevel", "SpeedTier", "ProxyType"]