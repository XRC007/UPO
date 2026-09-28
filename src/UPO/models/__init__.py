"""SECTION 1: DATA MODELS."""

from __future__ import annotations

from .enums import AnonymityLevel, ProxyProtocol, ProxyType, SpeedTier
from .proxy import Proxy

__all__ = [
    "Proxy",
    "ProxyProtocol",
    "AnonymityLevel",
    "SpeedTier",
    "ProxyType",
]