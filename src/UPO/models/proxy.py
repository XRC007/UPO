"""SECTION 1: DATA MODELS — the ``Proxy`` record.

A mutable dataclass that is filled in progressively as a proxy moves through
the pipeline (collection → geo → verification → anonymity → protocol →
speed/fingerprint/dns/ban → fraud → stealth). Field order and defaults are
unchanged from the monolith so serialized output stays byte-compatible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from .enums import AnonymityLevel, ProxyProtocol, ProxyType, SpeedTier


@dataclass
class Proxy:
    ip: str
    port: int
    protocol: ProxyProtocol
    source: str = ""
    alive: bool = False
    latency_ms: Optional[int] = None
    anonymity: Optional[AnonymityLevel] = None
    speed_tier: Optional[SpeedTier] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    asn: Optional[int] = None
    isp: Optional[str] = None
    proxy_type: ProxyType = ProxyType.UNKNOWN
    supports_https: bool = False
    detected_protocols: List[str] = field(default_factory=list)
    download_speed_kbps: Optional[float] = None
    stealth_score: Optional[int] = None
    dns_leak: Optional[bool] = None
    tcp_fingerprint: Optional[str] = None
    google_ban: Optional[bool] = None
    fraud_score: Optional[float] = None
    composite_score: Optional[int] = None
    is_vpn: Optional[bool] = None
    is_tor: Optional[bool] = None
    is_hosting: Optional[bool] = None
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_checked: Optional[str] = None
    check_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    reliability: float = 0.0
    avg_latency_ms: Optional[float] = None
    uptime_history: List[bool] = field(default_factory=list)

    def __post_init__(self):
        try:
            self.port = int(self.port)
        except (ValueError, TypeError):
            raise ValueError(f"Invalid port: {self.port}")

    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.protocol.value}://{self.ip}:{self.port}"

    @property
    def id(self) -> str:
        return f"{self.ip}:{self.port}:{self.protocol.value}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("uptime_history", None)
        d["protocol"] = self.protocol.value if self.protocol else None
        d["anonymity"] = self.anonymity.value if self.anonymity else None
        d["speed_tier"] = self.speed_tier.value if self.speed_tier else None
        d["proxy_type"] = self.proxy_type.value if self.proxy_type else None
        return d


__all__ = ["Proxy"]