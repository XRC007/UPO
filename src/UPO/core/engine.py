"""SECTION 5: CORE ENGINE — the pipeline hub.

``UPOEngine`` owns all mutable run state (config, proxy registry, judge pool,
geoip readers, history/verified DB handles, fraud rate limiters) and the
``initialize`` bootstrap. Every other capability is contributed by a mixin so
that the code physically lives with its subsystem:

    collection      -> UPO.collectors.fetcher.CollectMixin
    verification    -> UPO.checks.verify.VerifyMixin
    anonymity       -> UPO.checks.anonymity.AnonymityMixin
    protocol detect -> UPO.checks.protocol.ProtocolMixin
    speed test      -> UPO.checks.speed.SpeedMixin
    fingerprint     -> UPO.checks.fingerprint.FingerprintMixin
    dns leak        -> UPO.checks.dns.DnsMixin
    ban check       -> UPO.checks.ban.BanMixin
    fraud scoring   -> UPO.checks.fraud.FraudMixin
    export          -> UPO.export.exporter.ExportMixin
    stats           -> UPO.export.stats.StatsMixin

The mixins are plain classes with no dependency on ``UPOEngine`` beyond the
attributes defined in ``__init__``, which keeps the import graph acyclic and
lets ``UPOEngine`` be the only place that needs the full picture.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
import aiohttp_socks
import geoip2.database

from ..config import (
    DEFAULT_CONFIG,
    GITHUB_HTTP_SOURCES,
    GITHUB_SOCKS4_SOURCES,
    GITHUB_SOCKS5_SOURCES,
    API_SOURCES,
    DATACENTER_ASNS,
    RESIDENTIAL_ASNS,
    MOBILE_ASNS,
    CDN_ASNS,
    CLOUDFLARE_IP_RANGES,
    PROXY_REGEX,
    total_source_count,
)
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console
from .filter import IPFilter
from .limiter import RateLimiter
from ..db.history import ProxyHistory
from ..db.verified import VerifiedProxyDB
from ..collectors.fetcher import CollectMixin
from ..checks.verify import VerifyMixin
from ..checks.anonymity import AnonymityMixin
from ..checks.protocol import ProtocolMixin
from ..checks.speed import SpeedMixin
from ..checks.fingerprint import FingerprintMixin
from ..checks.dns import DnsMixin
from ..checks.ban import BanMixin
from ..checks.fraud import FraudMixin
from ..export.exporter import ExportMixin
from ..export.stats import StatsMixin
from .lifecycle import LifecycleMixin


class UPOEngine(
    LifecycleMixin,
    CollectMixin,
    VerifyMixin,
    AnonymityMixin,
    ProtocolMixin,
    SpeedMixin,
    FingerprintMixin,
    DnsMixin,
    BanMixin,
    FraudMixin,
    ExportMixin,
    StatsMixin,
):
    def __init__(self, config: Dict):
        super().__init__()
        self.config = config
        self.headers = {"User-Agent": config["general"]["user_agent"]}
        self.proxies: Dict[str, Proxy] = {}
        self.judges: List[Tuple[str, float]] = []
        self.geoip_city = None
        self.geoip_asn = None
        self.blacklist: Set[str] = set()
        self.my_ip: Optional[str] = None
        self.my_dns_ip: Optional[str] = None
        self.ip_filter = IPFilter()
        self.history: Optional[ProxyHistory] = None
        self.verified_db: Optional[VerifiedProxyDB] = None
        self.getipintel_limiter = RateLimiter(14)
        self.iphub_limiter = RateLimiter(100)
        self.ipinfo_limiter = RateLimiter(600)
        self.stats: Dict[str, Any] = {
            "collected_raw": 0, "filtered": 0,
            "tcp_prefilter_removed": 0,   # ← NEW: tracks TCP-dead count
            "verified_total": 0, "verified_alive": 0,
            "api_calls": {
                "ipinfo": 0, "iphub": 0, "getipintel": 0,
                "ipqs": 0, "cache_hits": 0,
            },
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    def _create_proxy_session(
        self, proxy: Proxy, timeout: aiohttp.ClientTimeout
    ) -> Tuple[Optional[aiohttp.ClientSession], Dict[str, str]]:
        try:
            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                connector = aiohttp_socks.ProxyConnector.from_url(
                    proxy.url, rdns=True
                )
                session = aiohttp.ClientSession(
                    connector=connector, headers=self.headers, timeout=timeout
                )
                return session, {}
            else:
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(
                    connector=connector, headers=self.headers, timeout=timeout
                )
                return session, {"proxy": proxy.url}
        except Exception as e:
            console.print(
                f"[dim red]Session error {proxy.address}: {e}[/dim red]"
            )
            return None, {}

    # FIX #3: Judge rotation — returns judge URL for a given module index
    def _get_judge(self, module_index: int = 0) -> str:
        """
        Rotate judges across modules to spread load.
        module_index 0 = verification
        module_index 1 = anonymity (always httpbin.org/headers)
        module_index 2 = protocol detection
        module_index 3 = speed test / ban check / fingerprint
        """
        if not self.judges:
            # Should never reach here — verify() aborts if no judges
            # Use ipify as last resort (lightweight, no rate limit issues)
            return "http://api.ipify.org"
        idx = module_index % len(self.judges)
        return self.judges[idx][0]

    # ── Initialize ────────────────────────────────────────────────────────

    async def initialize(self):
        if self.config["geoip"]["enabled"]:
            try:
                self.geoip_city = geoip2.database.Reader(
                    self.config["geoip"]["city_db"]
                )
                self.geoip_asn = geoip2.database.Reader(
                    self.config["geoip"]["asn_db"]
                )
                console.print("[green]✓[/] GeoIP databases loaded.")
            except FileNotFoundError:
                console.print("[yellow]⚠[/] GeoIP databases not found.")
                self.config["geoip"]["enabled"] = False

        bl_path = self.config["filter"]["blacklist"]
        if os.path.exists(bl_path):
            with open(bl_path, "r") as f:
                self.blacklist = {l.strip() for l in f if l.strip()}
            if self.blacklist:
                console.print(
                    f"[green]✓[/] Blacklist: {len(self.blacklist)} IPs."
                )

        if self.config["history"]["enabled"]:
            self.history = ProxyHistory(self.config["history"]["db_path"])
            s = self.history.get_stats()
            console.print(
                f"[green]✓[/] History DB: {s['total_tracked']:,} tracked."
            )

        if self.config["verified_db"]["enabled"]:
            self.verified_db = VerifiedProxyDB(
                self.config["verified_db"]["db_path"]
            )
            vcount = self.verified_db.count()
            console.print(
                f"[green]✓[/] Verified DB: {vcount:,} previously working."
            )

        console.print("[cyan]Detecting your real IP...[/cyan]")
        judges = [
            "http://api.ipify.org", "http://icanhazip.com",
            "http://checkip.amazonaws.com",
        ]
        async with aiohttp.ClientSession(headers=self.headers) as s:
            for j in judges:
                try:
                    async with s.get(
                        j, timeout=aiohttp.ClientTimeout(total=10)
                    ) as r:
                        if r.status == 200:
                            text = (await r.text()).strip()
                            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
                                self.my_ip = text
                                console.print(
                                    f"[green]✓[/] Your IP: "
                                    f"[bold]{self.my_ip}[/bold]"
                                )
                                break
                except Exception:
                    continue

        if not self.my_ip:
            console.print("[red]✗[/] Could not detect your IP.")

        if self.config["dns_leak"]["enabled"]:
            try:
                async with aiohttp.ClientSession(
                    headers=self.headers
                ) as s:
                    async with s.get(
                        "https://1.1.1.1/cdn-cgi/trace",
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as r:
                        if r.status == 200:
                            for line in (await r.text()).strip().split("\n"):
                                if line.startswith("ip="):
                                    self.my_dns_ip = line.split("=")[1].strip()
                                    break
            except Exception:
                pass
