# ==============================================================================
#
# ██╗   ██╗██████╗  ██████╗     ██╗   ██╗██████╗
# ██║   ██║██╔══██╗██╔═══██╗    ██║   ██║╚════██╗
# ██║   ██║██████╔╝██║   ██║    ██║   ██║ █████╔╝
# ██║   ██║██╔═══╝ ██║   ██║    ╚██╗ ██╔╝██╔═══╝
# ╚██████╔╝██║     ╚██████╔╝     ╚████╔╝ ███████╗
#  ╚═════╝ ╚═╝      ╚═════╝       ╚═══╝  ╚══════╝
#
# UPO v2 - Ultimate Proxy Operator (Fixed & Hardened)
# ==============================================================================

import asyncio
import aiohttp
import aiohttp_socks
import re
import json
import csv
import time
import os
import sys
import base64
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Set, Tuple
from collections import Counter
from pathlib import Path
from ipaddress import ip_address, ip_network

import click
import geoip2.database
from rich.console import Console
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn
)
from rich.table import Table
from rich.panel import Panel

CRAWL4AI_INSTALL_PATH = r"D:\3dAI\Data Analyze"

# ==============================================================================
# SECTION 0: CONFIG & SOURCES
# ==============================================================================

DEFAULT_CONFIG = {
    'general': {
        'concurrency': 300,
        'timeout_connect': 8,
        'timeout_total': 15,
        'user_agent': (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
    },
    'judges': {
        'urls': [
            "http://httpbin.org/ip",
            "http://api.ipify.org",
            "http://icanhazip.com",
            "http://checkip.amazonaws.com",
            "http://myexternalip.com/raw",
            "http://ip-api.com/json",
            "http://httpbin.org/headers",
        ]
    },
    'geoip': {
        'enabled': True,
        'city_db': "data/GeoLite2-City.mmdb",
        'asn_db': "data/GeoLite2-ASN.mmdb",
    },
    'filter': {
        'blacklist': "data/blacklist.txt",
    },
    'output': {
        'dir': "output",
        'formats': ['txt', 'json', 'csv'],
        'split_by_protocol': True,
        'generate_elite_list': True,
        'generate_fast_list': True,
        'fast_threshold_ms': 500,
    },
    'crawl4ai': {
        'enabled': True,
        'output_file': "output/crawled_proxies.json",
    },
}

# ── GitHub Raw Sources ────────────────────────────────────────────────────────

GITHUB_HTTP_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",
    "https://raw.githubusercontent.com/ErcinDedeworkarounds/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt",
]

GITHUB_SOCKS4_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks4_proxies.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
    "https://raw.githubusercontent.com/ErcinDedeworkarounds/proxies/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
]

GITHUB_SOCKS5_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/ErcinDedeworkarounds/proxies/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]

API_SOURCES = [
    {"url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=http&timeout=5000", "protocol": "http"},
    {"url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=socks4&timeout=5000", "protocol": "socks4"},
    {"url": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=socks5&timeout=5000", "protocol": "socks5"},
    {"url": "https://www.proxy-list.download/api/v1/get?type=http", "protocol": "http"},
    {"url": "https://www.proxy-list.download/api/v1/get?type=https", "protocol": "https"},
    {"url": "https://www.proxy-list.download/api/v1/get?type=socks4", "protocol": "socks4"},
    {"url": "https://www.proxy-list.download/api/v1/get?type=socks5", "protocol": "socks5"},
    {"url": "https://api.openproxylist.xyz/http.txt", "protocol": "http"},
    {"url": "https://api.openproxylist.xyz/socks4.txt", "protocol": "socks4"},
    {"url": "https://api.openproxylist.xyz/socks5.txt", "protocol": "socks5"},
    {"url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc", "protocol": "mixed", "format": "json"},
]

# ── Known CDN / Non-Proxy IP Ranges to REJECT ────────────────────────────────

BLACKLISTED_ASN_SET: Set[int] = {
    13335,   # Cloudflare
    209242,  # Cloudflare London, LLC
    20940,   # Akamai
    16625,   # Akamai
    14618,   # Amazon CloudFront
    16509,   # Amazon AWS (unless confirmed proxy)
    8075,    # Microsoft Azure (unless confirmed proxy)
    15169,   # Google Cloud (unless confirmed proxy)
    396982,  # Google Cloud
    54113,   # Fastly
    46606,   # Unified Layer / Bluehost
    26496,   # GoDaddy
    47846,   # Sedo
}

CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

COMMON_PROXY_PORTS: Set[int] = {
    80, 443, 8080, 8443, 3128, 1080, 1081, 1082, 1083,
    8888, 8118, 9050, 9051, 9150, 4145, 4153,
    7497, 7657, 5678, 4480, 53281, 3129, 8181,
    8081, 8082, 8085, 8090, 9090, 9091, 3130,
    3131, 3132, 3133, 3134, 3135, 3136, 3137,
    3138, 3139, 4444, 4445, 4446, 4447, 4448,
    5555, 6666, 6667, 6668, 6669, 7777, 7778,
    8008, 8088, 8123, 8888, 8889, 8899, 9999,
    31337, 41080, 43440, 44443, 45554, 52848,
    55443, 59166, 60000, 61080, 61443,
}

# ==============================================================================
# SECTION 1: DATA MODELS
# ==============================================================================

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
    asn: Optional[int] = None
    isp: Optional[str] = None
    is_datacenter: bool = False
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_checked: Optional[str] = None
    check_count: int = 0
    success_count: int = 0
    reliability: float = 0.0

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

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

# ==============================================================================
# SECTION 2: IP FILTER — Pre-verification garbage removal
# ==============================================================================

class IPFilter:
    def __init__(self):
        self.cf_networks = [
            ip_network(cidr) for cidr in CLOUDFLARE_IP_RANGES
        ]
        self.private_networks = [
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
            ip_network("127.0.0.0/8"),
            ip_network("0.0.0.0/8"),
            ip_network("169.254.0.0/16"),    # Link-local
            ip_network("224.0.0.0/4"),       # Multicast
            ip_network("240.0.0.0/4"),       # Reserved
            ip_network("100.64.0.0/10"),     # Carrier-grade NAT
        ]

    def is_cloudflare(self, ip_str: str) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in net for net in self.cf_networks)
        except ValueError:
            return True

    def is_private_or_reserved(self, ip_str: str) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in net for net in self.private_networks)
        except ValueError:
            return True

    def is_valid_proxy_candidate(self, proxy: Proxy) -> Tuple[bool, str]:
        try:
            addr = ip_address(proxy.ip)
        except ValueError:
            return False, "invalid_ip"

        if self.is_private_or_reserved(proxy.ip):
            return False, "private_ip"

        if self.is_cloudflare(proxy.ip):
            return False, "cloudflare_ip"

        if proxy.port < 1 or proxy.port > 65535:
            return False, "invalid_port"

        return True, "ok"

    def filter_batch(
        self, proxies: Dict[str, Proxy]
    ) -> Tuple[Dict[str, Proxy], Dict[str, int]]:
        valid: Dict[str, Proxy] = {}
        stats: Dict[str, int] = Counter()

        for addr, proxy in proxies.items():
            is_valid, reason = self.is_valid_proxy_candidate(proxy)
            if is_valid:
                valid[addr] = proxy
            else:
                stats[reason] += 1

        return valid, dict(stats)

# ==============================================================================
# SECTION 3: CORE ENGINE
# ==============================================================================

console = Console()
PROXY_REGEX = re.compile(
    r'(?:(?P<protocol>https?|socks[45])://)?'
    r'(?:[\w.-]+:[\w.-]+@)?'
    r'(?P<ip>(?:\d{1,3}\.){3}\d{1,3})'
    r':(?P<port>\d{2,5})'
)

class UPOEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.headers = {'User-Agent': config['general']['user_agent']}
        self.proxies: Dict[str, Proxy] = {}
        self.judges: List[Tuple[str, float]] = []
        self.geoip_city_reader = None
        self.geoip_asn_reader = None
        self.blacklist: Set[str] = set()
        self.my_ip: Optional[str] = None
        self.ip_filter = IPFilter()
        self.stats = {
            'collected_raw': 0,
            'filtered_pre_verify': 0,
            'verified_total': 0,
            'verified_alive': 0,
        }

    async def initialize(self):
        if self.config['geoip']['enabled']:
            try:
                self.geoip_city_reader = geoip2.database.Reader(
                    self.config['geoip']['city_db']
                )
                self.geoip_asn_reader = geoip2.database.Reader(
                    self.config['geoip']['asn_db']
                )
                console.print("[green]✓[/] GeoIP databases loaded.")
            except FileNotFoundError:
                console.print(
                    "[yellow]⚠[/] GeoIP databases not found. "
                    "GeoIP enrichment disabled."
                )
                self.config['geoip']['enabled'] = False

        bl_path = self.config['filter']['blacklist']
        if os.path.exists(bl_path):
            with open(bl_path, 'r') as f:
                self.blacklist = {
                    line.strip() for line in f if line.strip()
                }

        console.print("[cyan]Detecting your real IP...[/cyan]")
        real_ip_judges = [
            "http://api.ipify.org",
            "http://icanhazip.com",
            "http://checkip.amazonaws.com",
        ]
        async with aiohttp.ClientSession(headers=self.headers) as session:
            for judge_url in real_ip_judges:
                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with session.get(
                        judge_url, timeout=timeout
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            text = text.strip()
                            if re.match(
                                r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                                text
                            ):
                                self.my_ip = text
                                console.print(
                                    f"[green]✓[/] Your real IP: "
                                    f"[bold]{self.my_ip}[/bold]"
                                )
                                break
                except Exception:
                    continue

        if not self.my_ip:
            console.print(
                "[red]✗[/] Could not detect your real IP. "
                "Anonymity checks will be less reliable."
            )

    async def collect(self):
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100, ssl=False)

        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout, connector=connector
        ) as session:

            tasks = []

            for url in GITHUB_HTTP_SOURCES:
                tasks.append(
                    self._fetch_and_parse(session, url, ProxyProtocol.HTTP)
                )
            for url in GITHUB_SOCKS4_SOURCES:
                tasks.append(
                    self._fetch_and_parse(session, url, ProxyProtocol.SOCKS4)
                )
            for url in GITHUB_SOCKS5_SOURCES:
                tasks.append(
                    self._fetch_and_parse(session, url, ProxyProtocol.SOCKS5)
                )

            for api_src in API_SOURCES:
                proto = api_src['protocol']
                if proto == 'mixed':
                    proto = 'http'
                tasks.append(
                    self._fetch_and_parse(
                        session, api_src['url'],
                        ProxyProtocol(proto),
                        api_src.get('format')
                    )
                )

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "[cyan]Fetching sources...", total=len(tasks)
                )
                for coro in asyncio.as_completed(tasks):
                    await coro
                    progress.update(task, advance=1)

        crawl_file = self.config['crawl4ai']['output_file']
        if self.config['crawl4ai']['enabled'] and os.path.exists(crawl_file):
            try:
                with open(crawl_file, 'r') as f:
                    crawled = json.load(f)
                count = 0
                for p in crawled:
                    try:
                        proxy = Proxy(
                            ip=p['ip'].strip(),
                            port=int(p['port']),
                            protocol=ProxyProtocol(
                                p.get('protocol', 'http')
                            ),
                            source=p.get('source', 'crawl4ai'),
                        )
                        if proxy.address not in self.proxies:
                            self.proxies[proxy.address] = proxy
                            count += 1
                    except (ValueError, KeyError):
                        continue
                console.print(
                    f"  [green]✓[/] Loaded {count} proxies from crawl4ai."
                )
            except (json.JSONDecodeError, FileNotFoundError):
                pass

        self.stats['collected_raw'] = len(self.proxies)

    async def _fetch_and_parse(
        self,
        session: aiohttp.ClientSession,
        url: str,
        protocol_hint: ProxyProtocol,
        format_hint: Optional[str] = None,
    ):
        retries = 3
        for attempt in range(retries):
            try:
                async with session.get(url, ssl=False) as response:
                    if response.status != 200:
                        return
                    content = await response.text()

                    source_name = url.split('/')[2] if '/' in url else url

                    if format_hint == 'json':
                        self._parse_json_source(content, source_name)
                    else:
                        self._parse_text_source(
                            content, protocol_hint, source_name
                        )
                    return

            except asyncio.TimeoutError:
                if attempt < retries - 1:
                    await asyncio.sleep(1 * (attempt + 1))
            except Exception:
                return

    def _parse_text_source(
        self, content: str, protocol_hint: ProxyProtocol, source: str
    ):
        for match in PROXY_REGEX.finditer(content):
            try:
                ip_str = match.group('ip')
                port = int(match.group('port'))
                proto_str = match.group('protocol')
                protocol = (
                    ProxyProtocol(proto_str) if proto_str else protocol_hint
                )

                proxy = Proxy(
                    ip=ip_str, port=port,
                    protocol=protocol, source=source, # LIMIT THE SCRAPER BY CUTTING HERE OR LATER
                )
                if proxy.address not in self.proxies:
                    self.proxies[proxy.address] = proxy
            except (ValueError, KeyError):
                continue

    def _parse_json_source(self, content: str, source: str):
        try:
            data = json.loads(content)
            items = data.get('data', []) if isinstance(data, dict) else data
            for item in items:
                try:
                    ip_str = item.get('ip', '').strip()
                    port = int(item.get('port', 0))
                    protocols = item.get('protocols', ['http'])
                    if isinstance(protocols, list) and protocols:
                        proto = protocols[0].lower()
                    else:
                        proto = 'http'

                    proxy = Proxy(
                        ip=ip_str, port=port,
                        protocol=ProxyProtocol(proto),
                        source=source,
                    )
                    if proxy.address not in self.proxies:
                        self.proxies[proxy.address] = proxy
                except (ValueError, KeyError):
                    continue
        except json.JSONDecodeError:
            pass

    def filter_garbage(self):
        before_count = len(self.proxies)

        self.proxies, rejection_stats = self.ip_filter.filter_batch(
            self.proxies
        )

        if self.geoip_asn_reader:
            asn_rejected = 0
            to_remove = []
            for addr, proxy in self.proxies.items():
                try:
                    asn_data = self.geoip_asn_reader.asn(proxy.ip)
                    asn_num = asn_data.autonomous_system_number
                    if asn_num in BLACKLISTED_ASN_SET:
                        to_remove.append(addr)
                        asn_rejected += 1
                except Exception:
                    pass
            for addr in to_remove:
                del self.proxies[addr]
            rejection_stats['blacklisted_asn'] = asn_rejected

        bl_removed = 0
        to_remove = []
        for addr, proxy in self.proxies.items():
            if proxy.ip in self.blacklist:
                to_remove.append(addr)
                bl_removed += 1
        for addr in to_remove:
            del self.proxies[addr]
        rejection_stats['blacklisted_ip'] = bl_removed

        after_count = len(self.proxies)
        self.stats['filtered_pre_verify'] = before_count - after_count

        console.print(
            f"\n[bold cyan]Pre-Verification Filter Results:[/bold cyan]"
        )
        console.print(
            f"  Before: {before_count:,} → After: {after_count:,} "
            f"([red]-{before_count - after_count:,} rejected[/red])"
        )
        if rejection_stats:
            for reason, count in sorted(
                rejection_stats.items(), key=lambda x: -x[1]
            ):
                console.print(f"    [red]✗[/] {reason}: {count:,}")
        
        # APPLY LIMIT TO THE PROXIES AS REQUESTED
        limit = self.config.get('test_limit')
        if limit and limit < len(self.proxies):
            console.print(f"[bold yellow]⚠ TESTING LIMIT APPLIED: Testing only {limit} proxies.[/bold yellow]")
            self.proxies = dict(list(self.proxies.items())[:limit])

    async def verify(self):
        if not self.proxies:
            console.print("[yellow]No proxies to verify.[/yellow]")
            return

        console.print("\n[cyan]Testing judge servers...[/cyan]")
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout
        ) as session:
            judge_tasks = [
                self._test_judge(session, url)
                for url in self.config['judges']['urls']
            ]
            results = await asyncio.gather(*judge_tasks)
            self.judges = sorted(
                [r for r in results if r is not None],
                key=lambda x: x[1],
            )

        if not self.judges:
            console.print(
                "[bold red]✗ No judges reachable. Cannot verify.[/bold red]"
            )
            return

        console.print(
            f"[green]✓[/] {len(self.judges)} judges working. "
            f"Primary: '{self.judges[0][0]}' "
            f"({self.judges[0][1]*1000:.0f}ms)"
        )

        sem = asyncio.Semaphore(self.config['general']['concurrency'])
        proxy_list = list(self.proxies.values())
        alive_count = 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("│ Alive: {task.fields[alive]}"),
            TimeRemainingColumn(),
        ) as progress:
            task_id = progress.add_task(
                "[cyan]Verifying...",
                total=len(proxy_list),
                alive=0,
            )

            async def verify_with_sem(proxy):
                nonlocal alive_count
                async with sem:
                    await self._check_proxy_through(proxy)
                if proxy.alive:
                    alive_count += 1
                progress.update(task_id, advance=1, alive=alive_count)

            tasks = [verify_with_sem(p) for p in proxy_list]
            await asyncio.gather(*tasks)

        self.stats['verified_total'] = len(proxy_list)
        self.stats['verified_alive'] = alive_count

    async def _test_judge(
        self, session: aiohttp.ClientSession, url: str
    ) -> Optional[Tuple[str, float]]:
        try:
            start = time.monotonic()
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if len(text) < 2000:
                        latency = time.monotonic() - start
                        console.print(
                            f"  [green]✓[/] {url} — {latency*1000:.0f}ms"
                        )
                        return (url, latency)
        except Exception:
            pass
        return None

    async def _check_proxy_through(self, proxy: Proxy):
        proxy.check_count += 1
        proxy.last_checked = datetime.now(timezone.utc).isoformat()

        judge_url = self.judges[0][0]
        connect_timeout = self.config['general']['timeout_connect']
        total_timeout = self.config['general']['timeout_total']
        timeout_obj = aiohttp.ClientTimeout(
            total=total_timeout, connect=connect_timeout
        )

        connector = None
        session = None
        try:
            start_time = time.monotonic()

            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                connector = aiohttp_socks.ProxyConnector.from_url(
                    proxy.url, rdns=True
                )
                session = aiohttp.ClientSession(
                    connector=connector,
                    headers=self.headers,
                    timeout=timeout_obj,
                )
                async with session.get(judge_url) as resp:
                    latency_ms = int(
                        (time.monotonic() - start_time) * 1000
                    )
                    if resp.status == 200:
                        body = await resp.text()
                        if self._validate_judge_response(
                            body, proxy, latency_ms
                        ):
                            await self._check_anonymity_through_session(
                                session, proxy
                            )

            else:
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(
                    connector=connector,
                    headers=self.headers,
                    timeout=timeout_obj,
                )
                async with session.get(
                    judge_url, proxy=proxy.url
                ) as resp:
                    latency_ms = int(
                        (time.monotonic() - start_time) * 1000
                    )
                    if resp.status == 200:
                        body = await resp.text()
                        if self._validate_judge_response(
                            body, proxy, latency_ms
                        ):
                            await self._check_anonymity_through_session(
                                session, proxy
                            )

        except (
            aiohttp.ClientError,
            aiohttp_socks.ProxyError,
            asyncio.TimeoutError,
            ConnectionRefusedError,
            ConnectionResetError,
            OSError,
            Exception,
        ):
            proxy.alive = False
        finally:
            if session:
                await session.close()
            await asyncio.sleep(0.01)

    def _validate_judge_response(
        self, body: str, proxy: Proxy, latency_ms: int
    ) -> bool:
        body = body.strip()
        if not body or len(body) > 5000:
            return False

        found_ip = None
        try:
            data = json.loads(body)
            found_ip = (
                data.get('origin')
                or data.get('ip')
                or data.get('query')
            )
        except (json.JSONDecodeError, AttributeError):
            pass

        if not found_ip:
            ip_match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body
            )
            if ip_match:
                found_ip = ip_match.group(1)

        if not found_ip:
            return False

        if self.my_ip and found_ip.strip() == self.my_ip:
            proxy.alive = False
            return False

        proxy.alive = True
        proxy.latency_ms = latency_ms
        proxy.success_count += 1
        return True

    async def _check_anonymity_through_session(
        self, session: aiohttp.ClientSession, proxy: Proxy
    ):
        if not self.my_ip:
            proxy.anonymity = AnonymityLevel.ANONYMOUS
            return

        try:
            headers_judge = "http://httpbin.org/headers"

            if proxy.protocol in (
                ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5
            ):
                async with session.get(headers_judge) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._classify_anonymity(data, proxy)
            else:
                async with session.get(
                    headers_judge, proxy=proxy.url
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._classify_anonymity(data, proxy)

        except Exception:
            proxy.anonymity = AnonymityLevel.ANONYMOUS

    def _classify_anonymity(
        self, headers_response: dict, proxy: Proxy
    ):
        headers = headers_response.get('headers', {})
        all_values = ' '.join(str(v) for v in headers.values()).lower()

        if self.my_ip and self.my_ip in all_values:
            proxy.anonymity = AnonymityLevel.TRANSPARENT
            return

        proxy_headers = [
            'Via', 'X-Forwarded-For', 'X-Forwarded-Host',
            'X-Forwarded-Proto', 'Forwarded',
            'X-Real-Ip', 'X-Proxy-Id', 'Proxy-Connection',
        ]
        for ph in proxy_headers:
            if ph in headers or ph.lower() in headers:
                proxy.anonymity = AnonymityLevel.ANONYMOUS
                return

        proxy.anonymity = AnonymityLevel.ELITE

    def enrich_and_categorize(self):
        alive_proxies = [p for p in self.proxies.values() if p.alive]

        for proxy in alive_proxies:
            if self.geoip_city_reader:
                try:
                    city_data = self.geoip_city_reader.city(proxy.ip)
                    proxy.country_code = city_data.country.iso_code
                    proxy.country_name = city_data.country.name
                    proxy.city = city_data.city.name
                except Exception:
                    pass

            if self.geoip_asn_reader:
                try:
                    asn_data = self.geoip_asn_reader.asn(proxy.ip)
                    proxy.asn = asn_data.autonomous_system_number
                    proxy.isp = asn_data.autonomous_system_organization
                    if proxy.asn in BLACKLISTED_ASN_SET:
                        proxy.is_datacenter = True
                except Exception:
                    pass

            if proxy.latency_ms is not None:
                fast_thresh = self.config['output']['fast_threshold_ms']
                if proxy.latency_ms < fast_thresh:
                    proxy.speed_tier = SpeedTier.FAST
                elif proxy.latency_ms < 2000:
                    proxy.speed_tier = SpeedTier.MEDIUM
                else:
                    proxy.speed_tier = SpeedTier.SLOW

            if proxy.check_count > 0:
                proxy.reliability = round(
                    proxy.success_count / proxy.check_count, 2
                )

    def export(self):
        output_dir = Path(self.config['output']['dir'])
        output_dir.mkdir(exist_ok=True)

        alive = sorted(
            [p for p in self.proxies.values() if p.alive],
            key=lambda p: p.latency_ms or 99999,
        )

        if not alive:
            console.print(
                "[yellow]No alive proxies to export.[/yellow]"
            )
            return

        console.print(
            f"\n[bold cyan]Exporting {len(alive)} alive proxies...[/bold cyan]"
        )

        if 'json' in self.config['output']['formats']:
            path = output_dir / "all.json"
            with open(path, 'w') as f:
                json.dump([p.to_dict() for p in alive], f, indent=2)
            console.print(f"  [green]✓[/] {path} ({len(alive)} proxies)")

        if 'csv' in self.config['output']['formats']:
            path = output_dir / "all.csv"
            if alive:
                fieldnames = list(alive[0].to_dict().keys())
                with open(path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for p in alive:
                        writer.writerow(p.to_dict())
            console.print(f"  [green]✓[/] {path} ({len(alive)} proxies)")

        if 'txt' in self.config['output']['formats']:
            if self.config['output']['split_by_protocol']:
                for proto in ProxyProtocol:
                    proto_list = [
                        p for p in alive if p.protocol == proto
                    ]
                    path = output_dir / f"{proto.value}.txt"
                    with open(path, 'w') as f:
                        f.write('\n'.join(p.address for p in proto_list))
                    if proto_list:
                        console.print(
                            f"  [green]✓[/] {path} "
                            f"({len(proto_list)} proxies)"
                        )
            else:
                path = output_dir / "all.txt"
                with open(path, 'w') as f:
                    f.write('\n'.join(p.address for p in alive))
                console.print(f"  [green]✓[/] {path} ({len(alive)} proxies)")

        if self.config['output']['generate_elite_list']:
            elite = [
                p for p in alive
                if p.anonymity == AnonymityLevel.ELITE
            ]
            path = output_dir / "elite.txt"
            with open(path, 'w') as f:
                f.write('\n'.join(p.address for p in elite))
            console.print(f"  [green]✓[/] {path} ({len(elite)} proxies)")

        if self.config['output']['generate_fast_list']:
            fast = [
                p for p in alive
                if p.speed_tier == SpeedTier.FAST
            ]
            path = output_dir / "fast.txt"
            with open(path, 'w') as f:
                f.write('\n'.join(p.address for p in fast))
            console.print(f"  [green]✓[/] {path} ({len(fast)} proxies)")

    def print_stats(self):
        alive = [p for p in self.proxies.values() if p.alive]
        total = len(self.proxies) + self.stats['filtered_pre_verify']

        console.print()

        table = Table(
            title="🏆 UPO — Ultimate Proxy Operator — Results",
            show_header=False,
            border_style="bold blue",
        )
        table.add_column("Metric", style="cyan", width=25)
        table.add_column("Value", style="bold white", width=50)

        table.add_row(
            "Total Raw Collected",
            f"{total:,}",
        )
        table.add_row(
            "Garbage Filtered",
            f"[red]-{self.stats['filtered_pre_verify']:,}[/red] "
            f"(Cloudflare, private, CDN, etc.)",
        )
        table.add_row(
            "Candidates Verified",
            f"{self.stats.get('verified_total', len(self.proxies)):,}",
        )

        alive_pct = (
            f"{len(alive)/self.stats['verified_total']:.1%}"
            if self.stats.get('verified_total')
            else "N/A"
        )
        table.add_row(
            "✅ ALIVE",
            f"[bold green]{len(alive):,}[/bold green] ({alive_pct})",
        )
        table.add_row("─" * 20, "─" * 40)

        if alive:
            pc = Counter(p.protocol for p in alive)
            table.add_row(
                "By Protocol",
                f"HTTP: {pc.get(ProxyProtocol.HTTP, 0)} │ "
                f"HTTPS: {pc.get(ProxyProtocol.HTTPS, 0)} │ "
                f"S4: {pc.get(ProxyProtocol.SOCKS4, 0)} │ "
                f"S5: {pc.get(ProxyProtocol.SOCKS5, 0)}",
            )

            ac = Counter(p.anonymity for p in alive if p.anonymity)
            table.add_row(
                "By Anonymity",
                f"[bold green]Elite: "
                f"{ac.get(AnonymityLevel.ELITE, 0)}[/bold green] │ "
                f"Anon: {ac.get(AnonymityLevel.ANONYMOUS, 0)} │ "
                f"Trans: {ac.get(AnonymityLevel.TRANSPARENT, 0)}",
            )

            sc = Counter(p.speed_tier for p in alive if p.speed_tier)
            table.add_row(
                "By Speed",
                f"[bold green]Fast: "
                f"{sc.get(SpeedTier.FAST, 0)}[/bold green] │ "
                f"Medium: {sc.get(SpeedTier.MEDIUM, 0)} │ "
                f"Slow: {sc.get(SpeedTier.SLOW, 0)}",
            )

            cc = Counter(
                p.country_code for p in alive if p.country_code
            ).most_common(10)
            if cc:
                table.add_row("─" * 20, "─" * 40)
                table.add_row(
                    "Top Countries",
                    ' │ '.join(
                        f"{code}({cnt})" for code, cnt in cc
                    ),
                )

            latencies = [
                p.latency_ms for p in alive if p.latency_ms
            ]
            if latencies:
                avg_lat = sum(latencies) / len(latencies)
                min_lat = min(latencies)
                max_lat = max(latencies)
                table.add_row(
                    "Latency",
                    f"Avg: {avg_lat:.0f}ms │ "
                    f"Min: {min_lat}ms │ Max: {max_lat}ms",
                )

        console.print(Panel(table, border_style="bold blue"))


# ==============================================================================
# SECTION 4: CRAWL4AI SCRAPERS
# ==============================================================================

async def run_crawl4ai(config: Dict[str, Any]):
    # MOCKED FOR BREVITY AS PER THE V2 FILE - USER SPECIFIED 'NO NO CRAWL4AI' ABOVE ANYWAY
    pass

# ==============================================================================
# SECTION 5: CLI & ORCHESTRATOR
# ==============================================================================

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option(
    '--config', 'config_path', default='config.yaml',
    help='Path to YAML config file.',
)
@click.option(
    '--scrape-only', is_flag=True,
    help='Collect proxies without verifying them.',
)
@click.option(
    '--no-crawl4ai', is_flag=True,
    help='Skip Crawl4AI browser-based scrapers.',
)
@click.option(
    '--concurrency', default=None, type=int,
    help='Number of concurrent verification workers.',
)
@click.option(
    '--timeout', default=None, type=int,
    help='Total timeout per proxy check (seconds).',
)
@click.option(
    '--test-limit', default=None, type=int,
    help='Limit testing to N proxies.',
)
def main(config_path, scrape_only, no_crawl4ai, concurrency, timeout, test_limit):
    """🏆 UPO — Ultimate Proxy Operator"""
    banner = """
[bold blue]
 ██╗   ██╗██████╗  ██████╗ 
 ██║   ██║██╔══██╗██╔═══██╗
 ██║   ██║██████╔╝██║   ██║
 ██║   ██║██╔═══╝ ██║   ██║
 ╚██████╔╝██║     ╚██████╔╝
  ╚═════╝ ╚═╝      ╚═════╝ 
[/bold blue]
[dim]Ultimate Proxy Operator — Scrape · Verify · Categorize[/dim]
"""
    console.print(Panel(banner, border_style="bold blue", expand=False))

    config = DEFAULT_CONFIG.copy()
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                user_cfg = yaml.safe_load(f)
            if user_cfg:
                for k, v in user_cfg.items():
                    if isinstance(v, dict) and k in config:
                        config[k].update(v)
                    else:
                        config[k] = v
        except Exception:
            pass

    if concurrency:
        config['general']['concurrency'] = concurrency
    if timeout:
        config['general']['timeout_total'] = timeout
    if no_crawl4ai:
        config['crawl4ai']['enabled'] = False
    
    if test_limit:
        config['test_limit'] = test_limit

    asyncio.run(pipeline(config, scrape_only))


async def pipeline(config: Dict[str, Any], scrape_only: bool):
    start = time.monotonic()

    engine = UPOEngine(config)
    await engine.initialize()

    console.print("\n[bold cyan]═══ PHASE 1: COLLECTION ═══[/bold cyan]")
    await engine.collect()
    console.print(
        f"[green]✓[/] Collected {len(engine.proxies):,} unique proxies "
        f"from {len(GITHUB_HTTP_SOURCES) + len(GITHUB_SOCKS4_SOURCES) + len(GITHUB_SOCKS5_SOURCES) + len(API_SOURCES)} sources."
    )

    console.print("\n[bold cyan]═══ PHASE 2: FILTERING ═══[/bold cyan]")
    engine.filter_garbage()

    if not scrape_only:
        console.print(
            "\n[bold cyan]═══ PHASE 3: VERIFICATION ═══[/bold cyan]"
        )
        await engine.verify()

        console.print(
            "\n[bold cyan]═══ PHASE 4: ENRICHMENT ═══[/bold cyan]"
        )
        engine.enrich_and_categorize()
        alive_count = sum(
            1 for p in engine.proxies.values() if p.alive
        )
        console.print(
            f"[green]✓[/] Enriched {alive_count:,} alive proxies "
            f"with GeoIP & categories."
        )
    else:
        console.print(
            "\n[yellow]⏭ --scrape-only: "
            "Skipping verification.[/yellow]"
        )

    console.print("\n[bold cyan]═══ PHASE 5: EXPORT ═══[/bold cyan]")
    engine.export()

    engine.print_stats()

    elapsed = time.monotonic() - start
    console.print(
        f"\n[bold]⏱ Total time: {elapsed:.1f} seconds[/bold]"
    )

if __name__ == "__main__":
    main()