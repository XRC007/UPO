# ==============================================================================
#
# ██╗   ██╗██████╗  ██████╗    ██╗   ██╗███████╗    ███████╗██╗██╗  ██╗
# ██║   ██║██╔══██╗██╔═══██╗   ██║   ██║██╔════╝    ██╔════╝██║╚██╗██╔╝
# ██║   ██║██████╔╝██║   ██║   ██║   ██║███████╗    █████╗  ██║ ╚███╔╝
# ██║   ██║██╔═══╝ ██║   ██║   ╚██╗ ██╔╝╚════██║    ██╔══╝  ██║ ██╔██╗
# ╚██████╔╝██║     ╚██████╔╝    ╚████╔╝ ███████║    ██║     ██║██╔╝ ██╗
#  ╚═════╝ ╚═╝      ╚═════╝      ╚═══╝  ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝
#
# UPO v5-fix2 — All review fixes applied
#
# FIX #1: Stealth score recalculated AFTER fraud scoring in categorize phase
# FIX #2: Reliability threshold > 0.5 for 2-round mode (requires 2/2 pass)
# FIX #3: Judge rotation across modules (verify/anon/protocol/speed use different judges)
# FIX #4: detected_protocols deduplicated
# FIX #5: Anonymity check uses shorter 5s timeout
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
import sqlite3
import hashlib
import copy
import threading
import random
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple
from collections import Counter
from pathlib import Path
from ipaddress import ip_address, ip_network

import click
import geoip2.database
import yaml
from rich.console import Console
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

CRAWL4AI_INSTALL_PATH = r"D:\3dAI\Data Analyze"
console = Console()

# ==============================================================================
# SECTION 0: CONFIG & SOURCES
# ==============================================================================

DEFAULT_CONFIG = {
    "general": {
        "concurrency": 300,
        "timeout_connect": 8,
        "timeout_total": 15,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "verification_rounds": 2,
    },
    "judges": {
        "urls": [
            "http://httpbin.org/ip",
            "http://api.ipify.org",
            "http://icanhazip.com",
            "http://checkip.amazonaws.com",
            "http://myexternalip.com/raw",
            "http://ip-api.com/json",
            "http://httpbin.org/headers",
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "http://ipecho.net/plain",
            "http://whatismyip.akamai.com",
        ]
    },
    "geoip": {
        "enabled": True,
        "city_db": "data/GeoLite2-City.mmdb",
        "asn_db": "data/GeoLite2-ASN.mmdb",
    },
    "filter": {
        "blacklist": "data/blacklist.txt",
        "allowed_countries": [],
        "blocked_countries": [],
        "exclude_datacenters": False,
        "min_anonymity": None,
    },
    "output": {
        "dir": "output",
        "formats": ["txt", "json", "csv"],
        "split_by_protocol": True,
        "generate_elite_list": True,
        "generate_fast_list": True,
        "fast_threshold_ms": 500,
        "split_by_country": False,
        "generate_residential_list": True,
        "generate_mobile_list": True,
        "generate_stealth_list": True,
        "generate_clean_list": True,
    },
    "crawl4ai": {
        "enabled": True,
        "output_file": "output/crawled_proxies.json",
    },
    "ban_check": {
        "enabled": True,
        "sites": [
            {"name": "google", "url": "https://www.google.com/search?q=test",
             "success_pattern": "google"},
            {"name": "bing", "url": "https://www.bing.com/search?q=test",
             "success_pattern": "bing"},
        ],
    },
    "speed_test": {
        "enabled": True,
        "test_url": "https://speed.cloudflare.com/__down?bytes=102400",
        "test_size_bytes": 102400,
    },
    "fraud_check": {
        "enabled": False,
        "top_n": 100,
        "keys": {
            "ipinfo": os.getenv("API_IPINFO", ""),
            "iphub": os.getenv("API_IPHUB", ""),
            "getipintel_email": os.getenv("API_GETIPINTEL_EMAIL", ""),
            "ipqs": os.getenv("API_IPQS", ""),
        },
    },
    "dns_leak": {"enabled": True},
    "protocol_detection": {"enabled": True},
    "stealth_score": {"enabled": True},
    "history": {"enabled": True, "db_path": "data/proxy_history.db"},
    "verified_db": {"enabled": True, "db_path": "data/verified_proxies.db"},
    "checked_output": {"enabled": True, "dir": "checked"},
    "api": {"enabled": False, "host": "127.0.0.1", "port": 8000},
}

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
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
    "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
    "https://raw.githubusercontent.com/aslisk/proxyhttps/main/https.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/https_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/https.txt",
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
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks4.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/socks4.txt",
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
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks5.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/socks5.txt",
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
    {"url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc", "protocol": "mixed", "format": "json"},
    {"url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=3&sort_by=lastChecked&sort_type=desc", "protocol": "mixed", "format": "json"},
]

DATACENTER_ASNS: Set[int] = {
    16509, 14618, 15169, 396982, 36492, 8075, 8068, 8069,
    45102, 37963, 45096, 14061, 63949, 63018, 20473, 20454,
    24940, 16276, 35540, 31898, 7160, 19994, 46606, 53831,
    32244, 36351, 3223, 30633, 51167, 60781, 197540, 55286,
    54825, 12876, 9009, 202422, 60068, 131199, 51396, 41436,
    62240, 42831, 398101, 26496, 174, 3356, 6939,
}
RESIDENTIAL_ASNS: Set[int] = {
    7922, 20115, 22773, 7018, 701, 3320, 12322, 3215,
    5089, 2856, 4134, 4837, 9299, 17676, 4755, 9121,
    6830, 6805, 3269, 12479, 8151, 10481, 11351, 4788,
    45609, 55410, 24560, 9829, 18881, 28573, 27699, 8167,
}
MOBILE_ASNS: Set[int] = {
    21928, 7065, 6167, 10507, 23089, 12430, 6739, 25135,
    15480, 8412, 12529, 20801, 21334, 45271, 55836, 17421,
    23969, 132199, 10139, 4818, 9808, 56040, 56041, 56042,
    36935, 37457, 33771, 15802, 39386, 26615, 27747,
}
CDN_ASNS: Set[int] = {
    13335, 209242, 20940, 16625, 54113, 15133, 22822, 2906,
}
CLOUDFLARE_IP_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
PROXY_REGEX = re.compile(
    r"(?:(?P<protocol>https?|socks[45])://)?"
    r"(?:[\w.-]+:[\w.-]+@)?"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{2,5})"
)


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

class ProxyType(str, Enum):
    RESIDENTIAL = "residential"
    DATACENTER = "datacenter"
    MOBILE = "mobile"
    UNKNOWN = "unknown"

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


# ==============================================================================
# SECTION 2: IP FILTER
# ==============================================================================

class IPFilter:
    def __init__(self):
        self.cf_networks = [ip_network(c) for c in CLOUDFLARE_IP_RANGES]
        self.private_networks = [
            ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"), ip_network("127.0.0.0/8"),
            ip_network("0.0.0.0/8"), ip_network("169.254.0.0/16"),
            ip_network("224.0.0.0/4"), ip_network("240.0.0.0/4"),
            ip_network("100.64.0.0/10"),
        ]

    def is_cloudflare(self, ip_str: str) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in n for n in self.cf_networks)
        except ValueError:
            return True

    def is_private(self, ip_str: str) -> bool:
        try:
            addr = ip_address(ip_str)
            return any(addr in n for n in self.private_networks)
        except ValueError:
            return True

    def filter_batch(
        self, proxies: Dict[str, "Proxy"], config: Dict
    ) -> Tuple[Dict[str, "Proxy"], Dict[str, int]]:
        valid = {}
        stats: Counter = Counter()
        for addr, p in proxies.items():
            try:
                ip_address(p.ip)
            except ValueError:
                stats["invalid_ip"] += 1
                continue
            if self.is_private(p.ip):
                stats["private_ip"] += 1
                continue
            if self.is_cloudflare(p.ip):
                stats["cloudflare_ip"] += 1
                continue
            if p.port < 1 or p.port > 65535:
                stats["invalid_port"] += 1
                continue
            allowed = config["filter"].get("allowed_countries", [])
            blocked = config["filter"].get("blocked_countries", [])
            if allowed and p.country_code and p.country_code not in allowed:
                stats["country_filtered"] += 1
                continue
            if blocked and p.country_code and p.country_code in blocked:
                stats["country_blocked"] += 1
                continue
            valid[addr] = p
        return valid, dict(stats)


# ==============================================================================
# SECTION 3: HISTORY DB
# ==============================================================================

class ProxyHistory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS proxies (
            id TEXT PRIMARY KEY, ip TEXT, port INT, protocol TEXT,
            first_seen TEXT, last_seen TEXT, last_alive TEXT,
            total_checks INT DEFAULT 0, successful_checks INT DEFAULT 0,
            avg_latency REAL, country TEXT, asn INT, isp TEXT, proxy_type TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, proxy_id TEXT,
            checked_at TEXT, alive INT, latency INT, anonymity TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS api_cache (
            ip TEXT PRIMARY KEY, checked_at TEXT, composite_score INT,
            raw_data TEXT)""")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_checks_pid ON checks(proxy_id)"
        )
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def update(self, proxy: "Proxy"):
        conn = self._conn()
        try:
            c = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            c.execute("SELECT id FROM proxies WHERE id=?", (proxy.id,))
            if c.fetchone():
                c.execute(
                    """UPDATE proxies SET last_seen=?,
                    last_alive=CASE WHEN ?=1 THEN ? ELSE last_alive END,
                    total_checks=total_checks+1,
                    successful_checks=successful_checks+?,
                    avg_latency=CASE
                        WHEN ? IS NOT NULL AND avg_latency IS NOT NULL
                        THEN (avg_latency+?)/2
                        WHEN ? IS NOT NULL THEN ?
                        ELSE avg_latency END,
                    country=COALESCE(?,country), asn=COALESCE(?,asn),
                    isp=COALESCE(?,isp), proxy_type=COALESCE(?,proxy_type)
                    WHERE id=?""",
                    (now, 1 if proxy.alive else 0, now,
                     1 if proxy.alive else 0,
                     proxy.latency_ms, proxy.latency_ms,
                     proxy.latency_ms, proxy.latency_ms,
                     proxy.country_code, proxy.asn, proxy.isp,
                     proxy.proxy_type.value if proxy.proxy_type else None,
                     proxy.id),
                )
            else:
                c.execute(
                    "INSERT INTO proxies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (proxy.id, proxy.ip, proxy.port, proxy.protocol.value,
                     proxy.first_seen, now, now if proxy.alive else None,
                     1, 1 if proxy.alive else 0, proxy.latency_ms,
                     proxy.country_code, proxy.asn, proxy.isp,
                     proxy.proxy_type.value if proxy.proxy_type else None),
                )
            c.execute(
                "INSERT INTO checks (proxy_id,checked_at,alive,latency,anonymity) VALUES (?,?,?,?,?)",
                (proxy.id, now, 1 if proxy.alive else 0, proxy.latency_ms,
                 proxy.anonymity.value if proxy.anonymity else None),
            )
            conn.commit()
        except sqlite3.Error as e:
            console.print(f"[dim red]DB write error: {e}[/dim red]")
        finally:
            conn.close()

    def get_cached_score(self, ip: str) -> Optional[int]:
        conn = self._conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT checked_at, composite_score FROM api_cache WHERE ip=?",
                (ip,),
            )
            row = c.fetchone()
            if row and row[1] is not None:
                checked = datetime.fromisoformat(row[0])
                if (datetime.now(timezone.utc) - checked).total_seconds() < 86400:
                    return row[1]
        except Exception:
            pass
        finally:
            conn.close()
        return None

    def save_cached_score(self, ip: str, score: int):
        conn = self._conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.cursor().execute(
                """INSERT INTO api_cache (ip, checked_at, composite_score)
                VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET
                checked_at=excluded.checked_at,
                composite_score=excluded.composite_score""",
                (ip, now, score),
            )
            conn.commit()
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        conn = self._conn()
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM proxies")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM checks")
            checks = c.fetchone()[0]
            return {"total_tracked": total, "total_checks": checks}
        finally:
            conn.close()


# ==============================================================================
# SECTION 3B: VERIFIED PROXY DB
# ==============================================================================

class VerifiedProxyDB:
    """Stores only working proxies. Wiped and rewritten each run."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS verified (
            address TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            port INT NOT NULL,
            protocol TEXT NOT NULL,
            last_verified TEXT,
            latency_ms INT,
            country_code TEXT,
            anonymity TEXT,
            proxy_type TEXT)""")
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def load_all(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT ip, port, protocol FROM verified"
            ).fetchall()
            return [
                {"ip": r[0], "port": r[1], "protocol": r[2]}
                for r in rows
            ]
        finally:
            conn.close()

    def save_all(self, proxies: List["Proxy"]):
        conn = self._conn()
        try:
            conn.execute("DELETE FROM verified")
            now = datetime.now(timezone.utc).isoformat()
            for p in proxies:
                conn.execute(
                    """INSERT OR REPLACE INTO verified
                    (address, ip, port, protocol, last_verified,
                     latency_ms, country_code, anonymity, proxy_type)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (p.address, p.ip, p.port, p.protocol.value, now,
                     p.latency_ms, p.country_code,
                     p.anonymity.value if p.anonymity else None,
                     p.proxy_type.value if p.proxy_type else None),
                )
            conn.commit()
        except sqlite3.Error as e:
            console.print(f"[dim red]VerifiedDB write error: {e}[/dim red]")
        finally:
            conn.close()

    def count(self) -> int:
        conn = self._conn()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM verified"
            ).fetchone()[0]
        finally:
            conn.close()


# ==============================================================================
# SECTION 4: RATE LIMITER
# ==============================================================================

class RateLimiter:
    def __init__(self, calls_per_min: float):
        self.interval = 60.0 / calls_per_min if calls_per_min > 0 else 0
        self.last_call = 0.0
        self._lock: Optional[asyncio.Lock] = None

    async def wait(self):
        if self.interval <= 0:
            return
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_call
            if elapsed < self.interval:
                await asyncio.sleep(self.interval - elapsed)
            self.last_call = time.monotonic()


# ==============================================================================
# SECTION 5: CORE ENGINE
# ==============================================================================

class UPOEngine:
    def __init__(self, config: Dict):
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

    # ── Collection ────────────────────────────────────────────────────────

    async def collect(self):
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100, ssl=False)
        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout, connector=connector
        ) as session:
            tasks = []
            for url in GITHUB_HTTP_SOURCES:
                tasks.append(self._fetch(session, url, ProxyProtocol.HTTP))
            for url in GITHUB_SOCKS4_SOURCES:
                tasks.append(self._fetch(session, url, ProxyProtocol.SOCKS4))
            for url in GITHUB_SOCKS5_SOURCES:
                tasks.append(self._fetch(session, url, ProxyProtocol.SOCKS5))
            for api in API_SOURCES:
                proto = api["protocol"]
                if proto == "mixed":
                    proto = "http"
                tasks.append(
                    self._fetch(
                        session, api["url"], ProxyProtocol(proto),
                        api.get("format"),
                    )
                )

            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"),
                BarColumn(), MofNCompleteColumn(), transient=True,
            ) as prog:
                tid = prog.add_task(
                    "[cyan]Fetching sources...", total=len(tasks)
                )
                for coro in asyncio.as_completed(tasks):
                    await coro
                    prog.update(tid, advance=1)

        cf = self.config["crawl4ai"]["output_file"]
        if self.config["crawl4ai"]["enabled"] and os.path.exists(cf):
            try:
                with open(cf) as f:
                    crawled = json.load(f)
                count = 0
                for p in crawled:
                    try:
                        px = Proxy(
                            ip=p["ip"].strip(), port=int(p["port"]),
                            protocol=ProxyProtocol(
                                p.get("protocol", "http")
                            ),
                            source=p.get("source", "crawl4ai"),
                        )
                        if px.address not in self.proxies:
                            self.proxies[px.address] = px
                            count += 1
                    except (ValueError, KeyError):
                        continue
                if count:
                    console.print(
                        f"  [green]✓[/] Crawl4AI: {count} proxies."
                    )
            except Exception as e:
                console.print(f"  [yellow]⚠[/] Crawl4AI error: {e}")

        # ── Load previously verified working proxies for re-check ─
        if self.verified_db:
            prev = self.verified_db.load_all()
            loaded = 0
            for row in prev:
                try:
                    px = Proxy(
                        ip=row["ip"], port=int(row["port"]),
                        protocol=ProxyProtocol(row["protocol"]),
                        source="verified_db",
                    )
                    if px.address not in self.proxies:
                        self.proxies[px.address] = px
                        loaded += 1
                except (ValueError, KeyError):
                    continue
            if loaded:
                console.print(
                    f"  [green]✓[/] Verified DB: {loaded} previously "
                    f"working proxies loaded for re-check."
                )

        self.stats["collected_raw"] = len(self.proxies)

    async def _fetch(
        self, session: aiohttp.ClientSession, url: str,
        proto: ProxyProtocol, fmt: Optional[str] = None,
    ):
        for attempt in range(3):
            try:
                async with session.get(url, ssl=False) as r:
                    if r.status != 200:
                        return
                    content = await r.text()
                    source = url.split("/")[2] if "/" in url else url
                    if fmt == "json":
                        self._parse_json(content, source)
                    else:
                        self._parse_text(content, proto, source)
                    return
            except asyncio.TimeoutError:
                if attempt < 2:
                    await asyncio.sleep(1 + attempt)
            except Exception:
                return

    def _parse_text(self, content: str, proto: ProxyProtocol, source: str):
        for m in PROXY_REGEX.finditer(content):
            try:
                ip = m.group("ip")
                port = int(m.group("port"))
                ps = m.group("protocol")
                protocol = ProxyProtocol(ps) if ps else proto
                px = Proxy(
                    ip=ip, port=port, protocol=protocol, source=source
                )
                if px.address not in self.proxies:
                    self.proxies[px.address] = px
            except (ValueError, KeyError):
                continue

    def _parse_json(self, content: str, source: str):
        try:
            data = json.loads(content)
            items = data.get("data", []) if isinstance(data, dict) else data
            for it in items:
                try:
                    ip = it.get("ip", "").strip()
                    port = int(it.get("port", 0))
                    protocols = it.get("protocols", ["http"])
                    pr = protocols[0].lower() if protocols else "http"
                    px = Proxy(
                        ip=ip, port=port, protocol=ProxyProtocol(pr),
                        source=source,
                    )
                    if px.address not in self.proxies:
                        self.proxies[px.address] = px
                except (ValueError, KeyError):
                    continue
        except json.JSONDecodeError:
            pass

    # ── Pre-Enrich ────────────────────────────────────────────────────────

    def pre_enrich(self):
        for p in self.proxies.values():
            if self.geoip_asn:
                try:
                    asn_data = self.geoip_asn.asn(p.ip)
                    p.asn = asn_data.autonomous_system_number
                    p.isp = asn_data.autonomous_system_organization
                    if p.asn in CDN_ASNS:
                        p.proxy_type = ProxyType.DATACENTER
                    elif p.asn in MOBILE_ASNS:
                        p.proxy_type = ProxyType.MOBILE
                    elif p.asn in DATACENTER_ASNS:
                        p.proxy_type = ProxyType.DATACENTER
                    elif p.asn in RESIDENTIAL_ASNS:
                        p.proxy_type = ProxyType.RESIDENTIAL
                except Exception:
                    pass
            if self.geoip_city:
                try:
                    c = self.geoip_city.city(p.ip)
                    p.country_code = c.country.iso_code
                    p.country_name = c.country.name
                    p.city = c.city.name
                    if c.subdivisions:
                        p.region = c.subdivisions.most_specific.name
                except Exception:
                    pass

    # ── Filter ────────────────────────────────────────────────────────────

    def filter_garbage(self):
        before = len(self.proxies)
        self.proxies, rstats = self.ip_filter.filter_batch(
            self.proxies, self.config
        )
        cdn_rm = [
            a for a, p in self.proxies.items()
            if p.asn and p.asn in CDN_ASNS
        ]
        for a in cdn_rm:
            del self.proxies[a]
        rstats["cdn_asn"] = len(cdn_rm)

        bl_rm = [
            a for a, p in self.proxies.items() if p.ip in self.blacklist
        ]
        for a in bl_rm:
            del self.proxies[a]
        rstats["blacklisted"] = len(bl_rm)

        if self.config["filter"].get("exclude_datacenters"):
            dc_rm = [
                a for a, p in self.proxies.items()
                if p.proxy_type == ProxyType.DATACENTER
            ]
            for a in dc_rm:
                del self.proxies[a]
            rstats["datacenter"] = len(dc_rm)

        after = len(self.proxies)
        self.stats["filtered"] = before - after
        console.print(
            f"\n[bold cyan]Pre-Verification Filter:[/bold cyan]"
        )
        console.print(
            f"  Before: {before:,} → After: {after:,} "
            f"([red]-{before - after:,}[/red])"
        )
        for reason, count in sorted(rstats.items(), key=lambda x: -x[1]):
            if count > 0:
                console.print(f"    [red]✗[/] {reason}: {count:,}")

    # ── Judge Testing ─────────────────────────────────────────────────────

    async def test_judges(self):
        console.print("\n[cyan]Testing judge servers...[/cyan]")
        timeout = aiohttp.ClientTimeout(total=10)
        results = []
        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout
        ) as session:
            for url in self.config["judges"]["urls"]:
                try:
                    start = time.monotonic()
                    async with session.get(url) as r:
                        if r.status == 200:
                            text = await r.text()
                            if len(text) < 2000:
                                latency = time.monotonic() - start
                                results.append((url, latency))
                except Exception:
                    continue

        # Remove httpbin judges from rotation pool since anonymity
        # module always hits httpbin.org/headers directly.
        # This prevents double-hammering httpbin from both
        # the anonymity module AND verification/protocol modules.
        filtered = [
            (url, lat) for url, lat in results
            if "httpbin.org" not in url
        ]
        # Fall back to unfiltered if all non-httpbin judges failed
        self.judges = sorted(
            filtered if filtered else results,
            key=lambda x: x[1],
        )[:5]
        if self.judges:
            console.print(
                f"[green]✓[/] {len(self.judges)} judges online. "
                f"Fastest: {self.judges[0][0]} "
                f"({self.judges[0][1]*1000:.0f}ms)"
            )
            # FIX #3: Show judge assignment plan
            labels = ["verify", "anonymity", "protocol", "speed/ban/fp"]
            for i, label in enumerate(labels):
                j = self._get_judge(i)
                console.print(f"  [dim]{label} → {j}[/dim]")
        else:
            console.print("[bold red]✗ No judges reachable![/bold red]")

    # ── Verification ──────────────────────────────────────────────────────

    async def verify(self):
        if not self.proxies:
            return
        await self.test_judges()
        if not self.judges:
            console.print(
                "[bold red]FATAL: No judges reachable. "
                "Cannot verify proxies. Check your internet "
                "connection or judge URLs in config.[/bold red]"
            )
            console.print(
                "[yellow]Tip: Run with --scrape-only to skip "
                "verification and just collect proxies.[/yellow]"
            )
            return

        rounds = self.config["general"].get("verification_rounds", 1)

        for round_num in range(1, rounds + 1):
            if round_num == 1:
                to_check = list(self.proxies.values())
            else:
                to_check = [
                    p for p in self.proxies.values()
                    if p.success_count > 0
                ]
                if not to_check:
                    break
                for p in to_check:
                    p.alive = False
                console.print(
                    f"\n[cyan]Round {round_num}: Re-checking "
                    f"{len(to_check):,} proxies...[/cyan]"
                )
                await asyncio.sleep(3)

            sem = asyncio.Semaphore(self.config["general"]["concurrency"])
            alive_count = 0

            # FIX #3: Use verification judge (module 0), rotate per round
            judge_idx = (round_num - 1) % len(self.judges)
            judge_url = self.judges[judge_idx][0]

            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"),
                BarColumn(), MofNCompleteColumn(),
                TextColumn("│ Alive: {task.fields[alive]}"),
                TimeRemainingColumn(),
            ) as prog:
                tid = prog.add_task(
                    f"[cyan]Round {round_num}/{rounds}...",
                    total=len(to_check), alive=0,
                )

                async def worker(p):
                    nonlocal alive_count
                    async with sem:
                        await self._check_one(p, judge_url)
                    if p.alive:
                        alive_count += 1
                    prog.update(tid, advance=1, alive=alive_count)

                await asyncio.gather(*[worker(p) for p in to_check])

        # FIX #2: Smarter reliability threshold based on round count
        rounds = self.config["general"].get("verification_rounds", 1)
        for p in self.proxies.values():
            if p.check_count > 0:
                p.reliability = round(p.success_count / p.check_count, 2)
                if rounds <= 2:
                    # For 1-2 rounds: require ALL checks to pass
                    # 1 round: 1/1=1.0 (pass) or 0/1=0.0 (fail)
                    # 2 rounds: 2/2=1.0 (pass), 1/2=0.5 (FAIL), 0/2=0.0 (fail)
                    p.alive = p.reliability > 0.5
                else:
                    # For 3+ rounds: require majority to pass
                    # 3 rounds: 2/3=0.67 (pass), 1/3=0.33 (fail)
                    p.alive = p.reliability >= 0.5
            else:
                p.alive = False

        self.stats["verified_total"] = len(self.proxies)
        self.stats["verified_alive"] = sum(
            1 for p in self.proxies.values() if p.alive
        )

    async def _check_one(self, proxy: Proxy, judge_url: str):
        proxy.check_count += 1
        proxy.last_checked = datetime.now(timezone.utc).isoformat()
        timeout = aiohttp.ClientTimeout(
            total=self.config["general"]["timeout_total"],
            connect=self.config["general"]["timeout_connect"],
        )
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            proxy.alive = False
            proxy.fail_count += 1
            return
        try:
            start = time.monotonic()
            async with session.get(judge_url, **kwargs) as r:
                latency_ms = int((time.monotonic() - start) * 1000)
                if r.status == 200:
                    body = (await r.text()).strip()
                    self._validate_judge(body, proxy, latency_ms)
                else:
                    proxy.alive = False
                    proxy.fail_count += 1
        except Exception:
            proxy.alive = False
            proxy.fail_count += 1
        finally:
            await session.close()
            await asyncio.sleep(0.01)

    def _validate_judge(self, body: str, proxy: Proxy, latency_ms: int):
        if not body or len(body) > 5000:
            proxy.alive = False
            proxy.fail_count += 1
            return
        found_ip = None
        try:
            data = json.loads(body)
            found_ip = (
                data.get("origin") or data.get("ip") or data.get("query")
            )
        except (json.JSONDecodeError, AttributeError):
            pass
        if not found_ip:
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", body)
            if m:
                found_ip = m.group(1)
        if not found_ip:
            proxy.alive = False
            proxy.fail_count += 1
            return
        if self.my_ip and found_ip.strip() == self.my_ip:
            proxy.alive = False
            proxy.fail_count += 1
            return
        proxy.alive = True
        proxy.latency_ms = latency_ms
        proxy.success_count += 1
        proxy.uptime_history.append(True)
        if len(proxy.uptime_history) > 100:
            proxy.uptime_history = proxy.uptime_history[-100:]

    # ── Anonymity (FIX #3: uses judge module 1, FIX #5: 5s timeout) ──────

    async def check_anonymity(self):
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive or not self.my_ip:
            return

        console.print(
            f"\n[cyan]Anonymity check on {len(alive)} proxies...[/cyan]"
        )
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        # Anonymity MUST use httpbin.org/headers (only public judge
        # that returns full HTTP headers for Via/X-Forwarded-For analysis)
        console.print(f"  [dim]Using judge: httpbin.org/headers (required for header analysis)[/dim]")

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Anonymity...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._anon_check_one(p)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        ac = Counter(p.anonymity for p in alive if p.anonymity)
        console.print(
            f"[green]✓[/] Elite: {ac.get(AnonymityLevel.ELITE, 0)} │ "
            f"Anon: {ac.get(AnonymityLevel.ANONYMOUS, 0)} │ "
            f"Trans: {ac.get(AnonymityLevel.TRANSPARENT, 0)}"
        )

    async def _anon_check_one(self, proxy: Proxy):
        # FIX #5: Shorter 5s timeout for anonymity — httpbin is slow
        timeout = aiohttp.ClientTimeout(total=5, connect=3)
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            proxy.anonymity = AnonymityLevel.ANONYMOUS
            return
        try:
            # httpbin.org/headers is the only judge that returns full headers
            # so we must use it specifically here regardless of rotation
            url = "http://httpbin.org/headers"
            async with session.get(url, **kwargs) as r:
                if r.status == 200:
                    data = await r.json()
                    headers = data.get("headers", {})
                    all_vals = " ".join(str(v) for v in headers.values())

                    if self.my_ip and self.my_ip in all_vals:
                        proxy.anonymity = AnonymityLevel.TRANSPARENT
                        return

                    proxy_hdrs = [
                        "Via", "X-Forwarded-For", "X-Forwarded-Host",
                        "Forwarded", "X-Real-Ip", "X-Proxy-Id",
                        "Proxy-Connection",
                    ]
                    for h in proxy_hdrs:
                        if h in headers or h.lower() in headers:
                            proxy.anonymity = AnonymityLevel.ANONYMOUS
                            return

                    proxy.anonymity = AnonymityLevel.ELITE
                else:
                    proxy.anonymity = AnonymityLevel.ANONYMOUS
        except asyncio.TimeoutError:
            # httpbin timed out — default to anonymous, not crash
            proxy.anonymity = AnonymityLevel.ANONYMOUS
        except Exception as e:
            proxy.anonymity = AnonymityLevel.ANONYMOUS
            # Log only unusual errors (not connection resets which are normal)
            err_name = type(e).__name__
            if err_name not in ("ClientError", "ServerDisconnectedError",
                                "ClientOSError", "ClientConnectorError"):
                console.print(
                    f"[dim red]Anon check {proxy.address}: "
                    f"{err_name}[/dim red]"
                )
        finally:
            await session.close()

    # ── Protocol Detection (FIX #3: judge module 2, FIX #4: dedup) ────────

    async def detect_protocols(self):
        if not self.config["protocol_detection"]["enabled"]:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        # FIX #3: Use protocol detection judge (module 2)
        judge_url = self._get_judge(2)
        console.print(
            f"\n[cyan]Protocol detection on {len(alive)} proxies...[/cyan]"
        )
        console.print(f"  [dim]Using judge: {judge_url}[/dim]")
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Protocols...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._detect_protocols_one(p, judge_url)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        multi = sum(1 for p in alive if len(p.detected_protocols) > 1)
        console.print(f"[green]✓[/] {multi} proxies support 2+ protocols.")

    async def _detect_protocols_one(self, proxy: Proxy, judge_url: str):
        proxy.detected_protocols = []
        timeout = aiohttp.ClientTimeout(total=8, connect=5)
        for proto in [ProxyProtocol.SOCKS5, ProxyProtocol.SOCKS4,
                      ProxyProtocol.HTTPS, ProxyProtocol.HTTP]:
            test_proxy = Proxy(
                ip=proxy.ip, port=proxy.port, protocol=proto, source=""
            )
            session, kwargs = self._create_proxy_session(test_proxy, timeout)
            if not session:
                continue
            try:
                async with session.get(judge_url, **kwargs) as r:
                    if r.status == 200:
                        text = await r.text()
                        if re.search(r"\d+\.\d+\.\d+\.\d+", text):
                            proxy.detected_protocols.append(proto.value)
                            if proto == ProxyProtocol.HTTP:
                                try:
                                    async with session.get(
                                        "https://httpbin.org/ip", **kwargs
                                    ) as r2:
                                        if r2.status == 200:
                                            proxy.supports_https = True
                                except Exception:
                                    pass
            except Exception:
                pass
            finally:
                await session.close()

        # FIX #4: Deduplicate detected protocols
        proxy.detected_protocols = list(
            dict.fromkeys(proxy.detected_protocols)
        )

    # ── Speed Test (FIX #3: uses judge module 3 for the download) ─────────

    async def speed_test(self):
        if not self.config["speed_test"]["enabled"]:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        test_url = self.config["speed_test"]["test_url"]
        console.print(
            f"\n[cyan]Speed testing {len(alive)} proxies (100KB)...[/cyan]"
        )
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Speed test...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._speed_test_one(p, test_url)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        tested = [
            p for p in alive if p.download_speed_kbps is not None
        ]
        if tested:
            avg = sum(p.download_speed_kbps for p in tested) / len(tested)
            console.print(
                f"[green]✓[/] Tested {len(tested)}. "
                f"Avg: {avg:.1f} KB/s"
            )

    async def _speed_test_one(self, proxy: Proxy, test_url: str):
        timeout = aiohttp.ClientTimeout(total=20, connect=8)
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            return
        try:
            start = time.monotonic()
            async with session.get(test_url, **kwargs) as r:
                if r.status == 200:
                    data = await r.read()
                    elapsed = time.monotonic() - start
                    if elapsed > 0:
                        proxy.download_speed_kbps = round(
                            len(data) / 1024 / elapsed, 2
                        )
        except Exception:
            pass
        finally:
            await session.close()

    # ── TCP Fingerprint (FIX #3: uses judge module 3) ─────────────────────

    async def fingerprint(self):
        if not self.config["stealth_score"]["enabled"]:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        console.print(
            f"\n[cyan]TCP fingerprinting {len(alive)} proxies...[/cyan]"
        )
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Fingerprint...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._fingerprint_one(p)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        fp_counts = Counter(
            p.tcp_fingerprint for p in alive if p.tcp_fingerprint
        )
        console.print(
            f"[green]✓[/] Fingerprints: "
            + " │ ".join(f"{k}:{v}" for k, v in fp_counts.most_common())
        )

    async def _fingerprint_one(self, proxy: Proxy):
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            return
        try:
            async with session.get(
                "https://1.1.1.1/cdn-cgi/trace", **kwargs
            ) as r:
                if r.status == 200:
                    text = await r.text()
                    data = {}
                    for line in text.strip().split("\n"):
                        if "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip()
                    tls = data.get("tls", "")
                    http_ver = data.get("http", "")
                    if "TLSv1.3" in tls and "h2" in http_ver:
                        proxy.tcp_fingerprint = "modern"
                    elif "TLSv1.3" in tls:
                        proxy.tcp_fingerprint = "tls13"
                    elif "TLSv1.2" in tls:
                        proxy.tcp_fingerprint = "tls12_legacy"
                    else:
                        proxy.tcp_fingerprint = "unknown"
        except Exception:
            pass
        finally:
            await session.close()

    # FIX #1: Stealth calculation is now a SEPARATE method
    # called AFTER fraud scoring in the categorize phase
    def _calc_stealth(self, proxy: Proxy):
        """
        Composite stealth score 0-100.
        MUST be called AFTER fraud scoring so composite_score is available.
        """
        score = 0

        # Anonymity: 0-30
        if proxy.anonymity == AnonymityLevel.ELITE:
            score += 30
        elif proxy.anonymity == AnonymityLevel.ANONYMOUS:
            score += 15

        # Proxy type: 0-30
        if proxy.proxy_type == ProxyType.MOBILE:
            score += 30
        elif proxy.proxy_type == ProxyType.RESIDENTIAL:
            score += 25
        elif proxy.proxy_type == ProxyType.UNKNOWN:
            score += 15
        else:  # Datacenter
            score += 5

        # TCP fingerprint: 0-15
        if proxy.tcp_fingerprint == "modern":
            score += 15
        elif proxy.tcp_fingerprint == "tls13":
            score += 10
        elif proxy.tcp_fingerprint == "unknown":
            score += 5
        # tls12_legacy = 0

        # HTTPS support: 0-10
        if proxy.supports_https:
            score += 10

        # Speed bonus: 0-10
        if proxy.latency_ms and proxy.latency_ms < 500:
            score += 10
        elif proxy.latency_ms and proxy.latency_ms < 1000:
            score += 5

        # FIX #1: Fraud score adjustment NOW WORKS because
        # stealth is calculated after fraud in the pipeline
        if proxy.composite_score is not None:
            if proxy.composite_score <= 20:
                score += 5   # Clean IP bonus
            elif proxy.composite_score >= 80:
                score -= 10  # Known bad IP

        # DNS leak penalty
        if proxy.dns_leak is True:
            score -= 15

        proxy.stealth_score = max(0, min(100, score))

    # ── DNS Leak ──────────────────────────────────────────────────────────

    async def dns_leak_check(self):
        if not self.config["dns_leak"]["enabled"] or not self.my_ip:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        console.print(
            f"\n[cyan]DNS leak testing {len(alive)} proxies...[/cyan]"
        )
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]DNS leak...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._dns_leak_one(p)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        leaking = sum(1 for p in alive if p.dns_leak is True)
        clean = sum(1 for p in alive if p.dns_leak is False)
        console.print(
            f"[green]✓[/] DNS: {clean} clean, {leaking} leaking."
        )

    async def _dns_leak_one(self, proxy: Proxy):
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            return
        try:
            async with session.get(
                "https://1.1.1.1/cdn-cgi/trace", **kwargs
            ) as r:
                if r.status == 200:
                    text = await r.text()
                    for line in text.strip().split("\n"):
                        if line.startswith("ip="):
                            visible_ip = line.split("=")[1].strip()
                            proxy.dns_leak = (visible_ip == self.my_ip)
                            break
        except Exception:
            pass
        finally:
            await session.close()

    # ── Ban Check ─────────────────────────────────────────────────────────

    async def check_bans(self):
        if not self.config["ban_check"]["enabled"]:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        sites = self.config["ban_check"]["sites"]
        console.print(
            f"\n[cyan]Ban check on {len(alive)} proxies "
            f"({len(sites)} sites)...[/cyan]"
        )
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Ban check...", total=len(alive))

            async def worker(p):
                async with sem:
                    for site in sites:
                        banned = await self._ban_check_one(
                            p, site["url"],
                            site.get("success_pattern", ""),
                        )
                        if site["name"] == "google":
                            p.google_ban = banned
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        gb = sum(1 for p in alive if p.google_ban is True)
        console.print(f"[green]✓[/] Google banned: {gb}/{len(alive)}")

    async def _ban_check_one(
        self, proxy: Proxy, url: str, pattern: str
    ) -> bool:
        timeout = aiohttp.ClientTimeout(total=15)
        session, kwargs = self._create_proxy_session(proxy, timeout)
        if not session:
            return True
        try:
            async with session.get(url, **kwargs) as r:
                if r.status == 200:
                    text = await r.text()
                    return pattern.lower() not in text.lower()
                return True
        except Exception:
            return True
        finally:
            await session.close()

    # ── Fraud Waterfall ───────────────────────────────────────────────────

    async def tiered_fraud_scoring(self):
        if not self.config["fraud_check"]["enabled"]:
            return
        alive = sorted(
            [p for p in self.proxies.values() if p.alive],
            key=lambda p: p.latency_ms or 99999,
        )
        top_n = self.config["fraud_check"].get("top_n", 100)
        target = alive[:top_n]
        if not target:
            return

        console.print(
            f"\n[cyan]Fraud waterfall on top {len(target)} "
            f"proxies...[/cyan]"
        )
        sem = asyncio.Semaphore(30)

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task(
                "[cyan]Fraud check...", total=len(target)
            )
            async with aiohttp.ClientSession() as shared:
                async def worker(p):
                    async with sem:
                        await self._waterfall_one(p, shared)
                    prog.update(tid, advance=1)

                await asyncio.gather(*[worker(p) for p in target])

        sc = self.stats["api_calls"]
        console.print(
            f"[green]✓[/] API → Cache:{sc['cache_hits']} │ "
            f"IPInfo:{sc['ipinfo']} │ IPHub:{sc['iphub']} │ "
            f"Intel:{sc['getipintel']} │ IPQS:{sc['ipqs']}"
        )

    async def _waterfall_one(
        self, proxy: Proxy, shared: aiohttp.ClientSession
    ):
        score = 0
        if self.history:
            cached = self.history.get_cached_score(proxy.ip)
            if cached is not None:
                proxy.composite_score = cached
                self.stats["api_calls"]["cache_hits"] += 1
                return

        keys = self.config["fraud_check"]["keys"]

        # Tier 1: ipinfo.io
        if keys.get("ipinfo"):
            await self.ipinfo_limiter.wait()
            try:
                url = f"https://ipinfo.io/{proxy.ip}?token={keys['ipinfo']}"
                async with shared.get(
                    url, timeout=aiohttp.ClientTimeout(total=8)
                ) as r:
                    self.stats["api_calls"]["ipinfo"] += 1
                    if r.status == 200:
                        data = await r.json()
                        privacy = data.get("privacy", {})
                        if privacy.get("vpn"):
                            score += 25
                            proxy.is_vpn = True
                        if privacy.get("proxy"):
                            score += 25
                        if privacy.get("tor"):
                            score += 40
                            proxy.is_tor = True
                        if privacy.get("hosting"):
                            score += 15
                            proxy.is_hosting = True
                        if privacy.get("vpn") or privacy.get("tor"):
                            proxy.composite_score = min(100, score)
                            self._save_fraud_cache(proxy)
                            return
            except Exception:
                pass

        # Tier 2: iphub.info
        if keys.get("iphub"):
            await self.iphub_limiter.wait()
            try:
                hdrs = {"X-Key": keys["iphub"]}
                url = f"http://v2.api.iphub.info/ip/{proxy.ip}"
                async with shared.get(
                    url, headers=hdrs,
                    timeout=aiohttp.ClientTimeout(total=8),
                ) as r:
                    self.stats["api_calls"]["iphub"] += 1
                    if r.status == 200:
                        block = (await r.json()).get("block", 2)
                        if block == 1:
                            score += 25
                        elif block == 0:
                            score -= 10
                        if block == 1:
                            proxy.composite_score = min(
                                100, max(0, score)
                            )
                            self._save_fraud_cache(proxy)
                            return
            except Exception:
                pass

        # Tier 3: getipintel (elite proxies only)
        email = keys.get("getipintel_email", "")
        if email and proxy.anonymity == AnonymityLevel.ELITE:
            await self.getipintel_limiter.wait()
            try:
                url = (
                    f"http://check.getipintel.net/check.php"
                    f"?ip={proxy.ip}&contact={email}"
                )
                async with shared.get(
                    url, timeout=aiohttp.ClientTimeout(total=15)
                ) as r:
                    self.stats["api_calls"]["getipintel"] += 1
                    if r.status == 200:
                        val = float((await r.text()).strip())
                        if -1 < val <= 1:
                            proxy.fraud_score = round(val, 3)
                            score += int(val * 30)
            except Exception:
                pass

        # Tier 4: IPQS (clean proxies only — score < 30)
        if keys.get("ipqs") and score < 30:
            try:
                url = (
                    f"https://ipqualityscore.com/api/json/ip/"
                    f"{keys['ipqs']}/{proxy.ip}"
                )
                async with shared.get(
                    url, timeout=aiohttp.ClientTimeout(total=8)
                ) as r:
                    self.stats["api_calls"]["ipqs"] += 1
                    if r.status == 200:
                        data = await r.json()
                        if data.get("success"):
                            score += int(data.get("fraud_score", 0) * 0.3)
                            if data.get("recent_abuse"):
                                score += 20
            except Exception:
                pass

        proxy.composite_score = min(100, max(0, score))
        self._save_fraud_cache(proxy)

    def _save_fraud_cache(self, proxy: Proxy):
        if self.history and proxy.composite_score is not None:
            self.history.save_cached_score(
                proxy.ip, proxy.composite_score
            )

    # ── Enrich & Categorize ───────────────────────────────────────────────
    # FIX #1: Stealth score calculated HERE (after fraud scoring)

    def enrich_and_categorize(self):
        levels = {"transparent": 0, "anonymous": 1, "elite": 2}
        min_anon = self.config["filter"].get("min_anonymity")
        req_level = (
            levels.get(str(min_anon).lower(), -1) if min_anon else -1
        )

        for p in self.proxies.values():
            if not p.alive:
                continue

            # Speed tier
            if p.latency_ms is not None:
                fast = self.config["output"].get("fast_threshold_ms", 500)
                if p.latency_ms < fast:
                    p.speed_tier = SpeedTier.FAST
                elif p.latency_ms < 2000:
                    p.speed_tier = SpeedTier.MEDIUM
                else:
                    p.speed_tier = SpeedTier.SLOW

            # Average latency
            if p.latency_ms:
                if p.avg_latency_ms:
                    p.avg_latency_ms = (
                        p.avg_latency_ms + p.latency_ms
                    ) / 2
                else:
                    p.avg_latency_ms = float(p.latency_ms)

            # Min anonymity filter
            if p.anonymity and req_level >= 0:
                if levels.get(p.anonymity.value, 0) < req_level:
                    p.alive = False
                    continue

            # FIX #1: Calculate stealth score HERE — after all data is
            # available (anonymity, fingerprint, fraud, DNS leak, etc.)
            if self.config["stealth_score"]["enabled"]:
                self._calc_stealth(p)

            # Save to history
            if self.history:
                self.history.update(p)

    # ── Export ────────────────────────────────────────────────────────────

    def export(self):
        out = Path(self.config["output"]["dir"])
        out.mkdir(exist_ok=True)
        alive = sorted(
            [p for p in self.proxies.values() if p.alive],
            key=lambda p: p.latency_ms or 99999,
        )
        if not alive:
            console.print("[yellow]No alive proxies to export.[/yellow]")
            if self.verified_db:
                self.verified_db.save_all([])
                console.print(
                    "  [yellow]⚠[/] Verified DB cleared (no alive proxies)."
                )
            return

        console.print(
            f"\n[bold cyan]Exporting {len(alive)} proxies...[/bold cyan]"
        )

        if "json" in self.config["output"]["formats"]:
            path = out / "all.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump([p.to_dict() for p in alive], f, indent=2)
            console.print(f"  [green]✓[/] {path} ({len(alive)})")

        if "csv" in self.config["output"]["formats"]:
            path = out / "all.csv"
            flds = list(alive[0].to_dict().keys())
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=flds)
                w.writeheader()
                for p in alive:
                    w.writerow(p.to_dict())
            console.print(f"  [green]✓[/] {path} ({len(alive)})")

        if "txt" in self.config["output"]["formats"]:
            if self.config["output"]["split_by_protocol"]:
                for proto in ProxyProtocol:
                    lst = [p for p in alive if p.protocol == proto]
                    path = out / f"{proto.value}.txt"
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("\n".join(p.address for p in lst))
                    if lst:
                        console.print(
                            f"  [green]✓[/] {path} ({len(lst)})"
                        )

        special = [
            ("elite", "generate_elite_list",
             lambda p: p.anonymity == AnonymityLevel.ELITE),
            ("fast", "generate_fast_list",
             lambda p: p.speed_tier == SpeedTier.FAST),
            ("residential", "generate_residential_list",
             lambda p: p.proxy_type == ProxyType.RESIDENTIAL),
            ("mobile", "generate_mobile_list",
             lambda p: p.proxy_type == ProxyType.MOBILE),
            ("stealth", "generate_stealth_list",
             lambda p: (p.stealth_score is not None
                        and p.stealth_score >= 70)),
            ("clean", "generate_clean_list",
             lambda p: (p.composite_score is not None
                        and p.composite_score <= 20)),
        ]
        for name, config_key, filt in special:
            if self.config["output"].get(config_key, False):
                lst = [p for p in alive if filt(p)]
                path = out / f"{name}.txt"
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(p.address for p in lst))
                console.print(f"  [green]✓[/] {path} ({len(lst)})")

        if self.config["output"].get("split_by_country"):
            countries = set(
                p.country_code for p in alive if p.country_code
            )
            for cc in countries:
                lst = [p for p in alive if p.country_code == cc]
                path = out / f"country_{cc.lower()}.txt"
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(p.address for p in lst))

        # ── Checked folder: dated export that never overwrites ────
        if self.config.get("checked_output", {}).get("enabled", False):
            checked_dir = Path(
                self.config["checked_output"].get("dir", "checked")
            )
            checked_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now().strftime("%Y-%m-%d")
            rand_suffix = f"{random.randint(100, 999)}"
            basename = f"proxies_{date_str}_{rand_suffix}"

            txt_path = checked_dir / f"{basename}.txt"
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(p.address for p in alive))
            console.print(
                f"  [green]✓[/] {txt_path} ({len(alive)})"
            )

            json_path = checked_dir / f"{basename}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([p.to_dict() for p in alive], f, indent=2)
            console.print(
                f"  [green]✓[/] {json_path} ({len(alive)})"
            )

        # ── Update verified DB: only current survivors persist ────
        if self.verified_db:
            if alive:
                self.verified_db.save_all(alive)
                console.print(
                    f"  [green]✓[/] Verified DB updated: "
                    f"{len(alive)} working proxies saved."
                )
            else:
                self.verified_db.save_all([])
                console.print(
                    "  [yellow]⚠[/] Verified DB cleared (no alive proxies)."
                )

    # ── Stats ─────────────────────────────────────────────────────────────

    def print_stats(self) -> Dict[str, Any]:
        alive = [p for p in self.proxies.values() if p.alive]
        total = len(self.proxies) + self.stats["filtered"]

        sd = {
            "total": total,
            "alive": len(alive),
            "elite": len(
                [p for p in alive if p.anonymity == AnonymityLevel.ELITE]
            ),
            "fast": len(
                [p for p in alive if p.speed_tier == SpeedTier.FAST]
            ),
        }

        t = Table(
            title="🏆 UPO v5-fix2 — Results",
            show_header=False, border_style="bold blue",
        )
        t.add_column("Metric", style="cyan", width=25)
        t.add_column("Value", style="bold white", width=55)

        t.add_row("Total Raw", f"{total:,}")
        t.add_row("Filtered", f"[red]-{self.stats['filtered']:,}[/red]")
        vt = self.stats.get("verified_total", len(self.proxies))
        t.add_row("Verified", f"{vt:,}")
        pct = f"{len(alive)/max(vt,1):.1%}"
        t.add_row(
            "✅ ALIVE",
            f"[bold green]{len(alive):,}[/bold green] ({pct})",
        )
        t.add_row("─" * 20, "─" * 45)

        if alive:
            pc = Counter(p.protocol for p in alive)
            t.add_row(
                "Protocol",
                f"HTTP:{pc.get(ProxyProtocol.HTTP,0)} │ "
                f"HTTPS:{pc.get(ProxyProtocol.HTTPS,0)} │ "
                f"S4:{pc.get(ProxyProtocol.SOCKS4,0)} │ "
                f"S5:{pc.get(ProxyProtocol.SOCKS5,0)}",
            )

            ac = Counter(p.anonymity for p in alive if p.anonymity)
            t.add_row(
                "Anonymity",
                f"[green]Elite:{ac.get(AnonymityLevel.ELITE,0)}[/green] │ "
                f"Anon:{ac.get(AnonymityLevel.ANONYMOUS,0)} │ "
                f"Trans:{ac.get(AnonymityLevel.TRANSPARENT,0)}",
            )

            sc = Counter(p.speed_tier for p in alive if p.speed_tier)
            t.add_row(
                "Speed",
                f"[green]Fast:{sc.get(SpeedTier.FAST,0)}[/green] │ "
                f"Med:{sc.get(SpeedTier.MEDIUM,0)} │ "
                f"Slow:{sc.get(SpeedTier.SLOW,0)}",
            )

            pt = Counter(p.proxy_type for p in alive)
            t.add_row(
                "Type",
                f"Res:{pt.get(ProxyType.RESIDENTIAL,0)} │ "
                f"DC:{pt.get(ProxyType.DATACENTER,0)} │ "
                f"Mobile:{pt.get(ProxyType.MOBILE,0)} │ "
                f"Unk:{pt.get(ProxyType.UNKNOWN,0)}",
            )

            mp = sum(1 for p in alive if len(p.detected_protocols) > 1)
            t.add_row("Multi-Protocol", f"{mp} support 2+ protocols")

            https_cnt = sum(1 for p in alive if p.supports_https)
            t.add_row(
                "HTTPS Support",
                f"{https_cnt:,} "
                f"({https_cnt/max(len(alive),1)*100:.1f}%)",
            )

            speeds = [
                p.download_speed_kbps for p in alive
                if p.download_speed_kbps
            ]
            if speeds:
                t.add_row(
                    "Download Speed",
                    f"Avg:{sum(speeds)/len(speeds):.0f} KB/s │ "
                    f"Max:{max(speeds):.0f} KB/s",
                )

            stealths = [
                p.stealth_score for p in alive
                if p.stealth_score is not None
            ]
            if stealths:
                high = sum(1 for s in stealths if s >= 70)
                t.add_row(
                    "Stealth",
                    f"Avg:{sum(stealths)/len(stealths):.0f}/100 │ "
                    f"High(≥70):{high}",
                )

            dns_l = sum(1 for p in alive if p.dns_leak is True)
            dns_c = sum(1 for p in alive if p.dns_leak is False)
            if dns_l or dns_c:
                t.add_row(
                    "DNS Leak",
                    f"Clean:{dns_c} │ Leaking:{dns_l}",
                )

            scored = [
                p for p in alive if p.composite_score is not None
            ]
            if scored:
                clean = sum(
                    1 for p in scored if p.composite_score <= 20
                )
                t.add_row(
                    "Fraud Score",
                    f"Scored:{len(scored)} │ Clean(≤20):{clean}",
                )

            t.add_row("─" * 20, "─" * 45)

            cc = Counter(
                p.country_code for p in alive if p.country_code
            ).most_common(10)
            if cc:
                t.add_row(
                    "Top Countries",
                    " │ ".join(f"{c}({n})" for c, n in cc),
                )

            lats = [p.latency_ms for p in alive if p.latency_ms]
            if lats:
                t.add_row(
                    "Latency",
                    f"Avg:{sum(lats)/len(lats):.0f}ms │ "
                    f"Min:{min(lats)}ms │ Max:{max(lats)}ms",
                )

        console.print(Panel(t, border_style="bold blue"))
        return sd


# ==============================================================================
# SECTION 6: CRAWL4AI
# ==============================================================================

async def run_crawl4ai(config: Dict):
    if not config["crawl4ai"]["enabled"]:
        return
    if not os.path.exists(CRAWL4AI_INSTALL_PATH):
        console.print(
            f"[yellow]⚠ Crawl4AI not found at "
            f"'{CRAWL4AI_INSTALL_PATH}'.[/yellow]"
        )
        return

    sys.path.insert(0, CRAWL4AI_INSTALL_PATH)
    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
        from crawl4ai.extraction_strategy import JsonCssExtractionStrategy
    except ImportError:
        console.print("[yellow]⚠ crawl4ai import failed.[/yellow]")
        return

    console.print("\n[bold cyan]Crawl4AI scraping...[/bold cyan]")
    proxy_rx = re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\|]\s*(\d{2,5})"
    )
    all_proxies: List[Dict] = []

    async def scrape_fpl(crawler):
        schema = {
            "name": "fpl",
            "baseSelector": "table.table tbody tr",
            "fields": [
                {"name": "ip", "selector": "td:nth-child(1)", "type": "text"},
                {"name": "port", "selector": "td:nth-child(2)", "type": "text"},
                {"name": "https", "selector": "td:nth-child(7)", "type": "text"},
            ],
        }
        cfg = CrawlerRunConfig(
            extraction_strategy=JsonCssExtractionStrategy(schema=schema)
        )
        result = await crawler.arun(
            url="https://free-proxy-list.net/", config=cfg
        )
        proxies = []
        if result.extracted_content:
            for row in json.loads(result.extracted_content):
                ip = row.get("ip", "").strip()
                port = row.get("port", "").strip()
                if ip and port and port.isdigit():
                    proto = (
                        "https"
                        if row.get("https", "").lower() == "yes"
                        else "http"
                    )
                    proxies.append({
                        "ip": ip, "port": port, "protocol": proto,
                        "source": "free-proxy-list.net",
                    })
        return proxies

    async def scrape_regex(crawler, url, name):
        result = await crawler.arun(url=url, config=CrawlerRunConfig())
        return [
            {"ip": m.group(1), "port": m.group(2),
             "protocol": "http", "source": name}
            for m in proxy_rx.finditer(result.markdown or "")
        ]

    bc = BrowserConfig(
        headless=True, user_agent=config["general"]["user_agent"]
    )
    async with AsyncWebCrawler(config=bc) as crawler:
        for name, fn in [("free-proxy-list.net", scrape_fpl)]:
            try:
                scraped = await asyncio.wait_for(fn(crawler), timeout=60)
                all_proxies.extend(scraped)
                console.print(
                    f"  [green]✓[/] {name}: {len(scraped)} proxies"
                )
            except Exception as e:
                console.print(f"  [red]✗[/] {name}: {e}")

        for name, url in [
            ("proxynova.com",
             "https://www.proxynova.com/proxy-server-list/"),
            ("proxy-daily.com", "https://proxy-daily.com/"),
            ("advanced.name", "https://advanced.name/freeproxy"),
        ]:
            try:
                scraped = await asyncio.wait_for(
                    scrape_regex(crawler, url, name), timeout=60
                )
                all_proxies.extend(scraped)
                console.print(
                    f"  [green]✓[/] {name}: {len(scraped)} proxies"
                )
            except Exception as e:
                console.print(f"  [red]✗[/] {name}: {e}")

    output_path = Path(config["crawl4ai"]["output_file"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_proxies, f, indent=2)
    console.print(
        f"[bold green]✓ Crawl4AI: "
        f"{len(all_proxies)} proxies saved.[/bold green]"
    )


# ==============================================================================
# SECTION 7: REST API
# ==============================================================================

def start_api(engine: UPOEngine, host: str, port: int):
    try:
        from fastapi import FastAPI, Query
        import uvicorn
    except ImportError:
        console.print(
            "[yellow]⚠ pip install fastapi uvicorn[/yellow]"
        )
        return

    app = FastAPI(title="UPO API")

    @app.get("/proxies")
    async def get_proxies(
        protocol: Optional[str] = Query(None),
        country: Optional[str] = Query(None),
        anonymity: Optional[str] = Query(None),
        min_stealth: Optional[int] = Query(None),
        proxy_type: Optional[str] = Query(None),
        max_latency: Optional[int] = Query(None),
        limit: int = Query(20),
    ):
        r = [p for p in engine.proxies.values() if p.alive]
        if protocol:
            r = [p for p in r if p.protocol.value == protocol]
        if country:
            r = [p for p in r if p.country_code == country.upper()]
        if anonymity:
            r = [
                p for p in r
                if p.anonymity and p.anonymity.value == anonymity
            ]
        if min_stealth is not None:
            r = [
                p for p in r
                if p.stealth_score is not None
                and p.stealth_score >= min_stealth
            ]
        if proxy_type:
            r = [p for p in r if p.proxy_type.value == proxy_type]
        if max_latency:
            r = [
                p for p in r
                if p.latency_ms and p.latency_ms <= max_latency
            ]
        r = sorted(r, key=lambda p: p.latency_ms or 99999)[:limit]
        return [p.to_dict() for p in r]

    @app.get("/random")
    async def get_random(
        protocol: Optional[str] = None,
        country: Optional[str] = None,
        anonymity: Optional[str] = None,
    ):
        r = [p for p in engine.proxies.values() if p.alive]
        if protocol:
            r = [p for p in r if p.protocol.value == protocol]
        if country:
            r = [p for p in r if p.country_code == country.upper()]
        if anonymity:
            r = [
                p for p in r
                if p.anonymity and p.anonymity.value == anonymity
            ]
        if not r:
            return {"error": "No proxies match"}
        return random.choice(r).to_dict()

    @app.get("/stats")
    async def get_stats():
        alive = [p for p in engine.proxies.values() if p.alive]
        return {
            "total": len(engine.proxies),
            "alive": len(alive),
            "elite": len(
                [p for p in alive
                 if p.anonymity == AnonymityLevel.ELITE]
            ),
            "fast": len(
                [p for p in alive if p.speed_tier == SpeedTier.FAST]
            ),
            "residential": len(
                [p for p in alive
                 if p.proxy_type == ProxyType.RESIDENTIAL]
            ),
            "mobile": len(
                [p for p in alive if p.proxy_type == ProxyType.MOBILE]
            ),
        }

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "alive": sum(
                1 for p in engine.proxies.values() if p.alive
            ),
        }

    def run():
        uvicorn.run(app, host=host, port=port, log_level="warning")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    console.print(
        f"[bold green]✓ API at http://{host}:{port}[/bold green]"
    )
    console.print(
        f"  [dim]GET /proxies?protocol=socks5&country=US"
        f"&anonymity=elite[/dim]"
    )
    console.print(f"  [dim]GET /random?protocol=http[/dim]")
    console.print(f"  [dim]GET /stats[/dim]")


# ==============================================================================
# SECTION 8: CLI & PIPELINE
# ==============================================================================

@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--config", "config_path", default="config.yaml")
@click.option("--scrape-only", is_flag=True)
@click.option("--no-crawl4ai", is_flag=True)
@click.option("--no-ban-check", is_flag=True)
@click.option("--no-speed-test", is_flag=True)
@click.option("--no-dns-leak", is_flag=True)
@click.option("--no-stealth", is_flag=True)
@click.option("--no-protocol-detect", is_flag=True)
@click.option("--enable-fraud", is_flag=True)
@click.option("--concurrency", default=None, type=int)
@click.option("--timeout", default=None, type=int)
@click.option("--rounds", default=None, type=int)
@click.option("--country", default=None)
@click.option("--exclude-dc", is_flag=True)
@click.option("--api", is_flag=True)
@click.option("--api-port", default=8000, type=int)
@click.option("--test-limit", default=None, type=int)
def main(
    config_path, scrape_only, no_crawl4ai, no_ban_check,
    no_speed_test, no_dns_leak, no_stealth, no_protocol_detect,
    enable_fraud, concurrency, timeout, rounds, country,
    exclude_dc, api, api_port, test_limit,
):
    """🏆 UPO v5-fix2 — Ultimate Proxy Operator"""
    banner = """[bold blue]
 ██╗   ██╗██████╗  ██████╗    ██╗   ██╗███████╗
 ██║   ██║██╔══██╗██╔═══██╗   ██║   ██║██╔════╝
 ██║   ██║██████╔╝██║   ██║   ██║   ██║███████╗
 ██║   ██║██╔═══╝ ██║   ██║   ╚██╗ ██╔╝╚════██║
 ╚██████╔╝██║     ╚██████╔╝    ╚████╔╝ ███████║
  ╚═════╝ ╚═╝      ╚═════╝      ╚═══╝  ╚══════╝[/bold blue]
[dim]v5-fix2 — Scrape · Verify · Fingerprint · Score · Serve[/dim]"""
    console.print(Panel(banner, border_style="bold blue", expand=False))

    config = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                uc = yaml.safe_load(f)
            if uc:
                for k, v in uc.items():
                    if isinstance(v, dict) and k in config:
                        config[k].update(v)
                    else:
                        config[k] = v
        except Exception as e:
            console.print(f"[yellow]⚠ Config error: {e}[/yellow]")

    if concurrency:
        config["general"]["concurrency"] = concurrency
    if timeout:
        config["general"]["timeout_total"] = timeout
    if rounds:
        config["general"]["verification_rounds"] = rounds
    if no_crawl4ai:
        config["crawl4ai"]["enabled"] = False
    if no_ban_check:
        config["ban_check"]["enabled"] = False
    if no_speed_test:
        config["speed_test"]["enabled"] = False
    if no_dns_leak:
        config["dns_leak"]["enabled"] = False
    if no_stealth:
        config["stealth_score"]["enabled"] = False
    if no_protocol_detect:
        config["protocol_detection"]["enabled"] = False
    if enable_fraud:
        config["fraud_check"]["enabled"] = True
    if country:
        config["filter"]["allowed_countries"] = [
            c.strip().upper() for c in country.split(",")
        ]
    if exclude_dc:
        config["filter"]["exclude_datacenters"] = True
    if api:
        config["api"]["enabled"] = True
        config["api"]["port"] = api_port

    asyncio.run(pipeline(config, scrape_only, test_limit))


async def pipeline(
    config: Dict, scrape_only: bool, test_limit: Optional[int]
):
    start = time.monotonic()

    # 1. Crawl4AI
    if config["crawl4ai"]["enabled"] and not scrape_only:
        await run_crawl4ai(config)

    # 2. Init
    engine = UPOEngine(config)
    await engine.initialize()

    # 3. Collect
    console.print("\n[bold cyan]═══ PHASE 1: COLLECTION ═══[/bold cyan]")
    await engine.collect()
    tsrc = (
        len(GITHUB_HTTP_SOURCES) + len(GITHUB_SOCKS4_SOURCES)
        + len(GITHUB_SOCKS5_SOURCES) + len(API_SOURCES)
    )
    console.print(
        f"[green]✓[/] {len(engine.proxies):,} unique proxies "
        f"from {tsrc} sources."
    )

    # 4. Pre-enrich
    console.print("\n[bold cyan]═══ PHASE 2: PRE-ENRICH ═══[/bold cyan]")
    engine.pre_enrich()
    mobile = sum(
        1 for p in engine.proxies.values()
        if p.proxy_type == ProxyType.MOBILE
    )
    res = sum(
        1 for p in engine.proxies.values()
        if p.proxy_type == ProxyType.RESIDENTIAL
    )
    console.print(
        f"[green]✓[/] Enriched. Mobile: {mobile}, Residential: {res}"
    )

    # 5. Filter
    console.print("\n[bold cyan]═══ PHASE 3: FILTER ═══[/bold cyan]")
    engine.filter_garbage()

    if test_limit:
        engine.proxies = dict(
            list(engine.proxies.items())[:test_limit]
        )
        console.print(
            f"[yellow]⚠ Test limit: {test_limit} proxies[/yellow]"
        )

    if not scrape_only:
        # Pipeline summary — show what's about to happen
        phases = ["Verification", "Anonymity"]
        if config["protocol_detection"]["enabled"]:
            phases.append("Protocol Detection")
        if config["speed_test"]["enabled"]:
            phases.append("Speed Test")
        if config["stealth_score"]["enabled"]:
            phases.append("TCP Fingerprint")
        if config["dns_leak"]["enabled"]:
            phases.append("DNS Leak")
        if config["fraud_check"]["enabled"]:
            phases.append(
                f"Fraud Waterfall (top {config['fraud_check'].get('top_n', 100)})"
            )
        if config["ban_check"]["enabled"]:
            phases.append(
                f"Ban Check ({len(config['ban_check']['sites'])} sites)"
            )
        phases.append("Categorize + Export")

        console.print(
            f"\n[bold cyan]Pipeline Plan "
            f"({len(engine.proxies):,} proxies):[/bold cyan]"
        )
        for i, phase in enumerate(phases, 1):
            console.print(f"  [dim]{i:2d}. {phase}[/dim]")
        console.print()
        # 6. Verify (FIX #2: smart threshold, FIX #3: judge rotation)
        console.print(
            f"\n[bold cyan]═══ PHASE 4: VERIFICATION "
            f"({config['general']['verification_rounds']} rounds) "
            f"═══[/bold cyan]"
        )
        await engine.verify()

        # 7. Anonymity (FIX #3: different judge, FIX #5: 5s timeout)
        console.print(
            "\n[bold cyan]═══ PHASE 5: ANONYMITY ═══[/bold cyan]"
        )
        await engine.check_anonymity()

        # 8. Protocol detection (FIX #3: different judge, FIX #4: dedup)
        if config["protocol_detection"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 6: PROTOCOL DETECTION "
                "═══[/bold cyan]"
            )
            await engine.detect_protocols()

        # 9. Speed test
        if config["speed_test"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 7: SPEED TEST ═══[/bold cyan]"
            )
            await engine.speed_test()

        # 10. TCP fingerprint (separate from stealth now)
        if config["stealth_score"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 8: TCP FINGERPRINT "
                "═══[/bold cyan]"
            )
            await engine.fingerprint()

        # 11. DNS leak
        if config["dns_leak"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 9: DNS LEAK ═══[/bold cyan]"
            )
            await engine.dns_leak_check()

        # 12. Fraud waterfall
        if config["fraud_check"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 10: FRAUD WATERFALL "
                "═══[/bold cyan]"
            )
            await engine.tiered_fraud_scoring()

        # 13. Ban check
        if config["ban_check"]["enabled"]:
            console.print(
                "\n[bold cyan]═══ PHASE 11: BAN CHECK ═══[/bold cyan]"
            )
            await engine.check_bans()

        # 14. Categorize (FIX #1: stealth calculated HERE, after fraud)
        console.print(
            "\n[bold cyan]═══ PHASE 12: CATEGORIZE ═══[/bold cyan]"
        )
        engine.enrich_and_categorize()
        alive_cnt = sum(
            1 for p in engine.proxies.values() if p.alive
        )
        console.print(
            f"[green]✓[/] Final alive: {alive_cnt:,}"
        )
    else:
        console.print(
            "\n[yellow]⏭ --scrape-only: Skipping verification.[/yellow]"
        )

    # 15. Export
    console.print("\n[bold cyan]═══ EXPORT ═══[/bold cyan]")
    engine.export()

    # 16. Stats
    stats = engine.print_stats()

    elapsed = time.monotonic() - start
    console.print(f"\n[bold]⏱ Total: {elapsed:.1f}s[/bold]")

    # 17. API
    if config["api"]["enabled"]:
        start_api(engine, config["api"]["host"], config["api"]["port"])
        console.print(
            "\n[bold]API running. Press Ctrl+C to stop.[/bold]"
        )
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")


if __name__ == "__main__":
    main()