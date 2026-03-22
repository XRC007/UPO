# ==============================================================================
#
# ██╗   ██╗██████╗  ██████╗     ██╗   ██╗██████╗
# ██║   ██║██╔══██╗██╔═══██╗    ██║   ██║╚════██╗
# ██║   ██║██████╔╝██║   ██║    ██║   ██║ █████╔╝
# ██║   ██║██╔═══╝ ██║   ██║    ╚██╗ ██╔╝ ╚═══██╗
# ╚██████╔╝██║     ╚██████╔╝     ╚████╔╝ ██████╔╝
#  ╚═════╝ ╚═╝      ╚═════╝       ╚═══╝  ╚═════╝
#
# UPO v3 - Ultimate Proxy Operator (Enhanced Edition)
#
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
import sqlite3
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple
from collections import Counter
from pathlib import Path
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

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
# SECTION 0: ENHANCED CONFIG & SOURCES
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
        'verification_rounds': 1,
        'retry_failed': False,
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
            "https://api.ipify.org?format=json",
            "https://ifconfig.me/ip",
            "http://ipecho.net/plain",
            "http://whatismyip.akamai.com",
        ]
    },
    'geoip': {
        'enabled': True,
        'city_db': "data/GeoLite2-City.mmdb",
        'asn_db': "data/GeoLite2-ASN.mmdb",
    },
    'filter': {
        'blacklist': "data/blacklist.txt",
        'allowed_countries': [],
        'blocked_countries': [],
        'exclude_datacenters': False,
        'min_anonymity': None,
    },
    'output': {
        'dir': "output",
        'formats': ['txt', 'json', 'csv'],
        'split_by_protocol': True,
        'generate_elite_list': True,
        'generate_fast_list': True,
        'fast_threshold_ms': 500,
        'split_by_country': False,
        'generate_residential_list': True,
    },
    'crawl4ai': {
        'enabled': True,
        'output_file': "output/crawled_proxies.json",
    },
    'ban_check': {
        'enabled': True,
        'sites': [
            {'name': 'google', 'url': 'https://www.google.com/search?q=test', 'success_pattern': 'google'},
            {'name': 'bing', 'url': 'https://www.bing.com/search?q=test', 'success_pattern': 'bing'},
            {'name': 'duckduckgo', 'url': 'https://duckduckgo.com/?q=test', 'success_pattern': 'duckduckgo'},
        ],
    },
    'history': {
        'enabled': True,
        'db_path': "data/proxy_history.db",
        'track_uptime': True,
    },
    'scheduler': {
        'enabled': False,
        'interval_minutes': 30,
    },
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
    {"url": "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list", "protocol": "mixed", "format": "jsonl"},
]

DATACENTER_ASNS: Set[int] = {
    16509, 14618, 16509, 15169, 396982, 36492, 8075, 8068, 8069,
    45102, 37963, 45096, 14061, 63949, 63018, 20473, 20454, 24940,
    16276, 35540, 31898, 7160, 19994, 46606, 53831, 32244, 36351,
    3223, 30633, 51167, 60781, 197540, 55286, 54825, 12876, 9009,
    202422, 60068, 131199, 51396, 41436, 62240, 42831, 398101,
    26496, 9009, 174, 3356, 6939,
}

RESIDENTIAL_ASNS: Set[int] = {
    7922, 20115, 22773, 7018, 701, 3320, 12322, 3215, 5089, 2856,
    4134, 4837, 9299, 17676, 4755,
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

# ==============================================================================
# SECTION 1: ENHANCED DATA MODELS
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
    google_ban: Optional[bool] = None
    cloudflare_ban: Optional[bool] = None
    detected_protocols: List[str] = field(default_factory=list)
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_checked: Optional[str] = None
    check_count: int = 0
    success_count: int = 0
    fail_count: int = 0
    reliability: float = 0.0
    uptime_history: List[bool] = field(default_factory=list)
    avg_latency_ms: Optional[float] = None

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
        return hashlib.md5(f"{self.ip}:{self.port}:{self.protocol.value}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d['protocol'] = self.protocol.value if self.protocol else None
        d['anonymity'] = self.anonymity.value if self.anonymity else None
        d['speed_tier'] = self.speed_tier.value if self.speed_tier else None
        d['proxy_type'] = self.proxy_type.value if self.proxy_type else None
        return d

# ==============================================================================
# SECTION 2: IP FILTER (Enhanced)
# ==============================================================================

class IPFilter:
    def __init__(self):
        self.cf_networks = [ip_network(cidr) for cidr in CLOUDFLARE_IP_RANGES]
        self.private_networks = [
            ip_network("10.0.0.0/8"),
            ip_network("172.16.0.0/12"),
            ip_network("192.168.0.0/16"),
            ip_network("127.0.0.0/8"),
            ip_network("0.0.0.0/8"),
            ip_network("169.254.0.0/16"),
            ip_network("224.0.0.0/4"),
            ip_network("240.0.0.0/4"),
            ip_network("100.64.0.0/10"),
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
        self, proxies: Dict[str, Proxy], config: Dict[str, Any]
    ) -> Tuple[Dict[str, Proxy], Dict[str, int]]:
        valid: Dict[str, Proxy] = {}
        stats: Dict[str, int] = Counter()

        for addr, proxy in proxies.items():
            is_valid, reason = self.is_valid_proxy_candidate(proxy)
            if not is_valid:
                stats[reason] += 1
                continue

            allowed = config['filter'].get('allowed_countries', [])
            blocked = config['filter'].get('blocked_countries', [])
            
            if allowed and proxy.country_code and proxy.country_code not in allowed:
                stats['country_not_allowed'] += 1
                continue
            
            if blocked and proxy.country_code and proxy.country_code in blocked:
                stats['country_blocked'] += 1
                continue

            valid[addr] = proxy

        return valid, dict(stats)

# ==============================================================================
# SECTION 3: HISTORY DATABASE
# ==============================================================================

class ProxyHistory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS proxies (
                id TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT,
                last_alive TEXT,
                total_checks INTEGER DEFAULT 0,
                successful_checks INTEGER DEFAULT 0,
                avg_latency_ms REAL,
                country_code TEXT,
                asn INTEGER,
                isp TEXT,
                proxy_type TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS check_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                proxy_id TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                alive INTEGER NOT NULL,
                latency_ms INTEGER,
                anonymity TEXT,
                FOREIGN KEY (proxy_id) REFERENCES proxies(id)
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_check_history_proxy_id 
            ON check_history(proxy_id)
        ''')
        
        conn.commit()
        conn.close()

    def update_proxy(self, proxy: Proxy):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute('SELECT id FROM proxies WHERE id = ?', (proxy.id,))
        exists = cursor.fetchone()
        
        if exists:
            cursor.execute('''
                UPDATE proxies SET
                    last_seen = ?,
                    last_alive = CASE WHEN ? = 1 THEN ? ELSE last_alive END,
                    total_checks = total_checks + 1,
                    successful_checks = successful_checks + ?,
                    avg_latency_ms = CASE 
                        WHEN ? IS NOT NULL AND avg_latency_ms IS NOT NULL 
                        THEN (avg_latency_ms + ?) / 2
                        WHEN ? IS NOT NULL THEN ?
                        ELSE avg_latency_ms
                    END,
                    country_code = COALESCE(?, country_code),
                    asn = COALESCE(?, asn),
                    isp = COALESCE(?, isp),
                    proxy_type = COALESCE(?, proxy_type)
                WHERE id = ?
            ''', (
                now,
                1 if proxy.alive else 0, now,
                1 if proxy.alive else 0,
                proxy.latency_ms, proxy.latency_ms,
                proxy.latency_ms, proxy.latency_ms,
                proxy.country_code,
                proxy.asn,
                proxy.isp,
                proxy.proxy_type.value if proxy.proxy_type else None,
                proxy.id
            ))
        else:
            cursor.execute('''
                INSERT INTO proxies 
                (id, ip, port, protocol, first_seen, last_seen, last_alive, 
                 total_checks, successful_checks, avg_latency_ms,
                 country_code, asn, isp, proxy_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                proxy.id, proxy.ip, proxy.port, proxy.protocol.value, proxy.first_seen, now,
                now if proxy.alive else None, 1, 1 if proxy.alive else 0, proxy.latency_ms,
                proxy.country_code, proxy.asn, proxy.isp,
                proxy.proxy_type.value if proxy.proxy_type else None
            ))
        
        cursor.execute('''
            INSERT INTO check_history (proxy_id, checked_at, alive, latency_ms, anonymity)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            proxy.id, now, 1 if proxy.alive else 0, proxy.latency_ms,
            proxy.anonymity.value if proxy.anonymity else None
        ))
        
        conn.commit()
        conn.close()

    def get_historical_reliability(self, proxy_id: str, days: int = 7) -> Optional[float]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        cursor.execute('''
            SELECT 
                COUNT(*) as total,
                SUM(alive) as successful
            FROM check_history
            WHERE proxy_id = ? AND checked_at > ?
        ''', (proxy_id, cutoff))
        
        row = cursor.fetchone()
        conn.close()
        
        if row and row[0] > 0:
            return row[1] / row[0]
        return None

    def get_stats(self) -> Dict[str, Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM proxies')
        total_proxies = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM proxies WHERE last_alive > datetime("now", "-1 hour")')
        recent_alive = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM check_history')
        total_checks = cursor.fetchone()[0]
        conn.close()
        
        return {
            'total_proxies_tracked': total_proxies,
            'alive_last_hour': recent_alive,
            'total_checks': total_checks,
        }


# ==============================================================================
# SECTION 5: CORE ENGINE (Enhanced)
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
        self.history: Optional[ProxyHistory] = None
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
                console.print("[yellow]⚠[/] GeoIP databases not found.")
                self.config['geoip']['enabled'] = False

        bl_path = self.config['filter']['blacklist']
        if os.path.exists(bl_path):
            with open(bl_path, 'r') as f:
                self.blacklist = {line.strip() for line in f if line.strip()}

        if self.config['history']['enabled']:
            self.history = ProxyHistory(self.config['history']['db_path'])
            db_stats = self.history.get_stats()
            console.print(
                f"[green]✓[/] History DB: {db_stats['total_proxies_tracked']:,} proxies tracked"
            )

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
                    async with session.get(judge_url, timeout=timeout) as resp:
                        if resp.status == 200:
                            text = (await resp.text()).strip()
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text):
                                self.my_ip = text
                                console.print(f"[green]✓[/] Your real IP: [bold]{self.my_ip}[/bold]")
                                break
                except Exception:
                    continue

        if not self.my_ip:
            console.print("[red]✗[/] Could not detect your real IP.")

    async def collect(self):
        timeout = aiohttp.ClientTimeout(total=30)
        connector = aiohttp.TCPConnector(limit=100, ssl=False)

        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout, connector=connector
        ) as session:
            tasks = []

            for url in GITHUB_HTTP_SOURCES:
                tasks.append(self._fetch_and_parse(session, url, ProxyProtocol.HTTP))
            for url in GITHUB_SOCKS4_SOURCES:
                tasks.append(self._fetch_and_parse(session, url, ProxyProtocol.SOCKS4))
            for url in GITHUB_SOCKS5_SOURCES:
                tasks.append(self._fetch_and_parse(session, url, ProxyProtocol.SOCKS5))

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
                task = progress.add_task("[cyan]Fetching sources...", total=len(tasks))
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
                            protocol=ProxyProtocol(p.get('protocol', 'http')),
                            source=p.get('source', 'crawl4ai'),
                        )
                        if proxy.address not in self.proxies:
                            self.proxies[proxy.address] = proxy
                            count += 1
                    except (ValueError, KeyError):
                        continue
                console.print(f"  [green]✓[/] Loaded {count} proxies from crawl4ai.")
            except Exception:
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
                    elif format_hint == 'jsonl':
                        self._parse_jsonl_source(content, source_name)
                    else:
                        self._parse_text_source(content, protocol_hint, source_name)
                    return
            except asyncio.TimeoutError:
                if attempt < retries - 1:
                    await asyncio.sleep(1 * (attempt + 1))
            except Exception:
                return

    def _parse_text_source(self, content: str, protocol_hint: ProxyProtocol, source: str):
        for match in PROXY_REGEX.finditer(content):
            try:
                ip_str = match.group('ip')
                port = int(match.group('port'))
                proto_str = match.group('protocol')
                protocol = ProxyProtocol(proto_str) if proto_str else protocol_hint

                proxy = Proxy(ip=ip_str, port=port, protocol=protocol, source=source)
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
                    proto = protocols[0].lower() if protocols else 'http'

                    proxy = Proxy(ip=ip_str, port=port, protocol=ProxyProtocol(proto), source=source)
                    if proxy.address not in self.proxies:
                        self.proxies[proxy.address] = proxy
                except (ValueError, KeyError):
                    continue
        except json.JSONDecodeError:
            pass

    def _parse_jsonl_source(self, content: str, source: str):
        for line in content.strip().split('\n'):
            try:
                item = json.loads(line)
                ip_str = item.get('host', '').strip()
                port = int(item.get('port', 0))
                proto = item.get('type', 'http').lower()
                if proto not in ['http', 'https', 'socks4', 'socks5']:
                    proto = 'http'

                proxy = Proxy(ip=ip_str, port=port, protocol=ProxyProtocol(proto), source=source)
                if proxy.address not in self.proxies:
                    self.proxies[proxy.address] = proxy
            except (ValueError, KeyError, json.JSONDecodeError):
                continue

    def pre_enrich(self):
        if not self.geoip_asn_reader:
            return

        for proxy in self.proxies.values():
            try:
                asn_data = self.geoip_asn_reader.asn(proxy.ip)
                proxy.asn = asn_data.autonomous_system_number
                proxy.isp = asn_data.autonomous_system_organization

                if proxy.asn in CDN_ASNS:
                    proxy.proxy_type = ProxyType.DATACENTER
                elif proxy.asn in DATACENTER_ASNS:
                    proxy.proxy_type = ProxyType.DATACENTER
                elif proxy.asn in RESIDENTIAL_ASNS:
                    proxy.proxy_type = ProxyType.RESIDENTIAL
                else:
                    proxy.proxy_type = ProxyType.UNKNOWN
            except Exception:
                pass

            if self.geoip_city_reader:
                try:
                    city_data = self.geoip_city_reader.city(proxy.ip)
                    proxy.country_code = city_data.country.iso_code
                    proxy.country_name = city_data.country.name
                    proxy.city = city_data.city.name
                    if city_data.subdivisions:
                        proxy.region = city_data.subdivisions.most_specific.name
                except Exception:
                    pass

    def filter_garbage(self):
        before_count = len(self.proxies)

        self.proxies, rejection_stats = self.ip_filter.filter_batch(self.proxies, self.config)

        cdn_rejected = 0
        to_remove = []
        for addr, proxy in self.proxies.items():
            if proxy.asn and proxy.asn in CDN_ASNS:
                to_remove.append(addr)
                cdn_rejected += 1
        for addr in to_remove:
            del self.proxies[addr]
        rejection_stats['cdn_asn'] = cdn_rejected

        bl_removed = 0
        to_remove = []
        for addr, proxy in self.proxies.items():
            if proxy.ip in self.blacklist:
                to_remove.append(addr)
                bl_removed += 1
        for addr in to_remove:
            del self.proxies[addr]
        rejection_stats['blacklisted_ip'] = bl_removed

        if self.config['filter'].get('exclude_datacenters', False):
            dc_removed = 0
            to_remove = []
            for addr, proxy in self.proxies.items():
                if proxy.proxy_type == ProxyType.DATACENTER:
                    to_remove.append(addr)
                    dc_removed += 1
            for addr in to_remove:
                del self.proxies[addr]
            rejection_stats['datacenter'] = dc_removed

        after_count = len(self.proxies)
        self.stats['filtered_pre_verify'] = before_count - after_count

        limit = self.config.get('test_limit')
        if limit and limit < len(self.proxies):
            console.print(f"\n[bold yellow]⚠ TESTING LIMIT APPLIED: Testing only {limit} proxies.[/bold yellow]")
            self.proxies = dict(list(self.proxies.items())[:limit])

        console.print(f"\n[bold cyan]Pre-Verification Filter:[/bold cyan]")
        console.print(f"  Before: {before_count:,} → After: {len(self.proxies):,} ([red]-{before_count - after_count:,}[/red])")
        if rejection_stats:
            for reason, count in sorted(rejection_stats.items(), key=lambda x: -x[1]):
                if count > 0:
                    console.print(f"    [red]✗[/] {reason}: {count:,}")

    async def verify(self):
        if not self.proxies:
            console.print("[yellow]No proxies to verify.[/yellow]")
            return

        console.print("\n[cyan]Testing judge servers...[/cyan]")
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(headers=self.headers, timeout=timeout) as session:
            judge_tasks = [self._test_judge(session, url) for url in self.config['judges']['urls']]
            results = await asyncio.gather(*judge_tasks)
            self.judges = sorted([r for r in results if r], key=lambda x: x[1])

        if not self.judges:
            console.print("[bold red]✗ No judges reachable.[/bold red]")
            return

        console.print(f"[green]✓[/] {len(self.judges)} judges working. Primary: '{self.judges[0][0]}' ({self.judges[0][1]*1000:.0f}ms)")

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
            task_id = progress.add_task("[cyan]Verifying...", total=len(proxy_list), alive=0)

            async def verify_with_sem(proxy):
                nonlocal alive_count
                async with sem:
                    await self._check_proxy_through(proxy)
                if proxy.alive:
                    alive_count += 1
                progress.update(task_id, advance=1, alive=alive_count)

            await asyncio.gather(*[verify_with_sem(p) for p in proxy_list])

        self.stats['verified_total'] = len(proxy_list)
        self.stats['verified_alive'] = alive_count

    async def _test_judge(self, session: aiohttp.ClientSession, url: str) -> Optional[Tuple[str, float]]:
        try:
            start = time.monotonic()
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    if len(text) < 2000:
                        latency = time.monotonic() - start
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
        timeout_obj = aiohttp.ClientTimeout(total=total_timeout, connect=connect_timeout)

        connector = None
        session = None
        try:
            start_time = time.monotonic()

            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                connector = aiohttp_socks.ProxyConnector.from_url(proxy.url, rdns=True)
                session = aiohttp.ClientSession(connector=connector, headers=self.headers, timeout=timeout_obj)
                async with session.get(judge_url) as resp:
                    latency_ms = int((time.monotonic() - start_time) * 1000)
                    if resp.status == 200:
                        body = await resp.text()
                        if self._validate_judge_response(body, proxy, latency_ms):
                            await self._check_anonymity_through_session(session, proxy)
                            await self._check_https_support(session, proxy)
            else:
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(connector=connector, headers=self.headers, timeout=timeout_obj)
                async with session.get(judge_url, proxy=proxy.url) as resp:
                    latency_ms = int((time.monotonic() - start_time) * 1000)
                    if resp.status == 200:
                        body = await resp.text()
                        if self._validate_judge_response(body, proxy, latency_ms):
                            await self._check_anonymity_through_session(session, proxy)
                            await self._check_https_support(session, proxy)

        except Exception:
            proxy.alive = False
            proxy.fail_count += 1
        finally:
            if session:
                await session.close()
            await asyncio.sleep(0.01)

    def _validate_judge_response(self, body: str, proxy: Proxy, latency_ms: int) -> bool:
        body = body.strip()
        if not body or len(body) > 5000:
            return False

        found_ip = None
        try:
            data = json.loads(body)
            found_ip = data.get('origin') or data.get('ip') or data.get('query')
        except (json.JSONDecodeError, AttributeError):
            pass

        if not found_ip:
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body)
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

        proxy.uptime_history.append(True)
        if len(proxy.uptime_history) > 100:
            proxy.uptime_history = proxy.uptime_history[-100:]

        return True

    async def _check_anonymity_through_session(self, session: aiohttp.ClientSession, proxy: Proxy):
        if not self.my_ip:
            proxy.anonymity = AnonymityLevel.ANONYMOUS
            return

        try:
            headers_judge = "http://httpbin.org/headers"
            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                async with session.get(headers_judge) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._classify_anonymity(data, proxy)
            else:
                async with session.get(headers_judge, proxy=proxy.url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self._classify_anonymity(data, proxy)
        except Exception:
            proxy.anonymity = AnonymityLevel.ANONYMOUS

    def _classify_anonymity(self, headers_response: dict, proxy: Proxy):
        headers = headers_response.get('headers', {})
        all_values = ' '.join(str(v) for v in headers.values()).lower()

        if self.my_ip and self.my_ip in all_values:
            proxy.anonymity = AnonymityLevel.TRANSPARENT
            return

        proxy_headers = ['Via', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-Proto', 
                        'Forwarded', 'X-Real-Ip', 'X-Proxy-Id', 'Proxy-Connection']
        for ph in proxy_headers:
            if ph in headers or ph.lower() in headers:
                proxy.anonymity = AnonymityLevel.ANONYMOUS
                return

        proxy.anonymity = AnonymityLevel.ELITE

    async def _check_https_support(self, session: aiohttp.ClientSession, proxy: Proxy):
        try:
            https_url = "https://httpbin.org/ip"
            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                async with session.get(https_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        proxy.supports_https = True
            else:
                async with session.get(https_url, proxy=proxy.url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        proxy.supports_https = True
        except Exception:
            proxy.supports_https = False

    async def check_bans(self):
        if not self.config['ban_check']['enabled']:
            return

        alive_proxies = [p for p in self.proxies.values() if p.alive]
        if not alive_proxies:
            return

        console.print(f"\n[cyan]Checking bans on {len(alive_proxies)} proxies...[/cyan]")

        sem = asyncio.Semaphore(self.config['general']['concurrency'])
        sites = self.config['ban_check']['sites']

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            transient=True,
        ) as progress:
            task_id = progress.add_task("[cyan]Ban checking...", total=len(alive_proxies))

            async def check_proxy_bans(proxy):
                async with sem:
                    for site in sites:
                        try:
                            banned = await self._check_site_ban(proxy, site['url'], site.get('success_pattern', ''))
                            if site['name'] == 'google':
                                proxy.google_ban = banned
                        except Exception:
                            pass
                progress.update(task_id, advance=1)

            await asyncio.gather(*[check_proxy_bans(p) for p in alive_proxies])

    async def _check_site_ban(self, proxy: Proxy, url: str, success_pattern: str) -> bool:
        timeout = aiohttp.ClientTimeout(total=15)
        connector = None
        session = None

        try:
            if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
                connector = aiohttp_socks.ProxyConnector.from_url(proxy.url, rdns=True)
                session = aiohttp.ClientSession(connector=connector, headers=self.headers, timeout=timeout)
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        return success_pattern.lower() not in text.lower()
                    return True
            else:
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(connector=connector, headers=self.headers, timeout=timeout)
                async with session.get(url, proxy=proxy.url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        return success_pattern.lower() not in text.lower()
                    return True
        except Exception:
            return True
        finally:
            if session:
                await session.close()

    def enrich_and_categorize(self):
        alive_proxies = [p for p in self.proxies.values() if p.alive]

        for proxy in alive_proxies:
            if proxy.latency_ms is not None:
                fast_thresh = self.config['output']['fast_threshold_ms']
                if proxy.latency_ms < fast_thresh:
                    proxy.speed_tier = SpeedTier.FAST
                elif proxy.latency_ms < 2000:
                    proxy.speed_tier = SpeedTier.MEDIUM
                else:
                    proxy.speed_tier = SpeedTier.SLOW

            if proxy.check_count > 0:
                proxy.reliability = round(proxy.success_count / proxy.check_count, 2)

            if proxy.latency_ms:
                if proxy.avg_latency_ms:
                    proxy.avg_latency_ms = (proxy.avg_latency_ms + proxy.latency_ms) / 2
                else:
                    proxy.avg_latency_ms = float(proxy.latency_ms)

            if self.history:
                self.history.update_proxy(proxy)

    def export(self):
        output_dir = Path(self.config['output']['dir'])
        output_dir.mkdir(exist_ok=True)

        alive = sorted(
            [p for p in self.proxies.values() if p.alive],
            key=lambda p: p.latency_ms or 99999,
        )

        if not alive:
            console.print("[yellow]No alive proxies to export.[/yellow]")
            return

        console.print(f"\n[bold cyan]Exporting {len(alive)} alive proxies...[/bold cyan]")

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
                    proto_list = [p for p in alive if p.protocol == proto]
                    path = output_dir / f"{proto.value}.txt"
                    with open(path, 'w') as f:
                        f.write('\n'.join(p.address for p in proto_list))
                    if proto_list:
                        console.print(f"  [green]✓[/] {path} ({len(proto_list)} proxies)")
            else:
                path = output_dir / "all.txt"
                with open(path, 'w') as f:
                    f.write('\n'.join(p.address for p in alive))
                console.print(f"  [green]✓[/] {path}")

        if self.config['output']['generate_elite_list']:
            elite = [p for p in alive if p.anonymity == AnonymityLevel.ELITE]
            path = output_dir / "elite.txt"
            with open(path, 'w') as f:
                f.write('\n'.join(p.address for p in elite))
            console.print(f"  [green]✓[/] {path} ({len(elite)} proxies)")

        if self.config['output']['generate_fast_list']:
            fast = [p for p in alive if p.speed_tier == SpeedTier.FAST]
            path = output_dir / "fast.txt"
            with open(path, 'w') as f:
                f.write('\n'.join(p.address for p in fast))
            console.print(f"  [green]✓[/] {path} ({len(fast)} proxies)")

        if self.config['output'].get('generate_residential_list', False):
            residential = [p for p in alive if p.proxy_type == ProxyType.RESIDENTIAL]
            path = output_dir / "residential.txt"
            with open(path, 'w') as f:
                f.write('\n'.join(p.address for p in residential))
            console.print(f"  [green]✓[/] {path} ({len(residential)} proxies)")

        if self.config['output'].get('split_by_country', False):
            countries = set(p.country_code for p in alive if p.country_code)
            for cc in countries:
                country_list = [p for p in alive if p.country_code == cc]
                path = output_dir / f"country_{cc.lower()}.txt"
                with open(path, 'w') as f:
                    f.write('\n'.join(p.address for p in country_list))

    def print_stats(self) -> Dict[str, Any]:
        alive = [p for p in self.proxies.values() if p.alive]
        total = len(self.proxies) + self.stats['filtered_pre_verify']

        stats_dict = {
            'total': total,
            'alive': len(alive),
            'elite': len([p for p in alive if p.anonymity == AnonymityLevel.ELITE]),
            'fast': len([p for p in alive if p.speed_tier == SpeedTier.FAST]),
        }

        console.print()

        table = Table(
            title="🏆 UPO v3 — Ultimate Proxy Operator",
            show_header=False,
            border_style="bold blue",
        )
        table.add_column("Metric", style="cyan", width=25)
        table.add_column("Value", style="bold white", width=55)

        table.add_row("Total Raw Collected", f"{total:,}")
        table.add_row("Garbage Filtered", f"[red]-{self.stats['filtered_pre_verify']:,}[/red]")
        table.add_row("Verified", f"{self.stats.get('verified_total', len(self.proxies)):,}")

        alive_pct = f"{len(alive)/self.stats['verified_total']:.1%}" if self.stats.get('verified_total') else "N/A"
        table.add_row("✅ ALIVE", f"[bold green]{len(alive):,}[/bold green] ({alive_pct})")
        table.add_row("─" * 20, "─" * 45)

        if alive:
            pc = Counter(p.protocol for p in alive)
            table.add_row(
                "By Protocol",
                f"HTTP: {pc.get(ProxyProtocol.HTTP, 0)} │ HTTPS: {pc.get(ProxyProtocol.HTTPS, 0)} │ S4: {pc.get(ProxyProtocol.SOCKS4, 0)} │ S5: {pc.get(ProxyProtocol.SOCKS5, 0)}"
            )

            ac = Counter(p.anonymity for p in alive if p.anonymity)
            table.add_row(
                "By Anonymity",
                f"[bold green]Elite: {ac.get(AnonymityLevel.ELITE, 0)}[/bold green] │ Anon: {ac.get(AnonymityLevel.ANONYMOUS, 0)} │ Trans: {ac.get(AnonymityLevel.TRANSPARENT, 0)}"
            )

            sc = Counter(p.speed_tier for p in alive if p.speed_tier)
            table.add_row(
                "By Speed",
                f"[bold green]Fast: {sc.get(SpeedTier.FAST, 0)}[/bold green] │ Medium: {sc.get(SpeedTier.MEDIUM, 0)} │ Slow: {sc.get(SpeedTier.SLOW, 0)}"
            )

            pt = Counter(p.proxy_type for p in alive)
            table.add_row(
                "By Type",
                f"Residential: {pt.get(ProxyType.RESIDENTIAL, 0)} │ Datacenter: {pt.get(ProxyType.DATACENTER, 0)} │ Unknown: {pt.get(ProxyType.UNKNOWN, 0)}"
            )

            https_count = len([p for p in alive if p.supports_https])
            table.add_row("HTTPS Support", f"{https_count:,} ({https_count/len(alive)*100:.1f}%)")

            table.add_row("─" * 20, "─" * 45)

            cc = Counter(p.country_code for p in alive if p.country_code).most_common(10)
            if cc:
                table.add_row("Top Countries", ' │ '.join(f"{code}({cnt})" for code, cnt in cc))

            latencies = [p.latency_ms for p in alive if p.latency_ms]
            if latencies:
                table.add_row(
                    "Latency",
                    f"Avg: {sum(latencies)/len(latencies):.0f}ms │ Min: {min(latencies)}ms │ Max: {max(latencies)}ms"
                )

        console.print(Panel(table, border_style="bold blue"))

        return stats_dict

# ==============================================================================
# SECTION 6: CRAWL4AI
# ==============================================================================

async def run_crawl4ai(config: Dict[str, Any]):
    if not config['crawl4ai']['enabled']:
        return

    if not os.path.exists(CRAWL4AI_INSTALL_PATH):
        console.print(f"[yellow]⚠ Crawl4AI not found. Skipping.[/yellow]")
        return

    sys.path.insert(0, CRAWL4AI_INSTALL_PATH)

    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
        from crawl4ai.extraction_strategy import JsonCssExtractionStrategy
    except ImportError:
        console.print("[yellow]⚠ Could not import crawl4ai. Skipping.[/yellow]")
        return

    console.print("\n[bold cyan]Starting Crawl4AI...[/bold cyan]")

    proxy_regex_simple = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\|]\s*(\d{2,5})')
    all_proxies: List[Dict] = []

    async def scrape_free_proxy_list_net(crawler):
        url = "https://free-proxy-list.net/"
        schema = {
            "name": "fpl",
            "baseSelector": "table.table tbody tr",
            "fields": [
                {"name": "ip", "selector": "td:nth-child(1)", "type": "text"},
                {"name": "port", "selector": "td:nth-child(2)", "type": "text"},
                {"name": "https", "selector": "td:nth-child(7)", "type": "text"},
            ],
        }
        run_cfg = CrawlerRunConfig(extraction_strategy=JsonCssExtractionStrategy(schema=schema))
        result = await crawler.arun(url=url, config=run_cfg)
        proxies = []
        if result.extracted_content:
            for row in json.loads(result.extracted_content):
                ip_val = row.get('ip', '').strip()
                port_val = row.get('port', '').strip()
                if ip_val and port_val and port_val.isdigit():
                    proto = 'https' if row.get('https', '').lower() == 'yes' else 'http'
                    proxies.append({"ip": ip_val, "port": port_val, "protocol": proto, "source": "free-proxy-list.net"})
        return proxies

    async def scrape_with_regex(crawler, url, name):
        run_cfg = CrawlerRunConfig()
        result = await crawler.arun(url=url, config=run_cfg)
        proxies = []
        if result.markdown:
            for match in proxy_regex_simple.finditer(result.markdown):
                proxies.append({"ip": match.group(1), "port": match.group(2), "protocol": "http", "source": name})
        return proxies

    scrapers = [
        ("free-proxy-list.net", scrape_free_proxy_list_net),
    ]
    regex_sites = [
        ("proxynova.com", "https://www.proxynova.com/proxy-server-list/"),
        ("proxy-daily.com", "https://proxy-daily.com/"),
    ]

    browser_config = BrowserConfig(headless=True, user_agent=config['general']['user_agent'])

    async with AsyncWebCrawler(config=browser_config) as crawler:
        for name, scraper_fn in scrapers:
            try:
                scraped = await asyncio.wait_for(scraper_fn(crawler), timeout=60)
                all_proxies.extend(scraped)
                console.print(f"  [green]✓[/] {name}: {len(scraped)} proxies")
            except Exception as e:
                console.print(f"  [red]✗[/] {name}: {e}")

        for name, url in regex_sites:
            try:
                scraped = await asyncio.wait_for(scrape_with_regex(crawler, url, name), timeout=60)
                all_proxies.extend(scraped)
                console.print(f"  [green]✓[/] {name}: {len(scraped)} proxies")
            except Exception as e:
                console.print(f"  [red]✗[/] {name}: {e}")

    output_path = Path(config['crawl4ai']['output_file'])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(all_proxies, f, indent=2)

    console.print(f"[bold green]✓ Crawl4AI: {len(all_proxies)} proxies saved.[/bold green]")


# ==============================================================================
# SECTION 7: CLI & PIPELINE
# ==============================================================================

@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--config', 'config_path', default='config.yaml', help='Path to YAML config.')
@click.option('--scrape-only', is_flag=True, help='Collect without verifying.')
@click.option('--no-crawl4ai', is_flag=True, help='Skip browser scrapers.')
@click.option('--no-ban-check', is_flag=True, help='Skip ban checking.')
@click.option('--concurrency', default=None, type=int, help='Override concurrency.')
@click.option('--timeout', default=None, type=int, help='Override timeout.')
@click.option('--country', default=None, help='Filter by country codes (comma-separated, e.g., US,DE,GB).')
@click.option('--exclude-dc', is_flag=True, help='Exclude datacenter proxies.')
@click.option('--test-limit', default=None, type=int, help='Limit testing to N proxies.')
def main(config_path, scrape_only, no_crawl4ai, no_ban_check, concurrency, timeout, country, exclude_dc, test_limit):
    """🏆 UPO v3 — Ultimate Proxy Operator (Enhanced)"""
    banner = """
[bold blue]
 ██╗   ██╗██████╗  ██████╗     ██╗   ██╗██████╗ 
 ██║   ██║██╔══██╗██╔═══██╗    ██║   ██║╚════██╗
 ██║   ██║██████╔╝██║   ██║    ██║   ██║ █████╔╝
 ██║   ██║██╔═══╝ ██║   ██║    ╚██╗ ██╔╝ ╚═══██╗
 ╚██████╔╝██║     ╚██████╔╝     ╚████╔╝ ██████╔╝
  ╚═════╝ ╚═╝      ╚═════╝       ╚═══╝  ╚═════╝ 
[/bold blue]
[dim]v3 Enhanced — Scrape · Verify · Categorize · Track[/dim]
"""
    console.print(Panel(banner, border_style="bold blue", expand=False))

    config = DEFAULT_CONFIG.copy()
    import copy
    config = copy.deepcopy(DEFAULT_CONFIG)
    
    if os.path.exists(config_path):
        try:
            import yaml
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
    if no_ban_check:
        config['ban_check']['enabled'] = False
    if country:
        config['filter']['allowed_countries'] = [c.strip().upper() for c in country.split(',')]
    if exclude_dc:
        config['filter']['exclude_datacenters'] = True
    if test_limit:
        config['test_limit'] = test_limit

    asyncio.run(pipeline(config, scrape_only))

async def pipeline(config: Dict[str, Any], scrape_only: bool):
    start = time.monotonic()

    if config['crawl4ai']['enabled'] and not scrape_only:
        await run_crawl4ai(config)

    engine = UPOEngine(config)
    await engine.initialize()

    console.print("\n[bold cyan]═══ PHASE 1: COLLECTION ═══[/bold cyan]")
    await engine.collect()
    total_sources = len(GITHUB_HTTP_SOURCES) + len(GITHUB_SOCKS4_SOURCES) + len(GITHUB_SOCKS5_SOURCES) + len(API_SOURCES)
    console.print(f"[green]✓[/] Collected {len(engine.proxies):,} unique proxies from {total_sources} sources.")

    console.print("\n[bold cyan]═══ PHASE 2: PRE-ENRICHMENT ═══[/bold cyan]")
    engine.pre_enrich()
    console.print(f"[green]✓[/] Pre-enriched {len(engine.proxies):,} proxies with GeoIP/ASN data.")

    console.print("\n[bold cyan]═══ PHASE 3: FILTERING ═══[/bold cyan]")
    engine.filter_garbage()

    if not scrape_only:
        console.print("\n[bold cyan]═══ PHASE 4: VERIFICATION ═══[/bold cyan]")
        await engine.verify()

        if config['ban_check']['enabled']:
            await engine.check_bans()

        console.print("\n[bold cyan]═══ PHASE 5: ENRICHMENT ═══[/bold cyan]")
        engine.enrich_and_categorize()
        alive_count = sum(1 for p in engine.proxies.values() if p.alive)
        console.print(f"[green]✓[/] Enriched {alive_count:,} alive proxies.")
    else:
        console.print("\n[yellow]⏭ --scrape-only: Skipping verification.[/yellow]")

    console.print("\n[bold cyan]═══ PHASE 6: EXPORT ═══[/bold cyan]")
    engine.export()

    stats = engine.print_stats()

    elapsed = time.monotonic() - start
    console.print(f"\n[bold]⏱ Total time: {elapsed:.1f} seconds[/bold]")


if __name__ == "__main__":
    main()
