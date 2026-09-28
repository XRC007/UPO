"""SECTION 0: CONFIG & SOURCES.

Static configuration data extracted verbatim from the ``UPO.py`` monolith:
the default config tree, every scrape source list, the ASN/country heuristics
and the proxy-matching regex.

Nothing here imports from the rest of the package, so it is safe to import from
any module (including ``UPO.core.engine``) without creating a cycle.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set

import yaml

from .utils.console import console

# Absolute root of the optional crawl4ai checkout used by
# ``UPO.collectors.crawl4ai_runner`` as a fallback when crawl4ai is not
# importable from the active virtualenv.
CRAWL4AI_INSTALL_PATH = r"D:\3dAI\Data Analyze"

DEFAULT_CONFIG = {
    "general": {
        "concurrency": 150,
        "timeout_connect": 12,
        "timeout_total": 25,
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "verification_rounds": 1,
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
            "https://api4.my-ip.io/ip.txt",
            "https://ip4.seeip.org",
            "https://4.ident.me",
            "https://ipv4.icanhazip.com",
            "https://api.my-ip.io/ip.txt",
            "https://ip.42.pl/raw",
            "https://eth0.me",
            "https://tnx.nl/ip",
            "https://myip.dnsomatic.com",
            "http://bot.whatismyipaddress.com",
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
        "max_per_subnet": 100,   # ← cap proxies per /24 subnet (0 = disabled)
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
    # ── Lifecycle (pipelined per-proxy engine, improvement I2–I6) ──────
    "lifecycle": {
        "enabled": True,          # default path; --serial opts back to phases
        "max_in_flight": 5000,    # admission semaphore: live coroutines at once
        "stage_limits": {         # per-stage concurrency gates
            "verify": None,       # None → follow general.concurrency
            "anonymity": None,
            "speed": 30,
            "fingerprint": 40,
            "dns": 40,
            "ban": 25,
            "protocol": 50,
        },
        "session_reuse": True,    # I4: one warm session per proxy for HTTP checks
        "tcp_dedup": True,        # I3: one probe per ip:port shared by variants
        "skip_known_dead": {      # I6 probation gate
            "enabled": True,
            "min_fails": 5,       # failures on the worst identity
            "stale_hours": 2.0,   # no variant seen alive within this window
            "probe_timeout": 2.0,  # probation TCP connect timeout (fast path)
        },
        "raw_socks": True,        # I5: asyncio SOCKS handshake for SOCKS proxies
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
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
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
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/yuceltoluyag/GoodProxy/main/raw.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/http.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/http.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/https.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt",
    "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
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
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks4_proxies.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks4.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/socks4.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks4",
]

GITHUB_SOCKS5_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/generated/socks5_proxies.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/master/proxies/socks5.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/socks5.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5",
]

API_SOURCES = [
    # (Legacy untargeted proxyscrape calls removed to prevent duplicate 2000-cap limiting)
    {"url": "https://api.openproxylist.xyz/http.txt", "protocol": "http"},
    {"url": "https://api.openproxylist.xyz/socks4.txt", "protocol": "socks4"},
    {"url": "https://api.openproxylist.xyz/socks5.txt", "protocol": "socks5"},
    # ─── 🆕 Bypass Geonode Limits (Geographically Targeted) ──────────
    *[
        {
            "url": f"https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&country={cc}", 
            "protocol": "mixed", "format": "json"
        }
        for cc in ["US", "GB", "DE", "FR", "NL", "CA", "KR", "JP", "SG", "AU", "TR", "BR", "RU", "IN", "ID", "MY", "TW", "HK", "VN", "PL"]
    ],

    # ─── 🆕 Proxifly (CDN - Updated every 5 min, 79+ countries) ─────────
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.txt", "protocol": "http"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks4/data.txt", "protocol": "socks4"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt", "protocol": "socks5"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt", "protocol": "mixed"},
    {"url": "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json", "protocol": "mixed", "format": "json"},

    # ─── 🆕 iplocate ─────────
    {"url": "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/http.txt", "protocol": "http"},
    {"url": "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/https.txt", "protocol": "https"},
    {"url": "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks4.txt", "protocol": "socks4"},
    {"url": "https://raw.githubusercontent.com/iplocate/free-proxy-list/refs/heads/main/protocols/socks5.txt", "protocol": "socks5"},

    # ─── 🆕 SpyS.one API (Raw list, huge DB) ─────────────────────────────
    {"url": "https://spys.me/proxy.txt", "protocol": "http"},
    {"url": "https://spys.me/socks.txt", "protocol": "socks5"},

    # ─── 🆕 redscrape ─────────────────────────────
    {"url": "https://free.redscrape.com/api/proxies?type=http&format=txt", "protocol": "http"},
    {"url": "https://free.redscrape.com/api/proxies?type=socks4&format=txt", "protocol": "socks4"},
    {"url": "https://free.redscrape.com/api/proxies?type=socks5&format=txt", "protocol": "socks5"},

    # ─── 🆕 Bypass ProxyScrape 2000 Hard Limit (Geographically Targeted) ──────────
    # Requesting "all" triggers a hard 2000-proxy limit, missing huge pockets.
    # By querying target countries individually, we can extract 10,000+ proxies!
    *[
        {
            "url": f"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type={pt}&timeout=10000&country={cc}", 
            "protocol": pt
        }
        for pt in ["http", "socks4", "socks5"]
        for cc in ["US", "GB", "DE", "FR", "NL", "CA", "KR", "JP", "SG", "AU", "TR", "BR", "RU", "IN", "ID", "MY", "TW", "HK", "VN", "PL"]
    ],

    # ─── 🆕 proxyspace.pro ────────────────────────────────────────────────
    {"url": "https://proxyspace.pro/http.txt",   "protocol": "http"},
    {"url": "https://proxyspace.pro/socks4.txt", "protocol": "socks4"},
    {"url": "https://proxyspace.pro/socks5.txt", "protocol": "socks5"},
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


def total_source_count() -> int:
    """Number of distinct scrape sources (used for the collection banner)."""
    return (
        len(GITHUB_HTTP_SOURCES) + len(GITHUB_SOCKS4_SOURCES)
        + len(GITHUB_SOCKS5_SOURCES) + len(API_SOURCES)
    )


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``override`` into ``base`` (mutates and returns base).

    Fix for improvement I7: the legacy shallow ``dict.update`` made a partial
    user section (e.g. ``general: {concurrency: 500}``) wipe every sibling
    default in that section. Nested dicts merge key-by-key; every other value
    (lists, scalars) replaces wholesale, which is the principle of least
    surprise for config.
    """
    for key, value in override.items():
        if (
            isinstance(value, dict)
            and isinstance(base.get(key), dict)
        ):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Build the effective config: ``DEFAULT_CONFIG`` + optional YAML override.

    Merge is a RECURSIVE deep merge (I7) — a partial section in the user file
    now keeps the untouched sibling defaults. Unknown keys are copied straight
    in, and a malformed file degrades to the defaults with a warning instead
    of aborting the run.
    """
    import copy

    config = copy.deepcopy(DEFAULT_CONFIG)
    if not config_path or not os.path.exists(config_path):
        return config
    try:
        # utf-8-sig transparently strips a BOM; without it a BOM silently
        # mangles the first YAML key ("\ufeffoutput") and that section's
        # overrides are ignored — silent config corruption.
        with open(config_path, encoding="utf-8-sig") as f:
            user_config = yaml.safe_load(f)
        if user_config:
            deep_merge(config, user_config)
    except Exception as e:
        console.print(f"[yellow]⚠ Config error: {e}[/yellow]")
    return config