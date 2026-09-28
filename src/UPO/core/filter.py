"""SECTION 2: IP FILTER.

Pure, engine-independent filtering of a collected proxy batch: malformed IPs,
private/reserved space, Cloudflare ranges, invalid ports and country
allow/deny lists. Blacklist enforcement lives in the collection phase, not
here — ``filter_batch`` deliberately has no blacklist parameter.
"""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address, ip_network
from typing import Dict, Tuple

from ..config import CLOUDFLARE_IP_RANGES
from ..models import Proxy


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


__all__ = ["IPFilter"]