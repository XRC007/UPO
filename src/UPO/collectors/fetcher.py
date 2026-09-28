from __future__ import annotations

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

import geoip2.database
import yaml
from rich.progress import (
    Progress, BarColumn, TextColumn,
    TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel

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
from ..core.filter import IPFilter
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


class CollectMixin:
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
                    if not ip:
                        continue
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

    def filter_garbage(self):
        before = len(self.proxies)

        # ── Track per-source contamination BEFORE we delete anything ──────
        # Build a snapshot: ip → source, for proxies we are about to
        # examine so that after deletion we can report which sources fed
        # the most garbage.
        _src: Dict[str, str] = {
            addr: p.source for addr, p in self.proxies.items()
        }
        # Counts: source → reason → count
        source_garbage: Dict[str, Counter] = {}

        def _record(addr: str, reason: str):
            src = _src.get(addr, "unknown")
            # Shorten raw GitHub/CDN URLs to just the hostname for readability
            if src.startswith("http"):
                try:
                    src = src.split("/")[2]
                except IndexError:
                    pass
            source_garbage.setdefault(src, Counter())[reason] += 1

        # ── IP-range / port / country filter ──────────────────────────────
        # We need to do this manually (not via filter_batch) so we can
        # record which source each dropped proxy came from.
        valid: Dict[str, Proxy] = {}
        rstats: Counter = Counter()
        for addr, p in self.proxies.items():
            try:
                ip_address(p.ip)
            except ValueError:
                rstats["invalid_ip"] += 1
                _record(addr, "invalid_ip")
                continue
            if self.ip_filter.is_private(p.ip):
                rstats["private_ip"] += 1
                _record(addr, "private_ip")
                continue
            if self.ip_filter.is_cloudflare(p.ip):
                rstats["cloudflare_ip"] += 1
                _record(addr, "cloudflare_ip")
                continue
            if p.port < 1 or p.port > 65535:
                rstats["invalid_port"] += 1
                _record(addr, "invalid_port")
                continue
            allowed = self.config["filter"].get("allowed_countries", [])
            blocked = self.config["filter"].get("blocked_countries", [])
            if allowed and p.country_code and p.country_code not in allowed:
                rstats["country_filtered"] += 1
                _record(addr, "country_filtered")
                continue
            if blocked and p.country_code and p.country_code in blocked:
                rstats["country_blocked"] += 1
                _record(addr, "country_blocked")
                continue
            valid[addr] = p
        self.proxies = valid

        # ── CDN ASN filter ─────────────────────────────────────────────────
        cdn_rm = [
            a for a, p in self.proxies.items()
            if p.asn and p.asn in CDN_ASNS
        ]
        for a in cdn_rm:
            _record(a, "cdn_asn")
            del self.proxies[a]
        rstats["cdn_asn"] = len(cdn_rm)

        # ── Blacklist filter ───────────────────────────────────────────────
        bl_rm = [
            a for a, p in self.proxies.items() if p.ip in self.blacklist
        ]
        for a in bl_rm:
            _record(a, "blacklisted")
            del self.proxies[a]
        rstats["blacklisted"] = len(bl_rm)

        # ── Datacenter filter (optional) ───────────────────────────────────
        if self.config["filter"].get("exclude_datacenters"):
            dc_rm = [
                a for a, p in self.proxies.items()
                if p.proxy_type == ProxyType.DATACENTER
            ]
            for a in dc_rm:
                _record(a, "datacenter")
                del self.proxies[a]
            rstats["datacenter"] = len(dc_rm)

        # ── Per /24 subnet cap — prevents single datacenter flooding ───────
        subnet_cap = self.config["filter"].get("max_per_subnet", 50)
        if subnet_cap and subnet_cap > 0:
            subnet_counts: Counter = Counter()
            subnet_rm = []
            priority_order = sorted(
                self.proxies.items(),
                key=lambda x: (0 if x[1].source == "verified_db" else 1)
            )
            for addr, p in priority_order:
                try:
                    parts = p.ip.split(".")
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                    if subnet_counts[subnet] >= subnet_cap:
                        subnet_rm.append(addr)
                    else:
                        subnet_counts[subnet] += 1
                except (IndexError, AttributeError):
                    continue
            for a in subnet_rm:
                if a in self.proxies:
                    _record(a, "subnet_capped")
                    del self.proxies[a]
            rstats["subnet_capped"] = len(subnet_rm)

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

        # ── Source contamination leaderboard ──────────────────────────────
        # Rank sources by total garbage they contributed.
        # This identifies which upstream feeds are polluted so you can
        # remove or deprioritise them.
        if source_garbage:
            # Total dropped per source
            src_totals = {
                src: sum(c.values())
                for src, c in source_garbage.items()
            }
            top_polluters = sorted(
                src_totals.items(), key=lambda x: -x[1]
            )[:10]
            console.print(
                "\n  [bold yellow]Noisy Sources (top garbage contributors):[/bold yellow]"
            )
            for src, total in top_polluters:
                breakdown = source_garbage[src]
                # Show the top 2 reasons for this source
                top_reasons = ", ".join(
                    f"{r}={n}"
                    for r, n in breakdown.most_common(2)
                )
                console.print(
                    f"    [yellow]⚠[/] {src}: "
                    f"[red]{total:,}[/red] dropped "
                    f"[dim]({top_reasons})[/dim]"
                )

