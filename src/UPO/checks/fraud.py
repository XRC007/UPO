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
from ..core.limiter import RateLimiter
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


class FraudMixin:
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

