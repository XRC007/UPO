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
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


class FingerprintMixin:
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

    async def _fingerprint_one(
        self, proxy: Proxy, session=None, kwargs=None
    ):
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        own = session is None
        if own:
            session, kwargs = self._create_proxy_session(proxy, timeout)
            if not session:
                return
        try:
            async with session.get(
                "https://1.1.1.1/cdn-cgi/trace",
                timeout=timeout, **(kwargs or {})
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
            if own:
                await session.close()

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

