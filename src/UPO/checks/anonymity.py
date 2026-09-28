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


class AnonymityMixin:
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

    async def _anon_check_one(
        self, proxy: Proxy, session=None, kwargs=None
    ):
        # FIX #5: Shorter 5s timeout for anonymity — httpbin is slow
        timeout = aiohttp.ClientTimeout(total=5, connect=3)
        own = session is None
        if own:
            session, kwargs = self._create_proxy_session(proxy, timeout)
            if not session:
                proxy.anonymity = AnonymityLevel.ANONYMOUS
                return
        try:
            # httpbin.org/headers is the only judge that returns full headers
            # so we must use it specifically here regardless of rotation
            url = "http://httpbin.org/headers"
            async with session.get(url, timeout=timeout, **(kwargs or {})) as r:
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
            # These are all expected/normal for SOCKS5 → HTTP tunnel failures
            EXPECTED_ERRORS = {
                "ClientError",
                "ServerDisconnectedError",
                "ClientOSError",
                "ClientConnectorError",
                "ClientProxyConnectionError",
                "ProxyConnectionError",
                "ProxyError",
                "IncompleteReadError",
                "ContentTypeError",
                "JSONDecodeError",
                "ServerTimeoutError",
                "ClientResponseError",
                "TooManyRedirects",
            }
            err_name = type(e).__name__
            if err_name not in EXPECTED_ERRORS:
                console.print(
                    f"[dim red]Anon check {proxy.address}: "
                    f"{err_name}: {e}[/dim red]"
                )
        finally:
            if own:
                await session.close()

