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


class DnsMixin:
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

    async def _dns_leak_one(
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
                    for line in text.strip().split("\n"):
                        if line.startswith("ip="):
                            visible_ip = line.split("=")[1].strip()
                            proxy.dns_leak = (visible_ip == self.my_ip)
                            break
        except Exception:
            pass
        finally:
            if own:
                await session.close()

