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


class BanMixin:
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
        self, proxy: Proxy, url: str, pattern: str,
        session=None, kwargs=None,
    ) -> bool:
        timeout = aiohttp.ClientTimeout(total=15)
        own = session is None
        if own:
            session, kwargs = self._create_proxy_session(proxy, timeout)
            if not session:
                return True
        try:
            async with session.get(url, timeout=timeout, **(kwargs or {})) as r:
                if r.status == 200:
                    text = await r.text()
                    return pattern.lower() not in text.lower()
                return True
        except Exception:
            return True
        finally:
            if own:
                await session.close()

