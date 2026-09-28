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


class SpeedMixin:
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

    async def _speed_test_one(
        self, proxy: Proxy, test_url: str, session=None, kwargs=None
    ):
        timeout = aiohttp.ClientTimeout(total=20, connect=8)
        own = session is None
        if own:
            session, kwargs = self._create_proxy_session(proxy, timeout)
            if not session:
                return
        try:
            start = time.monotonic()
            async with session.get(test_url, timeout=timeout, **(kwargs or {})) as r:
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
            if own:
                await session.close()

