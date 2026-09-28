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
from .. import socks as socks_mod
from ..utils.console import console


class ProtocolMixin:
    async def detect_protocols(self):
        if not self.config["protocol_detection"]["enabled"]:
            return
        alive = [p for p in self.proxies.values() if p.alive]
        if not alive:
            return

        # FIX #3: Use protocol detection judge (module 2)
        judge_url = self._get_judge(2)
        console.print(
            f"\n[cyan]Protocol detection on {len(alive)} proxies...[/cyan]"
        )
        console.print(f"  [dim]Using judge: {judge_url}[/dim]")
        sem = asyncio.Semaphore(self.config["general"]["concurrency"])

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), transient=True,
        ) as prog:
            tid = prog.add_task("[cyan]Protocols...", total=len(alive))

            async def worker(p):
                async with sem:
                    await self._detect_protocols_one(p, judge_url)
                prog.update(tid, advance=1)

            await asyncio.gather(*[worker(p) for p in alive])

        multi = sum(1 for p in alive if len(p.detected_protocols) > 1)
        console.print(f"[green]✓[/] {multi} proxies support 2+ protocols.")

    async def _detect_protocols_one(
        self, proxy: Proxy, judge_url: str,
        session=None, kwargs=None, raw_socks: bool = False,
    ):
        """Probe which protocols this endpoint actually serves.

        ``session``/``kwargs`` are an already-created warm session for the
        proxy's *own* protocol (used by the lifecycle engine, I4) — it is
        only reused for the variant matching ``proxy.protocol``; the other
        variants get fresh sessions (or, with ``raw_socks=True``, the cheap
        asyncio SOCKS client of UPO.socks, I5).
        """
        proxy.detected_protocols = []
        timeout = aiohttp.ClientTimeout(total=8, connect=5)
        shared_session, shared_kwargs = session, (kwargs or {})
        for proto in [ProxyProtocol.SOCKS5, ProxyProtocol.SOCKS4,
                      ProxyProtocol.HTTPS, ProxyProtocol.HTTP]:
            used_shared = False
            try:
                if (
                    raw_socks
                    and proto in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5)
                ):
                    version = (
                        socks_mod.SOCKS_VERSION_5
                        if proto == ProxyProtocol.SOCKS5
                        else socks_mod.SOCKS_VERSION_4
                    )
                    status, text = await socks_mod.socks_http_get(
                        proxy.ip, proxy.port, version, "GET",
                        judge_url, self.headers, timeout=8,
                    )
                    if status == 200 and re.search(
                        r"\d+\.\d+\.\d+\.\d+", text
                    ):
                        proxy.detected_protocols.append(proto.value)
                    continue
                if shared_session is not None and proto == proxy.protocol:
                    used_shared = True
                    test_session, test_kwargs = shared_session, shared_kwargs
                else:
                    test_proxy = Proxy(
                        ip=proxy.ip, port=proxy.port, protocol=proto,
                        source="",
                    )
                    test_session, test_kwargs = self._create_proxy_session(
                        test_proxy, timeout
                    )
                if not test_session:
                    continue
                try:
                    async with test_session.get(
                        judge_url, timeout=timeout, **(test_kwargs or {})
                    ) as r:
                        if r.status == 200:
                            text = await r.text()
                            if re.search(r"\d+\.\d+\.\d+\.\d+", text):
                                proxy.detected_protocols.append(proto.value)
                                if proto == ProxyProtocol.HTTP:
                                    try:
                                        async with test_session.get(
                                            "https://httpbin.org/ip",
                                            timeout=timeout,
                                            **(test_kwargs or {})
                                        ) as r2:
                                            if r2.status == 200:
                                                proxy.supports_https = True
                                    except Exception:
                                        pass
                except Exception:
                    pass
                finally:
                    if not used_shared:
                        try:
                            await test_session.close()
                        except Exception:
                            pass
            except Exception:
                pass

        # FIX #4: Deduplicate detected protocols
        proxy.detected_protocols = list(
            dict.fromkeys(proxy.detected_protocols)
        )

