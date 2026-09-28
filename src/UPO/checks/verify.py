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
from ..core.limiter import RateLimiter
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


class VerifyMixin:
    async def test_judges(self):
        console.print("\n[cyan]Testing judge servers...[/cyan]")
        timeout = aiohttp.ClientTimeout(total=10)
        results = []
        async with aiohttp.ClientSession(
            headers=self.headers, timeout=timeout
        ) as session:
            for url in self.config["judges"]["urls"]:
                try:
                    start = time.monotonic()
                    async with session.get(url) as r:
                        if r.status == 200:
                            text = await r.text()
                            if len(text) < 2000:
                                latency = time.monotonic() - start
                                results.append((url, latency))
                except Exception:
                    continue

        # Remove httpbin judges from rotation pool since anonymity
        # module always hits httpbin.org/headers directly.
        # This prevents double-hammering httpbin from both
        # the anonymity module AND verification/protocol modules.
        filtered = [
            (url, lat) for url, lat in results
            if "httpbin.org" not in url
        ]
        # Fall back to unfiltered if all non-httpbin judges failed
        self.judges = sorted(
            filtered if filtered else results,
            key=lambda x: x[1],
        )[:5]
        if self.judges:
            console.print(
                f"[green]✓[/] {len(self.judges)} judges online. "
                f"Fastest: {self.judges[0][0]} "
                f"({self.judges[0][1]*1000:.0f}ms)"
            )
            # FIX #3: Show judge assignment plan
            labels = ["verify", "anonymity", "protocol", "speed/ban/fp"]
            for i, label in enumerate(labels):
                j = self._get_judge(i)
                console.print(f"  [dim]{label} → {j}[/dim]")
        else:
            console.print("[bold red]✗ No judges reachable![/bold red]")

    async def tcp_prefilter(self):
        """
        Fast TCP connect sweep — eliminates unreachable proxies in <90s.
        No HTTP overhead, just checks if the port accepts connections.
        Runs BEFORE full verification to dramatically shrink the check pool.
        """
        total = len(self.proxies)
        console.print(
            f"\n[cyan]TCP pre-filter: {total:,} proxies "
            f"(3s connect timeout)...[/cyan]"
        )
        sem = asyncio.Semaphore(500)
        reachable = 0

        async def tcp_check(proxy: Proxy):
            nonlocal reachable
            async with sem:
                try:
                    conn = asyncio.open_connection(proxy.ip, proxy.port)
                    reader, writer = await asyncio.wait_for(conn, timeout=3.0)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    proxy._tcp_ok = True
                    reachable += 1
                except Exception:
                    proxy._tcp_ok = False

        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(),
            TextColumn("│ Open: {task.fields[reachable]}"),
            TimeRemainingColumn(),
        ) as prog:
            tid = prog.add_task(
                "[cyan]TCP ping...", total=total, reachable=0
            )

            async def worker(p):
                await tcp_check(p)
                prog.update(tid, advance=1, reachable=reachable)

            await asyncio.gather(*[worker(p) for p in self.proxies.values()])

        # Remove TCP-dead proxies from the pool entirely
        before = len(self.proxies)
        self.proxies = {
            a: p for a, p in self.proxies.items()
            if getattr(p, "_tcp_ok", False)
        }
        after = len(self.proxies)
        removed = before - after
        pct = removed / max(before, 1) * 100
        # ← Save for correct Total Raw stat in print_stats()
        self.stats["tcp_prefilter_removed"] = removed
        console.print(
            f"[green]✓[/] TCP pre-filter: "
            f"{before:,} → {after:,} "
            f"([red]-{removed:,} / {pct:.0f}% dead removed[/red])"
        )

    async def verify(self):
        if not self.proxies:
            return
        await self.test_judges()
        if not self.judges:
            console.print(
                "[bold red]FATAL: No judges reachable. "
                "Cannot verify proxies. Check your internet "
                "connection or judge URLs in config.[/bold red]"
            )
            console.print(
                "[yellow]Tip: Run with --scrape-only to skip "
                "verification and just collect proxies.[/yellow]"
            )
            return

        rounds = self.config["general"].get("verification_rounds", 1)

        for round_num in range(1, rounds + 1):
            if round_num == 1:
                to_check = list(self.proxies.values())
            else:
                to_check = [
                    p for p in self.proxies.values()
                    if p.success_count > 0
                ]
                if not to_check:
                    break
                for p in to_check:
                    p.alive = False
                console.print(
                    f"\n[cyan]Round {round_num}: Re-checking "
                    f"{len(to_check):,} proxies...[/cyan]"
                )
                await asyncio.sleep(3)

            sem = asyncio.Semaphore(self.config["general"]["concurrency"])
            alive_count = 0

            # FIX #3: Use verification judge (module 0), rotate per round
            judge_idx = (round_num - 1) % len(self.judges)
            judge_url = self.judges[judge_idx][0]

            with Progress(
                SpinnerColumn(), TextColumn("{task.description}"),
                BarColumn(), MofNCompleteColumn(),
                TextColumn("│ Alive: {task.fields[alive]}"),
                TimeRemainingColumn(),
            ) as prog:
                tid = prog.add_task(
                    f"[cyan]Round {round_num}/{rounds}...",
                    total=len(to_check), alive=0,
                )

                async def worker(p):
                    nonlocal alive_count
                    async with sem:
                        await self._check_one(p, judge_url)
                    if p.alive:
                        alive_count += 1
                    prog.update(tid, advance=1, alive=alive_count)

                # Process in 5k chunks to keep memory and sockets flat
                CHUNK_SIZE = 5000
                for chunk_start in range(0, len(to_check), CHUNK_SIZE):
                    chunk = to_check[chunk_start:chunk_start + CHUNK_SIZE]
                    await asyncio.gather(*[worker(p) for p in chunk])
                    # Brief pause between chunks — lets OS reclaim sockets
                    if chunk_start + CHUNK_SIZE < len(to_check):
                        await asyncio.sleep(0.3)

        # Reliability threshold — STRICT majority required (FIX #2)
        # 1 round:  1/1=1.0 ✓   0/1=0.0 ✗
        # 2 rounds: 2/2=1.0 ✓   1/2=0.5 ✗   0/2=0.0 ✗
        # 3 rounds: 3/3=1.0 ✓   2/3=0.67 ✓  1/3=0.33 ✗
        rounds = self.config["general"].get("verification_rounds", 1)
        for p in self.proxies.values():
            if p.check_count > 0:
                p.reliability = round(p.success_count / p.check_count, 2)
                p.alive = p.reliability > 0.5
            else:
                p.alive = False

        self.stats["verified_total"] = len(self.proxies)
        self.stats["verified_alive"] = sum(
            1 for p in self.proxies.values() if p.alive
        )

    async def _check_one(
        self, proxy: Proxy, judge_url: str,
        session=None, kwargs=None,
    ):
        """Single verification check through one proxy against a judge.

        ``session``/``kwargs`` may be supplied by the lifecycle engine to
        reuse a warm proxy session (I4). When omitted, the legacy behavior
        is preserved exactly: create a session with the configured timeouts,
        use it once, close it.
        """
        proxy.check_count += 1
        proxy.last_checked = datetime.now(timezone.utc).isoformat()
        own = session is None
        if own:
            timeout = aiohttp.ClientTimeout(
                total=self.config["general"]["timeout_total"],
                connect=self.config["general"]["timeout_connect"],
            )
            session, kwargs = self._create_proxy_session(proxy, timeout)
            if not session:
                proxy.alive = False
                proxy.fail_count += 1
                return
        try:
            start = time.monotonic()
            async with session.get(judge_url, **kwargs) as r:
                latency_ms = int((time.monotonic() - start) * 1000)
                if r.status == 200:
                    body = (await r.text()).strip()
                    self._validate_judge(body, proxy, latency_ms)
                else:
                    proxy.alive = False
                    proxy.fail_count += 1
        except Exception:
            proxy.alive = False
            proxy.fail_count += 1
        finally:
            if own:
                await session.close()
                await asyncio.sleep(0.01)
        # NOTE: when the lifecycle engine passes a shared session (own=False)
        # it stays open on purpose — lifecycle closes it once after all
        # stages. Per-stage pacing is replaced by the lifecycle's semaphores.

    def _validate_judge(self, body: str, proxy: Proxy, latency_ms: int):
        if not body or len(body) > 5000:
            proxy.alive = False
            proxy.fail_count += 1
            return

        found_ips: List[str] = []

        # Try JSON first — handles httpbin, ipify, ip-api formats
        try:
            data = json.loads(body)
            raw = (
                data.get("origin") or
                data.get("ip") or
                data.get("query") or
                data.get("YourFuckingIPAddress", "")
            )
            if raw:
                # httpbin returns "1.2.3.4, 5.6.7.8" for chained proxies
                found_ips = [ip.strip() for ip in str(raw).split(",")]
        except (json.JSONDecodeError, AttributeError):
            pass

        # Fallback: regex scrape all IPs from plain-text response
        if not found_ips:
            found_ips = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", body)

        if not found_ips:
            proxy.alive = False
            proxy.fail_count += 1
            return

        # Only fail if EVERY found IP matches our real IP
        # (one different IP = proxy is working)
        if self.my_ip and all(ip.strip() == self.my_ip for ip in found_ips):
            proxy.alive = False
            proxy.fail_count += 1
            return

        proxy.alive = True
        proxy.latency_ms = latency_ms
        proxy.success_count += 1
        proxy.uptime_history.append(True)
        if len(proxy.uptime_history) > 100:
            proxy.uptime_history = proxy.uptime_history[-100:]

