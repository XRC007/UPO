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
from ..config import CRAWL4AI_INSTALL_PATH
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


async def run_crawl4ai(config: Dict):
    """Run Crawl4AI in a separate thread with ProactorEventLoop.

    The main loop uses WindowsSelectorEventLoopPolicy (for aiohttp),
    but Playwright needs ProactorEventLoop for subprocess support.
    We solve this by running the entire crawl4ai pipeline in a
    dedicated thread with its own ProactorEventLoop.
    """
    if not config["crawl4ai"]["enabled"]:
        return

    try:
        from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig
        from crawl4ai.extraction_strategy import JsonCssExtractionStrategy
    except Exception as e:
        import traceback
        console.print(f"[yellow]⚠ crawl4ai import failed:[/yellow]")
        traceback.print_exc()
        return

    console.print("\n[bold cyan]Crawl4AI scraping...[/bold cyan]")

    # ── Inner async function that runs on a ProactorEventLoop ──
    async def _crawl4ai_inner():
        proxy_rx = re.compile(
            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*[:\|]\s*(\d{2,5})"
        )
        all_proxies: List[Dict] = []

        async def scrape_fpl(crawler):
            schema = {
                "name": "fpl",
                "baseSelector": "table.table tbody tr",
                "fields": [
                    {"name": "ip", "selector": "td:nth-child(1)", "type": "text"},
                    {"name": "port", "selector": "td:nth-child(2)", "type": "text"},
                    {"name": "https", "selector": "td:nth-child(7)", "type": "text"},
                ],
            }
            cfg = CrawlerRunConfig(
                extraction_strategy=JsonCssExtractionStrategy(schema=schema)
            )
            result = await crawler.arun(
                url="https://free-proxy-list.net/", config=cfg
            )
            proxies = []
            if result.extracted_content:
                for row in json.loads(result.extracted_content):
                    ip = row.get("ip", "").strip()
                    port = row.get("port", "").strip()
                    if ip and port and port.isdigit():
                        proto = (
                            "https"
                            if row.get("https", "").lower() == "yes"
                            else "http"
                        )
                        proxies.append({
                            "ip": ip, "port": port, "protocol": proto,
                            "source": "free-proxy-list.net",
                        })
            return proxies

        async def scrape_regex(crawler, url, name):
            result = await crawler.arun(url=url, config=CrawlerRunConfig())
            return [
                {"ip": m.group(1), "port": m.group(2),
                 "protocol": "http", "source": name}
                for m in proxy_rx.finditer(result.markdown or "")
            ]

        # ── proxy-daily.com: uses a JS DataTable fed by their JSON API ──
        # The static HTML only has placeholder "-" cells; we must hit the
        # real serverside endpoint directly (no browser required).
        async def scrape_proxy_daily_api() -> List[Dict]:
            base = "https://proxy-daily.com"
            headers = {
                "User-Agent": config["general"]["user_agent"],
                "Referer": "https://proxy-daily.com/",
                "X-Requested-With": "XMLHttpRequest",
            }
            proxies_out: List[Dict] = []
            # --- Strategy 1: paginated JSON serverside API ---
            try:
                page_size = 100
                start = 0
                draw = 1
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as sess:
                    while True:
                        url = (
                            f"{base}/api/serverside/proxies"
                            f"?draw={draw}&start={start}&length={page_size}"
                        )
                        async with sess.get(url) as resp:
                            if resp.status != 200:
                                break
                            data = await resp.json(content_type=None)
                        rows = data.get("data", [])
                        if not rows:
                            break
                        for row in rows:
                            ip   = str(row.get("ip", "")).strip()
                            port = str(row.get("port", "")).strip()
                            # protocol field can be "Http", "Socks4",
                            # "Http, Https", "Http, Socks4", etc.
                            raw_proto = row.get("protocol", "Http")
                            # Emit one entry per detected protocol
                            for p in [x.strip() for x in raw_proto.split(",")]:
                                p_lower = p.lower()
                                if p_lower in ("http", "https", "socks4", "socks5"):
                                    proto = p_lower
                                else:
                                    proto = "http"
                                if ip and port:
                                    proxies_out.append({
                                        "ip": ip, "port": port,
                                        "protocol": proto,
                                        "source": "proxy-daily.com",
                                    })
                        total = data.get("recordsTotal", 0)
                        start += page_size
                        draw  += 1
                        if start >= total:
                            break
            except Exception as e:
                console.print(f"  [dim yellow]proxy-daily JSON API warn: {e}[/dim yellow]")

            # --- Strategy 2: plain-text export fallback (all protocols) ---
            if not proxies_out:
                try:
                    connector2 = aiohttp.TCPConnector(ssl=False)
                    async with aiohttp.ClientSession(
                        connector=connector2,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as sess:
                        async with sess.get(
                            f"{base}/api/export_proxies_ip_port"
                        ) as resp:
                            text = await resp.text()
                        for line in text.splitlines():
                            m = proxy_rx.search(line)
                            if m:
                                proxies_out.append({
                                    "ip": m.group(1), "port": m.group(2),
                                    "protocol": "http",
                                    "source": "proxy-daily.com",
                                })
                except Exception as e:
                    console.print(f"  [dim yellow]proxy-daily export fallback warn: {e}[/dim yellow]")

            return proxies_out

        bc = BrowserConfig(
            headless=True, user_agent=config["general"]["user_agent"]
        )
        async with AsyncWebCrawler(config=bc) as crawler:
            for name, fn in [("free-proxy-list.net", scrape_fpl)]:
                try:
                    scraped = await asyncio.wait_for(fn(crawler), timeout=60)
                    all_proxies.extend(scraped)
                    console.print(
                        f"  [green]✓[/] {name}: {len(scraped)} proxies"
                    )
                except Exception as e:
                    console.print(f"  [red]✗[/] {name}: {e}")

            for name, url in [
                ("proxynova.com",
                 "https://www.proxynova.com/proxy-server-list/"),
                ("advanced.name", "https://advanced.name/freeproxy"),
            ]:
                try:
                    scraped = await asyncio.wait_for(
                        scrape_regex(crawler, url, name), timeout=60
                    )
                    all_proxies.extend(scraped)
                    console.print(
                        f"  [green]✓[/] {name}: {len(scraped)} proxies"
                    )
                except Exception as e:
                    console.print(f"  [red]✗[/] {name}: {e}")

        # proxy-daily.com: scraped outside the browser context via its API
        try:
            scraped = await asyncio.wait_for(scrape_proxy_daily_api(), timeout=90)
            all_proxies.extend(scraped)
            console.print(
                f"  [green]✓[/] proxy-daily.com: {len(scraped)} proxies"
            )
        except Exception as e:
            console.print(f"  [red]✗[/] proxy-daily.com: {e}")

        output_path = Path(config["crawl4ai"]["output_file"])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(all_proxies, f, indent=2)
        console.print(
            f"[bold green]✓ Crawl4AI: "
            f"{len(all_proxies)} proxies saved.[/bold green]"
        )

    # ── Run on a ProactorEventLoop in a separate thread ──
    def _run_in_thread():
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_crawl4ai_inner())
        finally:
            loop.close()

    # Run in a thread so the main SelectorEventLoop isn't blocked
    await asyncio.get_event_loop().run_in_executor(None, _run_in_thread)
