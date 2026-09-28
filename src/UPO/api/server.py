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
from ..core.engine import UPOEngine
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


def start_api(engine: UPOEngine, host: str, port: int):
    try:
        from fastapi import FastAPI, Query
        import uvicorn
    except ImportError:
        console.print(
            "[yellow]⚠ pip install fastapi uvicorn[/yellow]"
        )
        return

    app = FastAPI(title="UPO API")

    @app.get("/proxies")
    async def get_proxies(
        protocol: Optional[str] = Query(None),
        country: Optional[str] = Query(None),
        anonymity: Optional[str] = Query(None),
        min_stealth: Optional[int] = Query(None),
        proxy_type: Optional[str] = Query(None),
        max_latency: Optional[int] = Query(None),
        limit: int = Query(20),
    ):
        r = [p for p in engine.proxies.values() if p.alive]
        if protocol:
            r = [p for p in r if p.protocol.value == protocol]
        if country:
            r = [p for p in r if p.country_code == country.upper()]
        if anonymity:
            r = [
                p for p in r
                if p.anonymity and p.anonymity.value == anonymity
            ]
        if min_stealth is not None:
            r = [
                p for p in r
                if p.stealth_score is not None
                and p.stealth_score >= min_stealth
            ]
        if proxy_type:
            r = [p for p in r if p.proxy_type.value == proxy_type]
        if max_latency:
            r = [
                p for p in r
                if p.latency_ms and p.latency_ms <= max_latency
            ]
        r = sorted(r, key=lambda p: p.latency_ms or 99999)[:limit]
        return [p.to_dict() for p in r]

    @app.get("/random")
    async def get_random(
        protocol: Optional[str] = None,
        country: Optional[str] = None,
        anonymity: Optional[str] = None,
    ):
        r = [p for p in engine.proxies.values() if p.alive]
        if protocol:
            r = [p for p in r if p.protocol.value == protocol]
        if country:
            r = [p for p in r if p.country_code == country.upper()]
        if anonymity:
            r = [
                p for p in r
                if p.anonymity and p.anonymity.value == anonymity
            ]
        if not r:
            return {"error": "No proxies match"}
        return random.choice(r).to_dict()

    @app.get("/stats")
    async def get_stats():
        alive = [p for p in engine.proxies.values() if p.alive]
        return {
            "total": len(engine.proxies),
            "alive": len(alive),
            "elite": len(
                [p for p in alive
                 if p.anonymity == AnonymityLevel.ELITE]
            ),
            "fast": len(
                [p for p in alive if p.speed_tier == SpeedTier.FAST]
            ),
            "residential": len(
                [p for p in alive
                 if p.proxy_type == ProxyType.RESIDENTIAL]
            ),
            "mobile": len(
                [p for p in alive if p.proxy_type == ProxyType.MOBILE]
            ),
        }

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "alive": sum(
                1 for p in engine.proxies.values() if p.alive
            ),
        }

    def run():
        uvicorn.run(app, host=host, port=port, log_level="warning")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    console.print(
        f"[bold green]✓ API at http://{host}:{port}[/bold green]"
    )
    console.print(
        f"  [dim]GET /proxies?protocol=socks5&country=US"
        f"&anonymity=elite[/dim]"
    )
    console.print(f"  [dim]GET /random?protocol=http[/dim]")
    console.print(f"  [dim]GET /stats[/dim]")
