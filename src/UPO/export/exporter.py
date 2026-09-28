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
from ..models import (
    Proxy, ProxyProtocol, AnonymityLevel, SpeedTier, ProxyType,
)
from ..utils.console import console


class ExportMixin:
    def enrich_and_categorize(self):
        levels = {"transparent": 0, "anonymous": 1, "elite": 2}
        min_anon = self.config["filter"].get("min_anonymity")
        req_level = (
            levels.get(str(min_anon).lower(), -1) if min_anon else -1
        )

        for p in self.proxies.values():
            if not p.alive:
                continue

            # Speed tier
            if p.latency_ms is not None:
                fast = self.config["output"].get("fast_threshold_ms", 500)
                if p.latency_ms < fast:
                    p.speed_tier = SpeedTier.FAST
                elif p.latency_ms < 2000:
                    p.speed_tier = SpeedTier.MEDIUM
                else:
                    p.speed_tier = SpeedTier.SLOW

            # Average latency
            if p.latency_ms:
                if p.avg_latency_ms:
                    p.avg_latency_ms = (
                        p.avg_latency_ms + p.latency_ms
                    ) / 2
                else:
                    p.avg_latency_ms = float(p.latency_ms)

            # Min anonymity filter
            if p.anonymity and req_level >= 0:
                if levels.get(p.anonymity.value, 0) < req_level:
                    p.alive = False
                    continue

            # FIX #1: Calculate stealth score HERE — after all data is
            # available (anonymity, fingerprint, fraud, DNS leak, etc.)
            if self.config["stealth_score"]["enabled"]:
                self._calc_stealth(p)

            # Save to history
            if self.history:
                self.history.update(p)

    def export(self):
        out = Path(self.config["output"]["dir"])
        out.mkdir(exist_ok=True)
        alive = sorted(
            [p for p in self.proxies.values() if p.alive],
            key=lambda p: p.latency_ms or 99999,
        )
        if not alive:
            console.print("[yellow]No alive proxies to export.[/yellow]")
            if self.verified_db:
                self.verified_db.save_all([])
                console.print(
                    "  [yellow]⚠[/] Verified DB cleared (no alive proxies)."
                )
            return

        console.print(
            f"\n[bold cyan]Exporting {len(alive)} proxies...[/bold cyan]"
        )

        if "json" in self.config["output"]["formats"]:
            path = out / "all.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump([p.to_dict() for p in alive], f, indent=2)
            console.print(f"  [green]✓[/] {path} ({len(alive)})")

        if "csv" in self.config["output"]["formats"]:
            path = out / "all.csv"
            flds = list(alive[0].to_dict().keys())
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=flds)
                w.writeheader()
                for p in alive:
                    w.writerow(p.to_dict())
            console.print(f"  [green]✓[/] {path} ({len(alive)})")

        if "txt" in self.config["output"]["formats"]:
            if self.config["output"]["split_by_protocol"]:
                for proto in ProxyProtocol:
                    lst = [p for p in alive if p.protocol == proto]
                    path = out / f"{proto.value}.txt"
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("\n".join(p.address for p in lst))
                    if lst:
                        console.print(
                            f"  [green]✓[/] {path} ({len(lst)})"
                        )

        special = [
            ("elite", "generate_elite_list",
             lambda p: p.anonymity == AnonymityLevel.ELITE),
            ("fast", "generate_fast_list",
             lambda p: p.speed_tier == SpeedTier.FAST),
            ("residential", "generate_residential_list",
             lambda p: p.proxy_type == ProxyType.RESIDENTIAL),
            ("mobile", "generate_mobile_list",
             lambda p: p.proxy_type == ProxyType.MOBILE),
            ("stealth", "generate_stealth_list",
             lambda p: (p.stealth_score is not None
                        and p.stealth_score >= 70)),
            ("clean", "generate_clean_list",
             lambda p: (p.composite_score is not None
                        and p.composite_score <= 20)),
        ]
        for name, config_key, filt in special:
            if self.config["output"].get(config_key, False):
                lst = [p for p in alive if filt(p)]
                path = out / f"{name}.txt"
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(p.address for p in lst))
                console.print(f"  [green]✓[/] {path} ({len(lst)})")

        if self.config["output"].get("split_by_country"):
            countries = set(
                p.country_code for p in alive if p.country_code
            )
            for cc in countries:
                lst = [p for p in alive if p.country_code == cc]
                path = out / f"country_{cc.lower()}.txt"
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(p.address for p in lst))

        # ── Checked folder: dated export that never overwrites ────
        if self.config.get("checked_output", {}).get("enabled", False):
            checked_dir = Path(
                self.config["checked_output"].get("dir", "checked")
            )
            checked_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now().strftime("%Y-%m-%d")
            rand_suffix = f"{random.randint(100, 999)}"
            basename = f"proxies_{date_str}_{rand_suffix}"

            txt_path = checked_dir / f"{basename}.txt"
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(p.address for p in alive))
            console.print(
                f"  [green]✓[/] {txt_path} ({len(alive)})"
            )

            json_path = checked_dir / f"{basename}.json"
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump([p.to_dict() for p in alive], f, indent=2)
            console.print(
                f"  [green]✓[/] {json_path} ({len(alive)})"
            )

        # ── Update verified DB: only current survivors persist ────
        if self.verified_db:
            if alive:
                self.verified_db.save_all(alive)
                console.print(
                    f"  [green]✓[/] Verified DB updated: "
                    f"{len(alive)} working proxies saved."
                )
            else:
                self.verified_db.save_all([])
                console.print(
                    "  [yellow]⚠[/] Verified DB cleared (no alive proxies)."
                )

