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


class StatsMixin:
    def print_stats(self) -> Dict[str, Any]:
        alive = [p for p in self.proxies.values() if p.alive]
        total = len(self.proxies) + self.stats["filtered"]

        # ← Reconstruct true total: current pool + everything removed
        true_total = (
            len(self.proxies)
            + self.stats["filtered"]
            + self.stats.get("tcp_prefilter_removed", 0)
        )

        sd = {
            "total": true_total,
            "alive": len(alive),
            "elite": len(
                [p for p in alive if p.anonymity == AnonymityLevel.ELITE]
            ),
            "fast": len(
                [p for p in alive if p.speed_tier == SpeedTier.FAST]
            ),
        }

        t = Table(
            title="🏆 UPO v5-fix3 — Results",
            show_header=False, border_style="bold blue",
        )
        t.add_column("Metric", style="cyan", width=25)
        t.add_column("Value", style="bold white", width=55)

        t.add_row("Total Raw", f"{true_total:,}")
        t.add_row("Filtered (GeoIP/CDN)", f"[red]-{self.stats['filtered']:,}[/red]")
        tcp_rm = self.stats.get("tcp_prefilter_removed", 0)
        if tcp_rm:
            t.add_row("TCP Dead (removed)", f"[red]-{tcp_rm:,}[/red]")
        vt = self.stats.get("verified_total", len(self.proxies))
        t.add_row("HTTP Verified", f"{vt:,}")
        pct = f"{len(alive)/max(vt,1):.1%}"
        t.add_row(
            "✅ ALIVE",
            f"[bold green]{len(alive):,}[/bold green] ({pct})",
        )
        t.add_row("─" * 20, "─" * 45)

        if alive:
            pc = Counter(p.protocol for p in alive)
            t.add_row(
                "Protocol",
                f"HTTP:{pc.get(ProxyProtocol.HTTP,0)} │ "
                f"HTTPS:{pc.get(ProxyProtocol.HTTPS,0)} │ "
                f"S4:{pc.get(ProxyProtocol.SOCKS4,0)} │ "
                f"S5:{pc.get(ProxyProtocol.SOCKS5,0)}",
            )

            ac = Counter(p.anonymity for p in alive if p.anonymity)
            t.add_row(
                "Anonymity",
                f"[green]Elite:{ac.get(AnonymityLevel.ELITE,0)}[/green] │ "
                f"Anon:{ac.get(AnonymityLevel.ANONYMOUS,0)} │ "
                f"Trans:{ac.get(AnonymityLevel.TRANSPARENT,0)}",
            )

            sc = Counter(p.speed_tier for p in alive if p.speed_tier)
            t.add_row(
                "Speed",
                f"[green]Fast:{sc.get(SpeedTier.FAST,0)}[/green] │ "
                f"Med:{sc.get(SpeedTier.MEDIUM,0)} │ "
                f"Slow:{sc.get(SpeedTier.SLOW,0)}",
            )

            pt = Counter(p.proxy_type for p in alive)
            t.add_row(
                "Type",
                f"Res:{pt.get(ProxyType.RESIDENTIAL,0)} │ "
                f"DC:{pt.get(ProxyType.DATACENTER,0)} │ "
                f"Mobile:{pt.get(ProxyType.MOBILE,0)} │ "
                f"Unk:{pt.get(ProxyType.UNKNOWN,0)}",
            )

            mp = sum(1 for p in alive if len(p.detected_protocols) > 1)
            t.add_row("Multi-Protocol", f"{mp} support 2+ protocols")

            https_cnt = sum(1 for p in alive if p.supports_https)
            t.add_row(
                "HTTPS Support",
                f"{https_cnt:,} "
                f"({https_cnt/max(len(alive),1)*100:.1f}%)",
            )

            speeds = [
                p.download_speed_kbps for p in alive
                if p.download_speed_kbps
            ]
            if speeds:
                t.add_row(
                    "Download Speed",
                    f"Avg:{sum(speeds)/len(speeds):.0f} KB/s │ "
                    f"Max:{max(speeds):.0f} KB/s",
                )

            stealths = [
                p.stealth_score for p in alive
                if p.stealth_score is not None
            ]
            if stealths:
                high = sum(1 for s in stealths if s >= 70)
                t.add_row(
                    "Stealth",
                    f"Avg:{sum(stealths)/len(stealths):.0f}/100 │ "
                    f"High(≥70):{high}",
                )

            dns_l = sum(1 for p in alive if p.dns_leak is True)
            dns_c = sum(1 for p in alive if p.dns_leak is False)
            if dns_l or dns_c:
                t.add_row(
                    "DNS Leak",
                    f"Clean:{dns_c} │ Leaking:{dns_l}",
                )

            scored = [
                p for p in alive if p.composite_score is not None
            ]
            if scored:
                clean = sum(
                    1 for p in scored if p.composite_score <= 20
                )
                t.add_row(
                    "Fraud Score",
                    f"Scored:{len(scored)} │ Clean(≤20):{clean}",
                )

            t.add_row("─" * 20, "─" * 45)

            cc = Counter(
                p.country_code for p in alive if p.country_code
            ).most_common(10)
            if cc:
                t.add_row(
                    "Top Countries",
                    " │ ".join(f"{c}({n})" for c, n in cc),
                )

            lats = [p.latency_ms for p in alive if p.latency_ms]
            if lats:
                t.add_row(
                    "Latency",
                    f"Avg:{sum(lats)/len(lats):.0f}ms │ "
                    f"Min:{min(lats)}ms │ Max:{max(lats)}ms",
                )

        console.print(Panel(t, border_style="bold blue"))
        return sd

