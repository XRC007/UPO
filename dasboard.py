"""
UPO Dashboard v1.0 — Web analytics for Ultimate Proxy Operator
Run:  python dashboard.py
Then: http://localhost:8050
"""

# ==============================================================================
# SECTION 1: IMPORTS
# ==============================================================================

import json
import os
import sys
import csv
import io
import sqlite3
import re
import copy
import glob
import yaml
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from collections import Counter

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

# ==============================================================================
# SECTION 2: CONFIGURATION
# ==============================================================================

DASHBOARD_PORT = 8050
DASHBOARD_HOST = "0.0.0.0"

BASE_DIR = Path(__file__).parent
UPO_OUTPUT_DIR = BASE_DIR / "output"
UPO_CHECKED_DIR = BASE_DIR / "checked"
UPO_DATA_DIR = BASE_DIR / "data"
UPO_CONFIG_PATH = BASE_DIR / "config.yaml"
TEMPLATE_DIR = BASE_DIR / "dashboard_templates"

COUNTRY_COORDS = {
    "US": [39.8, -98.5], "CN": [35.8, 104.1], "RU": [61.5, 105.3],
    "DE": [51.1, 10.4], "GB": [55.3, -3.4], "FR": [46.2, 2.2],
    "BR": [-14.2, -51.9], "IN": [20.5, 78.9], "JP": [36.2, 138.2],
    "KR": [35.9, 127.7], "CA": [56.1, -106.3], "AU": [-25.2, 133.7],
    "ID": [-0.7, 113.9], "NL": [52.1, 5.2], "SG": [1.3, 103.8],
    "TR": [38.9, 35.2], "UA": [48.3, 31.1], "PL": [51.9, 19.1],
    "TH": [15.8, 100.9], "VN": [14.0, 108.2], "MX": [23.6, -102.5],
    "AR": [-38.4, -63.6], "CO": [4.5, -74.2], "EG": [26.8, 30.8],
    "ZA": [-30.5, 22.9], "KE": [-0.02, 37.9], "NG": [9.0, 8.6],
    "BD": [23.6, 90.3], "PK": [30.3, 69.3], "PH": [12.8, 121.7],
    "MY": [4.2, 101.9], "IT": [41.8, 12.5], "ES": [40.4, -3.7],
    "SE": [60.1, 18.6], "CZ": [49.8, 15.4], "RO": [45.9, 24.9],
    "BG": [42.7, 25.4], "HU": [47.1, 19.5], "AT": [47.5, 14.5],
    "CH": [46.8, 8.2], "BE": [50.5, 4.4], "PT": [39.3, -8.2],
    "GR": [39.0, 21.8], "IL": [31.0, 34.8], "IR": [32.4, 53.6],
    "SA": [23.8, 45.0], "AE": [23.4, 53.8], "CL": [-35.6, -71.5],
    "PE": [-9.1, -75.0], "VE": [6.4, -66.5], "EC": [-1.8, -78.1],
    "HK": [22.3, 114.1], "TW": [23.6, 120.9], "MM": [21.9, 95.9],
    "KH": [12.5, 104.9], "NP": [28.3, 84.1], "LK": [7.8, 80.7],
    "KZ": [48.0, 66.9], "UZ": [41.3, 64.5], "GE": [42.3, 43.3],
    "BY": [53.7, 27.9], "LT": [55.1, 23.8], "LV": [56.8, 24.6],
    "EE": [58.5, 25.0], "FI": [61.9, 25.7], "NO": [60.4, 8.4],
    "DK": [56.2, 9.5], "IE": [53.4, -8.2], "NZ": [-40.9, 174.8],
    "SK": [48.6, 19.6], "HR": [45.1, 15.2], "RS": [44.0, 21.0],
    "AL": [41.1, 20.1], "BA": [43.9, 17.6], "MK": [41.5, 21.7],
    "MD": [47.4, 28.3], "AM": [40.0, 45.0], "AZ": [40.1, 47.5],
}


# ==============================================================================
# SECTION 3: DATA MANAGER
# ==============================================================================

class DataManager:
    def __init__(self):
        self._cache = {}
        self._cache_time = {}

    def _is_stale(self, key: str, max_age: int = 30) -> bool:
        if key not in self._cache_time:
            return True
        return (datetime.now() - self._cache_time[key]).seconds > max_age

    def load_proxies(self) -> List[Dict]:
        if not self._is_stale("proxies"):
            return self._cache["proxies"]
        path = UPO_OUTPUT_DIR / "all.json"
        if not path.exists():
            return []
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self._cache["proxies"] = data
            self._cache_time["proxies"] = datetime.now()
            return data
        except Exception:
            return []

    def load_runs(self) -> List[Dict]:
        if not self._is_stale("runs", 60):
            return self._cache["runs"]
        runs = []
        if not UPO_CHECKED_DIR.exists():
            return []
        for jf in sorted(UPO_CHECKED_DIR.glob("proxies_*.json"), reverse=True):
            m = re.search(r"proxies_(\d{4}-\d{2}-\d{2})_(\d{3})", jf.name)
            if not m:
                continue
            try:
                with open(jf, encoding="utf-8") as f:
                    data = json.load(f)
                protos = Counter(p.get("protocol") for p in data)
                anons = Counter(p.get("anonymity") for p in data)
                types = Counter(p.get("proxy_type") for p in data)
                lats = [p["latency_ms"] for p in data if p.get("latency_ms")]
                stealths = [p["stealth_score"] for p in data
                            if p.get("stealth_score") is not None]
                runs.append({
                    "date": m.group(1),
                    "suffix": m.group(2),
                    "filename": jf.name,
                    "count": len(data),
                    "protocols": dict(protos),
                    "anonymity": dict(anons),
                    "types": dict(types),
                    "avg_latency": round(sum(lats) / len(lats)) if lats else 0,
                    "avg_stealth": (round(sum(stealths) / len(stealths))
                                    if stealths else 0),
                    "elite": anons.get("elite", 0),
                    "fast": sum(1 for p in data
                                if p.get("speed_tier") == "fast"),
                    "countries": len(set(
                        p.get("country_code") for p in data
                        if p.get("country_code")
                    )),
                })
            except Exception:
                continue
        self._cache["runs"] = runs
        self._cache_time["runs"] = datetime.now()
        return runs

    def get_summary(self) -> Dict:
        proxies = self.load_proxies()
        runs = self.load_runs()
        if not proxies:
            return {
                "total": 0, "alive": 0, "elite": 0, "fast": 0,
                "residential": 0, "mobile": 0, "stealth_high": 0,
                "avg_latency": 0, "avg_stealth": 0, "countries": 0,
                "https_pct": 0, "clean": 0,
                "delta": {}, "last_run": None,
            }
        alive = [p for p in proxies if p.get("alive", True)]
        lats = [p["latency_ms"] for p in alive if p.get("latency_ms")]
        stealths = [p["stealth_score"] for p in alive
                     if p.get("stealth_score") is not None]
        elite = sum(1 for p in alive if p.get("anonymity") == "elite")
        fast = sum(1 for p in alive if p.get("speed_tier") == "fast")
        res = sum(1 for p in alive if p.get("proxy_type") == "residential")
        mob = sum(1 for p in alive if p.get("proxy_type") == "mobile")
        stealth_hi = sum(1 for s in stealths if s >= 70)
        https_cnt = sum(1 for p in alive if p.get("supports_https"))
        clean = sum(1 for p in alive
                     if p.get("composite_score") is not None
                     and p["composite_score"] <= 20)
        countries = len(set(
            p.get("country_code") for p in alive if p.get("country_code")
        ))

        delta = {}
        if len(runs) >= 2:
            prev = runs[1]
            delta = {
                "alive": len(alive) - prev["count"],
                "elite": elite - prev.get("elite", 0),
                "fast": fast - prev.get("fast", 0),
                "latency": (
                    (round(sum(lats) / len(lats)) if lats else 0)
                    - prev.get("avg_latency", 0)
                ),
            }

        return {
            "total": len(alive),
            "alive": len(alive),
            "elite": elite,
            "fast": fast,
            "residential": res,
            "mobile": mob,
            "stealth_high": stealth_hi,
            "avg_latency": round(sum(lats) / len(lats)) if lats else 0,
            "avg_stealth": (round(sum(stealths) / len(stealths))
                            if stealths else 0),
            "countries": countries,
            "https_pct": (round(https_cnt / len(alive) * 100)
                          if alive else 0),
            "clean": clean,
            "delta": delta,
            "last_run": runs[0]["date"] if runs else None,
        }

    def get_analytics(self) -> Dict:
        proxies = self.load_proxies()
        if not proxies:
            return {}
        alive = [p for p in proxies if p.get("alive", True)]

        protocols = Counter(p.get("protocol", "unknown") for p in alive)
        anonymity = Counter(
            p.get("anonymity", "unknown") for p in alive
        )
        types = Counter(
            p.get("proxy_type", "unknown") for p in alive
        )
        speed_tiers = Counter(
            p.get("speed_tier", "unknown") for p in alive
        )
        fingerprints = Counter(
            p.get("tcp_fingerprint", "unknown") for p in alive
        )

        latencies = [p["latency_ms"] for p in alive if p.get("latency_ms")]
        lat_buckets = {"<200": 0, "200-500": 0, "500-1000": 0,
                       "1000-2000": 0, "2000-5000": 0, ">5000": 0}
        for l in latencies:
            if l < 200: lat_buckets["<200"] += 1
            elif l < 500: lat_buckets["200-500"] += 1
            elif l < 1000: lat_buckets["500-1000"] += 1
            elif l < 2000: lat_buckets["1000-2000"] += 1
            elif l < 5000: lat_buckets["2000-5000"] += 1
            else: lat_buckets[">5000"] += 1

        stealths = [p["stealth_score"] for p in alive
                     if p.get("stealth_score") is not None]
        stealth_buckets = {"0-20": 0, "20-40": 0, "40-60": 0,
                           "60-80": 0, "80-100": 0}
        for s in stealths:
            if s < 20: stealth_buckets["0-20"] += 1
            elif s < 40: stealth_buckets["20-40"] += 1
            elif s < 60: stealth_buckets["40-60"] += 1
            elif s < 80: stealth_buckets["60-80"] += 1
            else: stealth_buckets["80-100"] += 1

        dns_leak = Counter()
        for p in alive:
            if p.get("dns_leak") is True:
                dns_leak["leaking"] += 1
            elif p.get("dns_leak") is False:
                dns_leak["clean"] += 1
            else:
                dns_leak["unknown"] += 1

        google_ban = Counter()
        for p in alive:
            if p.get("google_ban") is True:
                google_ban["banned"] += 1
            elif p.get("google_ban") is False:
                google_ban["not_banned"] += 1
            else:
                google_ban["unknown"] += 1

        top_asns = Counter(
            f"{p.get('asn', '?')} ({p.get('isp', '?')[:25]})"
            for p in alive if p.get("asn")
        ).most_common(20)

        sources = Counter(p.get("source", "unknown") for p in alive)
        top_sources = sources.most_common(20)

        top_countries = Counter(
            p.get("country_code", "??") for p in alive
            if p.get("country_code")
        ).most_common(15)

        scatter = [
            {"x": p.get("latency_ms", 0),
             "y": p.get("stealth_score", 0),
             "label": p.get("ip", "?"),
             "type": p.get("proxy_type", "unknown")}
            for p in alive
            if p.get("latency_ms") and p.get("stealth_score") is not None
        ][:500]

        multi_proto = sum(
            1 for p in alive
            if len(p.get("detected_protocols", [])) > 1
        )

        return {
            "protocols": dict(protocols),
            "anonymity": dict(anonymity),
            "types": dict(types),
            "speed_tiers": dict(speed_tiers),
            "fingerprints": dict(fingerprints),
            "latency_buckets": lat_buckets,
            "stealth_buckets": stealth_buckets,
            "dns_leak": dict(dns_leak),
            "google_ban": dict(google_ban),
            "top_asns": top_asns,
            "top_sources": top_sources,
            "top_countries": top_countries,
            "scatter": scatter,
            "multi_protocol": multi_proto,
            "total": len(alive),
            "https_count": sum(
                1 for p in alive if p.get("supports_https")
            ),
        }

    def get_geo_data(self) -> Dict:
        proxies = self.load_proxies()
        alive = [p for p in proxies if p.get("alive", True)]
        countries = {}
        for p in alive:
            cc = p.get("country_code")
            if not cc:
                continue
            if cc not in countries:
                countries[cc] = {
                    "code": cc,
                    "name": p.get("country_name", cc),
                    "count": 0, "elite": 0, "fast": 0,
                    "avg_latency": [], "avg_stealth": [],
                    "residential": 0, "datacenter": 0, "mobile": 0,
                }
            c = countries[cc]
            c["count"] += 1
            if p.get("anonymity") == "elite":
                c["elite"] += 1
            if p.get("speed_tier") == "fast":
                c["fast"] += 1
            if p.get("proxy_type") == "residential":
                c["residential"] += 1
            elif p.get("proxy_type") == "datacenter":
                c["datacenter"] += 1
            elif p.get("proxy_type") == "mobile":
                c["mobile"] += 1
            if p.get("latency_ms"):
                c["avg_latency"].append(p["latency_ms"])
            if p.get("stealth_score") is not None:
                c["avg_stealth"].append(p["stealth_score"])

        for c in countries.values():
            lats = c["avg_latency"]
            c["avg_latency"] = round(sum(lats) / len(lats)) if lats else 0
            sts = c["avg_stealth"]
            c["avg_stealth"] = round(sum(sts) / len(sts)) if sts else 0
            c["coords"] = COUNTRY_COORDS.get(c["code"], [0, 0])

        return {
            "countries": list(countries.values()),
            "total_countries": len(countries),
        }

    def get_recommendations(self) -> List[Dict]:
        proxies = self.load_proxies()
        alive = [p for p in proxies if p.get("alive", True)]
        if not alive:
            return []
        recs = []

        # Best for scraping
        scraping = sorted(
            [p for p in alive
             if p.get("anonymity") == "elite"
             and p.get("speed_tier") == "fast"
             and p.get("google_ban") is not True],
            key=lambda p: p.get("latency_ms") or 99999,
        )[:10]
        recs.append({
            "title": "🕷️ Best for Web Scraping",
            "desc": "Fast + Elite + Not Google-banned",
            "proxies": scraping,
            "count": len(scraping),
        })

        # Best for social media
        social = sorted(
            [p for p in alive
             if p.get("proxy_type") == "residential"
             and (p.get("composite_score") or 999) <= 30
             and (p.get("stealth_score") or 0) >= 60],
            key=lambda p: -(p.get("stealth_score") or 0),
        )[:10]
        recs.append({
            "title": "📱 Best for Social Media",
            "desc": "Residential + Clean + Stealth ≥ 60",
            "proxies": social,
            "count": len(social),
        })

        # Best for streaming
        streaming = sorted(
            [p for p in alive
             if p.get("speed_tier") == "fast"
             and p.get("supports_https")
             and p.get("proxy_type") != "datacenter"],
            key=lambda p: -(p.get("download_speed_kbps") or 0),
        )[:10]
        recs.append({
            "title": "🎬 Best for Streaming",
            "desc": "Fast + HTTPS + Non-datacenter",
            "proxies": streaming,
            "count": len(streaming),
        })

        # Stealthiest
        stealth_top = sorted(
            alive,
            key=lambda p: -(p.get("stealth_score") or 0),
        )[:10]
        recs.append({
            "title": "🥷 Stealthiest Proxies",
            "desc": "Highest stealth scores",
            "proxies": stealth_top,
            "count": len(stealth_top),
        })

        # Quality leaderboard
        def quality(p):
            s = 0
            if p.get("anonymity") == "elite":
                s += 30
            if p.get("speed_tier") == "fast":
                s += 20
            if p.get("proxy_type") == "residential":
                s += 20
            elif p.get("proxy_type") == "mobile":
                s += 25
            s += (p.get("stealth_score") or 0) * 0.3
            if p.get("dns_leak") is False:
                s += 5
            if p.get("google_ban") is False:
                s += 5
            if (p.get("composite_score") or 999) <= 20:
                s += 10
            return s
        leaderboard = sorted(alive, key=quality, reverse=True)[:20]
        recs.append({
            "title": "🏆 Quality Leaderboard",
            "desc": "Top 20 by composite quality",
            "proxies": leaderboard,
            "count": len(leaderboard),
        })

        # Risk assessment
        risky = [p for p in alive
                  if (p.get("composite_score") or 0) >= 60]
        recs.append({
            "title": "⚠️ Risk Assessment",
            "desc": f"{len(risky)} proxies with fraud score ≥ 60",
            "proxies": sorted(
                risky,
                key=lambda p: -(p.get("composite_score") or 0),
            )[:10],
            "count": len(risky),
        })

        # Diversity check
        asn_counts = Counter(p.get("asn") for p in alive if p.get("asn"))
        dominant_asns = [
            (asn, cnt) for asn, cnt in asn_counts.most_common(5)
            if cnt > len(alive) * 0.1
        ]
        cc_counts = Counter(
            p.get("country_code") for p in alive if p.get("country_code")
        )
        recs.append({
            "title": "🌐 Diversity Analysis",
            "desc": (
                f"{len(asn_counts)} unique ASNs, "
                f"{len(cc_counts)} countries"
            ),
            "proxies": [],
            "count": len(alive),
            "dominant_asns": dominant_asns,
            "country_count": len(cc_counts),
            "asn_count": len(asn_counts),
        })

        # Country gap
        all_major = {
            "US", "GB", "DE", "FR", "JP", "KR", "BR",
            "IN", "CA", "AU", "NL", "SG", "RU",
        }
        present = set(cc_counts.keys())
        missing = all_major - present
        recs.append({
            "title": "🗺️ Country Gap Analysis",
            "desc": (
                f"Missing {len(missing)} major countries"
                if missing else "All major countries covered!"
            ),
            "proxies": [],
            "count": 0,
            "missing_countries": sorted(missing),
        })

        return recs

    def get_history(self) -> Dict:
        runs = self.load_runs()
        dates = [r["date"] for r in reversed(runs)]
        counts = [r["count"] for r in reversed(runs)]
        elite_counts = [r.get("elite", 0) for r in reversed(runs)]
        fast_counts = [r.get("fast", 0) for r in reversed(runs)]
        latencies = [r.get("avg_latency", 0) for r in reversed(runs)]
        stealths = [r.get("avg_stealth", 0) for r in reversed(runs)]
        country_counts = [r.get("countries", 0) for r in reversed(runs)]

        proto_series = {}
        for r in reversed(runs):
            for proto, cnt in r.get("protocols", {}).items():
                proto_series.setdefault(proto, []).append(cnt)
            for proto in proto_series:
                if proto not in r.get("protocols", {}):
                    proto_series[proto].append(0)

        survival = []
        run_list = list(reversed(runs))
        for i in range(1, len(run_list)):
            survival.append({
                "date": run_list[i]["date"],
                "prev": run_list[i - 1]["count"],
                "curr": run_list[i]["count"],
                "diff": run_list[i]["count"] - run_list[i - 1]["count"],
            })

        return {
            "dates": dates,
            "counts": counts,
            "elite_counts": elite_counts,
            "fast_counts": fast_counts,
            "latencies": latencies,
            "stealths": stealths,
            "country_counts": country_counts,
            "proto_series": proto_series,
            "survival": survival,
            "runs": runs[:50],
        }

    def filter_proxies(
        self, protocol=None, anonymity=None, speed=None,
        ptype=None, country=None, lat_min=None, lat_max=None,
        stealth_min=None, stealth_max=None, dns_clean=None,
        not_banned=None, https_only=None, sort="latency_ms",
        order="asc", page=1, per_page=50, search=None,
    ) -> Dict:
        proxies = self.load_proxies()
        alive = [p for p in proxies if p.get("alive", True)]
        if protocol:
            alive = [p for p in alive
                      if p.get("protocol") == protocol]
        if anonymity:
            alive = [p for p in alive
                      if p.get("anonymity") == anonymity]
        if speed:
            alive = [p for p in alive
                      if p.get("speed_tier") == speed]
        if ptype:
            alive = [p for p in alive
                      if p.get("proxy_type") == ptype]
        if country:
            alive = [p for p in alive
                      if p.get("country_code") == country.upper()]
        if lat_min is not None:
            alive = [p for p in alive
                      if (p.get("latency_ms") or 99999) >= lat_min]
        if lat_max is not None:
            alive = [p for p in alive
                      if (p.get("latency_ms") or 99999) <= lat_max]
        if stealth_min is not None:
            alive = [p for p in alive
                      if (p.get("stealth_score") or 0) >= stealth_min]
        if stealth_max is not None:
            alive = [p for p in alive
                      if (p.get("stealth_score") or 0) <= stealth_max]
        if dns_clean:
            alive = [p for p in alive if p.get("dns_leak") is False]
        if not_banned:
            alive = [p for p in alive if p.get("google_ban") is not True]
        if https_only:
            alive = [p for p in alive if p.get("supports_https")]
        if search:
            s = search.lower()
            alive = [p for p in alive
                      if s in (p.get("ip", "")).lower()
                      or s in (p.get("country_name", "")).lower()
                      or s in (p.get("isp", "")).lower()
                      or s in str(p.get("port", ""))]

        rev = order == "desc"
        def skey(p):
            v = p.get(sort)
            if v is None:
                return 99999 if not rev else -99999
            return v
        alive.sort(key=skey, reverse=rev)

        total = len(alive)
        start = (page - 1) * per_page
        end = start + per_page
        return {
            "proxies": alive[start:end],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }

    def export_proxies(
        self, fmt="txt", style="ip_port", protocol=None,
        anonymity=None, speed=None, ptype=None, country=None,
        stealth_min=None, dns_clean=None, not_banned=None,
        https_only=None,
    ) -> tuple:
        result = self.filter_proxies(
            protocol=protocol, anonymity=anonymity, speed=speed,
            ptype=ptype, country=country, stealth_min=stealth_min,
            dns_clean=dns_clean, not_banned=not_banned,
            https_only=https_only, per_page=999999,
        )
        proxies = result["proxies"]

        if fmt == "json":
            content = json.dumps(proxies, indent=2)
            return content, "application/json", "proxies.json"

        if fmt == "csv":
            if not proxies:
                return "", "text/csv", "proxies.csv"
            buf = io.StringIO()
            w = csv.DictWriter(buf, fieldnames=proxies[0].keys())
            w.writeheader()
            for p in proxies:
                w.writerow(p)
            return buf.getvalue(), "text/csv", "proxies.csv"

        if fmt == "yaml":
            content = yaml.dump(proxies, default_flow_style=False)
            return content, "text/yaml", "proxies.yaml"

        # txt with style
        lines = []
        for p in proxies:
            ip = p.get("ip", "")
            port = p.get("port", "")
            proto = p.get("protocol", "http")
            if style == "protocol_url":
                lines.append(f"{proto}://{ip}:{port}")
            elif style == "json_lines":
                lines.append(json.dumps(p))
            elif style == "curl":
                lines.append(
                    f'curl -x {proto}://{ip}:{port} http://httpbin.org/ip'
                )
            elif style == "env":
                lines.append(
                    f'HTTP_PROXY={proto}://{ip}:{port}'
                )
            elif style == "proxychains":
                ptype_map = {
                    "http": "http", "https": "http",
                    "socks4": "socks4", "socks5": "socks5",
                }
                lines.append(
                    f'{ptype_map.get(proto, "http")} {ip} {port}'
                )
            elif style == "haproxy":
                lines.append(f'  server proxy_{ip} {ip}:{port} check')
            else:
                lines.append(f"{ip}:{port}")

        content = "\n".join(lines)
        return content, "text/plain", f"proxies.{fmt}"

    def load_config(self) -> Dict:
        if not UPO_CONFIG_PATH.exists():
            return {}
        try:
            with open(UPO_CONFIG_PATH, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def save_config(self, data: Dict):
        with open(UPO_CONFIG_PATH, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)


dm = DataManager()


# ==============================================================================
# SECTION 4: FASTAPI APP
# ==============================================================================

app = FastAPI(title="UPO Dashboard", docs_url="/docs")


# ==============================================================================
# SECTION 5: API ROUTES
# ==============================================================================

@app.get("/api/summary")
async def api_summary():
    return dm.get_summary()


@app.get("/api/analytics")
async def api_analytics():
    return dm.get_analytics()


@app.get("/api/geo")
async def api_geo():
    return dm.get_geo_data()


@app.get("/api/history")
async def api_history():
    return dm.get_history()


@app.get("/api/recommendations")
async def api_recommendations():
    return dm.get_recommendations()


@app.get("/api/proxies")
async def api_proxies(
    protocol: Optional[str] = None,
    anonymity: Optional[str] = None,
    speed: Optional[str] = None,
    ptype: Optional[str] = None,
    country: Optional[str] = None,
    lat_min: Optional[int] = None,
    lat_max: Optional[int] = None,
    stealth_min: Optional[int] = None,
    stealth_max: Optional[int] = None,
    dns_clean: Optional[bool] = None,
    not_banned: Optional[bool] = None,
    https_only: Optional[bool] = None,
    sort: str = "latency_ms",
    order: str = "asc",
    page: int = 1,
    per_page: int = 50,
    search: Optional[str] = None,
):
    return dm.filter_proxies(
        protocol=protocol, anonymity=anonymity, speed=speed,
        ptype=ptype, country=country, lat_min=lat_min,
        lat_max=lat_max, stealth_min=stealth_min,
        stealth_max=stealth_max, dns_clean=dns_clean,
        not_banned=not_banned, https_only=https_only,
        sort=sort, order=order, page=page, per_page=per_page,
        search=search,
    )


@app.get("/api/proxy/{ip}/{port}")
async def api_proxy_detail(ip: str, port: int):
    proxies = dm.load_proxies()
    addr = f"{ip}:{port}"
    for p in proxies:
        if f"{p.get('ip')}:{p.get('port')}" == addr:
            return p
    return {"error": "Not found"}


@app.get("/api/export")
async def api_export(
    fmt: str = "txt",
    style: str = "ip_port",
    protocol: Optional[str] = None,
    anonymity: Optional[str] = None,
    speed: Optional[str] = None,
    ptype: Optional[str] = None,
    country: Optional[str] = None,
    stealth_min: Optional[int] = None,
    dns_clean: Optional[bool] = None,
    not_banned: Optional[bool] = None,
    https_only: Optional[bool] = None,
):
    content, mime, filename = dm.export_proxies(
        fmt=fmt, style=style, protocol=protocol,
        anonymity=anonymity, speed=speed, ptype=ptype,
        country=country, stealth_min=stealth_min,
        dns_clean=dns_clean, not_banned=not_banned,
        https_only=https_only,
    )
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type=mime,
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/config")
async def api_get_config():
    return dm.load_config()


@app.post("/api/config")
async def api_save_config(request: Request):
    data = await request.json()
    dm.save_config(data)
    return {"status": "ok"}


@app.get("/api/countries")
async def api_countries():
    proxies = dm.load_proxies()
    cc = sorted(set(
        p.get("country_code") for p in proxies
        if p.get("country_code")
    ))
    return cc


# ==============================================================================
# SECTION 6: PAGE ROUTES
# ==============================================================================

def _render(name: str, request: Request, **ctx):
    tp = TEMPLATE_DIR / name
    if not tp.exists():
        return HTMLResponse("<h1>Template not found. Restart dashboard.</h1>")
    with open(tp, encoding="utf-8") as f:
        tmpl = f.read()
    from jinja2 import Template
    html = Template(tmpl).render(request=request, **ctx)
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    return _render("index.html", request, page="dashboard")


@app.get("/proxies", response_class=HTMLResponse)
async def page_proxies(request: Request):
    return _render("proxies.html", request, page="proxies")


@app.get("/analytics", response_class=HTMLResponse)
async def page_analytics(request: Request):
    return _render("analytics.html", request, page="analytics")


@app.get("/map", response_class=HTMLResponse)
async def page_map(request: Request):
    return _render("map.html", request, page="map")


@app.get("/export", response_class=HTMLResponse)
async def page_export(request: Request):
    return _render("export.html", request, page="export")


@app.get("/history", response_class=HTMLResponse)
async def page_history(request: Request):
    return _render("history.html", request, page="history")


@app.get("/recommendations", response_class=HTMLResponse)
async def page_recs(request: Request):
    return _render("recommendations.html", request, page="recommendations")


@app.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request):
    return _render("settings.html", request, page="settings")


@app.get("/proxy/{ip}/{port}", response_class=HTMLResponse)
async def page_proxy_detail(request: Request, ip: str, port: int):
    return _render("proxy_detail.html", request,
                   page="proxies", proxy_ip=ip, proxy_port=port)


# ==============================================================================
# SECTION 7: TEMPLATES
# ==============================================================================

TEMPLATES = {}

# ────────────────────────────────────────────────────────────────
# BASE LAYOUT — shared by all pages
# ────────────────────────────────────────────────────────────────

TEMPLATES["base.html"] = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>UPO Dashboard — {% block title %}Home{% endblock %}</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
tailwind.config = {
  darkMode: 'class',
  theme: { extend: {
    colors: {
      dark: { 50:'#f8fafc',100:'#e2e8f0',200:'#94a3b8',
              700:'#1e293b',800:'#0f172a',900:'#020617' }
    }
  }}
}
</script>
<style>
body{background:#0f172a;color:#e2e8f0;font-family:system-ui,sans-serif}
.sidebar{width:240px;min-height:100vh;background:#020617;border-right:1px solid #1e293b}
.sidebar a{display:flex;align-items:center;gap:10px;padding:10px 18px;color:#94a3b8;
  text-decoration:none;font-size:14px;border-left:3px solid transparent;transition:.15s}
.sidebar a:hover,.sidebar a.active{color:#e2e8f0;background:#0f172a;border-left-color:#3b82f6}
.card{background:#1e293b;border-radius:12px;padding:20px;border:1px solid #334155}
.card-title{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;margin-bottom:6px}
.card-value{font-size:28px;font-weight:700}
.badge{display:inline-block;padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600}
.badge-green{background:#065f46;color:#6ee7b7}
.badge-blue{background:#1e3a5f;color:#7dd3fc}
.badge-yellow{background:#713f12;color:#fde68a}
.badge-red{background:#7f1d1d;color:#fca5a5}
.badge-purple{background:#4c1d95;color:#c4b5fd}
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;padding:10px 12px;background:#020617;color:#94a3b8;font-weight:600;
  border-bottom:1px solid #334155;position:sticky;top:0;cursor:pointer}
.tbl td{padding:8px 12px;border-bottom:1px solid #1e293b}
.tbl tr:hover td{background:#0f172a}
.btn{padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;
  border:none;transition:.15s}
.btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{background:#2563eb}
.btn-ghost{background:transparent;color:#94a3b8;border:1px solid #334155}
.btn-ghost:hover{background:#1e293b;color:#e2e8f0}
select,input[type=text],input[type=number]{background:#020617;color:#e2e8f0;border:1px solid #334155;
  padding:6px 10px;border-radius:6px;font-size:13px}
select:focus,input:focus{outline:none;border-color:#3b82f6}
.delta-up{color:#4ade80}.delta-down{color:#f87171}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:#0f172a}
::-webkit-scrollbar-thumb{background:#334155;border-radius:3px}
.chart-card{background:#1e293b;border-radius:12px;padding:16px;border:1px solid #334155}
.tab{padding:8px 16px;cursor:pointer;color:#94a3b8;border-bottom:2px solid transparent;font-size:13px}
.tab.active{color:#3b82f6;border-bottom-color:#3b82f6}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;display:none;
  justify-content:center;align-items:center}
.modal-overlay.show{display:flex}
.modal{background:#1e293b;border-radius:12px;padding:24px;max-width:700px;width:95%;
  max-height:85vh;overflow-y:auto;border:1px solid #334155}
</style>
</head>
<body class="flex">

<!-- Sidebar -->
<nav class="sidebar flex-shrink-0 flex flex-col">
  <div class="p-5 border-b border-dark-700">
    <div class="text-xl font-bold text-blue-400">🏆 UPO</div>
    <div class="text-xs text-dark-200 mt-1">Dashboard v1.0</div>
  </div>
  <div class="flex-1 py-4 flex flex-col gap-1">
    <a href="/" class="{% if page=='dashboard' %}active{% endif %}">📊 Dashboard</a>
    <a href="/proxies" class="{% if page=='proxies' %}active{% endif %}">📋 Proxies</a>
    <a href="/analytics" class="{% if page=='analytics' %}active{% endif %}">📈 Analytics</a>
    <a href="/map" class="{% if page=='map' %}active{% endif %}">🗺️ Map</a>
    <a href="/export" class="{% if page=='export' %}active{% endif %}">📥 Export</a>
    <a href="/history" class="{% if page=='history' %}active{% endif %}">📅 History</a>
    <a href="/recommendations" class="{% if page=='recommendations' %}active{% endif %}">🤖 Recommendations</a>
    <a href="/settings" class="{% if page=='settings' %}active{% endif %}">⚙️ Settings</a>
  </div>
  <div class="p-4 border-t border-dark-700 text-xs text-dark-200">
    <div id="sb-alive">—</div>
    <div id="sb-last">—</div>
  </div>
</nav>

<!-- Main -->
<main class="flex-1 overflow-y-auto" style="height:100vh">
  <div class="p-6">
    {% block content %}{% endblock %}
  </div>
</main>

<script>
async function fetchJSON(url){const r=await fetch(url);return r.json()}
document.addEventListener('DOMContentLoaded',async()=>{
  try{
    const s=await fetchJSON('/api/summary');
    document.getElementById('sb-alive').textContent=`✅ ${s.alive||0} alive`;
    document.getElementById('sb-last').textContent=s.last_run?`🕐 ${s.last_run}`:'No runs yet';
  }catch(e){}
});
const COLORS=['#3b82f6','#8b5cf6','#06b6d4','#10b981','#f59e0b',
  '#ef4444','#ec4899','#14b8a6','#f97316','#6366f1','#84cc16','#e879f9'];
function makePie(id,labels,data,title){
  const ctx=document.getElementById(id);
  if(!ctx)return;
  new Chart(ctx,{type:'doughnut',data:{labels,datasets:[{data,
    backgroundColor:COLORS.slice(0,labels.length),borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'right',labels:{color:'#94a3b8',boxWidth:12,font:{size:11}}},
        title:{display:!!title,text:title,color:'#e2e8f0'}}}});
}
function makeBar(id,labels,data,title,horizontal){
  const ctx=document.getElementById(id);
  if(!ctx)return;
  new Chart(ctx,{type:'bar',data:{labels,datasets:[{data,
    backgroundColor:COLORS.slice(0,labels.length),borderWidth:0,borderRadius:4}]},
    options:{indexAxis:horizontal?'y':'x',responsive:true,maintainAspectRatio:false,
      plugins:{legend:{display:false},title:{display:!!title,text:title,color:'#e2e8f0'}},
      scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}},
        y:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}}}}});
}
function makeLine(id,labels,datasets,title){
  const ctx=document.getElementById(id);
  if(!ctx)return;
  new Chart(ctx,{type:'line',data:{labels,datasets},
    options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},
      plugins:{legend:{labels:{color:'#94a3b8',boxWidth:12}},
        title:{display:!!title,text:title,color:'#e2e8f0'}},
      scales:{x:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}},
        y:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}}}}});
}
function makeScatter(id,data,title){
  const ctx=document.getElementById(id);
  if(!ctx)return;
  const tMap={residential:'#10b981',datacenter:'#ef4444',mobile:'#f59e0b',unknown:'#94a3b8'};
  const groups={};
  data.forEach(d=>{
    const t=d.type||'unknown';
    if(!groups[t])groups[t]=[];
    groups[t].push({x:d.x,y:d.y});
  });
  const ds=Object.entries(groups).map(([t,pts])=>({
    label:t,data:pts,backgroundColor:tMap[t]||'#94a3b8',pointRadius:3,
  }));
  new Chart(ctx,{type:'scatter',data:{datasets:ds},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{labels:{color:'#94a3b8'}},
        title:{display:!!title,text:title,color:'#e2e8f0'}},
      scales:{x:{title:{display:true,text:'Latency (ms)',color:'#94a3b8'},
        ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}},
        y:{title:{display:true,text:'Stealth Score',color:'#94a3b8'},
        ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}}}}});
}
function copyText(t){navigator.clipboard.writeText(t);
  const el=document.createElement('div');
  el.textContent='Copied!';
  el.style.cssText='position:fixed;top:20px;right:20px;background:#065f46;color:#6ee7b7;padding:8px 16px;border-radius:8px;z-index:9999;font-size:13px';
  document.body.appendChild(el);setTimeout(()=>el.remove(),1500)}
</script>
{% block scripts %}{% endblock %}
</body></html>"""

# ────────────────────────────────────────────────────────────────
# DASHBOARD
# ────────────────────────────────────────────────────────────────

TEMPLATES["index.html"] = r"""{% extends "base.html" %}
{% block title %}Dashboard{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">📊 Dashboard</h1>

<!-- Summary Cards -->
<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6" id="cards"></div>

<!-- Charts Row 1 -->
<div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Protocol Distribution</div>
    <div style="height:220px"><canvas id="ch-proto"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Anonymity Breakdown</div>
    <div style="height:220px"><canvas id="ch-anon"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Proxy Type</div>
    <div style="height:220px"><canvas id="ch-type"></canvas></div></div>
</div>

<!-- Charts Row 2 -->
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Top Countries</div>
    <div style="height:280px"><canvas id="ch-countries"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Latency Distribution</div>
    <div style="height:280px"><canvas id="ch-lat"></canvas></div></div>
</div>

<!-- Recent Runs -->
<div class="card">
  <div class="card-title mb-3">Recent Runs</div>
  <div style="overflow-x:auto">
    <table class="tbl" id="runs-tbl">
      <thead><tr><th>Date</th><th>Alive</th><th>Elite</th><th>Fast</th>
        <th>Avg Latency</th><th>Countries</th></tr></thead>
      <tbody id="runs-body"></tbody>
    </table>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const s=await fetchJSON('/api/summary');
  const a=await fetchJSON('/api/analytics');
  const h=await fetchJSON('/api/history');

  const cards=[
    {t:'Total Alive',v:s.alive,d:s.delta?.alive,color:'text-blue-400'},
    {t:'Elite',v:s.elite,d:s.delta?.elite,color:'text-green-400'},
    {t:'Fast',v:s.fast,d:s.delta?.fast,color:'text-cyan-400'},
    {t:'Residential',v:s.residential,color:'text-purple-400'},
    {t:'Stealth ≥70',v:s.stealth_high,color:'text-yellow-400'},
    {t:'Avg Latency',v:s.avg_latency+'ms',d:s.delta?.latency,color:'text-orange-400',inv:true},
  ];
  let ch='';
  cards.forEach(c=>{
    let delta='';
    if(c.d!==undefined&&c.d!==null){
      const cls=c.inv?(c.d<=0?'delta-up':'delta-down'):(c.d>=0?'delta-up':'delta-down');
      delta=`<span class="${cls}" style="font-size:12px">${c.d>0?'+':''}${c.d}</span>`;
    }
    ch+=`<div class="card"><div class="card-title">${c.t}</div>
      <div class="card-value ${c.color}">${c.v??'—'}</div>${delta}</div>`;
  });
  document.getElementById('cards').innerHTML=ch;

  if(a.protocols)makePie('ch-proto',Object.keys(a.protocols),Object.values(a.protocols));
  if(a.anonymity)makePie('ch-anon',Object.keys(a.anonymity),Object.values(a.anonymity));
  if(a.types)makePie('ch-type',Object.keys(a.types),Object.values(a.types));
  if(a.top_countries)makeBar('ch-countries',a.top_countries.map(c=>c[0]),a.top_countries.map(c=>c[1]),'',true);
  if(a.latency_buckets)makeBar('ch-lat',Object.keys(a.latency_buckets),Object.values(a.latency_buckets));

  if(h.runs){
    const tb=document.getElementById('runs-body');
    h.runs.slice(0,10).forEach(r=>{
      tb.innerHTML+=`<tr><td>${r.date}</td><td>${r.count}</td><td>${r.elite||0}</td>
        <td>${r.fast||0}</td><td>${r.avg_latency||0}ms</td><td>${r.countries||0}</td></tr>`;
    });
  }
});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# PROXY TABLE
# ────────────────────────────────────────────────────────────────

TEMPLATES["proxies.html"] = r"""{% extends "base.html" %}
{% block title %}Proxies{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-4">📋 Proxy Browser</h1>

<!-- Filters -->
<div class="card mb-4">
  <div class="flex flex-wrap gap-3 items-end">
    <div><label class="text-xs text-dark-200">Search</label><br>
      <input type="text" id="f-search" placeholder="IP, country, ISP..." class="w-40"></div>
    <div><label class="text-xs text-dark-200">Protocol</label><br>
      <select id="f-proto"><option value="">All</option>
        <option>http</option><option>https</option><option>socks4</option><option>socks5</option></select></div>
    <div><label class="text-xs text-dark-200">Anonymity</label><br>
      <select id="f-anon"><option value="">All</option>
        <option>elite</option><option>anonymous</option><option>transparent</option></select></div>
    <div><label class="text-xs text-dark-200">Speed</label><br>
      <select id="f-speed"><option value="">All</option>
        <option>fast</option><option>medium</option><option>slow</option></select></div>
    <div><label class="text-xs text-dark-200">Type</label><br>
      <select id="f-type"><option value="">All</option>
        <option>residential</option><option>datacenter</option><option>mobile</option><option>unknown</option></select></div>
    <div><label class="text-xs text-dark-200">Country</label><br>
      <select id="f-country"><option value="">All</option></select></div>
    <div><label class="text-xs text-dark-200">Max Latency</label><br>
      <input type="number" id="f-latmax" placeholder="ms" class="w-20"></div>
    <div><label class="text-xs text-dark-200">Min Stealth</label><br>
      <input type="number" id="f-stmin" placeholder="0-100" class="w-20"></div>
    <div class="flex gap-2 items-center pt-4">
      <label class="text-xs"><input type="checkbox" id="f-dns"> DNS Clean</label>
      <label class="text-xs"><input type="checkbox" id="f-ban"> Not Banned</label>
      <label class="text-xs"><input type="checkbox" id="f-https"> HTTPS</label>
    </div>
    <div class="pt-4 flex gap-2">
      <button class="btn btn-primary" onclick="loadProxies(1)">🔍 Filter</button>
      <button class="btn btn-ghost" onclick="resetFilters()">↺ Reset</button>
    </div>
  </div>
  <!-- Presets -->
  <div class="flex gap-2 mt-3">
    <button class="btn btn-ghost text-xs" onclick="preset('scraping')">🕷️ Scraping</button>
    <button class="btn btn-ghost text-xs" onclick="preset('stealth')">🥷 Stealth</button>
    <button class="btn btn-ghost text-xs" onclick="preset('fast')">⚡ Fast Elite</button>
    <button class="btn btn-ghost text-xs" onclick="preset('residential')">🏠 Residential</button>
    <button class="btn btn-ghost text-xs" onclick="preset('clean')">✨ Clean</button>
  </div>
</div>

<!-- Results info -->
<div class="flex justify-between items-center mb-3">
  <div class="text-sm text-dark-200" id="result-info">Loading...</div>
  <div class="flex gap-2">
    <button class="btn btn-ghost text-xs" onclick="copyAll()">📋 Copy All</button>
    <select id="pg-size" class="text-xs" onchange="loadProxies(1)">
      <option value="25">25</option><option value="50" selected>50</option>
      <option value="100">100</option><option value="500">500</option>
    </select>
  </div>
</div>

<!-- Table -->
<div class="card p-0" style="overflow-x:auto;max-height:60vh;overflow-y:auto">
  <table class="tbl">
    <thead><tr>
      <th onclick="sortBy('ip')">IP</th>
      <th onclick="sortBy('port')">Port</th>
      <th onclick="sortBy('protocol')">Proto</th>
      <th onclick="sortBy('anonymity')">Anon</th>
      <th onclick="sortBy('latency_ms')">Latency</th>
      <th onclick="sortBy('speed_tier')">Speed</th>
      <th onclick="sortBy('proxy_type')">Type</th>
      <th onclick="sortBy('country_code')">Country</th>
      <th onclick="sortBy('stealth_score')">Stealth</th>
      <th onclick="sortBy('composite_score')">Fraud</th>
      <th>Actions</th>
    </tr></thead>
    <tbody id="proxy-body"></tbody>
  </table>
</div>

<!-- Pagination -->
<div class="flex justify-center gap-2 mt-4" id="pagination"></div>

<!-- Detail Modal -->
<div class="modal-overlay" id="detail-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal" id="detail-content"></div>
</div>
{% endblock %}
{% block scripts %}
<script>
let curSort='latency_ms',curOrder='asc',curPage=1;
async function loadCountries(){
  const cc=await fetchJSON('/api/countries');
  const sel=document.getElementById('f-country');
  cc.forEach(c=>{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o)});
}
function getFilters(){
  return {
    search:document.getElementById('f-search').value||undefined,
    protocol:document.getElementById('f-proto').value||undefined,
    anonymity:document.getElementById('f-anon').value||undefined,
    speed:document.getElementById('f-speed').value||undefined,
    ptype:document.getElementById('f-type').value||undefined,
    country:document.getElementById('f-country').value||undefined,
    lat_max:document.getElementById('f-latmax').value||undefined,
    stealth_min:document.getElementById('f-stmin').value||undefined,
    dns_clean:document.getElementById('f-dns').checked||undefined,
    not_banned:document.getElementById('f-ban').checked||undefined,
    https_only:document.getElementById('f-https').checked||undefined,
  };
}
async function loadProxies(page){
  curPage=page||1;
  const f=getFilters();
  const ps=document.getElementById('pg-size').value;
  let url=`/api/proxies?page=${curPage}&per_page=${ps}&sort=${curSort}&order=${curOrder}`;
  Object.entries(f).forEach(([k,v])=>{if(v)url+=`&${k}=${encodeURIComponent(v)}`});
  const data=await fetchJSON(url);
  const tb=document.getElementById('proxy-body');
  tb.innerHTML='';
  data.proxies.forEach(p=>{
    const anonBadge={elite:'badge-green',anonymous:'badge-blue',transparent:'badge-yellow'}[p.anonymity]||'badge-purple';
    const speedBadge={fast:'badge-green',medium:'badge-yellow',slow:'badge-red'}[p.speed_tier]||'badge-purple';
    const typeBadge={residential:'badge-green',mobile:'badge-yellow',datacenter:'badge-red',unknown:'badge-purple'}[p.proxy_type]||'';
    tb.innerHTML+=`<tr style="cursor:pointer" ondblclick="showDetail('${p.ip}',${p.port})">
      <td class="font-mono text-xs">${p.ip}</td>
      <td>${p.port}</td>
      <td><span class="badge badge-blue">${p.protocol||'?'}</span></td>
      <td><span class="badge ${anonBadge}">${p.anonymity||'?'}</span></td>
      <td>${p.latency_ms||'—'}ms</td>
      <td><span class="badge ${speedBadge}">${p.speed_tier||'?'}</span></td>
      <td><span class="badge ${typeBadge}">${p.proxy_type||'?'}</span></td>
      <td>${p.country_code||'??'}</td>
      <td>${p.stealth_score??'—'}</td>
      <td>${p.composite_score??'—'}</td>
      <td>
        <button class="text-xs text-blue-400 hover:underline" onclick="event.stopPropagation();copyText('${p.ip}:${p.port}')">📋</button>
        <button class="text-xs text-blue-400 hover:underline ml-1" onclick="event.stopPropagation();showDetail('${p.ip}',${p.port})">👁</button>
      </td></tr>`;
  });
  document.getElementById('result-info').textContent=
    `${data.total} proxies — Page ${data.page}/${data.pages}`;
  // Pagination
  const pg=document.getElementById('pagination');
  pg.innerHTML='';
  for(let i=1;i<=Math.min(data.pages,20);i++){
    pg.innerHTML+=`<button class="btn ${i===data.page?'btn-primary':'btn-ghost'} text-xs"
      onclick="loadProxies(${i})">${i}</button>`;
  }
}
function sortBy(col){
  if(curSort===col)curOrder=curOrder==='asc'?'desc':'asc';
  else{curSort=col;curOrder='asc'}
  loadProxies(curPage);
}
function resetFilters(){
  ['f-search','f-proto','f-anon','f-speed','f-type','f-country','f-latmax','f-stmin'].forEach(id=>
    document.getElementById(id).value='');
  ['f-dns','f-ban','f-https'].forEach(id=>document.getElementById(id).checked=false);
  loadProxies(1);
}
function preset(name){
  resetFilters();
  if(name==='scraping'){document.getElementById('f-anon').value='elite';document.getElementById('f-speed').value='fast';document.getElementById('f-ban').checked=true}
  if(name==='stealth'){document.getElementById('f-stmin').value='70'}
  if(name==='fast'){document.getElementById('f-anon').value='elite';document.getElementById('f-speed').value='fast'}
  if(name==='residential'){document.getElementById('f-type').value='residential'}
  if(name==='clean'){document.getElementById('f-dns').checked=true;document.getElementById('f-ban').checked=true}
  loadProxies(1);
}
async function copyAll(){
  const f=getFilters();
  let url='/api/proxies?per_page=999999';
  Object.entries(f).forEach(([k,v])=>{if(v)url+=`&${k}=${encodeURIComponent(v)}`});
  const data=await fetchJSON(url);
  const txt=data.proxies.map(p=>`${p.ip}:${p.port}`).join('\n');
  copyText(txt);
}
async function showDetail(ip,port){
  const p=await fetchJSON(`/api/proxy/${ip}/${port}`);
  if(p.error){alert('Not found');return}
  const m=document.getElementById('detail-content');
  const fields=[
    ['IP',p.ip],['Port',p.port],['Protocol',p.protocol],['Anonymity',p.anonymity],
    ['Latency',`${p.latency_ms||'—'}ms`],['Speed',p.speed_tier],['Type',p.proxy_type],
    ['Country',`${p.country_code||'?'} — ${p.country_name||''}`],['City',p.city],
    ['Region',p.region],['ASN',p.asn],['ISP',p.isp],['Stealth',p.stealth_score],
    ['Fraud Score',p.composite_score],['DNS Leak',p.dns_leak],['Google Ban',p.google_ban],
    ['HTTPS',p.supports_https],['TCP FP',p.tcp_fingerprint],['Protocols',
      (p.detected_protocols||[]).join(', ')],['Speed KB/s',p.download_speed_kbps],
    ['Reliability',p.reliability],['Checks',`${p.success_count||0}/${p.check_count||0}`],
    ['First Seen',p.first_seen],['Last Checked',p.last_checked],['Source',p.source],
  ];
  m.innerHTML=`<h2 class="text-lg font-bold mb-4">${p.ip}:${p.port}</h2>
    <div class="grid grid-cols-2 gap-2 text-sm">${fields.map(([k,v])=>
      `<div class="text-dark-200">${k}</div><div class="font-mono">${v??'—'}</div>`).join('')}</div>
    <div class="flex gap-2 mt-4">
      <button class="btn btn-primary" onclick="copyText('${p.ip}:${p.port}')">📋 Copy ip:port</button>
      <button class="btn btn-ghost" onclick="copyText('${p.protocol}://${p.ip}:${p.port}')">📋 Copy URL</button>
      <button class="btn btn-ghost" onclick="copyText('curl -x ${p.protocol}://${p.ip}:${p.port} http://httpbin.org/ip')">📋 Curl</button>
      <button class="btn btn-ghost" onclick="document.getElementById('detail-modal').classList.remove('show')">Close</button>
    </div>`;
  document.getElementById('detail-modal').classList.add('show');
}
document.addEventListener('DOMContentLoaded',()=>{loadCountries();loadProxies(1)});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# ANALYTICS
# ────────────────────────────────────────────────────────────────

TEMPLATES["analytics.html"] = r"""{% extends "base.html" %}
{% block title %}Analytics{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">📈 Analytics</h1>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Protocol Distribution</div>
    <div style="height:260px"><canvas id="a-proto"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Anonymity Breakdown</div>
    <div style="height:260px"><canvas id="a-anon"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Proxy Type</div>
    <div style="height:260px"><canvas id="a-type"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Speed Tier</div>
    <div style="height:260px"><canvas id="a-speed"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Latency Distribution</div>
    <div style="height:260px"><canvas id="a-lat"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Stealth Score Distribution</div>
    <div style="height:260px"><canvas id="a-stealth"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">DNS Leak</div>
    <div style="height:260px"><canvas id="a-dns"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Google Ban</div>
    <div style="height:260px"><canvas id="a-ban"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">TCP Fingerprint</div>
    <div style="height:260px"><canvas id="a-fp"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Latency vs Stealth</div>
    <div style="height:260px"><canvas id="a-scatter"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Top 20 ASNs</div>
    <div style="height:400px"><canvas id="a-asn"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Top Sources (by alive count)</div>
    <div style="height:400px"><canvas id="a-src"></canvas></div></div>
</div>
<div class="grid grid-cols-1 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Top Countries</div>
    <div style="height:350px"><canvas id="a-cc"></canvas></div></div>
</div>

<!-- Summary cards -->
<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
  <div class="card"><div class="card-title">HTTPS Support</div>
    <div class="card-value text-green-400" id="a-https">—</div></div>
  <div class="card"><div class="card-title">Multi-Protocol</div>
    <div class="card-value text-blue-400" id="a-multi">—</div></div>
  <div class="card"><div class="card-title">Avg Stealth</div>
    <div class="card-value text-yellow-400" id="a-avgst">—</div></div>
  <div class="card"><div class="card-title">Total Alive</div>
    <div class="card-value text-cyan-400" id="a-total">—</div></div>
</div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const a=await fetchJSON('/api/analytics');
  if(!a.protocols)return;
  makePie('a-proto',Object.keys(a.protocols),Object.values(a.protocols));
  makePie('a-anon',Object.keys(a.anonymity),Object.values(a.anonymity));
  makePie('a-type',Object.keys(a.types),Object.values(a.types));
  makePie('a-speed',Object.keys(a.speed_tiers),Object.values(a.speed_tiers));
  makeBar('a-lat',Object.keys(a.latency_buckets),Object.values(a.latency_buckets));
  makeBar('a-stealth',Object.keys(a.stealth_buckets),Object.values(a.stealth_buckets));
  makePie('a-dns',Object.keys(a.dns_leak),Object.values(a.dns_leak));
  makePie('a-ban',Object.keys(a.google_ban),Object.values(a.google_ban));
  makePie('a-fp',Object.keys(a.fingerprints),Object.values(a.fingerprints));
  if(a.scatter)makeScatter('a-scatter',a.scatter,'Latency vs Stealth Score');
  if(a.top_asns)makeBar('a-asn',a.top_asns.map(x=>x[0]),a.top_asns.map(x=>x[1]),'',true);
  if(a.top_sources)makeBar('a-src',a.top_sources.map(x=>x[0].substring(0,30)),a.top_sources.map(x=>x[1]),'',true);
  if(a.top_countries)makeBar('a-cc',a.top_countries.map(x=>x[0]),a.top_countries.map(x=>x[1]));
  document.getElementById('a-https').textContent=`${a.https_count||0}/${a.total||0}`;
  document.getElementById('a-multi').textContent=a.multi_protocol||0;
  document.getElementById('a-total').textContent=a.total||0;
  // avg stealth from buckets
  const sb=a.stealth_buckets;
  const tot=Object.values(sb).reduce((a,b)=>a+b,0);
  document.getElementById('a-avgst').textContent=tot?'—':'—';
});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# MAP
# ────────────────────────────────────────────────────────────────

TEMPLATES["map.html"] = r"""{% extends "base.html" %}
{% block title %}Map{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-4">🗺️ Geographic Distribution</h1>
<div class="flex gap-4" style="height:calc(100vh - 140px)">
  <div id="map" class="flex-1 rounded-xl" style="min-height:400px"></div>
  <div class="w-72 overflow-y-auto">
    <div class="card mb-3">
      <div class="card-title">Summary</div>
      <div class="text-2xl font-bold text-blue-400" id="geo-total">—</div>
      <div class="text-sm text-dark-200" id="geo-countries">— countries</div>
    </div>
    <div id="country-list" class="space-y-2"></div>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const g=await fetchJSON('/api/geo');
  const map=L.map('map',{zoomControl:true}).setView([20,0],2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{
    attribution:'©CartoDB',maxZoom:18}).addTo(map);
  document.getElementById('geo-total').textContent=
    g.countries.reduce((a,c)=>a+c.count,0)+' proxies';
  document.getElementById('geo-countries').textContent=g.total_countries+' countries';
  const maxCount=Math.max(...g.countries.map(c=>c.count),1);
  const list=document.getElementById('country-list');
  g.countries.sort((a,b)=>b.count-a.count).forEach(c=>{
    if(c.coords[0]===0&&c.coords[1]===0)return;
    const r=Math.max(6,Math.sqrt(c.count/maxCount)*35);
    const circle=L.circleMarker(c.coords,{
      radius:r,fillColor:'#3b82f6',color:'#1d4ed8',weight:1,fillOpacity:.6
    }).addTo(map);
    circle.bindPopup(`<b>${c.name} (${c.code})</b><br>
      Proxies: ${c.count}<br>Elite: ${c.elite}<br>Fast: ${c.fast}<br>
      Avg Latency: ${c.avg_latency}ms<br>Avg Stealth: ${c.avg_stealth}`);
    list.innerHTML+=`<div class="card p-3 cursor-pointer hover:border-blue-500"
      onclick="map.setView([${c.coords}],5)">
      <div class="font-bold text-sm">${c.code} — ${c.name}</div>
      <div class="text-xs text-dark-200">${c.count} proxies · ${c.elite} elite · ${c.avg_latency}ms</div>
      <div class="w-full bg-dark-800 rounded-full h-1.5 mt-1">
        <div class="bg-blue-500 h-1.5 rounded-full" style="width:${(c.count/maxCount*100).toFixed(0)}%"></div>
      </div></div>`;
  });
});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# EXPORT
# ────────────────────────────────────────────────────────────────

TEMPLATES["export.html"] = r"""{% extends "base.html" %}
{% block title %}Export{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">📥 Export Center</h1>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
  <!-- Filters -->
  <div class="card">
    <div class="card-title mb-3">Filters</div>
    <div class="space-y-3">
      <div><label class="text-xs text-dark-200">Protocol</label>
        <select id="e-proto" class="w-full"><option value="">All</option>
          <option>http</option><option>https</option><option>socks4</option><option>socks5</option></select></div>
      <div><label class="text-xs text-dark-200">Anonymity</label>
        <select id="e-anon" class="w-full"><option value="">All</option>
          <option>elite</option><option>anonymous</option></select></div>
      <div><label class="text-xs text-dark-200">Speed</label>
        <select id="e-speed" class="w-full"><option value="">All</option>
          <option>fast</option><option>medium</option></select></div>
      <div><label class="text-xs text-dark-200">Type</label>
        <select id="e-type" class="w-full"><option value="">All</option>
          <option>residential</option><option>datacenter</option><option>mobile</option></select></div>
      <div><label class="text-xs text-dark-200">Country</label>
        <select id="e-country" class="w-full"><option value="">All</option></select></div>
      <div><label class="text-xs text-dark-200">Min Stealth</label>
        <input type="number" id="e-stmin" class="w-full" placeholder="0-100"></div>
      <label class="text-xs flex gap-2"><input type="checkbox" id="e-dns"> DNS Clean Only</label>
      <label class="text-xs flex gap-2"><input type="checkbox" id="e-ban"> Not Banned Only</label>
      <label class="text-xs flex gap-2"><input type="checkbox" id="e-https"> HTTPS Only</label>
    </div>
    <div class="card-title mt-5 mb-2">Quick Presets</div>
    <div class="flex flex-wrap gap-2">
      <button class="btn btn-ghost text-xs" onclick="ePreset('elite_socks5')">Elite SOCKS5</button>
      <button class="btn btn-ghost text-xs" onclick="ePreset('fast_res')">Fast Residential</button>
      <button class="btn btn-ghost text-xs" onclick="ePreset('stealth70')">Stealth ≥70</button>
      <button class="btn btn-ghost text-xs" onclick="ePreset('clean')">Clean Only</button>
      <button class="btn btn-ghost text-xs" onclick="ePreset('https')">HTTPS Capable</button>
      <button class="btn btn-ghost text-xs" onclick="ePreset('nobanned')">Not Google Banned</button>
    </div>
  </div>

  <!-- Format -->
  <div class="card">
    <div class="card-title mb-3">Format</div>
    <div class="space-y-3">
      <div><label class="text-xs text-dark-200">File Format</label>
        <select id="e-fmt" class="w-full">
          <option value="txt">TXT</option><option value="json">JSON</option>
          <option value="csv">CSV</option><option value="yaml">YAML</option></select></div>
      <div><label class="text-xs text-dark-200">Line Style (TXT only)</label>
        <select id="e-style" class="w-full">
          <option value="ip_port">ip:port</option>
          <option value="protocol_url">protocol://ip:port</option>
          <option value="json_lines">JSON Lines</option>
          <option value="curl">curl commands</option>
          <option value="env">ENV variables</option>
          <option value="proxychains">proxychains.conf</option>
          <option value="haproxy">HAProxy config</option>
        </select></div>
    </div>
    <button class="btn btn-primary w-full mt-6" onclick="doExport()">📥 Download</button>
    <button class="btn btn-ghost w-full mt-2" onclick="doPreview()">👁 Preview</button>
  </div>

  <!-- Preview -->
  <div class="card">
    <div class="card-title mb-3">Preview <span id="e-count" class="text-blue-400"></span></div>
    <pre id="e-preview" class="text-xs font-mono bg-dark-900 p-3 rounded-lg overflow-auto"
      style="max-height:500px;white-space:pre-wrap">Click "Preview" to see output...</pre>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
async function loadEC(){
  const cc=await fetchJSON('/api/countries');
  const sel=document.getElementById('e-country');
  cc.forEach(c=>{const o=document.createElement('option');o.value=c;o.textContent=c;sel.appendChild(o)});
}
function eParams(){
  let p=`fmt=${document.getElementById('e-fmt').value}&style=${document.getElementById('e-style').value}`;
  const m={protocol:'e-proto',anonymity:'e-anon',speed:'e-speed',ptype:'e-type',country:'e-country',stealth_min:'e-stmin'};
  Object.entries(m).forEach(([k,id])=>{const v=document.getElementById(id).value;if(v)p+=`&${k}=${v}`});
  if(document.getElementById('e-dns').checked)p+='&dns_clean=true';
  if(document.getElementById('e-ban').checked)p+='&not_banned=true';
  if(document.getElementById('e-https').checked)p+='&https_only=true';
  return p;
}
function doExport(){window.location.href='/api/export?'+eParams()}
async function doPreview(){
  const r=await fetch('/api/export?'+eParams());
  const t=await r.text();
  const lines=t.split('\n');
  document.getElementById('e-count').textContent=`(${lines.length} lines)`;
  document.getElementById('e-preview').textContent=lines.slice(0,100).join('\n')+(lines.length>100?'\n...':'');
}
function ePreset(name){
  ['e-proto','e-anon','e-speed','e-type','e-country','e-stmin'].forEach(id=>document.getElementById(id).value='');
  ['e-dns','e-ban','e-https'].forEach(id=>document.getElementById(id).checked=false);
  if(name==='elite_socks5'){document.getElementById('e-proto').value='socks5';document.getElementById('e-anon').value='elite'}
  if(name==='fast_res'){document.getElementById('e-speed').value='fast';document.getElementById('e-type').value='residential'}
  if(name==='stealth70')document.getElementById('e-stmin').value='70';
  if(name==='clean'){document.getElementById('e-dns').checked=true;document.getElementById('e-ban').checked=true}
  if(name==='https')document.getElementById('e-https').checked=true;
  if(name==='nobanned')document.getElementById('e-ban').checked=true;
}
document.addEventListener('DOMContentLoaded',loadEC);
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# HISTORY
# ────────────────────────────────────────────────────────────────

TEMPLATES["history.html"] = r"""{% extends "base.html" %}
{% block title %}History{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">📅 Historical Trends</h1>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Alive Count Over Time</div>
    <div style="height:280px"><canvas id="h-alive"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Elite & Fast Over Time</div>
    <div style="height:280px"><canvas id="h-quality"></canvas></div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Average Latency Over Time</div>
    <div style="height:280px"><canvas id="h-lat"></canvas></div></div>
  <div class="chart-card"><div class="card-title">Average Stealth Over Time</div>
    <div style="height:280px"><canvas id="h-stealth"></canvas></div></div>
</div>
<div class="grid grid-cols-1 gap-4 mb-4">
  <div class="chart-card"><div class="card-title">Countries Covered Over Time</div>
    <div style="height:250px"><canvas id="h-cc"></canvas></div></div>
</div>

<!-- Run table -->
<div class="card">
  <div class="card-title mb-3">All Runs</div>
  <div style="overflow-x:auto;max-height:400px;overflow-y:auto">
    <table class="tbl">
      <thead><tr><th>Date</th><th>ID</th><th>Count</th><th>Elite</th><th>Fast</th>
        <th>Avg Latency</th><th>Avg Stealth</th><th>Countries</th></tr></thead>
      <tbody id="h-runs"></tbody>
    </table>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const h=await fetchJSON('/api/history');
  if(!h.dates||!h.dates.length)return;
  makeLine('h-alive',h.dates,[{label:'Alive',data:h.counts,borderColor:'#3b82f6',
    backgroundColor:'rgba(59,130,246,.1)',fill:true,tension:.3}]);
  makeLine('h-quality',h.dates,[
    {label:'Elite',data:h.elite_counts,borderColor:'#10b981',tension:.3},
    {label:'Fast',data:h.fast_counts,borderColor:'#06b6d4',tension:.3}]);
  makeLine('h-lat',h.dates,[{label:'Avg Latency (ms)',data:h.latencies,
    borderColor:'#f59e0b',tension:.3}]);
  makeLine('h-stealth',h.dates,[{label:'Avg Stealth',data:h.stealths,
    borderColor:'#8b5cf6',tension:.3}]);
  makeLine('h-cc',h.dates,[{label:'Countries',data:h.country_counts,
    borderColor:'#ec4899',tension:.3}]);
  const tb=document.getElementById('h-runs');
  h.runs.forEach(r=>{
    tb.innerHTML+=`<tr><td>${r.date}</td><td class="font-mono text-xs">${r.suffix}</td>
      <td>${r.count}</td><td>${r.elite||0}</td><td>${r.fast||0}</td>
      <td>${r.avg_latency||0}ms</td><td>${r.avg_stealth||0}</td><td>${r.countries||0}</td></tr>`;
  });
});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# RECOMMENDATIONS
# ────────────────────────────────────────────────────────────────

TEMPLATES["recommendations.html"] = r"""{% extends "base.html" %}
{% block title %}Recommendations{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">🤖 Smart Recommendations</h1>
<div id="recs-container" class="space-y-6"></div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const recs=await fetchJSON('/api/recommendations');
  const c=document.getElementById('recs-container');
  if(!recs.length){c.innerHTML='<div class="card"><p class="text-dark-200">No data yet. Run UPO first.</p></div>';return}
  recs.forEach(r=>{
    let extra='';
    if(r.missing_countries&&r.missing_countries.length){
      extra=`<div class="mt-2"><span class="text-xs text-dark-200">Missing:</span>
        ${r.missing_countries.map(c=>`<span class="badge badge-red ml-1">${c}</span>`).join('')}</div>`;
    }
    if(r.dominant_asns&&r.dominant_asns.length){
      extra+=`<div class="mt-2"><span class="text-xs text-dark-200">Dominant ASNs:</span>
        ${r.dominant_asns.map(a=>`<span class="badge badge-yellow ml-1">ASN${a[0]} (${a[1]})</span>`).join('')}</div>`;
    }
    let tbl='';
    if(r.proxies&&r.proxies.length){
      tbl=`<div class="mt-3" style="overflow-x:auto"><table class="tbl">
        <thead><tr><th>IP</th><th>Port</th><th>Proto</th><th>Anon</th><th>Latency</th>
          <th>Stealth</th><th>Type</th><th>Country</th></tr></thead><tbody>
        ${r.proxies.map(p=>`<tr>
          <td class="font-mono text-xs">${p.ip}</td><td>${p.port}</td>
          <td><span class="badge badge-blue">${p.protocol||'?'}</span></td>
          <td>${p.anonymity||'?'}</td><td>${p.latency_ms||'—'}ms</td>
          <td>${p.stealth_score??'—'}</td><td>${p.proxy_type||'?'}</td>
          <td>${p.country_code||'?'}</td></tr>`).join('')}
        </tbody></table></div>`;
    }
    c.innerHTML+=`<div class="card">
      <div class="flex justify-between items-center mb-2">
        <h2 class="text-lg font-bold">${r.title}</h2>
        <span class="badge badge-blue">${r.count} proxies</span>
      </div>
      <p class="text-sm text-dark-200">${r.desc}</p>
      ${extra}${tbl}</div>`;
  });
});
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# SETTINGS
# ────────────────────────────────────────────────────────────────

TEMPLATES["settings.html"] = r"""{% extends "base.html" %}
{% block title %}Settings{% endblock %}
{% block content %}
<h1 class="text-2xl font-bold mb-6">⚙️ Settings</h1>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
  <!-- General -->
  <div class="card">
    <div class="card-title mb-4">General</div>
    <div class="space-y-3">
      <div><label class="text-xs text-dark-200">Concurrency</label>
        <input type="number" id="s-conc" class="w-full"></div>
      <div><label class="text-xs text-dark-200">Timeout Total (s)</label>
        <input type="number" id="s-timeout" class="w-full"></div>
      <div><label class="text-xs text-dark-200">Timeout Connect (s)</label>
        <input type="number" id="s-conn" class="w-full"></div>
      <div><label class="text-xs text-dark-200">Verification Rounds</label>
        <input type="number" id="s-rounds" class="w-full"></div>
    </div>
  </div>

  <!-- Toggles -->
  <div class="card">
    <div class="card-title mb-4">Modules</div>
    <div class="space-y-3">
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-ban"> Ban Check</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-speed"> Speed Test</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-dns"> DNS Leak Check</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-stealth"> Stealth Score</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-proto"> Protocol Detection</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-fraud"> Fraud Check</label>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-crawl"> Crawl4AI</label>
    </div>
  </div>

  <!-- Filter -->
  <div class="card">
    <div class="card-title mb-4">Filters</div>
    <div class="space-y-3">
      <div><label class="text-xs text-dark-200">Allowed Countries (comma-sep)</label>
        <input type="text" id="s-allow" class="w-full" placeholder="US,GB,DE"></div>
      <div><label class="text-xs text-dark-200">Blocked Countries</label>
        <input type="text" id="s-block" class="w-full" placeholder="CN,IR"></div>
      <label class="flex gap-2 text-sm"><input type="checkbox" id="s-exdc"> Exclude Datacenters</label>
      <div><label class="text-xs text-dark-200">Min Anonymity</label>
        <select id="s-minanon" class="w-full"><option value="">None</option>
          <option>anonymous</option><option>elite</option></select></div>
    </div>
  </div>

  <!-- Output -->
  <div class="card">
    <div class="card-title mb-4">Output</div>
    <div class="space-y-3">
      <div><label class="text-xs text-dark-200">Fast Threshold (ms)</label>
        <input type="number" id="s-fast" class="w-full"></div>
      <div><label class="text-xs text-dark-200">Fraud Top N</label>
        <input type="number" id="s-topn" class="w-full"></div>
    </div>
  </div>
</div>

<!-- Raw YAML Editor -->
<div class="card mt-6">
  <div class="card-title mb-3">Raw Config (YAML)</div>
  <textarea id="s-raw" class="w-full bg-dark-900 text-sm font-mono p-3 rounded-lg border border-dark-700"
    style="min-height:300px"></textarea>
</div>

<div class="flex gap-3 mt-4">
  <button class="btn btn-primary" onclick="saveConfig()">💾 Save</button>
  <button class="btn btn-ghost" onclick="loadConfig()">↺ Reload</button>
</div>
<div id="s-msg" class="mt-3 text-sm"></div>
{% endblock %}
{% block scripts %}
<script>
let currentConfig={};
async function loadConfig(){
  currentConfig=await fetchJSON('/api/config');
  const g=currentConfig.general||{};
  const f=currentConfig.filter||{};
  const o=currentConfig.output||{};
  const fr=currentConfig.fraud_check||{};
  document.getElementById('s-conc').value=g.concurrency||300;
  document.getElementById('s-timeout').value=g.timeout_total||15;
  document.getElementById('s-conn').value=g.timeout_connect||8;
  document.getElementById('s-rounds').value=g.verification_rounds||2;
  document.getElementById('s-ban').checked=currentConfig.ban_check?.enabled??true;
  document.getElementById('s-speed').checked=currentConfig.speed_test?.enabled??true;
  document.getElementById('s-dns').checked=currentConfig.dns_leak?.enabled??true;
  document.getElementById('s-stealth').checked=currentConfig.stealth_score?.enabled??true;
  document.getElementById('s-proto').checked=currentConfig.protocol_detection?.enabled??true;
  document.getElementById('s-fraud').checked=fr.enabled??false;
  document.getElementById('s-crawl').checked=currentConfig.crawl4ai?.enabled??false;
  document.getElementById('s-allow').value=(f.allowed_countries||[]).join(',');
  document.getElementById('s-block').value=(f.blocked_countries||[]).join(',');
  document.getElementById('s-exdc').checked=f.exclude_datacenters??false;
  document.getElementById('s-minanon').value=f.min_anonymity||'';
  document.getElementById('s-fast').value=o.fast_threshold_ms||500;
  document.getElementById('s-topn').value=fr.top_n||100;
  document.getElementById('s-raw').value=JSON.stringify(currentConfig,null,2);
}
async function saveConfig(){
  try{
    let cfg=JSON.parse(document.getElementById('s-raw').value);
    // Also apply form values on top
    if(!cfg.general)cfg.general={};
    cfg.general.concurrency=parseInt(document.getElementById('s-conc').value)||300;
    cfg.general.timeout_total=parseInt(document.getElementById('s-timeout').value)||15;
    cfg.general.timeout_connect=parseInt(document.getElementById('s-conn').value)||8;
    cfg.general.verification_rounds=parseInt(document.getElementById('s-rounds').value)||2;
    if(!cfg.ban_check)cfg.ban_check={};cfg.ban_check.enabled=document.getElementById('s-ban').checked;
    if(!cfg.speed_test)cfg.speed_test={};cfg.speed_test.enabled=document.getElementById('s-speed').checked;
    if(!cfg.dns_leak)cfg.dns_leak={};cfg.dns_leak.enabled=document.getElementById('s-dns').checked;
    if(!cfg.stealth_score)cfg.stealth_score={};cfg.stealth_score.enabled=document.getElementById('s-stealth').checked;
    if(!cfg.protocol_detection)cfg.protocol_detection={};cfg.protocol_detection.enabled=document.getElementById('s-proto').checked;
    if(!cfg.fraud_check)cfg.fraud_check={};cfg.fraud_check.enabled=document.getElementById('s-fraud').checked;
    if(!cfg.crawl4ai)cfg.crawl4ai={};cfg.crawl4ai.enabled=document.getElementById('s-crawl').checked;
    if(!cfg.filter)cfg.filter={};
    const allow=document.getElementById('s-allow').value.trim();
    cfg.filter.allowed_countries=allow?allow.split(',').map(s=>s.trim().toUpperCase()):[];
    const block=document.getElementById('s-block').value.trim();
    cfg.filter.blocked_countries=block?block.split(',').map(s=>s.trim().toUpperCase()):[];
    cfg.filter.exclude_datacenters=document.getElementById('s-exdc').checked;
    cfg.filter.min_anonymity=document.getElementById('s-minanon').value||null;
    if(!cfg.output)cfg.output={};
    cfg.output.fast_threshold_ms=parseInt(document.getElementById('s-fast').value)||500;
    cfg.fraud_check.top_n=parseInt(document.getElementById('s-topn').value)||100;
    await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});
    document.getElementById('s-msg').innerHTML='<span class="text-green-400">✓ Saved!</span>';
    setTimeout(()=>document.getElementById('s-msg').innerHTML='',3000);
  }catch(e){
    document.getElementById('s-msg').innerHTML=`<span class="text-red-400">✗ Error: ${e.message}</span>`;
  }
}
document.addEventListener('DOMContentLoaded',loadConfig);
</script>
{% endblock %}"""

# ────────────────────────────────────────────────────────────────
# PROXY DETAIL (standalone page)
# ────────────────────────────────────────────────────────────────

TEMPLATES["proxy_detail.html"] = r"""{% extends "base.html" %}
{% block title %}Proxy Detail{% endblock %}
{% block content %}
<div class="flex items-center gap-3 mb-6">
  <a href="/proxies" class="text-blue-400 hover:underline">← Back</a>
  <h1 class="text-2xl font-bold" id="pd-title">Loading...</h1>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
  <div class="card" id="pd-info"></div>
  <div class="card">
    <div class="card-title mb-3">Quick Actions</div>
    <div class="space-y-2" id="pd-actions"></div>
    <div class="card-title mt-5 mb-3">Similar Proxies (same ASN)</div>
    <div id="pd-similar" class="text-sm"></div>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script>
document.addEventListener('DOMContentLoaded',async()=>{
  const p=await fetchJSON('/api/proxy/{{ proxy_ip }}/{{ proxy_port }}');
  if(p.error){document.getElementById('pd-title').textContent='Not Found';return}
  document.getElementById('pd-title').textContent=`${p.ip}:${p.port}`;
  const fields=[
    ['Protocol',p.protocol],['Anonymity',p.anonymity],['Speed Tier',p.speed_tier],
    ['Latency',`${p.latency_ms||'—'}ms`],['Type',p.proxy_type],
    ['Country',`${p.country_code||'?'} ${p.country_name||''}`],
    ['City',p.city],['Region',p.region],['ASN',p.asn],['ISP',p.isp],
    ['Stealth Score',p.stealth_score],['Fraud Score',p.composite_score],
    ['DNS Leak',p.dns_leak],['Google Ban',p.google_ban],
    ['HTTPS Support',p.supports_https],['TCP Fingerprint',p.tcp_fingerprint],
    ['Detected Protocols',(p.detected_protocols||[]).join(', ')],
    ['Download Speed',p.download_speed_kbps?p.download_speed_kbps+' KB/s':'—'],
    ['Reliability',p.reliability],['Checks',`${p.success_count||0}/${p.check_count||0}`],
    ['Source',p.source],['First Seen',p.first_seen],['Last Checked',p.last_checked],
  ];
  document.getElementById('pd-info').innerHTML=`<div class="card-title mb-3">Details</div>
    <div class="grid grid-cols-2 gap-y-2 gap-x-4 text-sm">${fields.map(([k,v])=>
      `<div class="text-dark-200">${k}</div><div class="font-mono">${v??'—'}</div>`).join('')}</div>`;
  document.getElementById('pd-actions').innerHTML=`
    <button class="btn btn-primary w-full" onclick="copyText('${p.ip}:${p.port}')">📋 Copy ip:port</button>
    <button class="btn btn-ghost w-full" onclick="copyText('${p.protocol}://${p.ip}:${p.port}')">📋 Copy URL</button>
    <button class="btn btn-ghost w-full" onclick="copyText('curl -x ${p.protocol}://${p.ip}:${p.port} http://httpbin.org/ip')">📋 Copy curl</button>
    <button class="btn btn-ghost w-full" onclick="copyText('HTTP_PROXY=${p.protocol}://${p.ip}:${p.port}')">📋 Copy ENV</button>`;
  // Similar proxies
  if(p.asn){
    const all=await fetchJSON(`/api/proxies?per_page=10&sort=latency_ms&order=asc`);
    const sim=all.proxies.filter(x=>x.asn===p.asn&&x.ip!==p.ip).slice(0,5);
    if(sim.length){
      document.getElementById('pd-similar').innerHTML=sim.map(s=>
        `<div class="py-1"><a href="/proxy/${s.ip}/${s.port}" class="text-blue-400 hover:underline font-mono">${s.ip}:${s.port}</a>
          <span class="text-dark-200 ml-2">${s.latency_ms||'?'}ms · ${s.anonymity||'?'} · ${s.country_code||'?'}</span></div>`
      ).join('');
    }else{document.getElementById('pd-similar').innerHTML='<span class="text-dark-200">None found</span>'}
  }
});
</script>
{% endblock %}"""


# ==============================================================================
# SECTION 8: TEMPLATE WRITER & STARTUP
# ==============================================================================

def write_templates():
    """Write all template strings to disk, resolving extends."""
    TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
    base = TEMPLATES["base.html"]
    for name, content in TEMPLATES.items():
        if name == "base.html":
            path = TEMPLATE_DIR / name
            path.write_text(content, encoding="utf-8")
            continue
        # Simple template inheritance: replace extends + block tags
        html = content
        if '{% extends "base.html" %}' in html:
            html = html.replace('{% extends "base.html" %}', '')
            # Extract blocks
            blocks = {}
            for block_name in ["title", "content", "scripts"]:
                pattern = (
                    r'\{%\s*block\s+'
                    + block_name
                    + r'\s*%\}(.*?)\{%\s*endblock\s*%\}'
                )
                m = re.search(pattern, html, re.DOTALL)
                if m:
                    blocks[block_name] = m.group(1)
            # Build final HTML from base
            result = base
            for block_name, block_content in blocks.items():
                placeholder = (
                    r'\{%\s*block\s+'
                    + block_name
                    + r'\s*%\}.*?\{%\s*endblock\s*%\}'
                )
                result = re.sub(
                    placeholder, block_content, result, flags=re.DOTALL
                )
            html = result
        path = TEMPLATE_DIR / name
        path.write_text(html, encoding="utf-8")


def main():
    print("=" * 60)
    print("  🏆 UPO Dashboard v1.0")
    print("=" * 60)

    # Check for data
    has_data = (UPO_OUTPUT_DIR / "all.json").exists()
    if not has_data:
        print(f"\n⚠  No data found at {UPO_OUTPUT_DIR / 'all.json'}")
        print("   Run UPO first to generate proxy data.")
        print("   Dashboard will start with empty state.\n")
    else:
        try:
            with open(UPO_OUTPUT_DIR / "all.json", encoding="utf-8") as f:
                data = json.load(f)
            print(f"\n✓  Loaded {len(data)} proxies from all.json")
        except Exception as e:
            print(f"\n⚠  Error reading data: {e}")

    checked_count = len(list(UPO_CHECKED_DIR.glob("proxies_*.json"))) if UPO_CHECKED_DIR.exists() else 0
    print(f"✓  Found {checked_count} historical runs in checked/")

    # Write templates
    write_templates()
    print(f"✓  Templates written to {TEMPLATE_DIR}/")

    print(f"\n🌐 Starting dashboard at http://localhost:{DASHBOARD_PORT}")
    print(f"   Press Ctrl+C to stop.\n")

    uvicorn.run(
        app,
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        log_level="warning",
    )


if __name__ == "__main__":
    main()