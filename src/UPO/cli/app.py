from __future__ import annotations

import asyncio
import contextlib
import copy
import os
import time
from typing import Dict, Optional

import click
import yaml

from ..config import (
    API_SOURCES,
    DEFAULT_CONFIG,
    GITHUB_HTTP_SOURCES,
    GITHUB_SOCKS4_SOURCES,
    GITHUB_SOCKS5_SOURCES,
    load_config,
    total_source_count,
)
from ..core.engine import UPOEngine
from ..models import ProxyType
from ..utils.console import console
from ..collectors.crawl4ai_runner import run_crawl4ai
from ..export.stats import StatsMixin  # noqa: F401  (kept for API parity)
from ..api.server import start_api
from rich.panel import Panel


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option("--config", "config_path", default="config.yaml")
@click.option("--scrape-only", is_flag=True)
@click.option("--no-crawl4ai", is_flag=True)
@click.option("--no-ban-check", is_flag=True)
@click.option("--no-speed-test", is_flag=True)
@click.option("--no-dns-leak", is_flag=True)
@click.option("--no-stealth", is_flag=True)
@click.option("--no-protocol-detect", is_flag=True)
@click.option("--enable-fraud", is_flag=True)
@click.option("--concurrency", default=None, type=int)
@click.option("--timeout", default=None, type=int)
@click.option("--rounds", default=None, type=int)
@click.option("--country", default=None)
@click.option("--exclude-dc", is_flag=True)
@click.option("--api", is_flag=True)
@click.option("--api-port", default=8000, type=int)
@click.option("--test-limit", default=None, type=int)
@click.option(
    "--serial", "serial_phases", is_flag=True,
    help="Use the legacy sequential phase pipeline instead of the "
         "per-proxy lifecycle engine.",
)
def main(
    config_path, scrape_only, no_crawl4ai, no_ban_check,
    no_speed_test, no_dns_leak, no_stealth, no_protocol_detect,
    enable_fraud, concurrency, timeout, rounds, country,
    exclude_dc, api, api_port, test_limit, serial_phases,
):
    """🏆 UPO v5-fix2 — Ultimate Proxy Operator"""
    banner = """[bold blue]
 ██╗   ██╗██████╗  ██████╗    ██╗   ██╗███████╗
 ██║   ██║██╔══██╗██╔═══██╗   ██║   ██║██╔════╝
 ██║   ██║██████╔╝██║   ██║   ██║   ██║███████╗
 ██║   ██║██╔═══╝ ██║   ██║   ╚██╗ ██╔╝╚════██║
 ╚██████╔╝██║     ╚██████╔╝    ╚████╔╝ ███████║
  ╚═════╝ ╚═╝      ╚═════╝      ╚═══╝  ╚══════╝[/bold blue]
[dim]v5-fix2 — Scrape · Verify · Fingerprint · Score · Serve[/dim]"""
    console.print(Panel(banner, border_style="bold blue", expand=False))

    config = load_config(config_path)

    if concurrency:
        config["general"]["concurrency"] = concurrency
    if timeout:
        config["general"]["timeout_total"] = timeout
    if rounds:
        config["general"]["verification_rounds"] = rounds
    if no_crawl4ai:
        config["crawl4ai"]["enabled"] = False
    if no_ban_check:
        config["ban_check"]["enabled"] = False
    if no_speed_test:
        config["speed_test"]["enabled"] = False
    if no_dns_leak:
        config["dns_leak"]["enabled"] = False
    if no_stealth:
        config["stealth_score"]["enabled"] = False
    if no_protocol_detect:
        config["protocol_detection"]["enabled"] = False
    if enable_fraud:
        config["fraud_check"]["enabled"] = True
    if country:
        config["filter"]["allowed_countries"] = [
            c.strip().upper() for c in country.split(",")
        ]
    if exclude_dc:
        config["filter"]["exclude_datacenters"] = True
    if api:
        config["api"]["enabled"] = True
        config["api"]["port"] = api_port
    if serial_phases:
        config.setdefault("lifecycle", {})["enabled"] = False

    asyncio.run(pipeline(config, scrape_only, test_limit))


async def _run_serial_phases(engine: UPOEngine, config: Dict, _phase):
    """Legacy sequential pipeline (TCP-all → verify-all → … → ban-all).

    Kept verbatim as the ``--serial`` / ``lifecycle.enabled: false`` escape
    hatch — the behavior the pre-lifecycle test suite pins.
    """
    # ── TCP pre-filter (fast dead-proxy elimination) ──────────────
    console.print(
        "\n[bold cyan]═══ PHASE 3B: TCP PRE-FILTER ═══[/bold cyan]"
    )
    with _phase("tcp_prefilter"):
        await engine.tcp_prefilter()
    # Pipeline summary — show what's about to happen
    phases = ["Verification", "Anonymity"]
    if config["protocol_detection"]["enabled"]:
        phases.append("Protocol Detection")
    if config["speed_test"]["enabled"]:
        phases.append("Speed Test")
    if config["stealth_score"]["enabled"]:
        phases.append("TCP Fingerprint")
    if config["dns_leak"]["enabled"]:
        phases.append("DNS Leak")
    if config["fraud_check"]["enabled"]:
        phases.append(
            f"Fraud Waterfall (top {config['fraud_check'].get('top_n', 100)})"
        )
    if config["ban_check"]["enabled"]:
        phases.append(
            f"Ban Check ({len(config['ban_check']['sites'])} sites)"
        )
    phases.append("Categorize + Export")

    console.print(
        f"\n[bold cyan]Pipeline Plan "
        f"({len(engine.proxies):,} proxies):[/bold cyan]"
    )
    for i, phase in enumerate(phases, 1):
        console.print(f"  [dim]{i:2d}. {phase}[/dim]")
    console.print()
    # 6. Verify (FIX #2: smart threshold, FIX #3: judge rotation)
    console.print(
        f"\n[bold cyan]═══ PHASE 4: VERIFICATION "
        f"({config['general']['verification_rounds']} rounds) "
        f"═══[/bold cyan]"
    )
    with _phase("verify"):
        await engine.verify()

    # 7. Anonymity (FIX #3: different judge, FIX #5: 5s timeout)
    console.print(
        "\n[bold cyan]═══ PHASE 5: ANONYMITY ═══[/bold cyan]"
    )
    with _phase("anonymity"):
        await engine.check_anonymity()

    # 8. Protocol detection (FIX #3: different judge, FIX #4: dedup)
    if config["protocol_detection"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 6: PROTOCOL DETECTION "
            "═══[/bold cyan]"
        )
        with _phase("protocol_detect"):
            await engine.detect_protocols()

    # 9. Speed test
    if config["speed_test"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 7: SPEED TEST ═══[/bold cyan]"
        )
        with _phase("speed_test"):
            await engine.speed_test()

    # 10. TCP fingerprint (separate from stealth now)
    if config["stealth_score"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 8: TCP FINGERPRINT "
            "═══[/bold cyan]"
        )
        with _phase("fingerprint"):
            await engine.fingerprint()

    # 11. DNS leak
    if config["dns_leak"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 9: DNS LEAK ═══[/bold cyan]"
        )
        with _phase("dns_leak"):
            await engine.dns_leak_check()

    # 12. Fraud waterfall
    if config["fraud_check"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 10: FRAUD WATERFALL "
            "═══[/bold cyan]"
        )
        with _phase("fraud"):
            await engine.tiered_fraud_scoring()

    # 13. Ban check
    if config["ban_check"]["enabled"]:
        console.print(
            "\n[bold cyan]═══ PHASE 11: BAN CHECK ═══[/bold cyan]"
        )
        with _phase("ban_check"):
            await engine.check_bans()


async def pipeline(
    config: Dict, scrape_only: bool, test_limit: Optional[int]
):
    start = time.monotonic()
    timings: Dict[str, float] = {}

    @contextlib.contextmanager
    def _phase(name: str):
        t0 = time.monotonic()
        yield
        dt = time.monotonic() - t0
        timings[name] = round(dt, 1)
        console.print(f"  [dim]⏱ {name}: {dt:.1f}s[/dim]")

    # 1. Crawl4AI
    if config["crawl4ai"]["enabled"] and not scrape_only:
        with _phase("crawl4ai"):
            await run_crawl4ai(config)

    # 2. Init
    engine = UPOEngine(config)
    with _phase("initialize"):
        await engine.initialize()

    # 3. Collect
    console.print("\n[bold cyan]═══ PHASE 1: COLLECTION ═══[/bold cyan]")
    with _phase("collect"):
        await engine.collect()
    tsrc = (
        len(GITHUB_HTTP_SOURCES) + len(GITHUB_SOCKS4_SOURCES)
        + len(GITHUB_SOCKS5_SOURCES) + len(API_SOURCES)
    )
    console.print(
        f"[green]✓[/] {len(engine.proxies):,} unique proxies "
        f"from {tsrc} sources."
    )

    # 4. Pre-enrich
    console.print("\n[bold cyan]═══ PHASE 2: PRE-ENRICH ═══[/bold cyan]")
    with _phase("pre_enrich"):
        engine.pre_enrich()
    mobile = sum(
        1 for p in engine.proxies.values()
        if p.proxy_type == ProxyType.MOBILE
    )
    res = sum(
        1 for p in engine.proxies.values()
        if p.proxy_type == ProxyType.RESIDENTIAL
    )
    console.print(
        f"[green]✓[/] Enriched. Mobile: {mobile}, Residential: {res}"
    )

    # 5. Filter
    console.print("\n[bold cyan]═══ PHASE 3: FILTER ═══[/bold cyan]")
    with _phase("filter_garbage"):
        engine.filter_garbage()

    if test_limit:
        engine.proxies = dict(
            list(engine.proxies.items())[:test_limit]
        )
        console.print(
            f"[yellow]⚠ Test limit: {test_limit} proxies[/yellow]"
        )

    if not scrape_only:
        lifecycle_cfg = config.get("lifecycle", {})
        if lifecycle_cfg.get("enabled", True):
            console.print(
                "\n[bold cyan]═══ LIFECYCLE ENGINE (pipelined) ═══[/bold cyan]"
            )
            console.print(
                f"  [dim]max_in_flight="
                f"{lifecycle_cfg.get('max_in_flight', 5000)} │ "
                f"session_reuse={lifecycle_cfg.get('session_reuse', True)} │ "
                f"tcp_dedup={lifecycle_cfg.get('tcp_dedup', True)} │ "
                f"skip_known_dead="
                f"{lifecycle_cfg.get('skip_known_dead', {}).get('enabled', True)}"
                f"[/dim]"
            )
            with _phase("lifecycle"):
                await engine.run_lifecycle()
            if engine.stats.get("verified_total") and \
                    config["fraud_check"]["enabled"]:
                console.print(
                    "\n[bold cyan]═══ PHASE 10: FRAUD WATERFALL "
                    "═══[/bold cyan]"
                )
                with _phase("fraud"):
                    await engine.tiered_fraud_scoring()
        else:
            await _run_serial_phases(engine, config, _phase)

        # Categorize (FIX #1: stealth calculated HERE, after fraud)
        console.print(
            "\n[bold cyan]═══ PHASE 12: CATEGORIZE ═══[/bold cyan]"
        )
        with _phase("categorize"):
            engine.enrich_and_categorize()
        alive_cnt = sum(
            1 for p in engine.proxies.values() if p.alive
        )
        console.print(
            f"[green]✓[/] Final alive: {alive_cnt:,}"
        )
    else:
        console.print(
            "\n[yellow]⏭ --scrape-only: Skipping verification.[/yellow]"
        )

    # 15. Export
    console.print("\n[bold cyan]═══ EXPORT ═══[/bold cyan]")
    with _phase("export"):
        engine.export()

    # 16. Stats
    stats = engine.print_stats()

    elapsed = time.monotonic() - start
    engine.stats["phase_timings"] = timings
    console.print("\n[bold cyan]═══ PHASE TIMINGS ═══[/bold cyan]")
    for name, dt in sorted(timings.items(), key=lambda x: -x[1]):
        console.print(f"  {name:<18} {dt:>8.1f}s")
    console.print(f"\n[bold]⏱ Total: {elapsed:.1f}s[/bold]")

    # 17. API
    if config["api"]["enabled"]:
        start_api(engine, config["api"]["host"], config["api"]["port"])
        console.print(
            "\n[bold]API running. Press Ctrl+C to stop.[/bold]"
        )
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]Shutting down...[/yellow]")
