"""SECTION 5b: LIFECYCLE ENGINE — true pipelined verification (I2/I3/I4/I6).

Instead of walking the whole pool through 10 sequential phases (TCP-all →
verify-all → anonymity-all → …), ONE coroutine per proxy streams it through
its entire life:

    admission gate → I6 probation (known-dead?) → TCP probe (I3 cached per
    ip:port) → verify rounds → [alive only] anonymity → protocol → speed →
    fingerprint → DNS leak → ban → close shared session (I4)

Consequences:
* A proxy that fails TCP never pays for any downstream stage (74% of the
  pool dies here and used to still be iterated over in every phase).
* One warm ``aiohttp`` session per proxy instead of up to 7 create/close
  cycles per survivor (I4).
* Protocol variants collected from the same ``ip:port`` share a single TCP
  probe via ``_tcp_cache`` (I3).
* ``max_in_flight`` admission semaphore keeps 150k coroutines from ever
  materializing simultaneously; per-stage semaphores shape load per
  downstream judge/site.

Fraud scoring stays a post-pass (it needs the full alive set ranked first),
as does categorize/export — those read final state, not intermediate.

The legacy sequential path stays reachable via ``--serial`` /
``lifecycle.enabled: false`` and is what all pre-existing phase mixins
implement.
"""

from __future__ import annotations

import asyncio
from typing import Dict, Set

import aiohttp

from ..models import Proxy
from ..utils.console import console


async def _raw_tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


class LifecycleMixin:
    """Mixed into ``UPOEngine``; uses only public/engine attributes."""

    async def run_lifecycle(self, serial_fallback_reason: str = "") -> bool:
        """Stream every proxy through its full life. Returns True on run.

        False means lifecycle aborted (no judges) — caller should treat the
        pool as unverified, mirroring the sequential verify() behavior.
        """
        cfg = self.config.get("lifecycle", {})
        general = self.config["general"]
        rounds = general.get("verification_rounds", 1)
        lc_stats = {"skipped_known_dead": 0, "tcp_saved": 0}

        # Judges must be primed before any per-proxy verify (shared with
        # the sequential path).
        await self.test_judges()
        if not self.judges:
            console.print(
                "[bold red]FATAL: No judges reachable. "
                "Cannot verify proxies.[/bold red]"
            )
            return False

        # ── I6: probation set of chronically-dead endpoints ────────────
        dead_set: Set[str] = set()
        skip_cfg = cfg.get("skip_known_dead", {})
        if (
            skip_cfg.get("enabled", True)
            and getattr(self, "history", None) is not None
        ):
            try:
                dead_set = self.history.get_known_dead(
                    min_fails=skip_cfg.get("min_fails", 5),
                    stale_hours=skip_cfg.get("stale_hours", 2.0),
                )
            except Exception:
                dead_set = set()
            if dead_set:
                console.print(
                    f"[cyan]I6 probation list: {len(dead_set):,} "
                    f"known-dead endpoints get one 2s probe only[/cyan]"
                )

        # ── Gates ───────────────────────────────────────────────────────
        admission = asyncio.Semaphore(int(cfg.get("max_in_flight", 5000)))
        limits = cfg.get("stage_limits", {}) or {}
        sem_tcp = asyncio.Semaphore(500)  # parity with tcp_prefilter phase
        sems: Dict[str, asyncio.Semaphore] = {
            name: asyncio.Semaphore(
                int(limits.get(name) or general["concurrency"])
            )
            for name in
            ("verify", "anonymity", "speed", "fingerprint", "dns", "ban",
             "protocol")
        }

        # ── I3: shared TCP probe cache per ip:port ──────────────────────
        tcp_cache: Dict[str, bool] = {}
        tcp_locks: Dict[str, asyncio.Lock] = {}
        dedup_enabled = bool(cfg.get("tcp_dedup", True))

        async def tcp_alive(p: Proxy) -> bool:
            addr = p.address
            if not dedup_enabled:
                async with sem_tcp:
                    return await _raw_tcp_probe(p.ip, p.port, 3.0)
            lock = tcp_locks.get(addr)
            if lock is None:
                lock = tcp_locks[addr] = asyncio.Lock()
            async with lock:
                cached = tcp_cache.get(addr)
                if cached is not None:
                    lc_stats["tcp_saved"] += 1
                    return cached
                async with sem_tcp:
                    ok = await _raw_tcp_probe(p.ip, p.port, 3.0)
                tcp_cache[addr] = ok
                return ok

        # Counters shared across coroutines (event loop = no data races).
        n_tcp_removed = 0
        n_alive = 0
        n_done = 0
        total = len(self.proxies)
        # History learning: TCP/verify-dead proxies get one failure row each
        # (list.append is atomic on the single event loop — no lock needed).
        _dead_records: list = []

        probe_timeout = float(skip_cfg.get("probe_timeout", 2.0))

        async def lifecycle_one(addr: str, p: Proxy) -> None:
            nonlocal n_tcp_removed, n_alive, n_done
            async with admission:
                try:
                    # ── I6 gate: known-dead gets one short probe only ──
                    if p.address in dead_set:
                        ok = False
                        async with sem_tcp:
                            ok = await _raw_tcp_probe(p.ip, p.port, probe_timeout)
                        if not ok:
                            lc_stats["skipped_known_dead"] += 1
                            self.proxies.pop(addr, None)
                            _dead_records.append((p, 1))
                            return
                        tcp_cache[p.address] = True

                    # ── TCP gate (I3 cached) ───────────────────────────
                    if not await tcp_alive(p):
                        n_tcp_removed += 1
                        self.proxies.pop(addr, None)
                        _dead_records.append((p, 1))
                        return
                    p._tcp_ok = True

                    # ── I4: one warm session for every HTTP check ──────
                    reuse = bool(cfg.get("session_reuse", True))
                    own_session = None
                    own_kwargs: Dict[str, str] = {}
                    if reuse:
                        timeout = aiohttp.ClientTimeout(
                            total=general["timeout_total"],
                            connect=general["timeout_connect"],
                        )
                        own_session, own_kwargs = (
                            self._create_proxy_session(p, timeout)
                        )
                        if own_session is None:
                            reuse = False  # fall back to per-stage sessions

                    try:
                        # ── Verify (multi-round parity with verify()) ──
                        for round_num in range(1, rounds + 1):
                            if round_num > 1 and p.success_count == 0:
                                break  # never succeeded → later rounds skip
                            judge_url = self._get_judge(
                                (round_num - 1) % len(self.judges)
                            )
                            async with sems["verify"]:
                                if reuse:
                                    await self._check_one(
                                        p, judge_url,
                                        session=own_session,
                                        kwargs=own_kwargs,
                                    )
                                else:
                                    await self._check_one(p, judge_url)

                        if not p.alive:
                            _dead_records.append(
                                (p, max(p.check_count, 1))
                            )
                            return  # dead: no downstream work at all

                        # ── Anonymity (phase skips if no my_ip) ────────
                        if self.my_ip:
                            async with sems["anonymity"]:
                                await self._anon_check_one(
                                    p,
                                    session=own_session if reuse else None,
                                    kwargs=own_kwargs,
                                )

                        # ── Protocol detection (I5 raw SOCKS) ──────────
                        if self.config["protocol_detection"]["enabled"]:
                            judge_url = self._get_judge(2)
                            async with sems["protocol"]:
                                await self._detect_protocols_one(
                                    p, judge_url,
                                    session=own_session if reuse else None,
                                    kwargs=own_kwargs,
                                    raw_socks=bool(cfg.get("raw_socks", True)),
                                )

                        # ── Speed test ─────────────────────────────────
                        if self.config["speed_test"]["enabled"]:
                            async with sems["speed"]:
                                await self._speed_test_one(
                                    p, self.config["speed_test"]["test_url"],
                                    session=own_session if reuse else None,
                                    kwargs=own_kwargs,
                                )

                        # ── TCP fingerprint ────────────────────────────
                        if self.config["stealth_score"]["enabled"]:
                            async with sems["fingerprint"]:
                                await self._fingerprint_one(
                                    p,
                                    session=own_session if reuse else None,
                                    kwargs=own_kwargs,
                                )

                        # ── DNS leak ───────────────────────────────────
                        if (
                            self.config["dns_leak"]["enabled"]
                            and self.my_ip
                        ):
                            async with sems["dns"]:
                                await self._dns_leak_one(
                                    p,
                                    session=own_session if reuse else None,
                                    kwargs=own_kwargs,
                                )

                        # ── Ban check (google_ban semantics kept) ──────
                        if self.config["ban_check"]["enabled"]:
                            async with sems["ban"]:
                                for site in self.config["ban_check"]["sites"]:
                                    banned = await self._ban_check_one(
                                        p, site["url"],
                                        site.get("success_pattern", ""),
                                        session=(
                                            own_session if reuse else None
                                        ),
                                        kwargs=own_kwargs,
                                    )
                                    if site["name"] == "google":
                                        p.google_ban = banned

                        n_alive += 1
                    finally:
                        if reuse and own_session is not None:
                            try:
                                await own_session.close()
                            except Exception:
                                pass
                finally:
                    n_done += 1

        # Snapshot the pool — coroutines pop entries as they die.
        tasks = [
            asyncio.create_task(_guarded(lifecycle_one(addr, p)))
            for addr, p in list(self.proxies.items())
        ]

        with _LifecycleProgress(total) as update:
            done_set: Set[asyncio.Task] = set()
            while len(done_set) < len(tasks):
                finished, _ = await asyncio.wait(
                    set(tasks) - done_set, timeout=0.5
                )
                done_set |= finished
                update(
                    len(done_set), n_alive, n_tcp_removed,
                    lc_stats["skipped_known_dead"],
                    int(cfg.get("max_in_flight", 5000)) - admission._value,
                )

        # ── Reliability epilogue — exact parity with verify() ───────────
        for p in self.proxies.values():
            if p.check_count > 0:
                p.reliability = round(p.success_count / p.check_count, 2)
                p.alive = p.reliability > 0.5
            else:
                p.alive = False

        self.stats["tcp_prefilter_removed"] = self.stats.get(
            "tcp_prefilter_removed", 0
        ) + n_tcp_removed
        self.stats["verified_total"] = len(self.proxies)
        self.stats["verified_alive"] = sum(
            1 for p in self.proxies.values() if p.alive
        )
        self.stats["lifecycle"] = {
            "in_flight_cap": int(cfg.get("max_in_flight", 5000)),
            "tcp_probe_saved_by_cache": lc_stats["tcp_saved"],
            "skipped_known_dead": lc_stats["skipped_known_dead"],
        }
        # Feed I6: record every dead this run saw (TCP/verify-dead). Alive
        # proxies are still written by the exporter as before.
        if self.history and _dead_records:
            try:
                learned = self.history.bulk_update(_dead_records)
                self.stats["lifecycle"]["dead_learned"] = learned
            except Exception as e:
                console.print(f"[dim red]history bulk update: {e}[/dim red]")
        console.print(
            f"[green]✓[/] Lifecycle: {n_tcp_removed:,} TCP-dead removed │ "
            f"{self.stats['verified_alive']:,} alive │ "
            f"{lc_stats['tcp_saved']:,} probes saved by cache │ "
            f"{lc_stats['skipped_known_dead']:,} skipped via probation"
            + (f" │ {len(_dead_records):,} dead learned by history"
               if _dead_records else "")
        )
        return True


async def _guarded(coro) -> None:
    """One proxy's lifecycle must never crash the whole run."""
    try:
        await coro
    except Exception as e:
        console.print(f"[dim red]lifecycle worker error: {e}[/dim red]")


def _LifecycleProgress(total: int):
    """Transient rich progress with lifecycle counters."""
    import contextlib

    @contextlib.contextmanager
    def ctx():
        from rich.live import Live
        from rich.progress import (
            BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
            TextColumn, TimeElapsedColumn, TimeRemainingColumn,
        )
        prog = Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), MofNCompleteColumn(), TextColumn("│"),
            TextColumn("{task.fields[counters]}"),
            TimeElapsedColumn(), TimeRemainingColumn(), transient=True,
        )
        tid = prog.add_task(
            "[cyan]Lifecycle...", total=total, counters="",
        )

        def update(done, alive, tcp_dead, skipped, in_flight):
            prog.update(
                tid, completed=done,
                counters=(
                    f"⚡{alive} alive │ ✗{tcp_dead} tcp "
                    f"│ ⏭{skipped} skipped │ ≡{in_flight} in-flight"
                ),
            )

        with Live(prog, console=console, transient=True):
            yield update

    return ctx()


__all__ = ["LifecycleMixin"]
