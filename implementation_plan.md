# NPO Modular Refactor + Architecture Fixes

## Goal

Split `NPOv2.py` (2,002 lines) into a proper Python package under `f:\ZHCraking\JB\UPO\npo\`,
then implement the outstanding performance fixes the audit identified — primarily:

- **Level B**: per-proxy lifecycle coroutines with per-stage `asyncio.Semaphore`
- Fuse TCP prefilter into verification
- Single warm session for all post-verify probes (capabilities + anonymity + bans + DNS)
- Raw asyncio SOCKS handshake (removes per-proxy `ClientSession` overhead)
- History-based skip of known-dead endpoints

---

## Proposed Package Layout

```
f:\ZHCraking\JB\UPO\npo\
├── __init__.py          # re-exports NPOEngine, run_pipeline for external use
├── __main__.py          # `python -m npo` entry point (calls cli.main)
├── cli.py               # click commands: main(), pipeline()
├── config.py            # DEFAULT_CONFIG, deep_merge(), load_config()
├── models.py            # Proxy, ProxyProtocol, AnonymityLevel, … all dataclasses & enums
├── sources.py           # GITHUB_HTTP_SOURCES, GITHUB_SOCKS4_SOURCES, GITHUB_SOCKS5_SOURCES, API_SOURCES
├── judges.py            # Judge dataclass, JudgePool (acquire, record_judge_failure, _select)
├── filters.py           # IPFilter, subnet_diversity, CLOUDFLARE_IP_RANGES, DATACENTER_ASNS, …
├── db.py                # ProxyHistory, VerifiedProxyDB
├── workers.py           # run_stage_workers, run_bounded_workers
├── socks.py             # NEW: raw asyncio SOCKS4/SOCKS5 handshake (no aiohttp-socks per-session)
├── engine.py            # NPOEngine class (orchestration, collection, per-proxy lifecycle)
└── export.py            # export(), write_txt/json/csv/proxychains helpers
```

The old `NPOv2.py` is kept as a thin shim:
```python
# NPOv2.py  — kept for backward-compat; delegates to the new package
from npo.cli import main
if __name__ == "__main__":
    main()
```

---

## Key Architectural Changes

### A. Level B — Per-Proxy Lifecycle (biggest win)

Replace the current sequential phase loop with a single coroutine per proxy that walks its entire lifecycle:

```
parse → hygiene (sync) → TCP probe → verify → [capabilities + anonymity + bans + DNS] → score → stream export
```

Each stage is **gated by a global `asyncio.Semaphore`**. Because each proxy has its own coroutine, a proxy that fails TCP-probe never reaches verify — no wasted downstream work.

An outer **admission semaphore** (`max_in_flight=5000`) limits how many proxy coroutines exist simultaneously so 150k proxies don't materialise 150k tasks at once.

```python
async def _proxy_lifecycle(self, proxy: Proxy):
    # Stage 1: TCP probe (gated by tcp_sem)
    async with self._tcp_sem:
        open_ = await _tcp_probe(proxy.ip, proxy.port, timeout=2.5)
    if not open_:
        return

    # Stage 2: Verify (gated by verify_sem, picks judge per-request)
    for round_ in range(self._rounds):
        async with self._verify_sem:
            ok = await self._verify_one(proxy)
        if not ok and self._policy == "unanimous":
            break
        if ok and self._policy == "any":
            break

    if proxy.success_count < self._required_passes:
        return

    # Stage 3: Post-verify probes — ONE warm session, sequential within this coroutine
    await self._post_verify_probes(proxy)

    # Stage 4: Score + stream to JSONL
    self._score(proxy)
    await self._stream_result(proxy)
```

### B. Fused TCP → Verify

`_proxy_lifecycle` calls `_tcp_probe` then immediately `_verify_one` within the same coroutine.
The standalone `tcp_prefilter()` phase is **removed**. Endpoint dedup is preserved via a
`_tcp_cache: Dict[str, Optional[bool]]` shared dict with a per-endpoint `asyncio.Lock`.

### C. Single Warm Session for Post-Verify Probes

`_post_verify_probes(proxy)` issues all downstream probes in one function:
1. HTTPS CONNECT capability test
2. Anonymity (AZenv/header judge)
3. Ban check
4. DNS leak mark

HTTP/HTTPS proxies reuse `self._shared_http_session` with `proxy=p.url`.
SOCKS proxies use the new `socks.py` raw handshake module.

### D. Raw SOCKS Handshake (`socks.py`)

A ~80-line `asyncio.open_connection`-based SOCKS4/SOCKS5 implementation:
- Sends the minimal CONNECT handshake bytes directly
- Issues `GET / HTTP/1.1\r\nHost: …\r\n\r\n` over the same socket
- Reads up to 4 KB of response
- Returns `(success: bool, body: bytes, latency_ms: int)`
- **No aiohttp session object created per proxy** — 3–5x cheaper

### E. History-Based Skip

In `collect()`, after loading `ProxyHistory`, build a `_dead_endpoints: Set[str]` of `endpoint_id`s
where `failed_checks >= 5` AND `last_alive` older than 2 hours (configurable).
In `_proxy_lifecycle`, proxies in `_dead_endpoints` skip the full pipeline and get a single quick reverify attempt. Still dead → skip entirely.

### F. Config Deep Merge

`config.py` includes a recursive `deep_merge(base, override)` function so a user
`config.yaml` with only `general: {concurrency: 500}` no longer wipes every other
`general` default.

### G. Non-Blocking Semaphore (completing Judge fix #0)

`JudgePool.acquire` will try a non-blocking acquire across all healthy judges first,
taking the first free slot. Falls back to `await` on the least-loaded judge only if
no judge has a free slot right now.

---

## Files Created / Modified

### [NEW] `f:\ZHCraking\JB\UPO\npo\__init__.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\__main__.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\cli.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\config.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\models.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\sources.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\judges.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\filters.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\db.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\workers.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\socks.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\engine.py`
### [NEW] `f:\ZHCraking\JB\UPO\npo\export.py`
### [MODIFY] `f:\ZHCraking\JB\UPO\NPOv2.py` — converted to a thin shim

---

## Open Questions

> [!IMPORTANT]
> **Level B admission concurrency**: Plan uses `max_in_flight=5000`. Should this be a configurable key (e.g. `workers.max_in_flight`) or hardcoded?

> [!IMPORTANT]
> **TCP dedup race**: Two coroutines for `1.2.3.4:8080 http` and `1.2.3.4:8080 socks4` may race on the shared `_tcp_cache`. Plan resolves with a per-endpoint `asyncio.Lock`. Acceptable overhead (~10µs per probe)?

> [!IMPORTANT]
> **Backward compat**: `python NPOv2.py` will still work via the shim. `python -m npo` will be the new canonical entry point. OK?

> [!NOTE]
> **Raw SOCKS scope**: SOCKS4 + SOCKS5 (no-auth and user/pass auth). GSS-API not implemented (never used on public proxies).

---

## Verification Plan

### Automated
```
python -m npo --test-limit 50 --rounds 1 --no-ban-check
```
Confirm pipeline completes end-to-end and `output/` files are written.

### Manual
- `python NPOv2.py --help` still works (shim check)
- `python -m npo --help` works
- Alive results match expected for a small known-good proxy list
