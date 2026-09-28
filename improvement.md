# UPO / NPO — Planned Improvements

Tracking document for the UPO proxy-operator codebase.
Created 2026-09-13 from the state of the working tree at commit `4b469f3` (+ UTF-8 stdout patch),
cross-referenced with `implementation_plan.md`, `info.md`, and the actual test-suite run.

---

## Status snapshot (as of this writing)

| Item | State |
|---|---|
| Working engine | `UPO.py` v3 monolith (2,884 lines) — compiles clean, all deps on Python 3.13.5 |
| Working test suite | `test_upo.py` — 200 tests, fully mocked, no network/DB needed |
| Suite result | 199 passed, 1 failed (`test_reliability_2round_fail`) → **fixed in this run**, see I0 |
| Planned `npo/` package | **Not built.** `npo/` was empty; `test_npo_package.py` / `test_step2.py` at root import modules that do not exist |
| Deleted `tests/` suite | 68-test pytest suite (`tests/test_anonymity.py`, …) existed once (`.pytest_cache/v/cache/nodeids` still lists them) but is gone from disk and from git history |
| Test infra | `npo/test/` directory now created (see README inside) — placeholder for the future suite |
| Python env | PATH `python` = 3.14.7 **without** project deps; deps live in Python 3.13.5 only. No `requirements.txt`, no pinned venv |

---

## Improvement entries

### I0 — Reliability threshold: strict majority (FIX #2) — ✅ fixed in this run
- **Where:** `UPO.py` `verify()` epilogue (was line 1337)
- **Was:** `p.alive = p.reliability >= 0.5` — a proxy passing 1 of 2 rounds (reliability 0.50) counted as alive.
- **Now:** `p.alive = p.reliability > 0.5` (strict majority). 1/2 = 0.50 → dead; 2/3 = 0.67 → alive; 1/1 → alive.
- **Evidence:** `test_upo.py::TestVerification::test_reliability_2round_fail` ("FIX #2: 0.5 reliability fails in 2-round mode") was added in the newest commit `4b469f3` but the matching code change never landed — the suite failed 199/200. Only consumer of the threshold is that single line; `dasboard.py` merely displays the value.
- **Follow-up idea:** make the threshold configurable (`general.reliability_threshold`) if flaky-but-half-alive proxies ever become interesting.

### I1 — Build the `npo/` modular package (the refactor that never landed)
- **Where:** whole codebase; layout fully specified in `implementation_plan.md` (13 modules: `config`, `models`, `sources`, `judges`, `filters`, `db`, `workers`, `socks`, `engine`, `export`, `cli`, `__main__`, `__init__`).
- **Why:** 2,884-line monolith is at the limit of maintainability; the plan is already written and reviewed.
- **Blocked-by:** root `test_npo_package.py` (528 lines, 13 test sections) already encodes the expected API for this package — build the package to satisfy it, then move it into `npo/test/`.
- **Acceptance:** `python -m npo --help` works; `test_npo_package.py` passes; `UPO.py`/`NPOv2.py` remain as thin shims for backward compat.

### I2 — Level B: per-proxy lifecycle coroutines (biggest performance win)
- **Where:** new `npo/engine.py` (replaces `UPOEngine.verify()` phase loop, lines ~1276–1344)
- **What:** one coroutine per proxy walking parse → hygiene → TCP probe → verify → post-verify probes → score → stream-export, gated by per-stage `asyncio.Semaphore`; outer admission semaphore (`max_in_flight=5000`) so 150k proxies don't materialize as 150k tasks. A proxy failing TCP never reaches verify — no wasted downstream work.
- **Open decision (from plan):** `max_in_flight` configurable key vs hardcoded.

### I3 — Fuse TCP prefilter into verification + per-endpoint dedup
- **Where:** `UPO.py` `tcp_prefilter()` standalone phase
- **What:** merge TCP probe into the per-proxy lifecycle; share results across protocol variants of the same `ip:port` via a `_tcp_cache: Dict[str, Optional[bool]]` with per-endpoint `asyncio.Lock` (HTTP/SOCKS4/SOCKS5 variants of one endpoint = 1 probe, not 3 — `test_step2.py` TEST 3 demonstrates the intended dedup semantics).
- **Open decision (from plan):** per-endpoint lock overhead ~10µs/probe — acceptable?

### I4 — Single warm session for all post-verify probes
- **Where:** `UPO.py` capability/anonymity/ban/DNS stages (currently each opens its own session)
- **What:** one warm `ClientSession` (or raw socket) per proxy for HTTPS-CONNECT capability, anonymity judge, ban check, DNS-leak mark — sequentially inside the lifecycle coroutine. Cuts 3–4 TLS handshakes per surviving proxy.

### I5 — Raw asyncio SOCKS handshake (`npo/socks.py`)
- **Where:** new module; replaces `aiohttp_socks` per-proxy `ClientSession`
- **What:** ~80-line `asyncio.open_connection` SOCKS4/SOCKS5 CONNECT (no-auth + user/pass; GSS-API out of scope — never seen on public proxies). 3–5× cheaper per proxy.
- **Acceptance:** `socks4_connect`, `socks5_connect`, `socks_http_get` exported and unit-tested (signatures already asserted by `test_npo_package.py`).

### I6 — History-based skip of known-dead endpoints
- **Where:** `collect()` + lifecycle; uses existing `ProxyHistory` (`data/proxy_history.db`)
- **What:** build `_dead_endpoints: Set[str]` where `failed_checks >= 5` AND `last_alive` older than 2h (configurable). Dead-listed proxies get one quick reverify; still dead → skip entirely. Saves re-probing the ~90% of feeds that are chronically dead.

### I7 — Config deep merge (verified bug)
- **Where:** `UPO.py` main() config loading, line ~2662: `config[k].update(v)` — **shallow** merge confirmed in current code.
- **Bug:** a user `config.yaml` containing only `general: {concurrency: 500}` wipes every other `general` default (timeout, rounds, etc.) because `dict.update` replaces the whole nested dict.
- **Fix:** recursive `deep_merge(base, override)` in future `npo/config.py`; spec + test already in `test_npo_package.py` TEST 1.

### I8 — Test suite consolidation & restore
- **Where:** repo root + `npo/test/`
- **What:**
  - `test_upo.py` was deleted from the worktree (still in git HEAD) — restored in this run; 200/200 green after I0.
  - The vanished `tests/` suite (68 tests: anonymity, credentials-privacy redaction, DNS/ban tristate, ipv6 parsing/identity, judge cooldown, scoring, session double-close — per `.pytest_cache` nodeids) tested package features that never shipped; re-create those cases inside `npo/test/` as the package modules land. The credentials-privacy redaction tests are the most valuable to port first.
  - Move root `test_npo_package.py`/`test_step2.py` into `npo/test/` once I1 lands (they are dead weight at root until then).
  - `npo/test/README.md` documents the target layout.

### I9 — Environment reproducibility
- **Where:** repo root
- **What:** no `requirements.txt` exists (info.md §"FILE STRUCTURE" specifies one). PATH python (3.14) lacks all deps; only the 3.13.5 install has them. Pin deps (`aiohttp`, `aiohttp_socks`, `aiodns` if used, `click`, `geoip2`, `rich`, `pyyaml`, `pytest`, `pytest-asyncio`) + document the interpreter, so the suite runs with one command instead of a hardcoded absolute python path.
- **Also:** `dasboard.py` filename typo → `dashboard.py` (its own docstring already says `dashboard.py`).

### I10 — Repo hygiene
- **Where:** repo root
- **What:** tracked build artifacts/scratch outputs (`pytest_out.txt`, `summary*.txt`, `zaeem_summary.txt`, `.coverage`, `check_dupes.py`, deleted GeoLite2 tarballs in `data/`) are deleted in the worktree — commit the deletions; add `.gitignore` entries for `output/`, `checked/`, `__pycache__/`, `.pytest_cache/`, `.coverage` so generated proxy datasets stop flooding `git status` (currently 31 modified / 21 untracked).

---

## Verification commands (current, pre-refactor)

```bash
# Full suite — Python 3.13.5 (deps installed there), from F:/ZHCraking/JB/UPO
"C:/Users/Admin/AppData/Local/Programs/Python/Python313/python.exe" -m pytest test_upo.py -q

# Compile check
"C:/Users/Admin/AppData/Local/Programs/Python/Python313/python.exe" -m py_compile UPO.py
```

Result after I0: **200 passed** in ~17s.

---

## STATUS UPDATE 2026-09-28 — I1–I7 landed as `src/UPO/` (not `npo/`)

The refactor happened as the **`UPO` package under `src/`** (drop-in public API,
`pip install -e .`, entry points `main.py` / `python -m UPO` / `upo`) rather
than `npo/` — same layout goals, different name. Current verification:

```bash
"C:/Users/Admin/AppData/Local/Programs/Python/Python313/python.exe" -m pytest -q
# → 374 passed (test_upo.py 200 · test_upo_coverage.py 154 · test_lifecycle.py 20)
```

- **I1 ✅** split done (33 modules) + 2 split defects fixed; `UPO.py` retired,
  `backup_upo_monolith.py` kept as reference. `--serial` retains phase pipeline.
- **I2 ✅** `UPO/core/lifecycle.py`: per-proxy coroutine, admission sem
  (`lifecycle.max_in_flight`=5000), per-stage sems (`lifecycle.stage_limits`),
  fail-fast gates, live progress. Fraud stays a ranked post-pass (by design).
- **I3 ✅** TCP probe fused as the lifecycle's first gate + per-endpoint
  `_tcp_cache`/lock (`lifecycle.tcp_dedup`).
- **I4 ✅** one warm session per survivor reused by verify/anon/protocol/
  speed/fingerprint/dns/ban (each `_one` gained optional `session/kwargs`,
  legacy default behavior byte-preserved).
- **I5 ✅ (module)** `UPO/socks.py`: socks4/4a + socks5 (auth, ATYP 1/3) +
  `socks_http_get` (CONNECT+start_tls for https). Wired into protocol
  detection via `lifecycle.raw_socks`. Full aiohttp_socks replacement in
  verify() remains a stretch goal.
- **I6 ✅** `ProxyHistory.get_known_dead(min_fails, stale_hours)` + lifecycle
  probation gate (`lifecycle.skip_known_dead`). Pays off on warm history DBs.
- **I7 ✅** `UPO.config.deep_merge` + `load_config` used by `main()`; partial
  YAML sections keep sibling defaults. Bonus: loader reads `utf-8-sig` — the
  BOM that mangled `bench/old/config.yaml`'s first key retro-explains
  Round-1's "monolith ignored output.dir" claim (see `bench/COMPARISON.md`).
- **Windows FD cap:** default loop policy is now Proactor (IOCP) — the
  select()-based Selector loop (512-socket hard cap) can't host concurrent
  lifecycle stages. `UPO_SELECTOR_LOOP=1` opts back in for the serial path.

**Benchmark (Round 3, same pool ~235k, identical settings):**
serial 3,187.5 s vs lifecycle **1,598.3 s — −49.9% wall time**. Full table,
mechanism and caveats in `bench/COMPARISON.md`.

Still open: **I8** (partial — root tests consolidated into 3 files, but the
vanished 68-test `tests/` suite cases and `npo/test/` layout remain),
**I9** (no `requirements.txt` yet; dasboard.py still misspelled),
**I10** (git hygiene).
