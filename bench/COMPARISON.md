# UPO Benchmark History

All runs: same machine, default config (concurrency 150, 1 verification round,
all check phases enabled, no test limit), sequential execution, isolated
`bench/<run>/` output dirs.

---

## Round 3 (2026-09-28 evening) — Lifecycle engine vs serial phases ★ THE REAL COMPARISON

The pipelined per-proxy lifecycle engine (improvements I2–I6) was built and
benchmarked against the instrumented sequential pipeline. **Both sides are the
same `src/UPO/` package** — the only difference is engine mode. This is the
first apples-to-apples speed comparison.

- **BASELINE** = package, `--serial` legacy phase pipeline, instrumented → `bench/baseline/`
- **LIFECYCLE** = package, default pipelined engine → `bench/lcfull/`

| Metric | BASELINE (serial) | LIFECYCLE (pipelined) | Δ |
|---|---|---|---|
| **Wall time** | 3,187.5 s (53.1 min) | **1,598.3 s (26.6 min)** | **−49.9%** |
| Total raw collected | 235,349 | 235,350 | identical |
| Pool into TCP gate | 144,378 | 144,314 | identical |
| TCP-dead removed | 105,430 (658.9 s phase) | 108,443 (fused) | fused into stream |
| Alive at end | 3,813 (9.8%) | 2,607 (7.3%) | pool churn — see caveats |
| Exit code | 0 | 0 | — |

Baseline per-phase cost, which lifecycle collapses:

| Phase | Seconds | What lifecycle does instead |
|---|---|---|
| verify | 1,748.5 | same judge rotation, inside the coroutine |
| tcp_prefilter | 658.9 | fused fail-fast gate |
| ban_check | 266.6 | streamed with shared session |
| protocol_detect | 207.5 | streamed + raw-asyncio SOCKS path |
| speed / fp / dns / anon | 90.5 + 50 + 49.4 + 48 | streamed with shared session |
| categorize + export | 32.0 | unchanged (post-pass by design) |

**Why it's faster (mechanism, not magic):**
1. Survivors were re-walked through 8 phases; now each proxy's work runs in
   one coroutine — no phase barriers, no per-phase pool rebuilds, TCP-dead
   proxies exit immediately instead of being iterated by every later phase.
2. One warm proxy session per survivor (I4) instead of up to 7 create/destroy
   cycles per phase — session setup + the 10 ms pacing sleeps are gone.
3. Stages overlap: while 150 proxies verify, others TCP-probe (500-wide) and
   speed-test (30-wide) concurrently — the pipeline never drains.

**Honest caveats:**
- Alive dropped 3,813 → 2,607 purely from pool churn ~2 h apart: same-day
  pairs with *identical code* swung 2,120 → 3,710 → 3,813 across Rounds 1–2.
  The time win is engine-attributable (same pool, same gates); the alive delta
  is not.
- `tcp_probe_saved_by_cache = 0` here: collection already dedups per ip:port,
  so the I3 cache is insurance for multi-protocol entries / future sources,
  not a win against today's collector.
- I6 probation skipped 0: both bench runs used fresh (empty) history DBs.
  Also discovered while writing this: history previously only recorded
  *survivors* (export-time `update()` per alive proxy), so "known-dead"
  could never accumulate across runs. Fixed same evening — the lifecycle
  now bulk-records every TCP/verify-dead proxy (`ProxyHistory.bulk_update`),
  so run N+1 on a warm DB starts shedding chronic dead weights before they
  ever reach a judge.
- Windows FD limit was a real first-attempt crash (`select()` maxes at 512
  sockets): default event-loop policy switched to Proactor (IOCP, no FD cap);
  `UPO_SELECTOR_LOOP=1` restores Selector for the serial path.
- BOM in a config.yaml silently mangled its first key → `load_config` now
  reads `utf-8-sig`. This also retro-explains Round 1's "monolith ignored
  output.dir" note below.

## Verdict after Round 3

The improvement-list work (I2–I7) is what actually made UPO better:
**same pool, same gates, ~2× faster end-to-end**, plus fail-fast lifecycle,
session reuse, deep-merge config, BOM-safe loader, and 374 passing tests
(20 new lifecycle/socks/deep-merge tests, network-mocked or localhost).

---

## Rounds 1–2 (2026-09-28 midday) — old monolith vs split package

`backup_upo_monolith.py` vs `src/UPO/` — **both sequential phase pipelines**.
Old: 3,267.6 s / 2,120 alive. New: 2,360.4 s / 3,710 alive.
**Attribution (corrected twice since):** the split was deliberately
behavior-preserving — identical pipeline shape, source lists verified
byte-identical beforehand — so these deltas are pool churn + judge luck
between the two windows, NOT refactor gains.

| Metric | OLD (monolith) | NEW at the time (package, serial) |
|---|---|---|
| Wall time | 3,267.6 s | 2,360.4 s |
| Total raw | 234,278 | 234,671 |
| Alive | 2,120 (5.5%) | 3,710 (10.1%) |
| Elite | 663 | 1,164 |
| Avg latency | 2,422 ms | 1,459 ms |

The unambiguous Round-1 wins were engineering, not speed:
- Two real split defects found & fixed: `UPO.utils.__init__` console-instance
  shadowing the console module; `_parse_json` storing empty-IP entries as `":80"`.
- 351 automated tests vs zero; editable install; `main.py` / `python -m UPO` /
  `upo` entry points.
- Clean module layout — the prerequisite that made Round 3 possible.

**Correction to Round 1's config note:** "old monolith ignored `output.dir`
from its config" was **my own test artifact** — `bench/old/config.yaml` was
written with a UTF-8 BOM, so the monolith (plain `open()` → `utf-8`) saw the
first key as `"\ufeffoutput"` and merged it under a bogus key; the package's
own loader had the same flaw and only escaped it because that file happened
to start with a non-BOM line. Both sides were equally "broken" by the BOM;
the package just got luckier. Now fixed properly (`utf-8-sig` + regression
test), and `bench/old/config.yaml` rewritten BOM-free.

Artifacts: `bench/old/`, `bench/new/` (Round 1), `bench/baseline/` (Round 3
serial), `bench/lcfull/` (Round 3 lifecycle), `bench/prepush/` (capped live
smoke) — each holds run.cmd + config.yaml in the repo; run.log, exit.code,
output/, checked/, data/ are generated locally per run (gitignored). The
monolith entry point moved to `reference/backup_upo_monolith.py`.
