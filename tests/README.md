# tests/ — recovered & new test suites

This directory implements improvement **I8** (test-suite consolidation).

## Layout

- `test_privacy_redaction.py` — **ported (I8 first priority).** Recovered from
  the spec of the vanished `tests/test_credentials_privacy.py` (whose test
  names survive in `.pytest_cache/v/cache/nodeids`). Re-expressed against the
  current `src/UPO` package: a planted credential secret
  (`user:pass@ip:port`) must never reach the Proxy model, any export
  (JSON/CSV/TXT/checked), or any DB row (history/verified). 7 tests, all
  offline.
- `archive/` — **dead specs, kept for reference, excluded from collection**
  (`norecursedirs = ["archive", ...]` in `pyproject.toml`):
  - `test_npo_package.py` (528 lines) — API spec of the `npo/` package that
    was never built. The refactor instead shipped as `src/UPO/`; its TEST 1
    (deep merge) is already honored by `UPO.config.deep_merge` +
    `TestDeepMerge` in `test_lifecycle.py`.
  - `test_step2.py` — early lifecycle/dedup sketch; its intended TCP-dedup
    semantics now live in `UPO.core.lifecycle` and are pinned by
    `TestLifecycleEngine::test_tcp_cache_dedups_variants`.
  - `fix_npo.py` — one-off patch scratch for the deleted `NPOv2.py`.

## Why not every vanished test was ported

The old `tests/` suite (68 tests across 13 files, gone since before commit
`4b469f3`) targeted features the code never grew:

| Old file | Feature | Status vs current code |
|---|---|---|
| test_credentials_privacy.py | secret redaction | **PORTED here** ✅ |
| test_anonymity.py | azenv header format, "unknown" tier, healthy-judge gating | code only classifies elite/anonymous/transparent via httpbin; no azenv parser, no "unknown" — cannot port as-is |
| test_verification.py | per-proxy verify policies (any/majority/unanimous) | current policy is strict-majority (I0) inside verify()/lifecycle — partially pinned in test_upo.py |
| test_dns_and_ban.py | tri-state dns/ban "no false safe on timeout" | **real gap** — current code leaves None on failure (which is tri-state-ish); export-side handling differs |
| test_judges.py | 429 cooldown/backoff pool | never implemented — feature request, not test debt |
| test_identity.py | ipv6 canonical identity | IPv6 never supported by PROXY_REGEX — feature gap |
| test_parsing.py (ipv6 bits) | bracketed ipv6 parsing | same |
| test_history_db.py | WAL mode + batch upsert | **now partially true**: `ProxyHistory.bulk_update` batches; WAL still off |
| test_session.py | engine-held shared warm session | **now true via lifecycle I4** — pinned in `test_lifecycle.py` |
| test_concurrency.py / test_worker_resilience.py | bounded worker pool + worker crash isolation | lifecycle admission sem + `_guarded()` cover the intent; pinned in `test_lifecycle.py` |
| test_scoring.py, test_filter.py (ipv6), test_integration.py, test_crawl4ai.py | assorted | covered in spirit by test_upo_coverage.py |

**Genuine follow-up features surfaced by the dead suite** (filed here so they
are not lost): judge 429-cooldown pool, IPv6 support, "unknown" anonymity
tier, WAL-mode history. These are product decisions, not test debt.
