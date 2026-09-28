# UPO — Ultimate Proxy Operator

Scrapes ~235k free proxies from 180+ sources, verifies, categorizes, scores
and exports them. Python 3.13, single package: `src/UPO/`.

## Setup (one command)

```bash
# interpreter: Python 3.13.x (project deps live in 3.13.5; plain `python`
# may be 3.14 without deps — use the pinned interpreter)
py -3.13 -m pip install -r requirements.txt
py -3.13 -m pip install -e .          # installs editable + `upo` command
```

## Run

```bash
py -3.13 main.py                        # full pipeline (lifecycle engine)
py -3.13 main.py --test-limit 100       # quick capped run
py -3.13 main.py --serial               # legacy sequential phase pipeline
py -3.13 main.py --scrape-only          # collect only, no verification
python -m UPO --help                    # same CLI after editable install
upo --help                              # console-script entry point
```

API keys for the fraud-waterfall tiers go in `.env`
(`API_IPINFO`, `API_IPHUB`, `API_IPQS`, `API_GETIPINTEL_EMAIL`).

## Test

```bash
py -3.13 -m pytest -q                   # 381 tests, fully offline
```

Suite map: `test_upo.py` (engine legacy), `test_upo_coverage.py` (split
faithfulness, CLI, API, exports), `test_lifecycle.py` (pipelined engine I2–I7,
raw SOCKS against a mock server), `tests/` (recovered suites; see
`tests/README.md`).

## Windows note

The lifecycle engine needs >512 concurrent sockets, so the default event loop
policy is Proactor (IOCP). Set `UPO_SELECTOR_LOOP=1` to restore the legacy
Selector policy (then use `--serial`).

## Layout & docs

- `src/UPO/` — the package (config, models, collectors, checks, core/lifecycle,
  db, export, api, cli, utils)
- `info.md` — original project brief · `implementation_plan.md` /
  `improvement.md` — status-tracked plan (I0–I10) · `bench/COMPARISON.md` —
  benchmark history (serial vs lifecycle)
- `backup_upo_monolith.py` / `UPObyAstra.py` — historical single-file versions
- `dashboard.py` — web analytics UI (`py -3.13 dashboard.py` → :8050)
