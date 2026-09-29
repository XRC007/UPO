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
py -3.13 -m pytest -q                   # 384 tests, fully offline
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
- `main.py` / `dashboard.py` — entry points (pipeline run; web analytics UI on
  :8050)
- `improvement.md` — status-tracked improvement plan (I1–I10, all shipped) ·
  `bench/COMPARISON.md` — benchmark history (serial vs lifecycle); `bench/*/`
  hold reproducible run scripts/configs — logs, outputs and DBs are generated
  locally and gitignored
- `reference/backup_upo_monolith.py` — the pre-split monolith, kept because
  `test_no_method_lost_vs_monolith` guards the split stayed faithful
- `config.yaml` is machine-local (not tracked); the app runs on built-in
  defaults when it is absent
- History: the original project brief and npo-era scratch files were dropped in
  the repo clean-up; `git log` still has them
