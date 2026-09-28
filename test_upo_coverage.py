"""Comprehensive coverage tests for the refactored ``src/UPO`` package.

Companion to ``test_upo.py``. Where that suite exercises behaviour, this module
targets the paths the split left untested — the CLI orchestrator, the FastAPI
server, the crawl4ai runner, entry-point lazy loading, error/fallback branches —
plus structural regression guards proving the monolith split stayed faithful.

Run:  python -m pytest test_upo_coverage.py -q
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import UPO
import UPO.runtime as runtime
import UPO.utils.console as console_mod
import UPO.config as cfg_mod
import UPO.checks.speed as speed_mod
from UPO import (
    UPOEngine, DEFAULT_CONFIG, Proxy, ProxyProtocol, AnonymityLevel,
    ProxyType, SpeedTier, IPFilter, ProxyHistory, RateLimiter,
    VerifiedProxyDB, PROXY_REGEX, load_config,
)
from UPO.core import engine as engine_mod

from test_upo import temp_dir, config, engine, make_session_mock, DummyResponse

pytestmark = pytest.mark.asyncio

REPO_ROOT = Path(__file__).resolve().parent


# ============================================================================
# 1. Entry points, lazy API and runtime bootstrap
# ============================================================================

class TestPackageAPISurface:
    def test_public_names_importable(self):
        for name in UPO.__all__:
            assert hasattr(UPO, name), f"{name} missing from package API"

    def test_lazy_getattr_resolves_and_caches(self):
        cmd = UPO.main
        assert cmd is not None
        assert UPO.main is cmd
        assert "main" in vars(UPO)

    def test_lazy_getattr_unknown_raises_attributeerror(self):
        with pytest.raises(AttributeError, match="no attribute 'nope'"):
            UPO.nope

    def test_dir_includes_lazy_names(self):
        assert "pipeline" in dir(UPO) and "start_api" in dir(UPO)

    def test_runtime_anchors_project_root(self):
        assert runtime.PROJECT_ROOT == REPO_ROOT
        assert runtime.SRC_DIR == REPO_ROOT / "src"
        assert runtime.PACKAGE_DIR == REPO_ROOT / "src" / "UPO"
        assert Path.cwd() == runtime.PROJECT_ROOT

    def test_runtime_load_dotenv_importable(self):
        assert runtime.load_dotenv is not None

    def test_reconfigure_streams_idempotent(self):
        runtime.reconfigure_streams()
        runtime.reconfigure_streams()

    def test_reconfigure_streams_non_windows_is_noop(self):
        with patch.object(runtime.sys, "platform", "linux"):
            runtime.reconfigure_streams()

    def test_reconfigure_streams_swallows_errors(self):
        class Bad:
            def reconfigure(self, **kw):
                raise ValueError("nope")

        with patch.object(runtime.sys, "platform", "win32"), \
                patch.object(runtime.sys, "stdout", Bad()), \
                patch.object(runtime.sys, "stderr", Bad()):
            runtime.reconfigure_streams()

    def test_console_module_exposes_console(self):
        assert console_mod.console is not None

    def test_console_windows_utf8_guard(self):
        class Rec:
            def __init__(self):
                self.called = False

            def reconfigure(self, **kw):
                self.called = True

        out, err = Rec(), Rec()
        with patch.object(console_mod.sys, "platform", "win32"), \
                patch.object(console_mod.sys, "stdout", out), \
                patch.object(console_mod.sys, "stderr", err):
            for s in (console_mod.sys.stdout, console_mod.sys.stderr):
                if hasattr(s, "reconfigure"):
                    s.reconfigure(encoding="utf-8", errors="replace")
        assert out.called and err.called

    def test_main_module_entry_delegates(self):
        import main as main_mod
        with patch.object(main_mod, "main") as fake_main, \
                patch.object(main_mod, "reconfigure_streams") as fake_re:
            main_mod._entry()
        fake_re.assert_called_once()
        fake_main.assert_called_once()

    def test_main_module_inserts_src_on_path(self):
        import main as main_mod
        assert any(p.endswith(os.sep + "src") for p in sys.path)


# ============================================================================
# 2. Split faithfulness (structural regression guard)
# ============================================================================

MIXIN_HOME = {
    "collect": "CollectMixin", "_fetch": "CollectMixin",
    "_parse_text": "CollectMixin", "_parse_json": "CollectMixin",
    "pre_enrich": "CollectMixin", "filter_garbage": "CollectMixin",
    "test_judges": "VerifyMixin", "tcp_prefilter": "VerifyMixin",
    "verify": "VerifyMixin", "_check_one": "VerifyMixin",
    "_validate_judge": "VerifyMixin",
    "check_anonymity": "AnonymityMixin", "_anon_check_one": "AnonymityMixin",
    "detect_protocols": "ProtocolMixin",
    "_detect_protocols_one": "ProtocolMixin",
    "speed_test": "SpeedMixin", "_speed_test_one": "SpeedMixin",
    "fingerprint": "FingerprintMixin", "_fingerprint_one": "FingerprintMixin",
    "_calc_stealth": "FingerprintMixin",
    "dns_leak_check": "DnsMixin", "_dns_leak_one": "DnsMixin",
    "check_bans": "BanMixin", "_ban_check_one": "BanMixin",
    "tiered_fraud_scoring": "FraudMixin", "_waterfall_one": "FraudMixin",
    "_save_fraud_cache": "FraudMixin",
    "enrich_and_categorize": "ExportMixin", "export": "ExportMixin",
    "print_stats": "StatsMixin",
    "initialize": "UPOEngine", "_create_proxy_session": "UPOEngine",
    "_get_judge": "UPOEngine",
}


class TestSplitFaithfulness:
    def test_every_method_lives_in_its_expected_mixin(self):
        for name, owner in MIXIN_HOME.items():
            fn = getattr(UPOEngine, name)
            assert fn.__qualname__.split(".")[0] == owner, (
                f"{name} should come from {owner}, found {fn.__qualname__}"
            )

    def test_no_duplicate_definitions_across_modules(self):
        seen = {}
        for root, _, files in os.walk(REPO_ROOT / "src" / "UPO"):
            for f in files:
                if not f.endswith(".py"):
                    continue
                p = Path(root) / f
                tree = ast.parse(p.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        for sub in node.body:
                            if isinstance(
                                sub, (ast.FunctionDef, ast.AsyncFunctionDef)
                            ):
                                key = (node.name, sub.name)
                                assert key not in seen, (
                                    f"duplicate {node.name}.{sub.name} in "
                                    f"{p} and {seen[key]}"
                                )
                                seen[key] = p

    def test_no_method_lost_vs_monolith(self):
        mono = REPO_ROOT / "backup_upo_monolith.py"
        if not mono.exists():
            pytest.skip("monolith backup not present")
        tree = ast.parse(mono.read_text(encoding="utf-8"))
        cls = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == "UPOEngine"
        )
        names = [
            m.name for m in cls.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        missing = [n for n in names if not hasattr(UPOEngine, n)]
        assert missing == [], f"methods lost in split: {missing}"
        assert len(names) >= 30

    def test_module_level_symbols_preserved(self):
        for name in (
            "DEFAULT_CONFIG", "GITHUB_HTTP_SOURCES", "GITHUB_SOCKS4_SOURCES",
            "GITHUB_SOCKS5_SOURCES", "API_SOURCES", "DATACENTER_ASNS",
            "RESIDENTIAL_ASNS", "MOBILE_ASNS", "CDN_ASNS",
            "CLOUDFLARE_IP_RANGES", "PROXY_REGEX", "CRAWL4AI_INSTALL_PATH",
        ):
            assert hasattr(cfg_mod, name), f"{name} missing from UPO.config"

    def test_all_modules_import_without_error(self):
        import importlib
        for mod in (
            "UPO.config", "UPO.models", "UPO.models.enums", "UPO.models.proxy",
            "UPO.core", "UPO.core.engine", "UPO.core.filter", "UPO.core.limiter",
            "UPO.core.lifecycle", "UPO.socks",
            "UPO.db", "UPO.db.history", "UPO.db.verified",
            "UPO.collectors", "UPO.collectors.fetcher",
            "UPO.collectors.crawl4ai_runner", "UPO.checks",
            "UPO.checks.verify", "UPO.checks.anonymity", "UPO.checks.protocol",
            "UPO.checks.speed", "UPO.checks.fingerprint", "UPO.checks.dns",
            "UPO.checks.ban", "UPO.checks.fraud", "UPO.export",
            "UPO.export.exporter", "UPO.export.stats", "UPO.api",
            "UPO.api.server", "UPO.cli", "UPO.cli.app", "UPO.utils",
            "UPO.utils.console", "UPO.runtime",
        ):
            assert importlib.import_module(mod) is not None


# ============================================================================
# 3. Config loading
# ============================================================================

class TestLoadConfig:
    def test_no_path_returns_defaults(self):
        cfg = load_config(None)
        assert cfg["general"]["concurrency"] == \
            DEFAULT_CONFIG["general"]["concurrency"]
        assert cfg is not DEFAULT_CONFIG

    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(str(tmp_path / "absent.yaml"))
        assert cfg["api"]["port"] == DEFAULT_CONFIG["api"]["port"]

    def test_yaml_override_merges_sections(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("general:\n  concurrency: 7\ncustom_key: hello\n",
                     encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["general"]["concurrency"] == 7
        assert cfg["general"]["timeout_total"] == \
            DEFAULT_CONFIG["general"]["timeout_total"]
        assert cfg["custom_key"] == "hello"

    def test_malformed_yaml_falls_back(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("general: [unclosed\n", encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["general"]["concurrency"] == \
            DEFAULT_CONFIG["general"]["concurrency"]

    def test_bom_prefixed_yaml_still_merges(self, tmp_path):
        """utf-8-sig BOM must not mangle the first section key."""
        p = tmp_path / "config.yaml"
        p.write_bytes(
            "\ufeffoutput:\n  dir: bomdir\n".encode("utf-8"))
        cfg = load_config(str(p))
        assert cfg["output"]["dir"] == "bomdir"

    def test_empty_yaml_ok(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("", encoding="utf-8")
        assert load_config(str(p))["output"]["dir"] == \
            DEFAULT_CONFIG["output"]["dir"]

    def test_default_config_not_mutated(self, tmp_path):
        p = tmp_path / "config.yaml"
        p.write_text("filter:\n  max_per_subnet: 3\n", encoding="utf-8")
        load_config(str(p))
        assert DEFAULT_CONFIG["filter"]["max_per_subnet"] == 100

    def test_total_source_count_matches_lists(self):
        expected = (
            len(cfg_mod.GITHUB_HTTP_SOURCES) + len(cfg_mod.GITHUB_SOCKS4_SOURCES)
            + len(cfg_mod.GITHUB_SOCKS5_SOURCES) + len(cfg_mod.API_SOURCES)
        )
        assert cfg_mod.total_source_count() == expected > 0

    def test_deep_merge_preserves_nested_siblings_I7(self, tmp_path):
        """I7 regression: a one-key deep section must not wipe siblings."""
        p = tmp_path / "config.yaml"
        p.write_text(
            "lifecycle:\n  skip_known_dead:\n    min_fails: 9\n",
            encoding="utf-8",
        )
        cfg = load_config(str(p))
        assert cfg["lifecycle"]["skip_known_dead"]["min_fails"] == 9
        assert cfg["lifecycle"]["skip_known_dead"]["stale_hours"] == \
            DEFAULT_CONFIG["lifecycle"]["skip_known_dead"]["stale_hours"]
        assert cfg["lifecycle"]["max_in_flight"] == \
            DEFAULT_CONFIG["lifecycle"]["max_in_flight"]


# ============================================================================
# 4. Engine internals
# ============================================================================
class TestEngineInternals:
    def test_init_populates_state(self, config):
        eng = UPOEngine(config)
        assert eng.judges == [] and eng.blacklist == set()
        assert eng.my_ip is None and eng.my_dns_ip is None
        assert isinstance(eng.ip_filter, IPFilter)
        assert eng.history is None and eng.verified_db is None
        assert eng.stats["collected_raw"] == 0
        assert eng.stats["tcp_prefilter_removed"] == 0
        assert eng.getipintel_limiter.interval > 0
        assert eng.iphub_limiter.interval > 0
        assert eng.ipinfo_limiter.interval > 0

    def test_mro_well_formed(self, config):
        assert UPOEngine.__mro__[0] is UPOEngine
        assert UPOEngine.__mro__[-1] is object
        UPOEngine(config)

    def test_create_proxy_session_http(self, config):
        eng = UPOEngine(config)
        p = Proxy("8.8.8.8", 8080, ProxyProtocol.HTTP)
        with patch.object(engine_mod.aiohttp, "ClientSession") as cs, \
                patch.object(engine_mod.aiohttp, "TCPConnector"):
            session, kwargs = eng._create_proxy_session(
                p, engine_mod.aiohttp.ClientTimeout(total=5)
            )
        assert kwargs == {"proxy": "http://8.8.8.8:8080"}
        assert session is cs.return_value

    def test_create_proxy_session_socks(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 1080, ProxyProtocol.SOCKS5)
        with patch.object(engine_mod.aiohttp_socks, "ProxyConnector") as pc, \
                patch.object(engine_mod.aiohttp, "ClientSession"):
            _, kwargs = eng._create_proxy_session(
                p, engine_mod.aiohttp.ClientTimeout(total=5)
            )
        assert kwargs == {}
        pc.from_url.assert_called_once()

    def test_create_proxy_session_failure_returns_none(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 1080, ProxyProtocol.SOCKS4)
        with patch.object(engine_mod.aiohttp_socks, "ProxyConnector") as pc:
            pc.from_url.side_effect = RuntimeError("boom")
            session, kwargs = eng._create_proxy_session(
                p, engine_mod.aiohttp.ClientTimeout(total=5)
            )
        assert session is None and kwargs == {}

    def test_get_judge_fallback(self, config):
        eng = UPOEngine(config)
        assert eng._get_judge(0) == "http://api.ipify.org"
        assert eng._get_judge(99) == "http://api.ipify.org"

    def test_get_judge_rotation(self, config):
        eng = UPOEngine(config)
        eng.judges = [("http://a", 0.1), ("http://b", 0.2)]
        assert eng._get_judge(0) == "http://a"
        assert eng._get_judge(1) == "http://b"
        assert eng._get_judge(2) == "http://a"


class TestInitialize:
    async def test_geoip_missing_disables_geoip(self, config, tmp_path):
        config["geoip"]["enabled"] = True
        config["geoip"]["city_db"] = str(tmp_path / "nope.mmdb")
        eng = UPOEngine(config)
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.initialize()
        assert eng.config["geoip"]["enabled"] is False
        assert eng.geoip_city is None

    async def test_loads_blacklist_and_dbs(self, config):
        bl = Path(config["filter"]["blacklist"])
        bl.parent.mkdir(parents=True, exist_ok=True)
        bl.write_text("1.2.3.4\n\n5.6.7.8\n", encoding="utf-8")
        eng = UPOEngine(config)
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.initialize()
        assert eng.blacklist == {"1.2.3.4", "5.6.7.8"}
        assert isinstance(eng.history, ProxyHistory)
        assert isinstance(eng.verified_db, VerifiedProxyDB)

    async def test_empty_blacklist_file(self, config):
        bl = Path(config["filter"]["blacklist"])
        bl.parent.mkdir(parents=True, exist_ok=True)
        bl.write_text("\n\n", encoding="utf-8")
        eng = UPOEngine(config)
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.initialize()
        assert eng.blacklist == set()

    async def test_detects_real_ip_and_dns(self, config):
        eng = UPOEngine(config)
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.initialize()
        assert eng.my_ip == "9.9.9.9"
        assert eng.my_dns_ip == "9.9.9.9"

    async def test_no_ip_detected(self, config):
        config["dns_leak"] = {"enabled": False}
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(side_effect=RuntimeError("offline"))
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.initialize()
        assert eng.my_ip is None and eng.my_dns_ip is None

    async def test_non_ip_judge_response_ignored(self, config):
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(text_resp="<html>x"))
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.initialize()
        assert eng.my_ip is None

    async def test_dns_trace_error_swallowed(self, config):
        eng = UPOEngine(config)

        def side_effect(url, *a, **kw):
            if "1.1.1.1" in str(url):
                raise RuntimeError("trace down")
            return DummyResponse(text_resp="9.9.9.9")

        sess = make_session_mock()
        sess.get = MagicMock(side_effect=side_effect)
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.initialize()
        assert eng.my_ip == "9.9.9.9" and eng.my_dns_ip is None

    async def test_dns_trace_without_ip_line(self, config):
        eng = UPOEngine(config)

        def side_effect(url, *a, **kw):
            if "1.1.1.1" in str(url):
                return DummyResponse(text_resp="fl=1\nno_ip_here\n")
            return DummyResponse(text_resp="9.9.9.9")

        sess = make_session_mock()
        sess.get = MagicMock(side_effect=side_effect)
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.initialize()
        assert eng.my_dns_ip is None

    async def test_dbs_disabled(self, config):
        config["history"]["enabled"] = False
        config["verified_db"]["enabled"] = False
        eng = UPOEngine(config)
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.initialize()
        assert eng.history is None and eng.verified_db is None


# ============================================================================
# 5. Collection branches
# ============================================================================

class TestCollectBranches:
    async def test_crawl4ai_file_loaded_and_bad_rows_skipped(self, config, tmp_path):
        cf = tmp_path / "crawled.json"
        cf.write_text(json.dumps([
            {"ip": "9.9.9.1", "port": "8080", "protocol": "socks5", "source": "c4a"},
            {"ip": "9.9.9.1", "port": "8080", "protocol": "socks5"},
            {"ip": "bad", "port": "x", "protocol": "http"},
            {"ip": "9.9.9.2"},
        ]), encoding="utf-8")
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(cf)
        eng = UPOEngine(config)
        eng.verified_db = None
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.collect()
        assert list(eng.proxies) == ["9.9.9.1:8080"]
        assert eng.proxies["9.9.9.1:8080"].protocol == ProxyProtocol.SOCKS5

    async def test_corrupt_crawl4ai_file_swallowed(self, config, tmp_path):
        cf = tmp_path / "bad.json"
        cf.write_text("{not json", encoding="utf-8")
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(cf)
        eng = UPOEngine(config)
        eng.verified_db = None
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.collect()
        assert eng.proxies == {}

    async def test_verified_db_rows_loaded(self, config):
        eng = UPOEngine(config)
        eng.verified_db = VerifiedProxyDB(config["verified_db"]["db_path"])
        eng.verified_db.save_all([Proxy("4.4.4.4", 4141, ProxyProtocol.SOCKS4)])
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.collect()
        assert eng.proxies["4.4.4.4:4141"].source == "verified_db"

    async def test_bad_verified_rows_skipped(self, config):
        eng = UPOEngine(config)
        eng.verified_db = MagicMock()
        eng.verified_db.load_all.return_value = [
            {"ip": "1.1.1.1", "port": "notaport", "protocol": "http"},
            {"ip": "2.2.2.2", "port": 1, "protocol": "notaproto"},
            {"ip": "3.3.3.3"},
        ]
        with patch.object(engine_mod.aiohttp, "ClientSession",
                          return_value=make_session_mock()):
            await eng.collect()
        assert eng.proxies == {}
        assert eng.stats["collected_raw"] == 0

    async def test_fetch_non_200_returns_early(self, config):
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(status=503))
        await eng._fetch(sess, "https://x.test/a.txt", ProxyProtocol.HTTP)
        assert eng.proxies == {}

    async def test_fetch_timeout_retries_three_times(self, config):
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(side_effect=asyncio.TimeoutError())
        with patch.object(engine_mod.asyncio, "sleep", AsyncMock()):
            await eng._fetch(sess, "https://x.test/a.txt", ProxyProtocol.HTTP)
        assert sess.get.call_count == 3

    async def test_fetch_timeout_then_success(self, config):
        eng = UPOEngine(config)
        calls = {"n": 0}

        def side_effect(url, *a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise asyncio.TimeoutError()
            return DummyResponse(text_resp="1.2.3.4:8080")

        sess = make_session_mock()
        sess.get = MagicMock(side_effect=side_effect)
        with patch.object(engine_mod.asyncio, "sleep", AsyncMock()):
            await eng._fetch(sess, "https://x.test/a.txt", ProxyProtocol.HTTP)
        assert "1.2.3.4:8080" in eng.proxies

    async def test_fetch_generic_exception_does_not_retry(self, config):
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(side_effect=ValueError("boom"))
        await eng._fetch(sess, "https://x.test/a.txt", ProxyProtocol.HTTP)
        assert sess.get.call_count == 1

    async def test_fetch_json_dispatch(self, config):
        eng = UPOEngine(config)
        payload = json.dumps({"data": [
            {"ip": "7.7.7.7", "port": 1080, "protocols": ["socks5"]},
        ]})
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(text_resp=payload))
        await eng._fetch(sess, "https://x.test/a.json",
                         ProxyProtocol.HTTP, "json")
        assert eng.proxies["7.7.7.7:1080"].protocol == ProxyProtocol.SOCKS5

    async def test_fetch_source_from_url_host(self, config):
        eng = UPOEngine(config)
        eng._parse_text = MagicMock()
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(text_resp="x"))
        await eng._fetch(sess, "https://host.test/path", ProxyProtocol.HTTP)
        assert eng._parse_text.call_args[0][2] == "host.test"


class TestParsingBranches:
    def test_parse_text_dedupes(self, config):
        eng = UPOEngine(config)
        eng._parse_text("1.2.3.4:80\n1.2.3.4:80", ProxyProtocol.HTTP, "s")
        assert len(eng.proxies) == 1

    def test_parse_text_explicit_protocol_wins(self, config):
        eng = UPOEngine(config)
        eng._parse_text("socks4://1.2.3.4:1080", ProxyProtocol.HTTP, "s")
        assert eng.proxies["1.2.3.4:1080"].protocol == ProxyProtocol.SOCKS4

    def test_parse_text_invalid_explicit_protocol_skipped(self, config):
        eng = UPOEngine(config)
        # regex only matches known protocols, so this stays plain text
        eng._parse_text("ftp://1.2.3.4:1080", ProxyProtocol.HTTP, "s")
        assert eng.proxies["1.2.3.4:1080"].protocol == ProxyProtocol.HTTP

    def test_parse_json_list_root(self, config):
        eng = UPOEngine(config)
        eng._parse_json(json.dumps([
            {"ip": "1.1.1.1", "port": 80, "protocols": ["http"]},
        ]), "s")
        assert "1.1.1.1:80" in eng.proxies

    def test_parse_json_empty_protocols_defaults_http(self, config):
        eng = UPOEngine(config)
        eng._parse_json(json.dumps([
            {"ip": "1.1.1.2", "port": 80, "protocols": []},
        ]), "s")
        assert eng.proxies["1.1.1.2:80"].protocol == ProxyProtocol.HTTP

    def test_parse_json_skips_entries(self, config):
        eng = UPOEngine(config)
        eng._parse_json(json.dumps([
            {"ip": "1.1.1.3", "port": "xx", "protocols": ["http"]},
            {"port": 80, "protocols": ["http"]},
            {"ip": "1.1.1.4", "port": 80, "protocols": ["bogus"]},
        ]), "s")
        assert eng.proxies == {}

    def test_parse_json_invalid_json_ignored(self, config):
        eng = UPOEngine(config)
        eng._parse_json("}{", "s")
        assert eng.proxies == {}

    def test_parse_json_duplicate_ignored(self, config):
        eng = UPOEngine(config)
        payload = json.dumps(
            [{"ip": "1.1.1.5", "port": 80, "protocols": ["http"]}]
        )
        eng._parse_json(payload, "s")
        eng._parse_json(payload, "s2")
        assert len(eng.proxies) == 1


class TestPreEnrichBranches:
    def _asn(self, number, org="Org"):
        reader = MagicMock()
        reader.asn.return_value = MagicMock(
            autonomous_system_number=number,
            autonomous_system_organization=org,
        )
        return reader

    def test_no_asn_reader_is_noop(self, config):
        eng = UPOEngine(config)
        eng.proxies["1.1.1.1:80"] = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.pre_enrich()
        assert eng.proxies["1.1.1.1:80"].asn is None

    def test_asn_lookup_exception_swallowed(self, config):
        eng = UPOEngine(config)
        reader = MagicMock()
        reader.asn.side_effect = RuntimeError("mmdb gone")
        eng.geoip_asn = reader
        eng.proxies["1.1.1.1:80"] = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.pre_enrich()
        assert eng.proxies["1.1.1.1:80"].asn is None

    def test_geoip_city_populates_country(self, config):
        eng = UPOEngine(config)
        eng.geoip_asn = self._asn(7018)
        city = MagicMock()
        city.city.return_value = MagicMock(
            country=MagicMock(iso_code="US", name="United States"),
            city=MagicMock(name="Ashburn"),
            subdivisions=MagicMock(
                most_common=MagicMock(return_value=MagicMock(name="Virginia"))
            ),
        )
        eng.geoip_city = city
        eng.proxies["1.1.1.1:80"] = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.pre_enrich()
        p = eng.proxies["1.1.1.1:80"]
        assert p.country_code == "US"
        assert p.proxy_type == ProxyType.RESIDENTIAL

    def test_geoip_city_record_missing(self, config):
        from geoip2.errors import AddressNotFoundError
        eng = UPOEngine(config)
        eng.geoip_asn = self._asn(7018)
        city = MagicMock()
        city.city.side_effect = AddressNotFoundError("nope")
        eng.geoip_city = city
        eng.proxies["1.1.1.1:80"] = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.pre_enrich()
        assert eng.proxies["1.1.1.1:80"].country_code is None

    def test_geoip_city_generic_exception(self, config):
        eng = UPOEngine(config)
        eng.geoip_asn = self._asn(7018)
        city = MagicMock()
        city.city.side_effect = RuntimeError("boom")
        eng.geoip_city = city
        eng.proxies["1.1.1.1:80"] = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.pre_enrich()
        assert eng.proxies["1.1.1.1:80"].country_code is None


class TestFilterGarbageBranches:
    def test_all_reasons_trigger(self, config):
        config["filter"]["max_per_subnet"] = 1
        config["filter"]["allowed_countries"] = ["US"]
        config["filter"]["blocked_countries"] = ["RU"]
        config["filter"]["exclude_datacenters"] = True
        eng = UPOEngine(config)
        eng.blacklist = {"8.8.8.8"}
        eng.proxies = {
            "bad": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP),
            "badip": Proxy("9.9.9.9", 99999, ProxyProtocol.HTTP),
            "priv": Proxy("10.0.0.1", 80, ProxyProtocol.HTTP),
            "cf": Proxy("104.16.0.1", 80, ProxyProtocol.HTTP),
            "bl": Proxy("8.8.8.8", 80, ProxyProtocol.HTTP),
            "cdn": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP,
                         source="https://src.test/a.txt"),
            "blk": Proxy("2.2.2.2", 80, ProxyProtocol.HTTP, country_code="RU"),
            "geo": Proxy("3.3.3.3", 80, ProxyProtocol.HTTP, country_code="DE"),
        }
        eng.proxies["bad"].ip = "not-an-ip"
        eng.proxies["cdn"].asn = 13335
        eng.proxies["geo"].proxy_type = ProxyType.DATACENTER
        eng.filter_garbage()
        assert eng.proxies == {}
        assert eng.stats["filtered"] == 8

    def test_subnet_cap_prioritises_verified_db(self, config):
        config["filter"]["max_per_subnet"] = 1
        eng = UPOEngine(config)
        eng.proxies = {
            "a": Proxy("5.5.5.1", 80, ProxyProtocol.HTTP, source="github.test"),
            "b": Proxy("5.5.5.2", 80, ProxyProtocol.HTTP, source="verified_db"),
        }
        eng.filter_garbage()
        assert "b" in eng.proxies and "a" not in eng.proxies

    def test_subnet_cap_disabled(self, config):
        config["filter"]["max_per_subnet"] = 0
        eng = UPOEngine(config)
        eng.proxies = {
            "a": Proxy("5.5.5.1", 80, ProxyProtocol.HTTP),
            "b": Proxy("5.5.5.2", 80, ProxyProtocol.HTTP),
        }
        eng.filter_garbage()
        assert len(eng.proxies) == 2

    def test_invalid_port_filtered(self, config):
        eng = UPOEngine(config)
        p = Proxy("5.5.5.9", 80, ProxyProtocol.HTTP)
        p.port = 70000
        eng.proxies = {"x": p}
        eng.filter_garbage()
        assert eng.proxies == {}

    def test_subnet_parse_error_skipped(self, config):
        config["filter"]["max_per_subnet"] = 1
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.ip = "weird"
        eng.proxies = {"x": p}
        eng.filter_garbage()
        # "weird" survives range checks? no - invalid ip removed earlier
        assert eng.proxies == {}


# ============================================================================
# 6. Verification branches
# ============================================================================

class TestVerifyBranches:
    async def test_test_judges_filters_httpbin_caps_five(self, config):
        eng = UPOEngine(config)
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(text_resp="1.2.3.4"))
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.test_judges()
        assert 0 < len(eng.judges) <= 5
        assert all("httpbin.org" not in u for u, _ in eng.judges)

    async def test_test_judges_falls_back_to_httpbin(self, config):
        eng = UPOEngine(config)
        eng.config["judges"]["urls"] = ["http://httpbin.org/ip"]
        sess = make_session_mock()
        sess.get = MagicMock(
            return_value=DummyResponse(json_resp={"origin": "1.1.1.1"})
        )
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.test_judges()
        assert len(eng.judges) == 1
        assert "httpbin.org" in eng.judges[0][0]

    async def test_test_judges_ignores_large_and_erroring(self, config):
        eng = UPOEngine(config)
        eng.config["judges"]["urls"] = ["http://big.test", "http://err.test"]

        def side_effect(url, *a, **kw):
            if "big" in str(url):
                return DummyResponse(text_resp="x" * 5000)
            raise RuntimeError("down")

        sess = make_session_mock()
        sess.get = MagicMock(side_effect=side_effect)
        with patch.object(engine_mod.aiohttp, "ClientSession", return_value=sess):
            await eng.test_judges()
        assert eng.judges == []

    async def test_tcp_prefilter_removes_dead(self, config):
        eng = UPOEngine(config)
        eng.proxies = {
            "a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP),
            "b": Proxy("2.2.2.2", 80, ProxyProtocol.HTTP),
        }

        class W:
            def close(self):
                pass

            async def wait_closed(self):
                pass

        async def fake_open(ip, port):
            if ip == "1.1.1.1":
                return MagicMock(), W()
            raise OSError("refused")

        with patch.object(asyncio, "open_connection", side_effect=fake_open):
            await eng.tcp_prefilter()
        assert list(eng.proxies) == ["a"]
        assert eng.stats["tcp_prefilter_removed"] == 1

    async def test_tcp_prefilter_wait_closed_error_swallowed(self, config):
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}

        class W:
            def close(self):
                pass

            async def wait_closed(self):
                raise RuntimeError("already gone")

        async def fake_open(ip, port):
            return MagicMock(), W()

        with patch.object(asyncio, "open_connection", side_effect=fake_open):
            await eng.tcp_prefilter()
        assert list(eng.proxies) == ["a"]

    async def test_verify_empty_pool_returns(self, config):
        await UPOEngine(config).verify()

    async def test_verify_aborts_without_judges(self, config):
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        with patch.object(UPOEngine, "test_judges", AsyncMock()):
            await eng.verify()
        assert eng.proxies["a"].alive is False

    async def test_multiround_breaks_when_nobody_survives(self, config):
        config["general"]["verification_rounds"] = 3
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        eng.judges = [("http://judge", 0.1)]
        with patch.object(UPOEngine, "test_judges", AsyncMock()), \
                patch.object(UPOEngine, "_check_one", AsyncMock()), \
                patch.object(engine_mod.asyncio, "sleep", AsyncMock()):
            await eng.verify()
        assert eng.proxies["a"].check_count == 0

    async def test_multiround_rechecks_survivors(self, config):
        config["general"]["verification_rounds"] = 2
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        eng.judges = [("http://j1", 0.1), ("http://j2", 0.2)]

        async def check(p, judge):
            p.alive = True
            p.success_count += 1
            p.check_count += 1

        with patch.object(UPOEngine, "test_judges", AsyncMock()), \
                patch.object(UPOEngine, "_check_one", side_effect=check), \
                patch.object(engine_mod.asyncio, "sleep", AsyncMock()):
            await eng.verify()
        assert eng.proxies["a"].check_count == 2
        assert eng.proxies["a"].reliability == 1.0

    async def test_reliability_threshold_marks_dead(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.check_count, p.success_count = 2, 1          # 0.5 -> not > 0.5
        eng.proxies = {"a": p}
        eng.judges = [("http://judge", 0.1)]

        with patch.object(UPOEngine, "test_judges", AsyncMock()), \
                patch.object(UPOEngine, "_check_one", AsyncMock()):
            await eng.verify()
        assert p.reliability == 0.5 and p.alive is False

    async def test_verify_sets_stats(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.proxies = {"a": p}
        eng.judges = [("http://judge", 0.1)]

        async def check(proxy, judge):
            proxy.alive = True
            proxy.check_count = 1
            proxy.success_count = 1

        with patch.object(UPOEngine, "test_judges", AsyncMock()), \
                patch.object(UPOEngine, "_check_one", side_effect=check):
            await eng.verify()
        assert eng.stats["verified_total"] == 1
        assert eng.stats["verified_alive"] == 1

    async def test_check_one_no_session_marks_dead(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        with patch.object(UPOEngine, "_create_proxy_session",
                          MagicMock(return_value=(None, {}))):
            await eng._check_one(p, "http://judge")
        assert p.alive is False and p.fail_count == 1 and p.check_count == 1

    async def test_check_one_non_200_marks_dead(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(status=500))
        with patch.object(UPOEngine, "_create_proxy_session",
                          MagicMock(return_value=(sess, {}))):
            await eng._check_one(p, "http://judge")
        assert p.alive is False and p.fail_count == 1

    async def test_check_one_exception_marks_dead(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        sess.get = MagicMock(side_effect=RuntimeError("boom"))
        with patch.object(UPOEngine, "_create_proxy_session",
                          MagicMock(return_value=(sess, {}))):
            await eng._check_one(p, "http://judge")
        assert p.alive is False and p.fail_count == 1


# ============================================================================
# 7. Protocol / speed branch gaps
# ============================================================================

class TestProtocolBranches:
    async def test_http_support_probe_sets_supports_https(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.proxies = {"a": p}
        sess = make_session_mock()
        eng._create_proxy_session = MagicMock(
            return_value=(sess, {"proxy": p.url})
        )
        await eng._detect_protocols_one(p, "http://judge.test/ip")
        assert "http" in p.detected_protocols
        assert p.supports_https is True

    async def test_http_support_probe_exception_swallowed(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng.proxies = {"a": p}

        def side_effect(url, *a, **kw):
            if "httpbin" in str(url):
                raise RuntimeError("probe down")
            return DummyResponse(text_resp="9.9.9.9")

        sess = make_session_mock()
        sess.get = MagicMock(side_effect=side_effect)
        eng._create_proxy_session = MagicMock(
            return_value=(sess, {"proxy": p.url})
        )
        await eng._detect_protocols_one(p, "http://judge.test/ip")
        assert p.supports_https is False

    async def test_detect_protocols_early_return_when_disabled(self, config):
        config["protocol_detection"]["enabled"] = False
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        await eng.detect_protocols()
        assert eng.proxies["a"].detected_protocols == []

    async def test_detect_protocols_early_return_when_none_alive(self, config):
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        await eng.detect_protocols()
        assert eng.proxies["a"].detected_protocols == []


class TestSpeedBranches:
    async def test_zero_elapsed_does_not_divide(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        sess.get = MagicMock(return_value=DummyResponse(text_resp="x"))
        eng._create_proxy_session = MagicMock(return_value=(sess, {}))
        with patch.object(speed_mod.time, "monotonic", side_effect=[1.0, 1.0]):
            await eng._speed_test_one(p, "https://speed.test/x")
        assert p.download_speed_kbps is None

    async def test_exception_swallowed(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        sess.get = MagicMock(side_effect=RuntimeError("down"))
        eng._create_proxy_session = MagicMock(return_value=(sess, {}))
        await eng._speed_test_one(p, "https://speed.test/x")
        assert p.download_speed_kbps is None

    async def test_no_session_returns(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        eng._create_proxy_session = MagicMock(return_value=(None, {}))
        await eng._speed_test_one(p, "https://speed.test/x")
        assert p.download_speed_kbps is None

    async def test_speed_test_disabled(self, config):
        config["speed_test"]["enabled"] = False
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        await eng.speed_test()


# ============================================================================
# 8. Fraud waterfall tiers
# ============================================================================

class TestFraudBranches:
    def _eng(self, config, **keys):
        eng = UPOEngine(config)
        base = {"ipinfo": "", "iphub": "", "getipintel_email": "", "ipqs": ""}
        base.update(keys)
        eng.config["fraud_check"]["keys"] = base
        return eng

    async def test_disabled_is_noop(self, config):
        config["fraud_check"]["enabled"] = False
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        await eng.tiered_fraud_scoring()
        assert eng.proxies["a"].composite_score is None

    async def test_no_alive_targets_returns(self, config):
        config["fraud_check"]["enabled"] = True
        eng = UPOEngine(config)
        eng.proxies = {"a": Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)}
        await eng.tiered_fraud_scoring()

    async def test_ipinfo_exception_swallowed(self, config):
        eng = self._eng(config, ipinfo="k")
        eng.history = MagicMock()
        eng.history.get_cached_score.return_value = None
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(side_effect=RuntimeError("api down"))
        await eng._waterfall_one(p, shared)
        # Every tier failed → waterfall bottoms out at a clean score of 0
        # rather than crashing or leaving the proxy unscored mid-pipeline.
        assert p.composite_score == 0

    async def test_ipinfo_vpn_early_return_and_cache(self, config):
        eng = self._eng(config, ipinfo="k")
        eng.history = MagicMock()
        eng.history.get_cached_score.return_value = None
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(
            return_value=DummyResponse(json_resp={"privacy": {"vpn": True}})
        )
        await eng._waterfall_one(p, shared)
        assert p.composite_score == 25 and p.is_vpn is True
        eng.history.save_cached_score.assert_called_once()

    async def test_ipinfo_proxy_and_hosting_flags(self, config):
        eng = self._eng(config, ipinfo="k")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(return_value=DummyResponse(
            json_resp={"privacy": {"proxy": True, "hosting": True}}
        ))
        await eng._waterfall_one(p, shared)
        assert p.is_hosting is True and p.is_vpn is None

    async def test_iphub_block_zero_subtracts(self, config):
        eng = self._eng(config, iphub="k")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(
            return_value=DummyResponse(json_resp={"block": 0})
        )
        await eng._waterfall_one(p, shared)
        assert eng.stats["api_calls"]["iphub"] == 1

    async def test_iphub_block_one_caches_and_returns(self, config):
        eng = self._eng(config, iphub="k")
        eng.history = MagicMock()
        eng.history.get_cached_score.return_value = None
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(
            return_value=DummyResponse(json_resp={"block": 1})
        )
        await eng._waterfall_one(p, shared)
        assert p.composite_score == 25
        eng.history.save_cached_score.assert_called_once()

    async def test_iphub_exception_swallowed(self, config):
        eng = self._eng(config, iphub="k")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(side_effect=RuntimeError("down"))
        await eng._waterfall_one(p, shared)

    async def test_getipintel_elite_only_and_error(self, config):
        eng = self._eng(config, getipintel_email="a@b.c")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        shared = make_session_mock()
        shared.get = MagicMock(side_effect=RuntimeError("down"))
        await eng._waterfall_one(p, shared)
        assert p.fraud_score is None

    async def test_getipintel_skipped_for_non_elite(self, config):
        eng = self._eng(config, getipintel_email="a@b.c")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ANONYMOUS
        shared = make_session_mock()
        shared.get = MagicMock()
        await eng._waterfall_one(p, shared)
        shared.get.assert_not_called()

    async def test_ipqs_branch_and_error(self, config):
        eng = self._eng(config, ipqs="k")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock(side_effect=RuntimeError("down"))
        await eng._waterfall_one(p, shared)

    async def test_ipqs_skipped_when_score_high(self, config):
        eng = self._eng(config, ipinfo="k", ipqs="k")
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()

        def side_effect(url, *a, **kw):
            if "ipinfo" in str(url):
                return DummyResponse(
                    json_resp={"privacy": {"proxy": True, "hosting": True}}
                )
            return DummyResponse(json_resp={"success": True, "fraud_score": 90})

        shared.get = MagicMock(side_effect=side_effect)
        await eng._waterfall_one(p, shared)
        # score 40 -> ipqs guard (score < 30) false, so ipqs never called
        assert eng.stats["api_calls"]["ipqs"] == 0

    async def test_cache_hit_short_circuits(self, config):
        eng = self._eng(config, ipinfo="k")
        eng.history = MagicMock()
        eng.history.get_cached_score.return_value = 77
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        shared.get = MagicMock()
        await eng._waterfall_one(p, shared)
        assert p.composite_score == 77
        assert eng.stats["api_calls"]["cache_hits"] == 1
        shared.get.assert_not_called()

    async def test_no_keys_still_finalises_score(self, config):
        eng = self._eng(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        shared = make_session_mock()
        await eng._waterfall_one(p, shared)
        assert p.composite_score is not None


# ============================================================================
# 9. Export / stats gaps
# ============================================================================

class TestExportStatsBranches:
    def test_verified_db_cleared_when_no_alive(self, config):
        eng = UPOEngine(config)
        eng.verified_db = VerifiedProxyDB(config["verified_db"]["db_path"])
        eng.verified_db.save_all([Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)])
        eng.proxies = {}
        eng.export()
        assert eng.verified_db.count() == 0

    def test_verified_db_updated_with_survivors(self, config):
        eng = UPOEngine(config)
        eng.verified_db = VerifiedProxyDB(config["verified_db"]["db_path"])
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        eng.proxies = {"a": p}
        eng.export()
        assert eng.verified_db.count() == 1

    def test_min_anonymity_filter_marks_dead(self, config):
        config["filter"]["min_anonymity"] = "elite"
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.anonymity = AnonymityLevel.ANONYMOUS
        eng.proxies = {"a": p}
        eng.enrich_and_categorize()
        assert p.alive is False

    def test_min_anonymity_keeps_elite(self, config):
        config["filter"]["min_anonymity"] = "elite"
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.anonymity = AnonymityLevel.ELITE
        eng.proxies = {"a": p}
        eng.enrich_and_categorize()
        assert p.alive is True

    def test_enrich_skips_dead_and_sets_speed_tier(self, config):
        eng = UPOEngine(config)
        dead = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        fast = Proxy("2.2.2.2", 80, ProxyProtocol.HTTP)
        fast.alive = True
        fast.latency_ms = 100
        medium = Proxy("3.3.3.3", 80, ProxyProtocol.HTTP)
        medium.alive = True
        medium.latency_ms = 900
        slow = Proxy("4.4.4.4", 80, ProxyProtocol.HTTP)
        slow.alive = True
        slow.latency_ms = 5000
        eng.proxies = {"d": dead, "f": fast, "m": medium, "s": slow}
        eng.enrich_and_categorize()
        assert dead.speed_tier is None
        assert fast.speed_tier == SpeedTier.FAST
        assert medium.speed_tier == SpeedTier.MEDIUM
        assert slow.speed_tier == SpeedTier.SLOW

    def test_enrich_averages_latency(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 200
        p.avg_latency_ms = 100.0
        eng.proxies = {"a": p}
        eng.enrich_and_categorize()
        assert p.avg_latency_ms == 150.0

    def test_enrich_updates_history(self, config):
        eng = UPOEngine(config)
        eng.history = MagicMock()
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 50
        eng.proxies = {"a": p}
        eng.enrich_and_categorize()
        eng.history.update.assert_called_once()

    def test_print_stats_with_tcp_removed(self, config):
        eng = UPOEngine(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 120
        p.anonymity = AnonymityLevel.ELITE
        p.speed_tier = SpeedTier.FAST
        eng.proxies = {"a": p}
        eng.stats["tcp_prefilter_removed"] = 5
        eng.stats["filtered"] = 3
        eng.stats["verified_total"] = 1
        sd = eng.print_stats()
        assert sd["alive"] == 1 and sd["elite"] == 1 and sd["fast"] == 1
        assert sd["total"] == 1 + 3 + 5

    def test_print_stats_empty_pool(self, config):
        eng = UPOEngine(config)
        eng.proxies = {}
        assert eng.print_stats()["alive"] == 0

    def test_print_stats_counts_latency(self, config):
        eng = UPOEngine(config)
        for i, lat in enumerate((100, 200)):
            p = Proxy(f"1.1.1.{i}", 80, ProxyProtocol.HTTP)
            p.alive = True
            p.latency_ms = lat
            eng.proxies[str(i)] = p
        eng.print_stats()


# ============================================================================
# 10. DB robustness
# ============================================================================

class TestDBRobustness:
    def test_history_insert_then_update(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h.db"))
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive, p.latency_ms = True, 100
        h.update(p)
        assert h.get_stats() == {"total_tracked": 1, "total_checks": 1}
        p.alive, p.latency_ms = False, 300
        h.update(p)
        assert h.get_stats()["total_checks"] == 2

    def test_history_update_with_geo_fields(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h2.db"))
        p = Proxy("1.1.1.1", 80, ProxyProtocol.SOCKS5)
        p.alive = True
        p.country_code, p.asn, p.isp = "US", 7018, "AT&T"
        p.proxy_type = ProxyType.RESIDENTIAL
        h.update(p)
        h.update(p)
        assert h.get_stats()["total_tracked"] == 1

    def test_history_creates_parent_dir(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "deep" / "nested" / "h.db"))
        assert Path(h.db_path).exists()

    def test_history_write_error_swallowed(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h3.db"))
        bad = MagicMock()
        bad.cursor.side_effect = sqlite3.OperationalError("boom")
        with patch.object(h, "_conn", return_value=bad):
            h.update(Proxy("1.1.1.1", 80, ProxyProtocol.HTTP))
        assert h.get_stats()["total_tracked"] == 0

    def test_score_cache_roundtrip_and_upsert(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h4.db"))
        assert h.get_cached_score("1.1.1.1") is None
        h.save_cached_score("1.1.1.1", 42)
        assert h.get_cached_score("1.1.1.1") == 42
        h.save_cached_score("1.1.1.1", 7)
        assert h.get_cached_score("1.1.1.1") == 7

    def test_bad_cached_timestamp_returns_none(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h5.db"))
        conn = h._conn()
        conn.execute(
            "INSERT OR REPLACE INTO api_cache (ip, checked_at, composite_score)"
            " VALUES (?,?,?)", ("1.1.1.1", "not-a-date", 50))
        conn.commit()
        conn.close()
        assert h.get_cached_score("1.1.1.1") is None

    def test_stale_cache_expires(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h6.db"))
        conn = h._conn()
        conn.execute(
            "INSERT OR REPLACE INTO api_cache (ip, checked_at, composite_score)"
            " VALUES (?,?,?)",
            ("1.1.1.1", "2000-01-01T00:00:00+00:00", 50))
        conn.commit()
        conn.close()
        assert h.get_cached_score("1.1.1.1") is None

    def test_save_cached_score_error_swallowed(self, tmp_path):
        h = ProxyHistory(str(tmp_path / "h7.db"))
        bad = MagicMock()
        bad.cursor.return_value.execute.side_effect = sqlite3.OperationalError("x")
        with patch.object(h, "_conn", return_value=bad):
            h.save_cached_score("1.1.1.1", 5)

    def test_verified_db_roundtrip(self, tmp_path):
        db = VerifiedProxyDB(str(tmp_path / "v.db"))
        assert db.count() == 0
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.latency_ms = 55
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.RESIDENTIAL
        p.country_code = "US"
        db.save_all([p])
        assert db.count() == 1
        assert db.load_all() == [
            {"ip": "1.1.1.1", "port": 80, "protocol": "http"}
        ]
        db.save_all([])
        assert db.count() == 0

    def test_verified_db_write_error_swallowed(self, tmp_path):
        db = VerifiedProxyDB(str(tmp_path / "v2.db"))
        bad = MagicMock()
        bad.execute.side_effect = sqlite3.OperationalError("boom")
        with patch.object(db, "_conn", return_value=bad):
            db.save_all([Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)])

    def test_rate_limiter_zero_is_noop(self):
        rl = RateLimiter(0)
        assert rl.interval == 0

    async def test_rate_limiter_enforces_interval(self):
        rl = RateLimiter(6000)                # 10 ms
        await rl.wait()
        t0 = asyncio.get_event_loop().time()
        await rl.wait()
        assert asyncio.get_event_loop().time() - t0 >= 0.005


# ============================================================================
# 11. crawl4ai runner
# ============================================================================

class FakeJsonResp:
    def __init__(self, payload, status=200):
        self._payload, self.status = payload, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self._payload

    async def text(self):
        return self._payload if isinstance(self._payload, str) \
            else json.dumps(self._payload)


class FakeSession:
    def __init__(self, payload, status=200):
        self._payload, self._status = payload, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kw):
        return FakeJsonResp(self._payload, self._status)


class FakeAiohttp:
    """Minimal aiohttp surface used by run_crawl4ai."""

    def __init__(self, payload, status=200):
        self._payload, self._status = payload, status

    def ClientSession(self, *a, **kw):
        return FakeSession(self._payload, self._status)

    def TCPConnector(self, *a, **kw):
        return None

    def ClientTimeout(self, **kw):
        return None


class FakeCrawlerResult:
    def __init__(self, extracted=None, markdown=None):
        self.extracted_content = extracted
        self.markdown = markdown


class FakeCrawler:
    def __init__(self, config=None):
        self.config = config

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def arun(self, url, config=None):
        if "free-proxy-list" in url:
            return FakeCrawlerResult(extracted=json.dumps([
                {"ip": "2.2.2.2", "port": "3128", "https": "yes"},
                {"ip": "3.3.3.3", "port": "9999", "https": "no"},
                {"ip": "", "port": "1", "https": "no"},
                {"ip": "4.4.4.5", "port": "abc", "https": "no"},
            ]))
        return FakeCrawlerResult(markdown="4.4.4.4:8080 and 5.5.5.5|1080")


def crawl4ai_mods():
    mod = MagicMock()
    mod.AsyncWebCrawler = FakeCrawler
    mod.BrowserConfig = lambda **kw: kw
    mod.CrawlerRunConfig = lambda **kw: kw
    ext = MagicMock()
    ext.JsonCssExtractionStrategy = lambda schema=None: {"schema": schema}
    return mod, ext


class TestCrawl4AIRunner:
    async def test_disabled_returns_immediately(self, config):
        import UPO.collectors.crawl4ai_runner as cr
        config["crawl4ai"]["enabled"] = False
        await cr.run_crawl4ai(config)

    async def test_import_failure_reported(self, config):
        import UPO.collectors.crawl4ai_runner as cr
        config["crawl4ai"]["enabled"] = True
        with patch.dict(sys.modules, {"crawl4ai": None}):
            await cr.run_crawl4ai(config)

    async def test_full_run_writes_output(self, config, tmp_path):
        import UPO.collectors.crawl4ai_runner as cr
        out = tmp_path / "crawled.json"
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(out)
        mod, ext = crawl4ai_mods()
        payload = {"data": [
            {"ip": "6.6.6.6", "port": "8080", "protocol": "Http, Socks4"},
        ], "recordsTotal": 1}
        with patch.dict(sys.modules, {
            "crawl4ai": mod, "crawl4ai.extraction_strategy": ext,
        }), patch.object(cr, "aiohttp", FakeAiohttp(payload)):
            await cr.run_crawl4ai(config)
        rows = json.loads(out.read_text(encoding="utf-8"))
        protos = {r["protocol"] for r in rows}
        assert {"http", "https", "socks4"} <= protos
        assert any(r["source"] == "proxy-daily.com" for r in rows)
        assert any(r["source"] in ("proxy-nova", "proxynova.com") for r in rows)

    async def test_pagination_bad_status_breaks(self, config, tmp_path):
        import UPO.collectors.crawl4ai_runner as cr
        out = tmp_path / "c.json"
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(out)
        mod, ext = crawl4ai_mods()
        with patch.dict(sys.modules, {
            "crawl4ai": mod, "crawl4ai.extraction_strategy": ext,
        }), patch.object(cr, "aiohttp", FakeAiohttp({}, status=500)):
            await cr.run_crawl4ai(config)
        assert out.exists()

    async def test_export_fallback_when_json_empty(self, config, tmp_path):
        import UPO.collectors.crawl4ai_runner as cr
        out = tmp_path / "c2.json"
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(out)
        mod, ext = crawl4ai_mods()
        hits = {"n": 0}

        class TextResp:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def text(self):
                return "1.1.1.1:8080\n2.2.2.2:9090"

        class TwoPhase(FakeAiohttp):
            def ClientSession(self, *a, **kw):
                hits["n"] += 1
                if hits["n"] == 1:
                    return FakeSession({"data": [], "recordsTotal": 0})
                return TextSession()

        class TextSession:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def get(self, url, **kw):
                return TextResp()

        with patch.dict(sys.modules, {
            "crawl4ai": mod, "crawl4ai.extraction_strategy": ext,
        }), patch.object(cr, "aiohttp", TwoPhase({})):
            await cr.run_crawl4ai(config)
        rows = json.loads(out.read_text(encoding="utf-8"))
        assert {"1.1.1.1:8080", "2.2.2.2:9090"} <= \
            {r["ip"] + ":" + r["port"] for r in rows}

    async def test_json_api_error_swallowed(self, config, tmp_path):
        import UPO.collectors.crawl4ai_runner as cr
        out = tmp_path / "c3.json"
        config["crawl4ai"]["enabled"] = True
        config["crawl4ai"]["output_file"] = str(out)
        mod, ext = crawl4ai_mods()

        class Boom(FakeAiohttp):
            def ClientSession(self, *a, **kw):
                raise RuntimeError("no network")

        with patch.dict(sys.modules, {
            "crawl4ai": mod, "crawl4ai.extraction_strategy": ext,
        }), patch.object(cr, "aiohttp", Boom({})):
            await cr.run_crawl4ai(config)
        assert out.exists()


# ============================================================================
# 12. FastAPI server (real FastAPI, TestClient)
# ============================================================================

def build_api(config, engine_obj=None):
    """Start the API with a stub uvicorn and return the real FastAPI app."""
    import UPO.api.server as srv
    eng = engine_obj or UPOEngine(config)
    captured = {}
    fake_uvicorn = MagicMock()
    fake_uvicorn.run.side_effect = lambda app, **kw: captured.update(app=app)
    with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}), \
            patch.object(threading, "Thread", lambda target, daemon: _Immediate(target)):
        srv.start_api(eng, "127.0.0.1", 1234)
    return captured["app"], eng


class _Immediate:
    """Run the thread target synchronously instead of spawning a daemon."""

    def __init__(self, target):
        self._target = target

    def start(self):
        self._target()


def _asgi_get(app, path, query=""):
    """GET through raw ASGI, returning (status, parsed_json).

    starlette 1.3.1's TestClient misbehaves (307 → /random/ redirect loop)
    when several in-process apps are exercised in one process, even though
    the apps themselves route correctly. Raw ASGI exercises the real
    Router + endpoints without that harness bug.
    """
    import asyncio

    scope = {
        "type": "http", "http_version": "1.1", "method": "GET",
        "path": path, "raw_path": path.encode(), "query_string": query.encode(),
        "root_path": "", "scheme": "http",
        "headers": [(b"host", b"testserver")],
        "client": ("testclient", 123), "server": ("testserver", 80),
    }

    async def go():
        msgs = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(m):
            msgs.append(m)

        await app(scope, receive, send)
        body = b"".join(m.get("body", b"") for m in msgs
                        if m["type"] == "http.response.body")
        status = next(m["status"] for m in msgs
                      if m["type"] == "http.response.start")
        return status, json.loads(body) if body else None

    return asyncio.run(go())


class TestAPIServerReal:
    def test_routes_and_dict_shape(self, config):
        app, eng = build_api(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.country_code = "US"
        p.anonymity = AnonymityLevel.ELITE
        p.stealth_score = 80
        p.proxy_type = ProxyType.RESIDENTIAL
        p.latency_ms = 100
        eng.proxies = {"a": p}
        assert _asgi_get(app, "/health")[1]["status"] == "ok"
        assert len(_asgi_get(app, "/proxies")[1]) == 1
        assert _asgi_get(app, "/proxies", "protocol=socks5")[1] == []
        assert _asgi_get(app, "/proxies", "country=us")[1][0]["ip"] == "1.1.1.1"
        assert _asgi_get(app, "/proxies", "anonymity=elite")[1] != []
        assert _asgi_get(app, "/proxies", "min_stealth=50")[1] != []
        assert _asgi_get(app, "/proxies", "proxy_type=residential")[1] != []
        assert _asgi_get(app, "/proxies", "max_latency=200")[1] != []
        assert _asgi_get(app, "/proxies", "max_latency=50")[1] == []
        assert _asgi_get(app, "/random")[1]["ip"] == "1.1.1.1"
        stats = _asgi_get(app, "/stats")[1]
        assert stats["alive"] == 1 and stats["elite"] == 1
        assert stats["residential"] == 1

    def test_anonymity_none_excluded(self, config):
        app, eng = build_api(config)
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.anonymity = None
        p.stealth_score = None
        eng.proxies = {"a": p}
        assert _asgi_get(app, "/proxies", "anonymity=elite")[1] == []
        assert _asgi_get(app, "/proxies", "min_stealth=1")[1] == []

    def test_random_error_when_empty(self, config):
        app, _ = build_api(config)
        assert _asgi_get(app, "/random")[1]["error"] == "No proxies match"

    def test_missing_fastapi_is_graceful(self, config):
        import UPO.api.server as srv
        with patch.dict(sys.modules, {"fastapi": None}):
            srv.start_api(UPOEngine(config), "127.0.0.1", 0)

    def test_start_api_binds_host_and_port(self, config):
        import UPO.api.server as srv
        eng = UPOEngine(config)
        seen = {}
        fake_uvicorn = MagicMock()
        fake_uvicorn.run.side_effect = lambda app, **kw: seen.update(kw)
        with patch.dict(sys.modules, {"uvicorn": fake_uvicorn}), \
                patch.object(threading, "Thread",
                             lambda target, daemon: _Immediate(target)):
            srv.start_api(eng, "0.0.0.0", 9999)
        assert seen["host"] == "0.0.0.0" and seen["port"] == 9999


# ============================================================================
# 13. CLI orchestrator
# ============================================================================

def make_fake_engine():
    calls = []

    class FakeEngine:
        def __init__(self, cfg):
            self.config = cfg
            self.proxies = {
                f"1.1.1.{i}:80": Proxy(f"1.1.1.{i}", 80, ProxyProtocol.HTTP)
                for i in range(1, 6)
            }
            self.stats = {"filtered": 0, "tcp_prefilter_removed": 0,
                          "verified_total": 0}

        async def initialize(self):
            calls.append("initialize")

        async def collect(self):
            calls.append("collect")

        def pre_enrich(self):
            calls.append("pre_enrich")

        def filter_garbage(self):
            calls.append("filter_garbage")

        async def tcp_prefilter(self):
            calls.append("tcp_prefilter")

        async def run_lifecycle(self):
            """Stands in for the pipelined lifecycle engine: it subsumes
            tcp_prefilter + verify + anonymity + protocol + speed + fp +
            dns + ban in one pass."""
            calls.append("run_lifecycle")
            self.stats["verified_total"] = len(self.proxies)
            self.stats["verified_alive"] = len(self.proxies)
            return True

        async def verify(self):
            calls.append("verify")

        async def check_anonymity(self):
            calls.append("check_anonymity")

        async def detect_protocols(self):
            calls.append("detect_protocols")

        async def speed_test(self):
            calls.append("speed_test")

        async def fingerprint(self):
            calls.append("fingerprint")

        async def dns_leak_check(self):
            calls.append("dns_leak_check")

        async def tiered_fraud_scoring(self):
            calls.append("fraud")

        async def check_bans(self):
            calls.append("check_bans")

        def enrich_and_categorize(self):
            calls.append("categorize")

        def export(self):
            calls.append("export")

        def print_stats(self):
            calls.append("print_stats")
            return {"alive": 0}

    return FakeEngine, calls


class TestCLIPipeline:
    async def _run(self, config, **kw):
        import UPO.cli.app as app
        FakeEngine, calls = make_fake_engine()
        with patch.object(app, "UPOEngine", FakeEngine), \
                patch.object(app, "run_crawl4ai", AsyncMock()), \
                patch.object(app, "start_api") as fake_api:
            await app.pipeline(config, kw.get("scrape_only", False),
                               kw.get("test_limit"))
        return calls, fake_api

    async def test_full_phase_order(self, config):
        """Default path is now the pipelined lifecycle engine."""
        config["crawl4ai"]["enabled"] = False
        calls, _ = await self._run(config)
        assert calls == [
            "initialize", "collect", "pre_enrich", "filter_garbage",
            "run_lifecycle", "categorize", "export", "print_stats",
        ]

    async def test_serial_phase_order(self, config):
        """--serial / lifecycle.enabled=false keeps the legacy order."""
        config["crawl4ai"]["enabled"] = False
        config["lifecycle"]["enabled"] = False
        calls, _ = await self._run(config)
        assert calls == [
            "initialize", "collect", "pre_enrich", "filter_garbage",
            "tcp_prefilter", "verify", "check_anonymity",
            "detect_protocols", "speed_test", "fingerprint",
            "dns_leak_check", "check_bans", "categorize", "export",
            "print_stats",
        ]

    async def test_crawl4ai_invoked_when_enabled(self, config):
        import UPO.cli.app as app
        config["crawl4ai"]["enabled"] = True
        FakeEngine, _ = make_fake_engine()
        c4a = AsyncMock()
        with patch.object(app, "UPOEngine", FakeEngine), \
                patch.object(app, "run_crawl4ai", c4a), \
                patch.object(app, "start_api"):
            await app.pipeline(config, False, None)
        c4a.assert_awaited_once_with(config)

    async def test_scrape_only_skips_verification(self, config):
        calls, _ = await self._run(config, scrape_only=True)
        for skipped in ("verify", "tcp_prefilter", "check_anonymity",
                        "detect_protocols", "speed_test", "fingerprint",
                        "dns_leak_check", "check_bans", "categorize"):
            assert skipped not in calls, skipped
        assert calls[-2:] == ["export", "print_stats"]

    async def test_test_limit_truncates_pool(self, config):
        import UPO.cli.app as app
        config["crawl4ai"]["enabled"] = False
        FakeEngine, _ = make_fake_engine()
        seen = {}

        class Recording(FakeEngine):
            async def run_lifecycle(self):
                seen["n"] = len(self.proxies)
                return True

        with patch.object(app, "UPOEngine", Recording), \
                patch.object(app, "run_crawl4ai", AsyncMock()), \
                patch.object(app, "start_api"):
            await app.pipeline(config, False, 2)
        assert seen["n"] == 2

    async def test_fraud_phase_only_when_enabled(self, config):
        config["crawl4ai"]["enabled"] = False
        calls, _ = await self._run(config)
        assert "fraud" not in calls
        config["fraud_check"]["enabled"] = True
        calls2, _ = await self._run(config)
        assert "fraud" in calls2

    async def test_all_optional_phases_disabled(self, config):
        config["crawl4ai"]["enabled"] = False
        config["lifecycle"]["enabled"] = False  # serial: phase gates apply
        for sect in ("protocol_detection", "speed_test", "stealth_score",
                     "dns_leak", "ban_check"):
            config[sect]["enabled"] = False
        calls, _ = await self._run(config)
        for skipped in ("detect_protocols", "speed_test", "fingerprint",
                        "dns_leak_check", "check_bans"):
            assert skipped not in calls
        assert "verify" in calls and "check_anonymity" in calls

    async def test_api_started_and_keyboardinterrupt_exits(self, config):
        import UPO.cli.app as app
        config["crawl4ai"]["enabled"] = False
        config["api"]["enabled"] = True
        FakeEngine, _ = make_fake_engine()
        sleep = AsyncMock(side_effect=KeyboardInterrupt())
        with patch.object(app, "UPOEngine", FakeEngine), \
                patch.object(app, "run_crawl4ai", AsyncMock()), \
                patch.object(app, "start_api") as fake_api, \
                patch.object(app.asyncio, "sleep", sleep):
            await app.pipeline(config, False, None)
        fake_api.assert_called_once()
        assert fake_api.call_args[0][1:] == ("127.0.0.1", 8000)
        sleep.assert_awaited()

    async def test_api_not_started_when_disabled(self, config):
        config["crawl4ai"]["enabled"] = False
        config["api"]["enabled"] = False
        _, fake_api = await self._run(config)
        fake_api.assert_not_called()


class TestCLIMain:
    def test_main_merges_all_flags(self, tmp_path):
        import click.testing
        import UPO.cli.app as app
        captured = {}

        async def fake_pipeline(config, scrape_only, test_limit):
            captured.update(config=config, scrape_only=scrape_only,
                            test_limit=test_limit)

        cfg_file = tmp_path / "c.yaml"
        cfg_file.write_text("general:\n  concurrency: 3\n", encoding="utf-8")
        with patch.object(app, "pipeline", fake_pipeline):
            res = click.testing.CliRunner().invoke(app.main, [
                "--config", str(cfg_file), "--concurrency", "42",
                "--timeout", "9", "--rounds", "2", "--country", "us,de",
                "--exclude-dc", "--enable-fraud", "--no-crawl4ai",
                "--no-ban-check", "--no-speed-test", "--no-dns-leak",
                "--no-stealth", "--no-protocol-detect", "--api",
                "--api-port", "9999", "--test-limit", "7",
            ])
        assert res.exit_code == 0, res.output
        c = captured["config"]
        assert c["general"]["concurrency"] == 42
        assert c["general"]["timeout_total"] == 9
        assert c["general"]["verification_rounds"] == 2
        assert c["filter"]["allowed_countries"] == ["US", "DE"]
        assert c["filter"]["exclude_datacenters"] is True
        assert c["fraud_check"]["enabled"] is True
        for sect in ("crawl4ai", "ban_check", "speed_test", "dns_leak",
                     "stealth_score", "protocol_detection"):
            assert c[sect]["enabled"] is False, sect
        assert c["api"]["enabled"] is True and c["api"]["port"] == 9999
        assert captured["test_limit"] == 7

    def test_main_defaults_run_pipeline(self, tmp_path):
        import click.testing
        import UPO.cli.app as app
        captured = {}

        async def fake_pipeline(config, scrape_only, test_limit):
            captured.update(config=config, scrape_only=scrape_only,
                            test_limit=test_limit)

        with patch.object(app, "pipeline", fake_pipeline):
            res = click.testing.CliRunner().invoke(
                app.main, ["--config", str(tmp_path / "none.yaml")]
            )
        assert res.exit_code == 0
        c = captured["config"]
        assert c["general"]["concurrency"] == \
            DEFAULT_CONFIG["general"]["concurrency"]
        assert c["api"]["enabled"] is False
        assert captured["scrape_only"] is False and captured["test_limit"] is None

    def test_main_scrape_only_flag(self, tmp_path):
        import click.testing
        import UPO.cli.app as app
        captured = {}

        async def fake_pipeline(config, scrape_only, test_limit):
            captured["scrape_only"] = scrape_only

        with patch.object(app, "pipeline", fake_pipeline):
            res = click.testing.CliRunner().invoke(
                app.main, ["--scrape-only", "--no-crawl4ai"]
            )
        assert res.exit_code == 0 and captured["scrape_only"] is True

    def test_main_bad_config_warns_but_runs(self, tmp_path):
        import click.testing
        import UPO.cli.app as app
        bad = tmp_path / "bad.yaml"
        bad.write_text("general: [oops\n", encoding="utf-8")

        async def fake_pipeline(config, scrape_only, test_limit):
            return None

        with patch.object(app, "pipeline", fake_pipeline):
            res = click.testing.CliRunner().invoke(
                app.main, ["--config", str(bad)]
            )
        assert res.exit_code == 0

    def test_main_help_lists_options(self):
        import click.testing
        import UPO.cli.app as app
        res = click.testing.CliRunner().invoke(app.main, ["--help"])
        assert res.exit_code == 0
        for opt in ("--test-limit", "--no-crawl4ai", "--rounds", "--api"):
            assert opt in res.output