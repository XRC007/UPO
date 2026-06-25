import pytest
import asyncio
import os
import json
import copy
import time
import sqlite3
import random
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from UPO import (
    UPOEngine, DEFAULT_CONFIG, Proxy, ProxyType, ProxyProtocol,
    AnonymityLevel, SpeedTier, IPFilter, ProxyHistory, RateLimiter,
    PROXY_REGEX, VerifiedProxyDB
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dir(tmp_path):
    (tmp_path / "output").mkdir()
    (tmp_path / "data").mkdir()
    return tmp_path


@pytest.fixture
def config(temp_dir):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["history"]["db_path"] = str(temp_dir / "data" / "history.db")
    cfg["output"]["dir"] = str(temp_dir / "output")
    cfg["geoip"]["enabled"] = False
    cfg["stealth_score"]["enabled"] = True
    cfg["ban_check"]["enabled"] = True
    cfg["speed_test"]["enabled"] = True
    cfg["dns_leak"]["enabled"] = True
    cfg["protocol_detection"]["enabled"] = True
    cfg["fraud_check"]["enabled"] = False
    cfg["general"]["verification_rounds"] = 1
    cfg["general"]["concurrency"] = 10
    cfg["filter"]["blacklist"] = str(temp_dir / "data" / "blacklist.txt")
    cfg["crawl4ai"]["enabled"] = False
    cfg["api"]["enabled"] = False
    cfg["verified_db"]["db_path"] = str(temp_dir / "data" / "verified_proxies.db")
    cfg["checked_output"]["dir"] = str(temp_dir / "checked")
    return cfg


@pytest.fixture
def engine(config):
    eng = UPOEngine(config)
    eng.my_ip = "1.2.3.4"
    eng.my_dns_ip = "1.2.3.4"
    return eng


# ============================================================================
# Dummy Response & Session Helpers
# ============================================================================

class DummyResponse:
    def __init__(self, text_resp="9.9.9.9", json_resp=None, status=200):
        self.status = status
        self._text = str(text_resp) if text_resp is not None else ""
        self._json = json_resp or {}
        self._content = self._text.encode("utf-8")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def text(self):
        return self._text

    async def json(self):
        return self._json

    async def read(self):
        return self._content


def make_session_mock(responses=None):
    def side_effect(url, *args, **kwargs):
        u = str(url)
        if responses:
            for pattern, resp in responses.items():
                if pattern in u:
                    return resp
        if "httpbin.org/headers" in u:
            return DummyResponse(json_resp={"headers": {}})
        if "httpbin.org/ip" in u:
            return DummyResponse(json_resp={"origin": "9.9.9.9"})
        if "1.1.1.1/cdn-cgi/trace" in u:
            return DummyResponse(text_resp="fl=1\nip=9.9.9.9\ntls=TLSv1.3\nhttp=h2")
        if "ipinfo.io" in u:
            return DummyResponse(json_resp={"privacy": {}})
        if "iphub.info" in u:
            return DummyResponse(json_resp={"block": 0})
        if "getipintel" in u:
            return DummyResponse(text_resp="0.10")
        if "ipqualityscore" in u:
            return DummyResponse(json_resp={"success": True, "fraud_score": 10})
        if "google.com" in u:
            return DummyResponse(text_resp="google search results")
        if "bing.com" in u:
            return DummyResponse(text_resp="bing search results")
        if "speed.cloudflare" in u:
            return DummyResponse(text_resp="x" * 102400)
        if "ipify" in u:
            return DummyResponse(text_resp="9.9.9.9")
        if "icanhazip" in u:
            return DummyResponse(text_resp="9.9.9.9")
        if "checkip.amazonaws" in u:
            return DummyResponse(text_resp="9.9.9.9")
        return DummyResponse(text_resp="9.9.9.9")

    m = MagicMock()
    m.get = MagicMock(side_effect=side_effect)
    m.close = AsyncMock()
    m.__aenter__ = AsyncMock(return_value=m)
    m.__aexit__ = AsyncMock(return_value=False)
    return m


# ============================================================================
# Proxy Data Model
# ============================================================================

class TestProxy:
    def test_basic_creation(self):
        p = Proxy(ip="8.8.8.8", port=8080, protocol=ProxyProtocol.HTTP)
        assert p.ip == "8.8.8.8"
        assert p.port == 8080
        assert p.alive is False
        assert p.proxy_type == ProxyType.UNKNOWN

    def test_address(self):
        p = Proxy("8.8.8.8", 8080, ProxyProtocol.HTTP)
        assert p.address == "8.8.8.8:8080"

    def test_url_http(self):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        assert p.url == "http://8.8.8.8:80"

    def test_url_socks5(self):
        p = Proxy("1.1.1.1", 1080, ProxyProtocol.SOCKS5)
        assert p.url == "socks5://1.1.1.1:1080"

    def test_id(self):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        assert p.id == "8.8.8.8:80:http"

    def test_to_dict_full(self):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        p.speed_tier = SpeedTier.FAST
        p.proxy_type = ProxyType.RESIDENTIAL
        d = p.to_dict()
        assert d["protocol"] == "http"
        assert d["anonymity"] == "elite"
        assert d["speed_tier"] == "fast"
        assert d["proxy_type"] == "residential"
        assert "uptime_history" not in d

    def test_to_dict_none_enums(self):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        d = p.to_dict()
        assert d["anonymity"] is None
        assert d["speed_tier"] is None

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            Proxy("8.8.8.8", "abc", ProxyProtocol.HTTP)

    def test_port_string_cast(self):
        p = Proxy("8.8.8.8", "8080", ProxyProtocol.HTTP)
        assert p.port == 8080

    def test_defaults(self):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        assert p.first_seen is not None
        assert p.uptime_history == []
        assert p.detected_protocols == []
        assert p.check_count == 0
        assert p.reliability == 0.0


# ============================================================================
# Enums
# ============================================================================

class TestEnums:
    def test_all_protocols(self):
        assert ProxyProtocol.HTTP.value == "http"
        assert ProxyProtocol.HTTPS.value == "https"
        assert ProxyProtocol.SOCKS4.value == "socks4"
        assert ProxyProtocol.SOCKS5.value == "socks5"

    def test_all_anonymity(self):
        assert AnonymityLevel.TRANSPARENT.value == "transparent"
        assert AnonymityLevel.ANONYMOUS.value == "anonymous"
        assert AnonymityLevel.ELITE.value == "elite"

    def test_all_speed(self):
        assert SpeedTier.FAST.value == "fast"
        assert SpeedTier.MEDIUM.value == "medium"
        assert SpeedTier.SLOW.value == "slow"


# ============================================================================
# IP Filter
# ============================================================================

class TestIPFilter:
    def test_private_ranges(self):
        flt = IPFilter()
        assert flt.is_private("192.168.1.1")
        assert flt.is_private("10.0.0.1")
        assert flt.is_private("172.16.0.1")
        assert flt.is_private("127.0.0.1")
        assert flt.is_private("169.254.1.1")
        assert flt.is_private("100.64.0.1")
        assert flt.is_private("0.0.0.1")
        assert not flt.is_private("8.8.8.8")

    def test_private_invalid(self):
        assert IPFilter().is_private("not_ip") is True

    def test_cloudflare(self):
        flt = IPFilter()
        assert flt.is_cloudflare("104.16.1.1")
        assert not flt.is_cloudflare("8.8.8.8")

    def test_cloudflare_invalid(self):
        assert IPFilter().is_cloudflare("bad") is True

    def test_filter_batch_private(self):
        flt = IPFilter()
        proxies = {
            "8.8.8.8:80": Proxy("8.8.8.8", 80, ProxyProtocol.HTTP),
            "192.168.1.1:80": Proxy("192.168.1.1", 80, ProxyProtocol.HTTP),
        }
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": []}}
        valid, stats = flt.filter_batch(proxies, cfg)
        assert "8.8.8.8:80" in valid
        assert stats.get("private_ip") == 1

    def test_filter_batch_invalid_ip(self):
        flt = IPFilter()
        p = Proxy.__new__(Proxy)
        p.ip = "invalid"
        p.port = 80
        p.protocol = ProxyProtocol.HTTP
        p.country_code = None
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": []}}
        valid, stats = flt.filter_batch({"x:80": p}, cfg)
        assert len(valid) == 0
        assert stats["invalid_ip"] == 1

    def test_filter_batch_bad_port_low(self):
        flt = IPFilter()
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.port = 0
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": []}}
        valid, stats = flt.filter_batch({"8.8.8.8:0": p}, cfg)
        assert stats.get("invalid_port") == 1

    def test_filter_batch_bad_port_high(self):
        flt = IPFilter()
        p = Proxy("8.8.8.8", 99999, ProxyProtocol.HTTP)
        p.port = 99999
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": []}}
        valid, _ = flt.filter_batch({"x": p}, cfg)
        assert len(valid) == 0

    def test_filter_batch_cloudflare(self):
        flt = IPFilter()
        p = Proxy("104.16.1.1", 80, ProxyProtocol.HTTP)
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": []}}
        valid, stats = flt.filter_batch({"x": p}, cfg)
        assert stats.get("cloudflare_ip") == 1

    def test_filter_batch_allowed_country_pass(self):
        flt = IPFilter()
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.country_code = "US"
        cfg = {"filter": {"allowed_countries": ["US"], "blocked_countries": []}}
        valid, _ = flt.filter_batch({"x": p}, cfg)
        assert len(valid) == 1

    def test_filter_batch_allowed_country_fail(self):
        flt = IPFilter()
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.country_code = "DE"
        cfg = {"filter": {"allowed_countries": ["US"], "blocked_countries": []}}
        valid, stats = flt.filter_batch({"x": p}, cfg)
        assert stats.get("country_filtered") == 1

    def test_filter_batch_blocked_country(self):
        flt = IPFilter()
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.country_code = "CN"
        cfg = {"filter": {"allowed_countries": [], "blocked_countries": ["CN"]}}
        valid, stats = flt.filter_batch({"x": p}, cfg)
        assert stats.get("country_blocked") == 1


# ============================================================================
# Proxy History
# ============================================================================

class TestProxyHistory:
    def test_insert_and_stats(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.country_code = "US"
        p.asn = 15169
        p.isp = "Google"
        p.proxy_type = ProxyType.DATACENTER
        p.anonymity = AnonymityLevel.ELITE
        h.update(p)
        s = h.get_stats()
        assert s["total_tracked"] == 1
        assert s["total_checks"] == 1

    def test_update_existing(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        h.update(p)
        p.latency_ms = 200
        h.update(p)
        assert h.get_stats()["total_checks"] == 2

    def test_update_dead(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = False
        p.latency_ms = None
        p.proxy_type = None  # edge case
        h.update(p)
        assert h.get_stats()["total_tracked"] == 1

    def test_cached_score_roundtrip(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        h.save_cached_score("8.8.8.8", 15)
        assert h.get_cached_score("8.8.8.8") == 15

    def test_cached_score_missing(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        assert h.get_cached_score("9.9.9.9") is None

    def test_cached_score_overwrite(self, temp_dir):
        h = ProxyHistory(str(temp_dir / "data" / "h.db"))
        h.save_cached_score("8.8.8.8", 10)
        h.save_cached_score("8.8.8.8", 30)
        assert h.get_cached_score("8.8.8.8") == 30

    def test_creates_parent_dir(self, tmp_path):
        db = str(tmp_path / "deep" / "nested" / "h.db")
        h = ProxyHistory(db)
        assert Path(db).parent.exists()


# ============================================================================
# Verified Proxy DB
# ============================================================================

class TestVerifiedProxyDB:
    def test_init_and_count(self, temp_dir):
        db_path = str(temp_dir / "data" / "v.db")
        v = VerifiedProxyDB(db_path)
        assert v.count() == 0

    def test_save_and_load(self, temp_dir):
        db_path = str(temp_dir / "data" / "v2.db")
        v = VerifiedProxyDB(db_path)
        p = Proxy("1.2.3.4", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.RESIDENTIAL
        v.save_all([p])
        assert v.count() == 1
        all_px = v.load_all()
        assert len(all_px) == 1
        assert all_px[0]["ip"] == "1.2.3.4"

    def test_save_empty_clears(self, temp_dir):
        db_path = str(temp_dir / "data" / "v3.db")
        v = VerifiedProxyDB(db_path)
        p = Proxy("1.2.3.4", 80, ProxyProtocol.HTTP)
        v.save_all([p])
        v.save_all([])
        assert v.count() == 0

    def test_save_error_logs(self, temp_dir):
        db_path = str(temp_dir / "data" / "v4.db")
        v = VerifiedProxyDB(db_path)
        mock_conn = MagicMock()
        mock_conn.execute = MagicMock(side_effect=sqlite3.Error("fail"))
        mock_conn.close = MagicMock()
        with patch.object(v, "_conn", return_value=mock_conn):
            v.save_all([Proxy("8.8.8.8", 1, ProxyProtocol.HTTP)])  # no crash

    def test_creates_parent_dir(self, tmp_path):
        db = str(tmp_path / "deep" / "nested" / "v.db")
        v = VerifiedProxyDB(db)
        assert Path(db).parent.exists()

    def test_load_empty(self, temp_dir):
        v = VerifiedProxyDB(str(temp_dir / "data" / "v5.db"))
        assert v.load_all() == []

    def test_save_none_enums(self, temp_dir):
        v = VerifiedProxyDB(str(temp_dir / "data" / "v6.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = None
        p.proxy_type = None
        v.save_all([p])
        assert v.count() == 1

# ============================================================================
# Rate Limiter
# ============================================================================

class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_zero_rate(self):
        lim = RateLimiter(0)
        await lim.wait()

    @pytest.mark.asyncio
    async def test_high_rate(self):
        lim = RateLimiter(60000)
        await lim.wait()
        await lim.wait()


# ============================================================================
# Parsing
# ============================================================================

class TestParsing:
    def test_parse_text_basic(self, engine):
        engine._parse_text("9.9.9.9:8080\n1.2.3.4:1080", ProxyProtocol.HTTP, "t")
        assert len(engine.proxies) == 2

    def test_parse_text_with_protocol(self, engine):
        engine._parse_text("socks5://5.5.5.5:1080", ProxyProtocol.HTTP, "t")
        p = list(engine.proxies.values())[0]
        assert p.protocol == ProxyProtocol.SOCKS5

    def test_parse_text_dedup(self, engine):
        engine._parse_text("9.9.9.9:8080\n9.9.9.9:8080", ProxyProtocol.HTTP, "t")
        assert len(engine.proxies) == 1

    def test_parse_json_array(self, engine):
        engine._parse_json(json.dumps([
            {"ip": "2.2.2.2", "port": "3128", "protocols": ["socks5"]},
            {"ip": "3.3.3.3", "port": "8080", "protocols": ["http"]},
        ]), "t")
        assert len(engine.proxies) == 2

    def test_parse_json_dict_data(self, engine):
        engine._parse_json(json.dumps({
            "data": [{"ip": "2.2.2.2", "port": "3128", "protocols": ["http"]}]
        }), "t")
        assert len(engine.proxies) == 1

    def test_parse_json_no_protocols(self, engine):
        engine._parse_json(json.dumps([{"ip": "2.2.2.2", "port": "3128"}]), "t")
        p = list(engine.proxies.values())[0]
        assert p.protocol == ProxyProtocol.HTTP

    def test_parse_json_invalid(self, engine):
        engine._parse_json("not json", "t")
        assert len(engine.proxies) == 0

    def test_parse_json_bad_entry(self, engine):
        engine._parse_json(json.dumps([{"ip": "", "port": "abc"}]), "t")
        assert len(engine.proxies) == 0

    def test_parse_json_empty_protocols_list(self, engine):
        engine._parse_json(json.dumps([
            {"ip": "2.2.2.2", "port": "3128", "protocols": []}
        ]), "t")
        assert len(engine.proxies) == 1


# ============================================================================
# Validate Judge
# ============================================================================

class TestValidateJudge:
    def test_json_origin(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge('{"origin": "9.9.9.9"}', p, 150)
        assert p.alive and p.latency_ms == 150

    def test_json_ip(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge('{"ip": "5.5.5.5"}', p, 100)
        assert p.alive

    def test_json_query(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge('{"query": "5.5.5.5"}', p, 100)
        assert p.alive

    def test_text_ip_regex(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge("Your IP is 9.9.9.9 today", p, 200)
        assert p.alive

    def test_empty_body(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge("", p, 100)
        assert not p.alive

    def test_body_too_large(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge("x" * 6000, p, 100)
        assert not p.alive

    def test_own_ip_leak(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge("1.2.3.4", p, 100)
        assert not p.alive

    def test_no_ip_found(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge("no ip here", p, 100)
        assert not p.alive

    def test_uptime_history_cap(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.uptime_history = [True] * 100
        p.check_count = 1
        engine._validate_judge('{"origin": "9.9.9.9"}', p, 100)
        assert len(p.uptime_history) == 100

    def test_success_count_incremented(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 1
        engine._validate_judge('{"origin": "9.9.9.9"}', p, 100)
        assert p.success_count == 1


# ============================================================================
# Stealth Score
# ============================================================================

class TestStealthScore:
    def test_max_score(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE        # +30
        p.proxy_type = ProxyType.MOBILE            # +30
        p.tcp_fingerprint = "modern"               # +15
        p.supports_https = True                    # +10
        p.latency_ms = 100                         # +10
        p.composite_score = 10                     # +5
        p.dns_leak = False
        engine._calc_stealth(p)
        assert p.stealth_score == 100

    def test_anonymous_residential(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ANONYMOUS     # +15
        p.proxy_type = ProxyType.RESIDENTIAL       # +25
        p.tcp_fingerprint = "tls13"                # +10
        p.supports_https = True                    # +10
        p.latency_ms = 800                         # +5
        engine._calc_stealth(p)
        assert p.stealth_score == 65

    def test_transparent_datacenter_penalty(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.TRANSPARENT   # +0
        p.proxy_type = ProxyType.DATACENTER        # +5
        p.tcp_fingerprint = "tls12_legacy"         # +0
        p.supports_https = False                   # +0
        p.latency_ms = 5000                        # +0
        p.composite_score = 90                     # -10
        p.dns_leak = True                          # -15
        engine._calc_stealth(p)
        assert p.stealth_score == 0  # clamped to 0

    def test_unknown_type_unknown_fp(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE         # +30
        p.proxy_type = ProxyType.UNKNOWN           # +15
        p.tcp_fingerprint = "unknown"              # +5
        engine._calc_stealth(p)
        assert p.stealth_score == 50

    def test_no_composite(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.RESIDENTIAL
        p.composite_score = None
        engine._calc_stealth(p)
        assert p.stealth_score is not None

    def test_clean_ip_bonus(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.RESIDENTIAL
        p.composite_score = 15
        engine._calc_stealth(p)
        s1 = p.stealth_score
        p.composite_score = None
        engine._calc_stealth(p)
        s2 = p.stealth_score
        assert s1 > s2  # clean bonus made it higher

    def test_bad_ip_penalty(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.RESIDENTIAL
        p.composite_score = 85
        engine._calc_stealth(p)
        s1 = p.stealth_score
        p.composite_score = None
        engine._calc_stealth(p)
        s2 = p.stealth_score
        assert s1 < s2  # penalty made it lower

    def test_medium_latency(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        p.proxy_type = ProxyType.UNKNOWN
        p.latency_ms = 800
        engine._calc_stealth(p)
        # medium latency gives +5
        p2 = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p2.anonymity = AnonymityLevel.ELITE
        p2.proxy_type = ProxyType.UNKNOWN
        p2.latency_ms = 100
        engine._calc_stealth(p2)
        assert p2.stealth_score > p.stealth_score


# ============================================================================
# Filter Garbage
# ============================================================================

class TestFilterGarbage:
    def test_blacklist(self, engine):
        engine.blacklist = {"3.3.3.3"}
        engine.proxies = {
            "3.3.3.3:80": Proxy("3.3.3.3", 80, ProxyProtocol.HTTP),
            "8.8.8.8:80": Proxy("8.8.8.8", 80, ProxyProtocol.HTTP),
        }
        engine.filter_garbage()
        assert len(engine.proxies) == 1

    def test_cdn_removal(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.asn = 13335
        engine.proxies = {"8.8.8.8:80": p}
        engine.filter_garbage()
        assert len(engine.proxies) == 0

    def test_exclude_datacenters(self, engine):
        engine.config["filter"]["exclude_datacenters"] = True
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.proxy_type = ProxyType.DATACENTER
        engine.proxies = {"8.8.8.8:80": p}
        engine.filter_garbage()
        assert len(engine.proxies) == 0

    def test_stats_updated(self, engine):
        engine.proxies = {
            "192.168.1.1:80": Proxy("192.168.1.1", 80, ProxyProtocol.HTTP),
            "8.8.8.8:80": Proxy("8.8.8.8", 80, ProxyProtocol.HTTP),
        }
        engine.filter_garbage()
        assert engine.stats["filtered"] == 1


# ============================================================================
# Enrich & Categorize
# ============================================================================

class TestEnrichCategorize:
    def test_speed_fast(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.speed_tier == SpeedTier.FAST

    def test_speed_medium(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 1500
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.speed_tier == SpeedTier.MEDIUM

    def test_speed_slow(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 3000
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.speed_tier == SpeedTier.SLOW

    def test_min_anonymity_blocks(self, engine):
        engine.config["filter"]["min_anonymity"] = "elite"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.anonymity = AnonymityLevel.ANONYMOUS
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.alive is False

    def test_min_anonymity_passes(self, engine):
        engine.config["filter"]["min_anonymity"] = "elite"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.anonymity = AnonymityLevel.ELITE
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.alive is True

    def test_avg_latency_first(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 200
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.avg_latency_ms == 200.0

    def test_avg_latency_running(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 200
        p.avg_latency_ms = 100.0
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.avg_latency_ms == 150.0

    def test_stealth_calculated(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.anonymity = AnonymityLevel.ELITE
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.stealth_score is not None

    def test_stealth_disabled(self, engine):
        engine.config["stealth_score"]["enabled"] = False
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.stealth_score is None

    def test_dead_skipped(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = False
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert p.speed_tier is None

    def test_history_update(self, engine, temp_dir):
        engine.history = ProxyHistory(str(temp_dir / "data" / "h2.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        engine.proxies = {p.address: p}
        engine.enrich_and_categorize()
        assert engine.history.get_stats()["total_tracked"] == 1


# ============================================================================
# Export
# ============================================================================

class TestExport:
    def _alive(self, **kw):
        defaults = dict(
            alive=True, latency_ms=100, anonymity=AnonymityLevel.ELITE,
            speed_tier=SpeedTier.FAST, proxy_type=ProxyType.RESIDENTIAL,
            stealth_score=85, composite_score=10, country_code="US",
            supports_https=True, download_speed_kbps=500.0,
            detected_protocols=["http", "socks5"], dns_leak=False,
        )
        defaults.update(kw)
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        for k, v in defaults.items():
            setattr(p, k, v)
        return p

    def test_all_formats(self, engine):
        p1 = self._alive()
        p2 = Proxy("9.9.9.9", 1080, ProxyProtocol.SOCKS5)
        p2.alive = True
        p2.latency_ms = 200
        engine.proxies = {p1.address: p1, p2.address: p2}
        engine.export()
        out = Path(engine.config["output"]["dir"])
        assert (out / "all.json").exists()
        assert (out / "all.csv").exists()
        assert (out / "http.txt").exists()

    def test_special_lists(self, engine):
        p = self._alive()
        engine.proxies = {p.address: p}
        engine.export()
        out = Path(engine.config["output"]["dir"])
        assert (out / "elite.txt").exists()
        assert (out / "fast.txt").exists()
        assert (out / "residential.txt").exists()
        assert (out / "stealth.txt").exists()
        assert (out / "clean.txt").exists()

    def test_checked_output(self, engine):
        engine.config["checked_output"] = {"enabled": True, "dir": str(Path(engine.config["output"]["dir"]) / "checked")}
        p = self._alive()
        engine.proxies = {p.address: p}
        engine.export()
        checked_dir = Path(engine.config["checked_output"]["dir"])
        assert checked_dir.exists()
        assert any(checked_dir.glob("proxies_*.txt"))

    def test_verified_db_update(self, engine, temp_dir):
        vdb = VerifiedProxyDB(str(temp_dir / "data" / "v_export.db"))
        engine.verified_db = vdb
        p = self._alive()
        engine.proxies = {p.address: p}
        engine.export()
        assert vdb.count() == 1

    def test_verified_db_update_empty(self, engine, temp_dir):
        vdb = VerifiedProxyDB(str(temp_dir / "data" / "v_export_empty.db"))
        vdb.save_all([Proxy("1.1.1.1", 1, ProxyProtocol.HTTP)])
        engine.verified_db = vdb
        engine.proxies = {}
        engine.export()
        assert vdb.count() == 0

    def test_mobile_list(self, engine):
        engine.config["output"]["generate_mobile_list"] = True
        p = self._alive(proxy_type=ProxyType.MOBILE)
        engine.proxies = {p.address: p}
        engine.export()
        out = Path(engine.config["output"]["dir"])
        assert (out / "mobile.txt").exists()

    def test_country_split(self, engine):
        engine.config["output"]["split_by_country"] = True
        p = self._alive()
        engine.proxies = {p.address: p}
        engine.export()
        assert (Path(engine.config["output"]["dir"]) / "country_us.txt").exists()

    def test_no_alive(self, engine):
        engine.proxies = {}
        engine.export()  # no crash


# ============================================================================
# Print Stats
# ============================================================================

class TestPrintStats:
    def test_comprehensive(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        p.anonymity = AnonymityLevel.ELITE
        p.speed_tier = SpeedTier.FAST
        p.proxy_type = ProxyType.RESIDENTIAL
        p.country_code = "US"
        p.stealth_score = 85
        p.composite_score = 10
        p.download_speed_kbps = 500.0
        p.dns_leak = False
        p.detected_protocols = ["http", "socks5"]
        p.supports_https = True
        engine.proxies = {p.address: p}
        stats = engine.print_stats()
        assert stats["alive"] == 1
        assert stats["elite"] == 1
        assert stats["fast"] == 1

    def test_empty(self, engine):
        engine.proxies = {}
        stats = engine.print_stats()
        assert stats["alive"] == 0


# ============================================================================
# Verification
# ============================================================================

class TestVerification:
    @pytest.mark.asyncio
    async def test_check_one_success(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._check_one(p, "http://j.com")
        assert p.check_count == 1

    @pytest.mark.asyncio
    async def test_check_one_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._check_one(p, "http://j.com")
        assert not p.alive and p.fail_count == 1

    @pytest.mark.asyncio
    async def test_check_one_exception(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=Exception("fail"))
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._check_one(p, "http://j.com")
        assert not p.alive

    @pytest.mark.asyncio
    async def test_check_one_non_200(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"j.com": DummyResponse(status=503)})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._check_one(p, "http://j.com/check")
        assert not p.alive

    @pytest.mark.asyncio
    async def test_verify_no_proxies(self, engine):
        engine.proxies = {}
        await engine.verify()

    @pytest.mark.asyncio
    async def test_verify_no_judges(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = []
            await engine.verify()

    @pytest.mark.asyncio
    async def test_verify_single_round(self, engine):
        engine.judges = [("http://j.com", 0.1)]
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = [("http://j.com", 0.1)]
            with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
                await engine.verify()

    @pytest.mark.asyncio
    async def test_verify_two_rounds(self, engine):
        engine.config["general"]["verification_rounds"] = 2
        engine.judges = [("http://j1.com", 0.1), ("http://j2.com", 0.2)]
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = [("http://j1.com", 0.1), ("http://j2.com", 0.2)]
            with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
                await engine.verify()

    @pytest.mark.asyncio
    async def test_reliability_2round_fail(self, engine):
        """FIX #2: 0.5 reliability fails in 2-round mode"""
        engine.config["general"]["verification_rounds"] = 2
        engine.judges = [("http://j.com", 0.1), ("http://j2.com", 0.2)]
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 2
        p.success_count = 1
        engine.proxies = {p.address: p}
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = [("http://j.com", 0.1), ("http://j2.com", 0.2)]
            with patch.object(engine, "_check_one", new_callable=AsyncMock):
                await engine.verify()
        assert not p.alive

    @pytest.mark.asyncio
    async def test_reliability_3round_pass(self, engine):
        """3+ rounds: >= 0.5 passes"""
        engine.config["general"]["verification_rounds"] = 3
        engine.judges = [("http://j.com", 0.1)] * 3
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 3
        p.success_count = 2
        p.alive = True
        engine.proxies = {p.address: p}
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = [("http://j.com", 0.1)] * 3
            with patch.object(engine, "_check_one", new_callable=AsyncMock):
                await engine.verify()
        assert p.alive

    @pytest.mark.asyncio
    async def test_reliability_zero_checks(self, engine):
        engine.judges = [("http://j.com", 0.1)]
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.check_count = 0
        p.success_count = 0
        engine.proxies = {p.address: p}
        with patch.object(engine, "test_judges", new_callable=AsyncMock):
            engine.judges = [("http://j.com", 0.1)]
            with patch.object(engine, "_check_one", new_callable=AsyncMock):
                await engine.verify()
        assert not p.alive


# ============================================================================
# Anonymity
# ============================================================================

class TestAnonymity:
    @pytest.mark.asyncio
    async def test_elite(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({
            "httpbin.org/headers": DummyResponse(
                json_resp={"headers": {"Host": "httpbin.org"}}
            )
        })
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ELITE

    @pytest.mark.asyncio
    async def test_transparent(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({
            "httpbin.org/headers": DummyResponse(
                json_resp={"headers": {"X-Forwarded-For": "1.2.3.4"}}
            )
        })
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.TRANSPARENT

    @pytest.mark.asyncio
    async def test_anonymous_via(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({
            "httpbin.org/headers": DummyResponse(
                json_resp={"headers": {"Via": "1.1 proxy"}}
            )
        })
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ANONYMOUS

    @pytest.mark.asyncio
    async def test_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ANONYMOUS

    @pytest.mark.asyncio
    async def test_timeout(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=asyncio.TimeoutError)
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ANONYMOUS

    @pytest.mark.asyncio
    async def test_non_200(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"httpbin.org/headers": DummyResponse(status=503)})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ANONYMOUS

    @pytest.mark.asyncio
    async def test_generic_exception(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=ValueError("odd error"))
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._anon_check_one(p)
        assert p.anonymity == AnonymityLevel.ANONYMOUS

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.check_anonymity()
        assert p.anonymity is not None

    @pytest.mark.asyncio
    async def test_no_my_ip(self, engine):
        engine.my_ip = None
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        await engine.check_anonymity()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.check_anonymity()


# ============================================================================
# Protocol Detection
# ============================================================================

class TestProtocolDetection:
    @pytest.mark.asyncio
    async def test_detect_one(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._detect_protocols_one(p, "http://j.com")
        assert len(p.detected_protocols) > 0

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        engine.judges = [("http://j.com", 0.1)] * 5
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.detect_protocols()

    @pytest.mark.asyncio
    async def test_disabled(self, engine):
        engine.config["protocol_detection"]["enabled"] = False
        await engine.detect_protocols()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.detect_protocols()

    @pytest.mark.asyncio
    async def test_no_session_skips(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._detect_protocols_one(p, "http://j.com")
        assert p.detected_protocols == []


# ============================================================================
# Speed Test
# ============================================================================

class TestSpeedTest:
    @pytest.mark.asyncio
    async def test_speed_one(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)

        class SpeedResponse:
            status = 200
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                pass
            async def read(self):
                return b"x" * 102400

        sess = MagicMock()
        sess.get = MagicMock(return_value=SpeedResponse())
        sess.close = AsyncMock()

        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._speed_test_one(p, "https://speed.cloudflare.com/__down?bytes=102400")
        assert p.download_speed_kbps is not None

    @pytest.mark.asyncio
    async def test_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._speed_test_one(p, "http://t.com")
        assert p.download_speed_kbps is None

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.speed_test()

    @pytest.mark.asyncio
    async def test_disabled(self, engine):
        engine.config["speed_test"]["enabled"] = False
        await engine.speed_test()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.speed_test()


# ============================================================================
# Fingerprint
# ============================================================================

class TestFingerprint:
    @pytest.mark.asyncio
    async def test_modern(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="tls=TLSv1.3\nhttp=h2")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint == "modern"

    @pytest.mark.asyncio
    async def test_tls13(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="tls=TLSv1.3\nhttp=http/1.1")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint == "tls13"

    @pytest.mark.asyncio
    async def test_tls12(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="tls=TLSv1.2\nhttp=http/1.1")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint == "tls12_legacy"

    @pytest.mark.asyncio
    async def test_unknown(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="tls=TLSv1.0\nhttp=1.0")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint == "unknown"

    @pytest.mark.asyncio
    async def test_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint is None

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.fingerprint()

    @pytest.mark.asyncio
    async def test_disabled(self, engine):
        engine.config["stealth_score"]["enabled"] = False
        await engine.fingerprint()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.fingerprint()

    @pytest.mark.asyncio
    async def test_exception(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=Exception("fail"))
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._fingerprint_one(p)
        assert p.tcp_fingerprint is None


# ============================================================================
# DNS Leak
# ============================================================================

class TestDNSLeak:
    @pytest.mark.asyncio
    async def test_leak_detected(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="ip=1.2.3.4\ntls=TLSv1.3")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._dns_leak_one(p)
        assert p.dns_leak is True

    @pytest.mark.asyncio
    async def test_leak_clean(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"1.1.1.1/cdn-cgi/trace": DummyResponse(
            text_resp="ip=9.9.9.9\ntls=TLSv1.3")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._dns_leak_one(p)
        assert p.dns_leak is False

    @pytest.mark.asyncio
    async def test_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            await engine._dns_leak_one(p)
        assert p.dns_leak is None

    @pytest.mark.asyncio
    async def test_exception(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=Exception("fail"))
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine._dns_leak_one(p)
        assert p.dns_leak is None

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.dns_leak_check()

    @pytest.mark.asyncio
    async def test_disabled(self, engine):
        engine.config["dns_leak"]["enabled"] = False
        await engine.dns_leak_check()

    @pytest.mark.asyncio
    async def test_no_my_ip(self, engine):
        engine.my_ip = None
        await engine.dns_leak_check()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.dns_leak_check()


# ============================================================================
# Ban Check
# ============================================================================

class TestBanCheck:
    @pytest.mark.asyncio
    async def test_banned(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"google.com": DummyResponse(text_resp="blocked")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            r = await engine._ban_check_one(p, "http://google.com", "google")
        assert r is True

    @pytest.mark.asyncio
    async def test_not_banned(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"google.com": DummyResponse(text_resp="google results")})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            r = await engine._ban_check_one(p, "http://google.com/s", "google")
        assert r is False

    @pytest.mark.asyncio
    async def test_no_session(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        with patch.object(engine, "_create_proxy_session", return_value=(None, {})):
            r = await engine._ban_check_one(p, "http://g.com", "g")
        assert r is True

    @pytest.mark.asyncio
    async def test_exception(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = MagicMock()
        sess.get = MagicMock(side_effect=Exception("fail"))
        sess.close = AsyncMock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            r = await engine._ban_check_one(p, "http://g.com", "g")
        assert r is True

    @pytest.mark.asyncio
    async def test_non_200(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        sess = make_session_mock({"google.com": DummyResponse(status=403)})
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            r = await engine._ban_check_one(p, "http://google.com/s", "google")
        assert r is True

    @pytest.mark.asyncio
    async def test_orchestrator(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        engine.proxies = {p.address: p}
        sess = make_session_mock()
        with patch.object(engine, "_create_proxy_session", return_value=(sess, {})):
            await engine.check_bans()

    @pytest.mark.asyncio
    async def test_disabled(self, engine):
        engine.config["ban_check"]["enabled"] = False
        await engine.check_bans()

    @pytest.mark.asyncio
    async def test_no_alive(self, engine):
        engine.proxies = {}
        await engine.check_bans()


# ============================================================================
# Fraud Scoring
# ============================================================================

class TestFraudScoring:
    @pytest.mark.asyncio
    async def test_cached(self, engine, temp_dir):
        engine.history = ProxyHistory(str(temp_dir / "data" / "f.db"))
        engine.history.save_cached_score("8.8.8.8", 25)
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        await engine._waterfall_one(p, make_session_mock())
        assert p.composite_score == 25
        assert engine.stats["api_calls"]["cache_hits"] >= 1

    @pytest.mark.asyncio
    async def test_ipinfo_vpn(self, engine):
        engine.config["fraud_check"]["keys"]["ipinfo"] = "k"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"ipinfo.io": DummyResponse(
            json_resp={"privacy": {"vpn": True, "proxy": False, "tor": False, "hosting": False}})})
        await engine._waterfall_one(p, shared)
        assert p.is_vpn is True
        assert p.composite_score is not None

    @pytest.mark.asyncio
    async def test_ipinfo_tor(self, engine):
        engine.config["fraud_check"]["keys"]["ipinfo"] = "k"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"ipinfo.io": DummyResponse(
            json_resp={"privacy": {"vpn": False, "proxy": False, "tor": True, "hosting": False}})})
        await engine._waterfall_one(p, shared)
        assert p.is_tor is True

    @pytest.mark.asyncio
    async def test_ipinfo_hosting_proxy(self, engine):
        engine.config["fraud_check"]["keys"]["ipinfo"] = "k"
        engine.config["fraud_check"]["keys"]["iphub"] = ""
        engine.config["fraud_check"]["keys"]["getipintel_email"] = ""
        engine.config["fraud_check"]["keys"]["ipqs"] = ""
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"ipinfo.io": DummyResponse(
            json_resp={"privacy": {"vpn": False, "proxy": True, "tor": False, "hosting": True}})})
        await engine._waterfall_one(p, shared)
        assert p.is_hosting is True

    @pytest.mark.asyncio
    async def test_iphub_block1(self, engine):
        engine.config["fraud_check"]["keys"]["ipinfo"] = ""
        engine.config["fraud_check"]["keys"]["iphub"] = "k"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"iphub.info": DummyResponse(json_resp={"block": 1})})
        await engine._waterfall_one(p, shared)
        assert p.composite_score is not None

    @pytest.mark.asyncio
    async def test_iphub_block0(self, engine):
        engine.config["fraud_check"]["keys"]["ipinfo"] = ""
        engine.config["fraud_check"]["keys"]["iphub"] = "k"
        engine.config["fraud_check"]["keys"]["getipintel_email"] = ""
        engine.config["fraud_check"]["keys"]["ipqs"] = ""
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"iphub.info": DummyResponse(json_resp={"block": 0})})
        await engine._waterfall_one(p, shared)
        assert p.composite_score is not None

    @pytest.mark.asyncio
    async def test_getipintel(self, engine):
        engine.config["fraud_check"]["keys"] = {
            "ipinfo": "", "iphub": "",
            "getipintel_email": "t@t.com", "ipqs": "",
        }
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.anonymity = AnonymityLevel.ELITE
        shared = make_session_mock({"getipintel": DummyResponse(text_resp="0.15")})
        await engine._waterfall_one(p, shared)
        assert p.fraud_score is not None

    @pytest.mark.asyncio
    async def test_ipqs_recent_abuse(self, engine):
        engine.config["fraud_check"]["keys"] = {
            "ipinfo": "", "iphub": "",
            "getipintel_email": "", "ipqs": "k",
        }
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        shared = make_session_mock({"ipqualityscore": DummyResponse(
            json_resp={"success": True, "fraud_score": 10, "recent_abuse": True})})
        await engine._waterfall_one(p, shared)
        assert p.composite_score is not None
        assert p.composite_score >= 20  # recent_abuse adds 20

    @pytest.mark.asyncio
    async def test_orchestrator_enabled(self, engine):
        engine.config["fraud_check"]["enabled"] = True
        engine.config["fraud_check"]["top_n"] = 2
        engine.config["fraud_check"]["keys"] = {
            "ipinfo": "", "iphub": "", "getipintel_email": "", "ipqs": ""
        }
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.alive = True
        p.latency_ms = 100
        engine.proxies = {p.address: p}
        with patch("aiohttp.ClientSession") as mc:
            mc.return_value = make_session_mock()
            await engine.tiered_fraud_scoring()

    @pytest.mark.asyncio
    async def test_orchestrator_disabled(self, engine):
        engine.config["fraud_check"]["enabled"] = False
        await engine.tiered_fraud_scoring()

    @pytest.mark.asyncio
    async def test_orchestrator_no_alive(self, engine):
        engine.config["fraud_check"]["enabled"] = True
        engine.proxies = {}
        await engine.tiered_fraud_scoring()

    @pytest.mark.asyncio
    async def test_save_fraud_cache(self, engine, temp_dir):
        engine.history = ProxyHistory(str(temp_dir / "data" / "fc.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.composite_score = 42
        engine._save_fraud_cache(p)
        assert engine.history.get_cached_score("8.8.8.8") == 42

    @pytest.mark.asyncio
    async def test_save_fraud_cache_no_history(self, engine):
        engine.history = None
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.composite_score = 42
        engine._save_fraud_cache(p)  # no crash

    @pytest.mark.asyncio
    async def test_save_fraud_cache_no_score(self, engine, temp_dir):
        engine.history = ProxyHistory(str(temp_dir / "data" / "fc2.db"))
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        p.composite_score = None
        engine._save_fraud_cache(p)  # no crash


# ============================================================================
# Judges
# ============================================================================

class TestJudges:
    def test_rotation(self, engine):
        engine.judges = [("http://j1.com", 0.1), ("http://j2.com", 0.2), ("http://j3.com", 0.3)]
        assert engine._get_judge(0) == "http://j1.com"
        assert engine._get_judge(1) == "http://j2.com"
        assert engine._get_judge(2) == "http://j3.com"
        assert engine._get_judge(3) == "http://j1.com"

    def test_no_judges_fallback(self, engine):
        engine.judges = []
        assert engine._get_judge(0) == "http://api.ipify.org"

    @pytest.mark.asyncio
    async def test_test_judges(self, engine):
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.test_judges()


# ============================================================================
# Create Proxy Session
# ============================================================================

class TestCreateProxySession:
    def test_http(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        t = MagicMock()
        with patch("aiohttp.TCPConnector"), patch("aiohttp.ClientSession"):
            s, kw = engine._create_proxy_session(p, t)
            assert "proxy" in kw

    def test_socks5(self, engine):
        p = Proxy("8.8.8.8", 1080, ProxyProtocol.SOCKS5)
        t = MagicMock()
        with patch("aiohttp_socks.ProxyConnector.from_url"), patch("aiohttp.ClientSession"):
            s, kw = engine._create_proxy_session(p, t)
            assert "proxy" not in kw

    def test_socks4(self, engine):
        p = Proxy("8.8.8.8", 1080, ProxyProtocol.SOCKS4)
        t = MagicMock()
        with patch("aiohttp_socks.ProxyConnector.from_url"), patch("aiohttp.ClientSession"):
            s, kw = engine._create_proxy_session(p, t)
            assert "proxy" not in kw

    def test_https(self, engine):
        p = Proxy("8.8.8.8", 443, ProxyProtocol.HTTPS)
        t = MagicMock()
        with patch("aiohttp.TCPConnector"), patch("aiohttp.ClientSession"):
            s, kw = engine._create_proxy_session(p, t)
            assert "proxy" in kw


# ============================================================================
# Pre-Enrich
# ============================================================================

class TestPreEnrich:
    def test_no_geoip(self, engine):
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.country_code is None

    def _mock_asn(self, asn_num, org="ISP"):
        m = MagicMock()
        d = MagicMock()
        d.autonomous_system_number = asn_num
        d.autonomous_system_organization = org
        m.asn.return_value = d
        return m

    def test_residential(self, engine):
        engine.geoip_asn = self._mock_asn(7922, "Comcast")
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.proxy_type == ProxyType.RESIDENTIAL

    def test_datacenter(self, engine):
        engine.geoip_asn = self._mock_asn(16509, "Amazon")
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.proxy_type == ProxyType.DATACENTER

    def test_mobile(self, engine):
        engine.geoip_asn = self._mock_asn(21928, "T-Mobile")
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.proxy_type == ProxyType.MOBILE

    def test_cdn(self, engine):
        engine.geoip_asn = self._mock_asn(13335, "Cloudflare")
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.proxy_type == ProxyType.DATACENTER

    def test_city_enrichment(self, engine):
        mc = MagicMock()
        cd = MagicMock()
        cd.country.iso_code = "US"
        cd.country.name = "United States"
        cd.city.name = "Mountain View"
        cd.subdivisions.most_specific.name = "California"
        cd.subdivisions.__bool__ = lambda self: True
        mc.city.return_value = cd
        engine.geoip_city = mc
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.country_code == "US"
        assert p.city == "Mountain View"
        assert p.region == "California"

    def test_asn_exception(self, engine):
        m = MagicMock()
        m.asn.side_effect = Exception("fail")
        engine.geoip_asn = m
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.asn is None

    def test_city_exception(self, engine):
        m = MagicMock()
        m.city.side_effect = Exception("fail")
        engine.geoip_city = m
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.country_code is None

    def test_no_subdivisions(self, engine):
        mc = MagicMock()
        cd = MagicMock()
        cd.country.iso_code = "US"
        cd.country.name = "United States"
        cd.city.name = "City"
        cd.subdivisions = []  # falsy
        mc.city.return_value = cd
        engine.geoip_city = mc
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        engine.proxies = {p.address: p}
        engine.pre_enrich()
        assert p.region is None


# ============================================================================
# Initialize
# ============================================================================

class TestInitialize:
    @pytest.mark.asyncio
    async def test_basic(self, engine):
        sess = make_session_mock({"ipify": DummyResponse(text_resp="5.5.5.5")})
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()

    @pytest.mark.asyncio
    async def test_with_blacklist(self, engine, temp_dir):
        bl = temp_dir / "data" / "blacklist.txt"
        bl.write_text("1.1.1.1\n2.2.2.2\n")
        engine.config["filter"]["blacklist"] = str(bl)
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()
        assert "1.1.1.1" in engine.blacklist

    @pytest.mark.asyncio
    async def test_with_history(self, engine, temp_dir):
        engine.config["history"]["enabled"] = True
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()
        assert engine.history is not None

    @pytest.mark.asyncio
    async def test_ip_detection_failure(self, engine):
        sess = MagicMock()
        sess.get = MagicMock(side_effect=Exception("fail"))
        sess.__aenter__ = AsyncMock(return_value=sess)
        sess.__aexit__ = AsyncMock(return_value=False)
        engine.config["dns_leak"]["enabled"] = False
        engine.config["history"]["enabled"] = False
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()

    @pytest.mark.asyncio
    async def test_geoip_not_found(self, engine):
        engine.config["geoip"]["enabled"] = True
        engine.config["geoip"]["city_db"] = "/nonexistent/city.mmdb"
        engine.config["geoip"]["asn_db"] = "/nonexistent/asn.mmdb"
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()
        assert not engine.config["geoip"]["enabled"]


    @pytest.mark.asyncio
    async def test_with_verified_db(self, engine, temp_dir):
        db_path = str(temp_dir / "data" / "v_init.db")
        v = VerifiedProxyDB(db_path)
        v.save_all([Proxy("7.7.7.7", 8080, ProxyProtocol.HTTP)])
        engine.config["verified_db"] = {"enabled": True, "db_path": db_path}
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.initialize()
        assert engine.verified_db is not None

# ============================================================================
# Collect
# ============================================================================

class TestCollect:
    @pytest.mark.asyncio
    async def test_basic(self, engine):
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.collect()
        assert engine.stats["collected_raw"] >= 0

    @pytest.mark.asyncio
    async def test_crawl4ai_file(self, engine, temp_dir):
        cf = temp_dir / "output" / "crawled_proxies.json"
        cf.write_text(json.dumps([
            {"ip": "7.7.7.7", "port": 8080, "protocol": "http", "source": "c4a"},
        ]))
        engine.config["crawl4ai"]["enabled"] = True
        engine.config["crawl4ai"]["output_file"] = str(cf)
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.collect()

    @pytest.mark.asyncio
    async def test_crawl4ai_bad_json(self, engine, temp_dir):
        cf = temp_dir / "output" / "crawled_proxies.json"
        cf.write_text("NOT JSON")
        engine.config["crawl4ai"]["enabled"] = True
        engine.config["crawl4ai"]["output_file"] = str(cf)
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.collect()

    @pytest.mark.asyncio
    async def test_crawl4ai_bad_entry(self, engine, temp_dir):
        cf = temp_dir / "output" / "crawled_proxies.json"
        cf.write_text(json.dumps([{"ip": "", "port": "abc"}]))
        engine.config["crawl4ai"]["enabled"] = True
        engine.config["crawl4ai"]["output_file"] = str(cf)
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.collect()

    @pytest.mark.asyncio
    async def test_load_verified_db(self, engine, temp_dir):
        db_path = str(temp_dir / "data" / "v_collect.db")
        v = VerifiedProxyDB(db_path)
        v.save_all([Proxy("10.10.10.10", 1080, ProxyProtocol.SOCKS5)])
        engine.verified_db = v
        sess = make_session_mock()
        with patch("aiohttp.ClientSession", return_value=sess):
            await engine.collect()
        assert "10.10.10.10:1080" in engine.proxies


# ============================================================================
# Fetch
# ============================================================================

class TestFetch:
    @pytest.mark.asyncio
    async def test_success(self, engine):
        sess = make_session_mock({"ex.com": DummyResponse(text_resp="8.8.8.8:3128")})
        await engine._fetch(sess, "http://ex.com/l.txt", ProxyProtocol.HTTP)
        assert len(engine.proxies) == 1

    @pytest.mark.asyncio
    async def test_json_fmt(self, engine):
        sess = make_session_mock({"ex.com": DummyResponse(
            text_resp=json.dumps({"data": [{"ip": "1.1.1.1", "port": "80", "protocols": ["http"]}]}))})
        await engine._fetch(sess, "http://ex.com/api", ProxyProtocol.HTTP, "json")

    @pytest.mark.asyncio
    async def test_non_200(self, engine):
        sess = make_session_mock({"ex.com": DummyResponse(status=404)})
        await engine._fetch(sess, "http://ex.com/l.txt", ProxyProtocol.HTTP)
        assert len(engine.proxies) == 0

    @pytest.mark.asyncio
    async def test_exception(self, engine):
        sess = MagicMock()
        sess.get = MagicMock(side_effect=RuntimeError("bad"))
        await engine._fetch(sess, "http://ex.com/l.txt", ProxyProtocol.HTTP)
        assert len(engine.proxies) == 0

    @pytest.mark.asyncio
    async def test_timeout_retry(self, engine):
        call_count = 0
        def side_effect(url, *a, **kw):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise asyncio.TimeoutError
            return DummyResponse(text_resp="8.8.8.8:80")
        sess = MagicMock()
        sess.get = MagicMock(side_effect=side_effect)
        await engine._fetch(sess, "http://ex.com/l.txt", ProxyProtocol.HTTP)
        assert call_count == 3


# ============================================================================
# Regex
# ============================================================================

class TestProxyRegexPatterns:
    def test_basic(self):
        m = PROXY_REGEX.search("8.8.8.8:3128")
        assert m and m.group("ip") == "8.8.8.8" and m.group("port") == "3128"

    def test_with_proto(self):
        m = PROXY_REGEX.search("socks5://1.2.3.4:1080")
        assert m.group("protocol") == "socks5"

    def test_no_match(self):
        assert PROXY_REGEX.search("hello world") is None

    def test_with_auth(self):
        m = PROXY_REGEX.search("http://user:pass@1.2.3.4:8080")
        assert m and m.group("ip") == "1.2.3.4"


# ============================================================================
# Integration
# ============================================================================

class TestIntegration:
    @pytest.mark.asyncio
    async def test_full_minimal(self, engine):
        engine.judges = [("http://j.com", 0.1)]
        proxies = {}
        for i, proto in enumerate([ProxyProtocol.HTTP, ProxyProtocol.SOCKS5]):
            p = Proxy(f"8.8.8.{i+1}", 80+i, proto, source="test")
            p.alive = True
            p.latency_ms = 100 + i * 50
            p.check_count = 1
            p.success_count = 1
            p.reliability = 1.0
            p.anonymity = AnonymityLevel.ELITE
            p.speed_tier = SpeedTier.FAST
            p.proxy_type = ProxyType.RESIDENTIAL
            p.tcp_fingerprint = "modern"
            p.supports_https = True
            p.detected_protocols = ["http", "socks5"]
            p.download_speed_kbps = 500.0
            p.dns_leak = False
            p.composite_score = 10
            p.stealth_score = 85
            p.country_code = "US"
            p.country_name = "United States"
            proxies[p.address] = p
        engine.proxies = proxies
        engine.enrich_and_categorize()
        engine.export()
        stats = engine.print_stats()
        assert stats["alive"] == 2
        out = Path(engine.config["output"]["dir"])
        assert (out / "all.json").exists()
        assert (out / "all.csv").exists()