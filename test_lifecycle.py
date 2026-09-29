"""Tests for the lifecycle engine additions (I2–I7).

Covers: per-proxy lifecycle ordering + fail-fast + session reuse (I2/I4),
shared TCP probe cache (I3), known-dead probation (I6), deep config merge
(I7), and the raw SOCKS4/5 handshake framing (I5) against an in-process
mock server.

All network is mocked or localhost-only.
"""

from __future__ import annotations

import asyncio
import sqlite3
import struct
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from UPO import Proxy, ProxyProtocol, UPOEngine, load_config
from UPO import socks as socks_mod
from UPO.db.history import ProxyHistory
from UPO.db.verified import VerifiedProxyDB

from test_upo import temp_dir, config  # noqa: F401  (fixtures)

pytestmark = pytest.mark.asyncio


def _lc_config(base_config, **lifecycle_overrides):
    cfg = dict(base_config)
    cfg["lifecycle"] = {
        "enabled": True, "max_in_flight": 10,
        "stage_limits": {}, "session_reuse": True, "tcp_dedup": True,
        "skip_known_dead": {"enabled": False, "min_fails": 5,
                            "stale_hours": 2.0, "probe_timeout": 2.0},
        "raw_socks": False,
    }
    cfg["lifecycle"].update(lifecycle_overrides)
    return cfg


class _FakeSession:
    """Stand-in for aiohttp.ClientSession that never hits the network."""

    def __init__(self, record, ok=True):
        self.record = record
        self.ok = ok
        self.closed = False

    def get(self, url, **kw):
        self.record["gets"].append(url)
        outer = self

        class _Ctx:
            async def __aenter__(self):
                r = MagicMock()
                if outer.ok:
                    r.status = 200
                    r.text = AsyncMock(return_value="9.9.9.9")
                    r.read = AsyncMock(return_value=b"x" * 10)
                    r.json = AsyncMock(return_value={"headers": {}})
                else:
                    r.status = 500
                return r

            async def __aexit__(self, *a):
                return False

        return _Ctx()

    async def close(self):
        self.closed = True


# ============================================================================
# Lifecycle ordering / fail-fast / session reuse (I2 / I4)
# ============================================================================

class TestLifecycleEngine:
    async def _engine(self, config, n_alive=2, n_dead=1, reuse=True):
        cfg = _lc_config(config, session_reuse=reuse)
        eng = UPOEngine(cfg)
        eng.judges = [("http://judge.test/ip", 0.05)]
        eng.my_ip = "1.2.3.4"

        self.record = {"gets": [], "sessions": 0, "lifecycle_stages": []}

        proxies = {}
        for i in range(n_alive):
            proxies[f"10.0.0.{i}:80"] = Proxy(
                f"10.0.0.{i}", 80, ProxyProtocol.HTTP)
        for i in range(n_dead):
            proxies[f"10.9.9.{i}:81"] = Proxy(
                f"10.9.9.{i}", 81, ProxyProtocol.HTTP)
        eng.proxies = proxies

        self.alive_ips = {f"10.0.0.{i}" for i in range(n_alive)}

        async def fake_probe(ip, port, timeout):
            return ip in self.alive_ips

        def fake_create_session(proxy, timeout):
            self.record["sessions"] += 1
            ok = proxy.ip in self.alive_ips
            return _FakeSession(self.record, ok=ok), {}

        # Spy every per-stage _one method to record call order per proxy.
        real_check_one = eng._check_one

        async def spy_check_one(p, judge, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "verify"))
            if session is not None and not isinstance(session, _FakeSession):
                raise AssertionError("session passed but not fake")
            if p.ip in self.alive_ips:
                p.alive = True
                p.latency_ms = 50
                p.success_count += 1
            p.check_count += 1
            if session is None:
                self.record["gets"].append("OWN_SESSION")

        async def spy_anon(p, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "anon"))

        async def spy_proto(p, judge, session=None, kwargs=None,
                            raw_socks=False):
            self.record["lifecycle_stages"].append((p.ip, "proto"))

        async def spy_speed(p, url, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "speed"))

        async def spy_fp(p, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "fp"))

        async def spy_dns(p, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "dns"))

        async def spy_ban(p, url, pattern, session=None, kwargs=None):
            self.record["lifecycle_stages"].append((p.ip, "ban"))
            return False

        patches = [
            patch("UPO.core.lifecycle._raw_tcp_probe",
                  side_effect=fake_probe),
            patch.object(eng, "_create_proxy_session",
                         side_effect=fake_create_session),
            patch.object(eng, "_check_one", side_effect=spy_check_one),
            patch.object(eng, "_anon_check_one", side_effect=spy_anon),
            patch.object(eng, "_detect_protocols_one", side_effect=spy_proto),
            patch.object(eng, "_speed_test_one", side_effect=spy_speed),
            patch.object(eng, "_fingerprint_one", side_effect=spy_fp),
            patch.object(eng, "_dns_leak_one", side_effect=spy_dns),
            patch.object(eng, "_ban_check_one", side_effect=spy_ban),
            patch.object(eng, "test_judges", AsyncMock()),
        ]
        for pt in patches:
            pt.start()
        self.add_cleanup = [pt.stop for pt in patches]
        return eng

    async def test_alive_proxy_full_stage_order(self, config):
        eng = await self._engine(config)
        try:
            assert await eng.run_lifecycle() is True
            stages = [s for ip, s in self.record["lifecycle_stages"]
                      if ip == "10.0.0.0"]
            n_sites = len(config["ban_check"]["sites"])
            assert stages == ["verify", "anon", "proto", "speed",
                              "fp", "dns"] + ["ban"] * n_sites
        finally:
            for stop in self.add_cleanup:
                stop()

    async def test_dead_tcp_proxy_gets_no_downstream_work(self, config):
        eng = await self._engine(config)
        try:
            await eng.run_lifecycle()
            dead_stages = [s for ip, s in self.record["lifecycle_stages"]
                           if ip == "10.9.9.0"]
            assert dead_stages == []           # failed TCP → nothing at all
            assert "10.9.9.0:81" not in eng.proxies
            # TCP-dead proxies never even get a session created
            assert self.record["sessions"] == 2
        finally:
            for stop in self.add_cleanup:
                stop()

    async def test_verify_fail_skips_rest(self, config):
        # Alive TCP but judge returns 500 (ok=False for _check_one is
        # simulated by removing the ip from alive set AFTER tcp probe).
        cfg = _lc_config(config)
        eng = UPOEngine(cfg)
        eng.judges = [("http://judge.test/ip", 0.05)]
        eng.my_ip = "1.2.3.4"
        p = Proxy("8.8.8.8", 80, ProxyProtocol.HTTP)
        eng.proxies = {"8.8.8.8:80": p}
        calls = []

        async def fake_probe(ip, port, timeout):
            return True  # TCP alive

        async def failing_check(proxy, judge, session=None, kwargs=None):
            calls.append("verify")
            proxy.check_count += 1
            proxy.alive = False   # judge failure

        with patch("UPO.core.lifecycle._raw_tcp_probe",
                   side_effect=fake_probe), \
             patch.object(eng, "_create_proxy_session",
                          return_value=(_FakeSession({"gets": []}, ok=False),
                                        {})), \
             patch.object(eng, "_check_one", side_effect=failing_check), \
             patch.object(eng, "_anon_check_one",
                          AsyncMock(side_effect=lambda *a, **k: calls.append("anon"))), \
             patch.object(eng, "test_judges", AsyncMock()):
            await eng.run_lifecycle()
        assert calls == ["verify"]  # anonymity never reached

    async def test_session_created_once_per_alive_proxy(self, config):
        eng = await self._engine(config, n_alive=3, n_dead=0)
        try:
            await eng.run_lifecycle()
            assert self.record["sessions"] == 3   # I4: one per proxy, not 7
        finally:
            for stop in self.add_cleanup:
                stop()

    async def test_tcp_cache_dedups_variants(self, config):
        """Two Proxy objects sharing ip:port → exactly one raw probe."""
        cfg = _lc_config(config)
        eng = UPOEngine(cfg)
        eng.judges = [("http://judge.test/ip", 0.05)]
        eng.my_ip = "1.2.3.4"
        a = Proxy("5.5.5.5", 80, ProxyProtocol.HTTP)
        b = Proxy("5.5.5.5", 80, ProxyProtocol.SOCKS5)
        eng.proxies = {"k1": a, "k2": b}
        probes = []

        async def counting_probe(ip, port, timeout):
            probes.append(ip)
            return False  # both die at TCP

        with patch("UPO.core.lifecycle._raw_tcp_probe",
                   side_effect=counting_probe), \
             patch.object(eng, "_create_proxy_session",
                          return_value=(None, {})), \
             patch.object(eng, "test_judges", AsyncMock()):
            await eng.run_lifecycle()
        assert len(probes) == 1
        assert eng.stats["lifecycle"]["tcp_probe_saved_by_cache"] == 1

    async def test_stats_parity_fields(self, config):
        eng = await self._engine(config)
        try:
            await eng.run_lifecycle()
            assert eng.stats["verified_total"] == len(eng.proxies)
            assert eng.stats["verified_alive"] == 2
            assert eng.stats["tcp_prefilter_removed"] == 1
        finally:
            for stop in self.add_cleanup:
                stop()

    async def test_admission_gate_caps_in_flight(self, config):
        cfg = _lc_config(config, max_in_flight=2)
        eng = UPOEngine(cfg)
        eng.judges = [("http://judge.test/ip", 0.05)]
        eng.my_ip = "1.2.3.4"
        eng.proxies = {
            f"7.7.7.{i}:80": Proxy(f"7.7.7.{i}", 80, ProxyProtocol.HTTP)
            for i in range(10)
        }
        concurrent = {"now": 0, "max": 0}

        async def slow_probe(ip, port, timeout):
            concurrent["now"] += 1
            concurrent["max"] = max(concurrent["max"], concurrent["now"])
            await asyncio.sleep(0.02)
            concurrent["now"] -= 1
            return True

        with patch("UPO.core.lifecycle._raw_tcp_probe",
                   side_effect=slow_probe), \
             patch.object(eng, "_create_proxy_session",
                          return_value=(None, {})), \
             patch.object(eng, "test_judges", AsyncMock()):
            await eng.run_lifecycle()
        assert concurrent["max"] <= 2


# ============================================================================
# I6 — known-dead probation list
# ============================================================================

class TestKnownDead:
    # proxies table: id, ip, port, protocol, first_seen, last_seen,
    # last_alive, total_checks, successful_checks, avg_latency, country,
    # asn, isp, proxy_type
    @staticmethod
    def _row(pid, ip, port, proto, last_alive, total, success):
        return (pid, ip, port, proto, None, None, last_alive,
                total, success, None, None, None, None, None)

    def _db(self, tmp_path):
        rows = [
            self._row("a:1:http", "5.5.5.5", 80, "http",
                      _ago(days=10), 9, 0),      # chronically dead
            self._row("b:2:http", "6.6.6.6", 80, "http",
                      _ago(hours=1), 9, 0),      # alive 1h ago → exclude
            self._row("c:3:http", "7.7.7.7", 80, "http",
                      None, 3, 0),               # only 3 fails → exclude
            self._row("d:4:http", "8.8.8.8", 80, "http",
                      None, None, None),         # NULLs → exclude
        ]
        h = ProxyHistory(str(tmp_path / "h.db"))
        conn = sqlite3.connect(str(tmp_path / "h.db"))
        conn.executemany(
            "INSERT INTO proxies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        conn.commit()
        conn.close()
        return h

    def test_dead_inclusion_rules(self, tmp_path):
        h = self._db(tmp_path)
        dead = h.get_known_dead(min_fails=5, stale_hours=2.0)
        assert dead == {"5.5.5.5:80"}

    def test_variant_revives_whole_endpoint(self, tmp_path):
        self._db(tmp_path)
        # Add a socks5 row for 5.5.5.5 that was alive 1h ago → the http
        # variant's history must not condemn the shared endpoint.
        conn = sqlite3.connect(str(tmp_path / "h.db"))
        conn.execute(
            "INSERT INTO proxies VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            self._row("a:1:socks5", "5.5.5.5", 80, "socks5",
                      _ago(hours=1), 9, 9))
        conn.commit()
        conn.close()
        h = ProxyHistory(str(tmp_path / "h.db"))
        assert "5.5.5.5:80" not in h.get_known_dead(5, 2.0)

    async def test_lifecycle_probation_skips_confirmed_dead(self, config):
        cfg = _lc_config(config)
        cfg["lifecycle"]["skip_known_dead"]["enabled"] = True
        eng = UPOEngine(cfg)
        eng.judges = [("http://judge.test/ip", 0.05)]
        eng.my_ip = "1.2.3.4"
        p = Proxy("5.5.5.5", 80, ProxyProtocol.HTTP)
        eng.proxies = {"5.5.5.5:80": p}
        eng.history = MagicMock()
        eng.history.get_known_dead.return_value = {"5.5.5.5:80"}
        probes = []

        async def dead_probe(ip, port, timeout):
            probes.append((ip, timeout))
            return False

        with patch("UPO.core.lifecycle._raw_tcp_probe",
                   side_effect=dead_probe), \
             patch.object(eng, "test_judges", AsyncMock()):
            await eng.run_lifecycle()
        assert probes == [("5.5.5.5", 2.0)]      # one probation probe only
        assert "5.5.5.5:80" not in eng.proxies
        assert eng.stats["lifecycle"]["skipped_known_dead"] == 1


# ============================================================================
# I7 — deep merge
# ============================================================================

class TestDeepMerge:
    def test_partial_nested_survives(self, tmp_path):
        p = tmp_path / "c.yaml"
        p.write_text(
            "lifecycle:\n  stage_limits:\n    speed: 5\n",
            encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["lifecycle"]["stage_limits"]["speed"] == 5
        assert cfg["lifecycle"]["stage_limits"]["ban"] == 25
        assert cfg["lifecycle"]["max_in_flight"] == 5000

    def test_list_replace_not_merge(self, tmp_path):
        p = tmp_path / "c.yaml"
        p.write_text("judges:\n  urls: [\"http://x.test\"]\n",
                     encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["judges"]["urls"] == ["http://x.test"]


# ============================================================================
# I5 — raw SOCKS framing against an in-process mock server
# ============================================================================

def _ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()


class TestSocksFraming:
    async def _serve(self, handler):
        server = await asyncio.start_server(
            handler, "127.0.0.1", 0)
        return server, server.sockets[0].getsockname()[1]

    async def test_socks5_handshake_success(self):
        seen = {}

        async def handler(reader, writer):
            methods = await reader.readexactly(3)   # VER, NMETHODS, 0x00
            seen["greeting"] = methods
            writer.write(b"\x05\x00")
            req = await reader.readexactly(4 + 4 + 2)  # header+ipv4+port
            seen["req"] = req
            writer.write(
                b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x1f\x90"
            )
            # now echo HTTP request → fake response
            data = await reader.read(4096)
            seen["http"] = data
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nGOOD")
            await writer.drain()
            writer.close()

        server, port = await self._serve(handler)
        async with server:
            reader, writer = await socks_mod.socks5_connect(
                "127.0.0.1", port, "93.184.216.34", 80, timeout=5)
            writer.write(b"GET / HTTP/1.1\r\n\r\n")
            await writer.drain()
            status_line = await reader.readline()
            writer.close()
        assert seen["greeting"] == b"\x05\x01\x00"
        assert seen["req"][:4] == b"\x05\x01\x00\x01"
        assert struct.unpack("!H", seen["req"][-2:])[0] == 80
        assert status_line.startswith(b"HTTP/1.1 200")

    async def test_socks5_domain_atyp(self):
        seen = {}

        async def handler(reader, writer):
            await reader.readexactly(3)
            writer.write(b"\x05\x00")
            head = await reader.readexactly(4)
            (n,) = await reader.readexactly(1)
            host = (await reader.readexactly(n)).decode()
            port_b = await reader.readexactly(2)
            seen["host"] = host
            seen["port"] = struct.unpack("!H", port_b)[0]
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        server, port = await self._serve(handler)
        async with server:
            r, w = await socks_mod.socks5_connect(
                "127.0.0.1", port, "example.com", 8080, timeout=5)
            w.write(b"x")
            await r.read(2)
            w.close()
        assert seen["host"] == "example.com"
        assert seen["port"] == 8080

    async def test_socks5_refusal_raises(self):
        async def handler(reader, writer):
            await reader.readexactly(3)
            writer.write(b"\x05\x00")
            await reader.readexactly(10)
            writer.write(b"\x05\x01\x00\x00\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()

        server, port = await self._serve(handler)
        async with server:
            with pytest.raises(socks_mod.SocksError):
                await socks_mod.socks5_connect(
                    "127.0.0.1", port, "1.2.3.4", 80, timeout=5)

    async def test_socks4_grant_and_refuse(self):
        seen = {}

        async def read_socks4_head(reader):
            """SOCKS4 request: 8-byte header (may contain NUL bytes in the
            port field!) then userid terminated by NUL."""
            head = await reader.readexactly(8)
            userid = await reader.readuntil(b"\x00")
            return head + userid

        async def ok_handler(reader, writer):
            req = await read_socks4_head(reader)
            seen["req"] = req
            writer.write(b"\x00\x5a\x1f\x90\x00\x00\x00\x00")
            await writer.drain()
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        async def bad_handler(reader, writer):
            await read_socks4_head(reader)
            writer.write(b"\x00\x5b\x1f\x90\x00\x00\x00\x00")
            await writer.drain()
            writer.close()

        for handler, expect_error in ((ok_handler, False),
                                      (bad_handler, True)):
            server, port = await self._serve(handler)
            async with server:
                if expect_error:
                    with pytest.raises(socks_mod.SocksError):
                        await socks_mod.socks4_connect(
                            "127.0.0.1", port, "1.2.3.4", 80,
                            user="bob", timeout=5)
                else:
                    r, w = await socks_mod.socks4_connect(
                        "127.0.0.1", port, "1.2.3.4", 80,
                        user="bob", timeout=5)
                    w.write(b"GET / HTTP/1.1\r\n\r\n")
                    line = await r.readline()
                    assert b"200" in line
                    w.close()
        # VN=4 CD=1 port=80(\x00P) ip=1.2.3.4 userid=bob\0
        assert seen["req"] == b"\x04\x01\x00P\x01\x02\x03\x04bob\x00"

    async def test_socks_http_get_end_to_end(self):
        async def handler(reader, writer):
            await reader.readexactly(3)
            writer.write(b"\x05\x00")
            await reader.readexactly(10)
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await reader.read(4096)
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 7\r\n\r\n1.2.3.4"
            )
            await writer.drain()
            writer.close()

        server, port = await self._serve(handler)
        async with server:
            status, body = await socks_mod.socks_http_get(
                "127.0.0.1", port, socks_mod.SOCKS_VERSION_5,
                "GET", "http://example.com/ip", timeout=5)
        assert status == 200
        assert body == "1.2.3.4"

    async def test_socks5_auth_negotiation(self):
        seen = {}

        async def handler(reader, writer):
            await reader.readexactly(4)          # offers no-auth + userpass
            seen["greeting"] = True
            writer.write(b"\x05\x02")            # choose user/pass
            ver, ulen = await reader.readexactly(2)
            user = (await reader.readexactly(ulen)).decode()
            plen, = await reader.readexactly(1)
            pw = (await reader.readexactly(plen)).decode()
            seen["creds"] = (user, pw)
            writer.write(b"\x01\x00")
            await reader.readexactly(4)
            n, = await reader.readexactly(1)
            await reader.readexactly(n + 2)
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await reader.read(4096)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        server, port = await self._serve(handler)
        async with server:
            r, w = await socks_mod.socks5_connect(
                "127.0.0.1", port, "1.2.3.4", 80,
                user="u1", password="p2", timeout=5)
            w.write(b"x")
            await r.read(2)
            w.close()
        assert seen["creds"] == ("u1", "p2")


# ============================================================================
# Legacy-schema DB compatibility (real bugs found auditing production DBs:
# data/verified_proxies.db has an 8-col pre-address schema, and
# data/proxy_history.db's proxies table has 24 columns — positional INSERTs
# against either silently failed, swallowing the error into a console line)
# ============================================================================

class TestLegacySchemaCompat:
    async def test_history_update_into_wider_legacy_table(self, tmp_path):
        db = str(tmp_path / "wide.db")
        conn = sqlite3.connect(db)
        conn.execute(
            """CREATE TABLE proxies (
                id TEXT PRIMARY KEY, ip TEXT, port INT, protocol TEXT,
                first_seen TEXT, last_seen TEXT, last_alive TEXT,
                total_checks INT DEFAULT 0, successful_checks INT DEFAULT 0,
                avg_latency REAL, country TEXT, asn INT, isp TEXT,
                proxy_type TEXT, username TEXT, anonymity TEXT,
                https_connect INT, udp_supported INT, failed_checks INT,
                historical_reliability REAL, latency_sum REAL,
                latency_count INT, min_latency INT, max_latency INT)""")
        conn.execute(
            """CREATE TABLE checks (proxy_id TEXT, checked_at TEXT,
               alive INT, latency INT, anonymity TEXT,
               FOREIGN KEY (proxy_id) REFERENCES proxies(id))""")
        conn.execute(
            """CREATE TABLE api_cache (ip TEXT PRIMARY KEY, checked_at TEXT,
               ipinfo TEXT, iphub TEXT, getipintel TEXT, ipqs TEXT,
               composite_score INT)""")
        conn.commit()
        conn.close()

        h = ProxyHistory(db)
        p = Proxy("5.6.7.8", 8080, ProxyProtocol.SOCKS5)
        p.alive = True
        p.latency_ms = 42
        h.update(p)
        row = sqlite3.connect(db).execute(
            "SELECT total_checks, successful_checks FROM proxies WHERE id=?",
            (p.id,)).fetchone()
        assert row == (1, 1), "silent write failure vs legacy wide schema"

    async def test_verified_legacy_schema_recreated_and_writable(self, tmp_path):
        db = str(tmp_path / "old.db")
        conn = sqlite3.connect(db)
        conn.execute(
            """CREATE TABLE verified (
                id TEXT PRIMARY KEY, ip TEXT, port INT, protocol TEXT,
                latency_ms INT, anonymity TEXT, country TEXT,
                supports_https INT DEFAULT 0)""")
        conn.execute(
            "INSERT INTO verified VALUES ('a','1.1.1.1',1,'http',1,NULL,0,0)")
        conn.commit()
        conn.close()

        v = VerifiedProxyDB(db)          # detects missing address col → recreate
        p = Proxy("2.2.2.2", 80, ProxyProtocol.HTTP)
        p.alive = True
        v.save_all([p])                  # previously: silent write error
        assert v.count() == 1
        assert sqlite3.connect(db).execute(
            "SELECT address FROM verified").fetchall() == [("2.2.2.2:80",)]

    async def test_bulk_update_writes_wide_legacy_table(self, tmp_path):
        db = str(tmp_path / "wide3.db")
        conn = sqlite3.connect(db)
        conn.execute(
            """CREATE TABLE proxies (
                id TEXT PRIMARY KEY, ip TEXT, port INT, protocol TEXT,
                first_seen TEXT, last_seen TEXT, last_alive TEXT,
                total_checks INT DEFAULT 0, successful_checks INT DEFAULT 0,
                avg_latency REAL, country TEXT, asn INT, isp TEXT,
                proxy_type TEXT, username TEXT, anonymity TEXT,
                https_connect INT, udp_supported INT, failed_checks INT,
                historical_reliability REAL, latency_sum REAL,
                latency_count INT, min_latency INT, max_latency INT)""")
        conn.commit()
        conn.close()

        h = ProxyHistory(db)
        p = Proxy("9.9.9.9", 3128, ProxyProtocol.HTTP)
        assert h.bulk_update([(p, 4)]) == 1
        row = sqlite3.connect(db).execute(
            "SELECT total_checks FROM proxies WHERE id=?",
            (p.id,)).fetchone()
        assert row == (4,)


# ============================================================================
# _one signatures keep legacy (no session passed) behavior
# ============================================================================

class TestBackCompatSignatures:
    async def test_check_one_creates_and_closes_own_session(self, config):
        eng = UPOEngine(_lc_config(config))
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        rec = {"gets": []}
        sess = _FakeSession(rec, ok=True)
        with patch.object(eng, "_create_proxy_session",
                          return_value=(sess, {})):
            await eng._check_one(p, "http://judge.test/ip")
        assert sess.closed is True           # legacy path still closes
        assert p.check_count == 1

    async def test_check_one_shared_session_not_closed(self, config):
        eng = UPOEngine(_lc_config(config))
        p = Proxy("1.1.1.1", 80, ProxyProtocol.HTTP)
        sess = _FakeSession({"gets": []}, ok=True)
        await eng._check_one(
            p, "http://judge.test/ip", session=sess, kwargs={})
        assert sess.closed is False          # lifecycle owns closing
