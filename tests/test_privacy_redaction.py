"""Credential-privacy redaction tests (improvement I8 — first port).

Recovered from the spec of the vanished ``tests/test_credentials_privacy.py``
(listed in ``.pytest_cache/v/cache/nodeids``), re-expressed against the
current ``src/UPO`` package.

Design guarantee these pin: sources hand round text like
``http://user:pass@1.2.3.4:8080``. The collector DROPS the userinfo part at
parse time (PROXY_REGEX captures it but ``_parse_text`` never reads it), so
a credential can never exist on a Proxy object, in any export file, or in
any database row. These tests plant a canary secret and demand it appear
nowhere.
"""

from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import pytest

from UPO import (
    DEFAULT_CONFIG, PROXY_REGEX, Proxy, ProxyHistory, ProxyProtocol,
    UPOEngine, VerifiedProxyDB,
)

SECRET = "sup3rs3cr3tp4ss"
CRED_HOSTED = f"http://proxyuser:{SECRET}@203.0.113.7:8080"


@pytest.fixture()
def engine(tmp_path):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["history"]["db_path"] = str(tmp_path / "data" / "h.db")
    cfg["verified_db"]["db_path"] = str(tmp_path / "data" / "v.db")
    cfg["output"]["dir"] = str(tmp_path / "out")
    cfg["checked_output"]["dir"] = str(tmp_path / "checked")
    cfg["geoip"]["enabled"] = False
    eng = UPOEngine(cfg)
    eng.my_ip = "198.51.100.1"
    return eng


def _harvest(tmp_path: Path) -> str:
    """Concatenate every produced artifact for a secret scan."""
    blob = []
    for p in sorted(tmp_path.rglob("*")):
        if p.is_file() and p.suffix in (".json", ".csv", ".txt", ".db"):
            blob.append(p.read_bytes().decode("utf-8", errors="replace"))
    return "\n".join(blob)


class TestParsingDropsCredentials:
    def test_parse_text_strips_userinfo(self, engine):
        engine._parse_text(CRED_HOSTED, ProxyProtocol.HTTP, "src")
        assert len(engine.proxies) == 1
        p = next(iter(engine.proxies.values()))
        assert p.ip == "203.0.113.7"
        assert p.port == 8080
        assert SECRET not in p.address
        assert SECRET not in p.url
        assert SECRET not in p.id
        assert SECRET not in json.dumps(p.to_dict())

    def test_regex_skips_userinfo_without_capturing(self, engine):
        m = PROXY_REGEX.search(CRED_HOSTED)
        assert m is not None                       # matches…
        assert m.group("ip") == "203.0.113.7"      # anchored on the IP
        # The (?:user:pass@) prefix is NON-capturing: no group holds the
        # credential, so nothing downstream can accidentally persist it.
        captured = [g for g in m.groups() if g]
        assert SECRET not in captured and not any(
            SECRET in g for g in captured
        )
        engine._parse_text(CRED_HOSTED, ProxyProtocol.HTTP, "src")
        stored = next(iter(engine.proxies.values()))
        assert SECRET not in stored.source

    def test_no_credential_fields_on_model(self):
        p = Proxy("1.2.3.4", 80, ProxyProtocol.HTTP)
        d = p.to_dict()
        for banned in ("password", "user", "username", "auth", "token"):
            assert not any(banned in k.lower() for k in d), sorted(d)


class TestExportsAreClean:
    def _alive_with_history(self, engine, tmp_path):
        p = Proxy("203.0.113.7", 8080, ProxyProtocol.HTTP, source="cred.txt")
        p.alive = True
        p.latency_ms = 100
        engine.proxies = {"203.0.113.7:8080": p}
        engine.history = ProxyHistory(engine.config["history"]["db_path"])
        engine.verified_db = VerifiedProxyDB(
            engine.config["verified_db"]["db_path"]
        )
        return p

    def test_password_not_in_export_json_and_csv(self, engine, tmp_path):
        self._alive_with_history(engine, tmp_path)
        engine.export()
        blob = _harvest(tmp_path)
        assert SECRET not in blob
        assert "proxyuser" not in blob

    def test_password_not_in_checked_output(self, engine, tmp_path):
        self._alive_with_history(engine, tmp_path)
        engine.export()
        checked = list((tmp_path / "checked").glob("*.json"))
        assert checked, "checked export missing"
        assert SECRET not in checked[0].read_text(encoding="utf-8")

    def test_password_not_stored_in_history_db(self, engine, tmp_path):
        p = self._alive_with_history(engine, tmp_path)
        engine.history.update(p)
        conn = sqlite3.connect(engine.config["history"]["db_path"])
        rows = (
            conn.execute("SELECT * FROM proxies").fetchall()
            + conn.execute("SELECT * FROM checks").fetchall()
            + conn.execute("SELECT * FROM api_cache").fetchall()
        )
        conn.close()
        assert SECRET not in repr(rows)
        assert "proxyuser" not in repr(rows)

    def test_password_not_stored_in_verified_db(self, engine, tmp_path):
        p = self._alive_with_history(engine, tmp_path)
        engine.verified_db.save_all([p])
        conn = sqlite3.connect(engine.config["verified_db"]["db_path"])
        rows = conn.execute("SELECT * FROM verified").fetchall()
        conn.close()
        assert rows, "verified row missing"
        assert SECRET not in repr(rows)
        assert "proxyuser" not in repr(rows)
