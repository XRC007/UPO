"""SECTION 3: HISTORY DB.

Long-lived SQLite ledger of every proxy ever seen, keyed by ``Proxy.id``
(ip:port:protocol), plus an ``api_cache`` table that memoizes fraud-scoring
lookups for 24h so repeated runs do not re-hit paid APIs.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ..models import Proxy
from ..utils.console import console


class ProxyHistory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS proxies (
            id TEXT PRIMARY KEY, ip TEXT, port INT, protocol TEXT,
            first_seen TEXT, last_seen TEXT, last_alive TEXT,
            total_checks INT DEFAULT 0, successful_checks INT DEFAULT 0,
            avg_latency REAL, country TEXT, asn INT, isp TEXT, proxy_type TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, proxy_id TEXT,
            checked_at TEXT, alive INT, latency INT, anonymity TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS api_cache (
            ip TEXT PRIMARY KEY, checked_at TEXT, composite_score INT,
            raw_data TEXT)""")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_checks_pid ON checks(proxy_id)"
        )
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def update(self, proxy: "Proxy"):
        conn = self._conn()
        try:
            c = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            c.execute("SELECT id FROM proxies WHERE id=?", (proxy.id,))
            if c.fetchone():
                c.execute(
                    """UPDATE proxies SET last_seen=?,
                    last_alive=CASE WHEN ?=1 THEN ? ELSE last_alive END,
                    total_checks=total_checks+1,
                    successful_checks=successful_checks+?,
                    avg_latency=CASE
                        WHEN ? IS NOT NULL AND avg_latency IS NOT NULL
                        THEN (avg_latency+?)/2
                        WHEN ? IS NOT NULL THEN ?
                        ELSE avg_latency END,
                    country=COALESCE(?,country), asn=COALESCE(?,asn),
                    isp=COALESCE(?,isp), proxy_type=COALESCE(?,proxy_type)
                    WHERE id=?""",
                    (now, 1 if proxy.alive else 0, now,
                     1 if proxy.alive else 0,
                     proxy.latency_ms, proxy.latency_ms,
                     proxy.latency_ms, proxy.latency_ms,
                     proxy.country_code, proxy.asn, proxy.isp,
                     proxy.proxy_type.value if proxy.proxy_type else None,
                     proxy.id),
                )
            else:
                # Named columns: production DBs from earlier UPO/npo eras
                # carry extra columns (username, failed_checks, …) — a
                # positional VALUES(...) silently fails against them.
                c.execute(
                    """INSERT INTO proxies (id, ip, port, protocol,
                       first_seen, last_seen, last_alive, total_checks,
                       successful_checks, avg_latency, country, asn, isp,
                       proxy_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (proxy.id, proxy.ip, proxy.port, proxy.protocol.value,
                     proxy.first_seen, now, now if proxy.alive else None,
                     1, 1 if proxy.alive else 0, proxy.latency_ms,
                     proxy.country_code, proxy.asn, proxy.isp,
                     proxy.proxy_type.value if proxy.proxy_type else None),
                )
            c.execute(
                "INSERT INTO checks (proxy_id,checked_at,alive,latency,anonymity) VALUES (?,?,?,?,?)",
                (proxy.id, now, 1 if proxy.alive else 0, proxy.latency_ms,
                 proxy.anonymity.value if proxy.anonymity else None),
            )
            conn.commit()
        except sqlite3.Error as e:
            console.print(f"[dim red]DB write error: {e}[/dim red]")
        finally:
            conn.close()

    def get_cached_score(self, ip: str) -> Optional[int]:
        conn = self._conn()
        try:
            c = conn.cursor()
            c.execute(
                "SELECT checked_at, composite_score FROM api_cache WHERE ip=?",
                (ip,),
            )
            row = c.fetchone()
            if row and row[1] is not None:
                checked = datetime.fromisoformat(row[0])
                if (datetime.now(timezone.utc) - checked).total_seconds() < 86400:
                    return row[1]
        except Exception:
            pass
        finally:
            conn.close()
        return None

    def save_cached_score(self, ip: str, score: int):
        conn = self._conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            conn.cursor().execute(
                """INSERT INTO api_cache (ip, checked_at, composite_score)
                VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET
                checked_at=excluded.checked_at,
                composite_score=excluded.composite_score""",
                (ip, now, score),
            )
            conn.commit()
        except sqlite3.Error:
            pass
        finally:
            conn.close()

    def bulk_update(self, records) -> int:
        """Upsert many failure observations in ONE transaction.

        ``records`` is an iterable of ``(proxy, check_delta)`` pairs for
        proxies that were NOT alive at export time (TCP-dead or verify-dead)
        — alive proxies keep going through :meth:`update` from the exporter.
        Without this, history only ever learns about survivors and the
        I6 known-dead query would have nothing to condemn.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn = self._conn()
        n = 0
        try:
            rows = []
            for proxy, delta in records:
                rows.append(
                    (proxy.id, proxy.ip, proxy.port,
                     proxy.protocol.value if proxy.protocol else "http",
                     proxy.first_seen, now, None,
                     max(int(delta), 1), 0, None,
                     proxy.country_code, proxy.asn, proxy.isp,
                     proxy.proxy_type.value if proxy.proxy_type else None)
                )
            if not rows:
                return 0
            conn.executemany(
                """INSERT INTO proxies (id, ip, port, protocol, first_seen,
                       last_seen, last_alive, total_checks,
                       successful_checks, avg_latency, country, asn, isp,
                       proxy_type)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                       last_seen=excluded.last_seen,
                       total_checks=proxies.total_checks + excluded.total_checks,
                       last_alive=COALESCE(proxies.last_alive, excluded.last_alive),
                       country=COALESCE(excluded.country, proxies.country),
                       asn=COALESCE(excluded.asn, proxies.asn),
                       isp=COALESCE(excluded.isp, proxies.isp),
                       proxy_type=COALESCE(excluded.proxy_type, proxies.proxy_type)""",
                rows,
            )
            conn.commit()
            n = len(rows)
        except sqlite3.Error as e:
            console.print(f"[dim red]DB bulk write error: {e}[/dim red]")
        finally:
            conn.close()
        return n

    def get_stats(self) -> Dict[str, Any]:
        conn = self._conn()
        try:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM proxies")
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM checks")
            checks = c.fetchone()[0]
            return {"total_tracked": total, "total_checks": checks}
        finally:
            conn.close()

    def get_known_dead(self, min_fails: int = 5, stale_hours: float = 2.0) -> set:
        """Addresses (``ip:port``) chronically failing checks.

        An endpoint is "known dead" when its worst identity has
        ``total_checks - successful_checks >= min_fails`` AND no protocol
        variant of that address was seen alive within ``stale_hours``.
        Feeds the lifecycle engine's probation gate (improvement I6).
        """
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=stale_hours)).isoformat()
        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT ip, port,
                       MAX(total_checks - successful_checks) AS fails,
                       MAX(last_alive) AS last_alive
                FROM proxies GROUP BY ip, port
                """
            ).fetchall()
            dead = set()
            for ip, port, fails, last_alive in rows:
                if (fails or 0) < min_fails:
                    continue
                # MAX over TEXT ISO timestamps is order-preserving; if the
                # newest alive stamp is at/after the cutoff, not dead.
                if last_alive and last_alive >= cutoff:
                    continue
                dead.add(f"{ip}:{port}")
            return dead
        except Exception:
            return set()
        finally:
            conn.close()


__all__ = ["ProxyHistory"]