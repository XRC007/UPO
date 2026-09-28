"""SECTION 3B: VERIFIED PROXY DB.

Stores only working proxies. Wiped and rewritten each run.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from ..models import Proxy
from ..utils.console import console


class VerifiedProxyDB:
    """Stores only working proxies. Wiped and rewritten each run."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("""CREATE TABLE IF NOT EXISTS verified (
            address TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            port INT NOT NULL,
            protocol TEXT NOT NULL,
            last_verified TEXT,
            latency_ms INT,
            country_code TEXT,
            anonymity TEXT,
            proxy_type TEXT)""")
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def load_all(self) -> List[Dict[str, Any]]:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT ip, port, protocol FROM verified"
            ).fetchall()
            return [
                {"ip": r[0], "port": r[1], "protocol": r[2]}
                for r in rows
            ]
        finally:
            conn.close()

    def save_all(self, proxies: List["Proxy"]):
        conn = self._conn()
        try:
            conn.execute("DELETE FROM verified")
            now = datetime.now(timezone.utc).isoformat()
            for p in proxies:
                conn.execute(
                    """INSERT OR REPLACE INTO verified
                    (address, ip, port, protocol, last_verified,
                     latency_ms, country_code, anonymity, proxy_type)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    (p.address, p.ip, p.port, p.protocol.value, now,
                     p.latency_ms, p.country_code,
                     p.anonymity.value if p.anonymity else None,
                     p.proxy_type.value if p.proxy_type else None),
                )
            conn.commit()
        except sqlite3.Error as e:
            console.print(f"[dim red]VerifiedDB write error: {e}[/dim red]")
        finally:
            conn.close()

    def count(self) -> int:
        conn = self._conn()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM verified"
            ).fetchone()[0]
        finally:
            conn.close()


__all__ = ["VerifiedProxyDB"]