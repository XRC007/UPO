"""Raw asyncio SOCKS4/4a/5 client handshake (improvement I5).

Replaces per-proxy ``aiohttp_socks.ProxyConnector`` sessions for plain
HTTP-over-SOCKS requests (verification, protocol detection): one
``asyncio.open_connection`` + a few struct-packed bytes instead of a full
aiohttp client session per proxy — roughly 3-5× cheaper per endpoint.

API:
    socks4_connect(ip, port, dest_host, dest_port, user, timeout)
    socks5_connect(ip, port, dest_host, dest_port, user, password, timeout)
    socks_http_get(ip, port, version, method, url, headers, timeout) -> (status, body)

All raise :class:`SocksError`, :class:`asyncio.TimeoutError` or connection
errors on failure; callers treat any exception as "proxy dead for this
protocol".
"""

from __future__ import annotations

import asyncio
import ssl as _ssl
import struct
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

SOCKS_VERSION_4 = 4
SOCKS_VERSION_5 = 5


class SocksError(Exception):
    """SOCKS handshake or tunnel-level failure."""


def _parse_url(url: str) -> Tuple[str, int, str, bool]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        raise SocksError(f"URL has no host: {url!r}")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path, parts.scheme == "https"


def _encode_ipv4(ip: str) -> Optional[bytes]:
    try:
        octets = [int(o) for o in ip.split(".")]
        if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
            return bytes(octets)
    except ValueError:
        pass
    return None


def _host_header(host: str, port: int, https: bool) -> str:
    default = 443 if https else 80
    return host if port == default else f"{host}:{port}"


async def _read_exactly(reader: asyncio.StreamReader, n: int, timeout: float) -> bytes:
    return await asyncio.wait_for(reader.readexactly(n), timeout)


async def socks4_connect(
    proxy_ip: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    user: str = "",
    timeout: float = 10.0,
    use_4a: bool = True,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """SOCKS4/4a CONNECT. Returns the opened (reader, writer) tunnel pair."""
    packed = _encode_ipv4(dest_host)
    if packed is None:
        if not use_4a:
            raise SocksError(f"SOCKS4 cannot resolve host {dest_host!r}")
        command = b"\x00"            # 4a: domain name follows
        addr = b"\x00\x00\x00\x01"   # dummy ip, real name after userid
        name = dest_host.encode("idna")
    else:
        command = b"\x01"
        addr = packed
        name = b""

    req = (
        b"\x04" + command + struct.pack("!H", dest_port) + addr
        + user.encode() + b"\x00" + name
    )
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_ip, proxy_port), timeout
    )
    try:
        writer.write(req)
        await writer.drain()
        resp = await _read_exactly(reader, 8, timeout)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as e:
        writer.close()
        raise SocksError(f"SOCKS4 handshake failed: {e}") from e
    # Response: 0x00 | status(1) | port(2) | ip(4); status 90 = request granted.
    if resp[0] != 0x00 or resp[1] != 90:
        writer.close()
        raise SocksError(f"SOCKS4 refused (status {resp[1]})")
    return reader, writer


async def socks5_connect(
    proxy_ip: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    user: str = "",
    password: str = "",
    timeout: float = 10.0,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """SOCKS5 CONNECT (ATYP domain/IPv4, optional username/password auth)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy_ip, proxy_port), timeout
    )
    try:
        if user:
            writer.write(b"\x05\x02\x00\x02")  # no-auth + user/pass offered
            await writer.drain()
            ver, method = await _read_exactly(reader, 2, timeout)
            if ver != 5:
                raise SocksError("bad SOCKS5 greeting")
            if method == 2:
                upair = (
                    b"\x01" + bytes([len(user)]) + user.encode()
                    + bytes([len(password)]) + password.encode()
                )
                writer.write(upair)
                await writer.drain()
                _, status = await _read_exactly(reader, 2, timeout)
                if status != 0:
                    raise SocksError("SOCKS5 auth rejected")
            elif method != 0:
                raise SocksError(f"SOCKS5 server chose method {method}")
        else:
            writer.write(b"\x05\x01\x00")  # no-auth only
            await writer.drain()
            ver, method = await _read_exactly(reader, 2, timeout)
            if ver != 5 or method != 0:
                raise SocksError("SOCKS5 no-auth negotiation failed")

        packed = _encode_ipv4(dest_host)
        if packed is not None:
            atyp, dst = b"\x01", packed
        else:
            enc = dest_host.encode("idna")
            atyp, dst = b"\x03", bytes([len(enc)]) + enc
        writer.write(
            b"\x05\x01\x00" + atyp + dst + struct.pack("!H", dest_port)
        )
        await writer.drain()
        head = await _read_exactly(reader, 4, timeout)
        if head[0] != 5 or head[1] != 0:
            raise SocksError(f"SOCKS5 connect refused (rep {head[1]})")
        # Consume BND.ATYP-specific remainder so the stream is aligned.
        atyp_bnd = head[3]
        if atyp_bnd == 1:
            await _read_exactly(reader, 4 + 2, timeout)
        elif atyp_bnd == 3:
            (length,) = await _read_exactly(reader, 1, timeout)
            await _read_exactly(reader, length + 2, timeout)
        elif atyp_bnd == 4:
            await _read_exactly(reader, 16 + 2, timeout)
        else:
            await _read_exactly(reader, 2, timeout)
        return reader, writer
    except SocksError:
        writer.close()
        raise
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError) as e:
        writer.close()
        raise SocksError(f"SOCKS5 handshake failed: {e}") from e


async def socks_http_get(
    proxy_ip: str,
    proxy_port: int,
    version: int,
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    user: str = "",
    password: str = "",
) -> Tuple[int, str]:
    """One HTTP request through a SOCKS proxy → ``(status, body_text)``.

    ``http://`` URLs: absolute-URI request inside the tunnel.
    ``https://`` URLs: CONNECT + TLS upgrade via :meth:`StreamWriter.start_tls`.
    """
    host, port, path, https = _parse_url(url)
    if version == SOCKS_VERSION_5:
        reader, writer = await socks5_connect(
            proxy_ip, proxy_port, host, port, user, password, timeout
        )
    else:
        reader, writer = await socks4_connect(
            proxy_ip, proxy_port, host, port, user, timeout
        )
    try:
        if https:
            target = _host_header(host, port, True)
            writer.write(
                f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
            )
            await writer.drain()
            status_line = await asyncio.wait_for(reader.readline(), timeout)
            if b" 200 " not in status_line:
                raise SocksError(
                    f"CONNECT refused: {status_line[:60]!r}"
                )
            # Drain CONNECT response headers.
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout)
                if line in (b"\r\n", b"\n", b""):
                    break
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            try:
                await writer.start_tls(ctx, server_hostname=host)
            except Exception as e:
                raise SocksError(f"TLS upgrade failed: {e}") from e
            req = (
                f"{method} {path} HTTP/1.1\r\n"
                f"Host: {target}\r\nConnection: close\r\n"
            ).encode()
        else:
            req = (
                f"{method} {url} HTTP/1.1\r\n"
                f"Host: {_host_header(host, port, False)}\r\n"
                f"Connection: close\r\n"
            ).encode()
        for k, v in (headers or {}).items():
            req += f"{k}: {v}\r\n".encode()
        req += b"\r\n"
        writer.write(req)
        await writer.drain()

        status_line = await asyncio.wait_for(reader.readline(), timeout)
        try:
            status = int(status_line.split()[1])
        except (IndexError, ValueError):
            raise SocksError(f"bad HTTP status line: {status_line[:60]!r}")
        length: Optional[int] = None
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout)
            if line in (b"\r\n", b"\n", b""):
                break
            low = line.lower()
            if low.startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1])
                except ValueError:
                    pass
        if length is not None:
            body = await asyncio.wait_for(reader.readexactly(length), timeout)
        else:
            body = await asyncio.wait_for(reader.read(), timeout)
        return status, body.decode("utf-8", errors="replace")
    finally:
        try:
            writer.close()
        except Exception:
            pass


__all__ = [
    "SocksError",
    "socks4_connect",
    "socks5_connect",
    "socks_http_get",
    "SOCKS_VERSION_4",
    "SOCKS_VERSION_5",
]
