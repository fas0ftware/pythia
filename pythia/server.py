"""The DNS side: decide, answer or forward, over UDP and TCP (asyncio)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

from . import __version__, dns
from .blocklist import Lists
from .cache import Cache
from .config import Server, Settings
from .stats import Stats

UPSTREAM_TIMEOUT = 2.0
TCP_IDLE = 10.0
MAX_TCP_MESSAGE = 65535
MAX_IN_FLIGHT = 256       # upstream queries at once; more means a flood, answered SERVFAIL
MAX_TCP_CONNECTIONS = 100
MAX_TCP_PER_CLIENT = 10
IP_FREEBIND = 15   # Linux: bind an address this machine does not have yet (Wi-Fi not up at boot)


class RateLimiter:
    """Token bucket per client: `rate` per second, bursts up to twice that."""

    def __init__(self, rate: int, clock=time.monotonic):
        self.rate, self.burst, self.clock = rate, rate * 2, clock
        self.buckets: dict[str, tuple[float, float]] = {}

    def allow(self, client: str) -> bool:
        now = self.clock()
        tokens, last = self.buckets.get(client, (self.burst, now))
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if len(self.buckets) > 10_000:
            self.buckets.clear()        # a flood of fake source addresses: start over
        if tokens < 1:
            self.buckets[client] = (tokens, now)
            return False
        self.buckets[client] = (tokens - 1, now)
        return True


class DotConnection:
    """One TLS connection to a DNS-over-TLS server, shared by many queries at once
    (RFC 7858 pipelining). Each query gets an id unique on this connection; a reader task
    hands every answer to the query that waits for it."""

    def __init__(self, server: Server, ctx: ssl.SSLContext):
        self.server, self.ctx = server, ctx
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self.pending: dict[int, asyncio.Future] = {}
        self.reading: asyncio.Task | None = None
        self.lock = asyncio.Lock()

    @property
    def open(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()

    async def _connect(self) -> None:
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.server.host, self.server.port, ssl=self.ctx,
                                    server_hostname=self.server.tls_name), UPSTREAM_TIMEOUT + 1)
        self.reading = asyncio.get_running_loop().create_task(self._read_loop())

    async def _read_loop(self) -> None:
        reader = self.reader
        try:
            while True:
                size = struct.unpack("!H", await reader.readexactly(2))[0]
                data = await reader.readexactly(size)
                fut = self.pending.pop(dns.response_id(data), None) if len(data) >= 12 else None
                if fut and not fut.done():
                    fut.set_result(data)
        except (OSError, asyncio.IncompleteReadError, struct.error, ssl.SSLError) as exc:
            self._fail(exc)
        except asyncio.CancelledError:
            self._fail(OSError("closed"))

    def _fail(self, exc: BaseException) -> None:
        for fut in self.pending.values():
            if not fut.done():
                fut.set_exception(OSError(f"DNS over TLS connection lost ({exc!r})"))
        self.pending.clear()
        if self.writer is not None:
            self.writer.close()
        self.writer = None

    async def ask(self, packet: bytes) -> bytes:
        async with self.lock:
            if not self.open:
                await self._connect()
            qid = secrets.randbelow(65536)
            while qid in self.pending:
                qid = secrets.randbelow(65536)
            fut = asyncio.get_running_loop().create_future()
            self.pending[qid] = fut
            msg = dns.with_id(packet, qid)
            writer = self.writer          # the connection may be replaced once the lock is released
            writer.write(struct.pack("!H", len(msg)) + msg)
        try:
            await writer.drain()
            answer = await asyncio.wait_for(fut, UPSTREAM_TIMEOUT)
        finally:
            self.pending.pop(qid, None)
        return dns.with_id(answer, dns.response_id(packet))   # back to the id the caller chose

    def close(self) -> None:
        if self.reading:
            self.reading.cancel()
        self._fail(OSError("closed"))


def tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()          # system CAs, hostname check
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class Upstream:
    def __init__(self, servers: list[Server], ssl_context: ssl.SSLContext | None = None):
        self.servers = servers
        self.preferred = 0
        self.failures = {str(s): 0 for s in servers}
        self.last_ok: dict[str, float] = {}
        self._ctx = ssl_context
        self._dot: dict[Server, DotConnection] = {}

    async def _udp(self, server: Server, packet: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()

        class Proto(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                # Only an answer with our random id counts; anything else is ignored.
                if not fut.done() and len(data) >= 12 and data[:2] == packet[:2]:
                    fut.set_result(data)

            def error_received(self, exc):
                if not fut.done():
                    fut.set_exception(exc)

        family = socket.AF_INET6 if ":" in server.host else socket.AF_INET
        transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=(server.host, server.port), family=family)
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(fut, UPSTREAM_TIMEOUT)
        finally:
            transport.close()

    async def _tcp(self, server: Server, packet: bytes) -> bytes:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(server.host, server.port), UPSTREAM_TIMEOUT)
        try:
            writer.write(struct.pack("!H", len(packet)) + packet)
            await writer.drain()
            size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), UPSTREAM_TIMEOUT))[0]
            return await asyncio.wait_for(reader.readexactly(size), UPSTREAM_TIMEOUT)
        finally:
            writer.close()

    async def _tls(self, server: Server, packet: bytes) -> bytes:
        conn = self._dot.get(server)
        if conn is None:
            if self._ctx is None:
                self._ctx = tls_context()
            conn = self._dot[server] = DotConnection(server, self._ctx)
        reused = conn.open
        try:
            return await conn.ask(packet)
        except (OSError, asyncio.IncompleteReadError, ssl.SSLError):
            if not reused:
                raise
            # Servers close idle TLS connections; that is not a failure of the server.
            conn.close()
            return await conn.ask(packet)

    async def ask(self, packet: bytes, tcp: bool) -> bytes:
        """Forward a query (with its own random id) to the servers in turn. A TLS server is
        only ever asked over TLS: there is no silent fall back to plain DNS."""
        last_error: Exception | None = None
        n = len(self.servers)
        for i in range(n):
            idx = (self.preferred + i) % n
            server = self.servers[idx]
            key = str(server)
            try:
                if server.tls:
                    answer = await self._tls(server, packet)
                else:
                    answer = await (self._tcp(server, packet) if tcp else self._udp(server, packet))
                if dns.response_id(answer) != dns.response_id(packet):
                    raise OSError("answer with the wrong id")
                self.preferred = idx
                self.failures[key] = 0
                self.last_ok[key] = time.time()
                return answer
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, struct.error, ssl.SSLError) as exc:
                self.failures[key] += 1
                last_error = exc
        raise OSError(f"no upstream answered ({last_error!r})")

    def health(self) -> list[dict]:
        return [{"server": k, "failures_in_a_row": v, "last_ok": self.last_ok.get(k),
                 "encrypted": k.startswith("tls://")} for k, v in self.failures.items()]

    def close(self) -> None:
        for c in self._dot.values():
            c.close()


def _same_question(query: dns.Query, answer: bytes) -> bool:
    try:
        q = dns.parse_query(answer[:2] + b"\x00\x00" + answer[4:])   # clear the flags: read it like a query
    except dns.FormatError:
        return False
    return (q.name, q.qtype, q.qclass) == (query.name, query.qtype, query.qclass)


class Pythia:
    def __init__(self, settings: Settings, lists: Lists | None = None, upstream: Upstream | None = None,
                 stats: Stats | None = None):
        self.s = settings
        self.lists = lists or Lists()
        self.upstream = upstream or Upstream(settings.upstreams)
        self.cache = Cache(settings.cache_size)
        self.stats = stats or Stats(settings.log_queries)
        self.stats_lock = threading.Lock()
        self.limiter = RateLimiter(settings.rate_limit)
        self.paused_until = 0.0
        self.listening: list[str] = []
        self.lists_updated: str = ""
        self.at_home = True            # updated every 30 s when home_gateway_mac is set
        self.in_flight = 0
        self.tcp_open: dict[str, int] = {}

    # --- policy ------------------------------------------------------------------------------

    def client_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return False
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_loopback and not self.at_home:
            return False      # away from home: serve this machine only, never the network we are on
        return any(addr in n for n in self.s.allow_networks)

    @property
    def blocking(self) -> bool:
        return time.time() >= self.paused_until

    def record(self, *args, **kw) -> None:
        with self.stats_lock:
            self.stats.record(*args, **kw)

    async def handle(self, data: bytes, client: str, tcp: bool = False) -> bytes | None:
        """One query in, one answer out (None: drop it silently)."""
        start = time.monotonic()
        if not self.client_allowed(client):
            return None          # not ours to answer: never become an open resolver
        if not self.limiter.allow(client):
            self.record(client, "", "", "refused", "rate limit")
            return None
        try:
            q = dns.parse_query(data)
        except dns.FormatError:
            self.record(client, "", "", "error", "malformed")
            return dns.bare_error(data, dns.FORMERR)
        if q.opcode != 0:
            return dns.error_response(q, dns.NOTIMP)
        if q.qtype == dns.ANY or q.qclass != dns.CLASS_IN:
            self.record(client, q.name, q.type_name, "refused", "ANY/class")
            return dns.error_response(q, dns.REFUSED)
        if self.blocking:
            blocked, rule = self.lists.verdict(q.name)
            if blocked:
                self.record(client, q.name, q.type_name, "blocked", rule, (time.monotonic() - start) * 1000)
                return dns.blocked_response(q, self.s.blocked_ttl)
        key = (q.name, q.qtype, q.qclass)
        cached = self.cache.get(key, q.id)
        # Over UDP never send more than the client said it accepts (512 without EDNS).
        limit = dns.udp_limit(data)
        if cached is not None and not tcp and len(cached) > limit:
            self.record(client, q.name, q.type_name, "cached", "truncated", (time.monotonic() - start) * 1000)
            return dns.truncated_response(q)     # the client asks again over TCP
        if cached is not None:
            self.record(client, q.name, q.type_name, "cached", "", (time.monotonic() - start) * 1000)
            return cached
        if self.in_flight >= MAX_IN_FLIGHT:
            # Spoofed source addresses get past the per-client limit; this cap does not.
            self.record(client, q.name, q.type_name, "refused", "overloaded")
            return dns.error_response(q, dns.SERVFAIL)
        our_id = secrets.randbelow(65536)
        self.in_flight += 1
        try:
            answer = await self.upstream.ask(dns.with_id(data, our_id), tcp)
        except OSError:
            self.record(client, q.name, q.type_name, "error", "upstream", (time.monotonic() - start) * 1000)
            return dns.error_response(q, dns.SERVFAIL)
        finally:
            self.in_flight -= 1
        if not _same_question(q, answer):
            self.record(client, q.name, q.type_name, "error", "mismatched answer")
            return dns.error_response(q, dns.SERVFAIL)
        self.cache.put(key, answer)
        self.record(client, q.name, q.type_name, "forwarded", "", (time.monotonic() - start) * 1000)
        if not tcp and len(answer) > limit:
            # A TLS or TCP upstream answers in full; a UDP client then gets "truncated" and retries.
            return dns.truncated_response(q)
        return dns.with_id(answer, q.id)

    # --- status ---------------------------------------------------------------------------------

    def summary(self) -> dict:
        with self.stats_lock:
            st = self.stats.summary()
        return {
            "version": __version__,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "listening": self.listening,
            "at_home": self.at_home,
            "blocking": self.blocking,
            "paused_until": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.paused_until)) if not self.blocking else "",
            "domains_on_lists": self.lists.total(),
            "lists": self.lists.sources,
            "lists_updated": self.lists_updated,
            "allow_entries": len(self.lists.allow),
            "custom_blocks": len(self.lists.custom_block),
            "cache_entries": len(self.cache),
            "cache_hits": self.cache.hits,
            "upstreams": self.upstream.health(),
            **st,
        }

    def write_status(self) -> None:
        path = self.s.status_file
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.summary(), indent=2))
        os.replace(tmp, path)


# --- sockets ---------------------------------------------------------------------------------------

class UdpServer(asyncio.DatagramProtocol):
    def __init__(self, app: Pythia):
        self.app = app
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        asyncio.get_running_loop().create_task(self._answer(data, addr))

    async def _answer(self, data, addr):
        answer = await self.app.handle(data, addr[0])
        if answer is not None and self.transport is not None:
            self.transport.sendto(answer, addr)


async def _tcp_client(app: Pythia, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip = peer[0] if peer else ""
    counted = False
    try:
        if not peer or not app.client_allowed(ip):
            return
        # Idle connections cost a file descriptor each: cap them, in total and per device.
        if sum(app.tcp_open.values()) >= MAX_TCP_CONNECTIONS or app.tcp_open.get(ip, 0) >= MAX_TCP_PER_CLIENT:
            return
        app.tcp_open[ip] = app.tcp_open.get(ip, 0) + 1
        counted = True
        while True:
            head = await asyncio.wait_for(reader.readexactly(2), TCP_IDLE)
            size = struct.unpack("!H", head)[0]
            if not 12 <= size <= MAX_TCP_MESSAGE:
                return
            data = await asyncio.wait_for(reader.readexactly(size), TCP_IDLE)
            answer = await app.handle(data, peer[0], tcp=True)
            if answer is None:
                return
            writer.write(struct.pack("!H", len(answer)) + answer)
            await writer.drain()
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        if counted:
            app.tcp_open[ip] -= 1
            if not app.tcp_open[ip]:
                del app.tcp_open[ip]
        writer.close()


def _socket(host: str, port: int, kind: int) -> socket.socket:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_IP if family == socket.AF_INET else socket.SOL_IPV6, IP_FREEBIND, 1)
    except OSError:
        pass
    s.bind((host, port))
    if kind == socket.SOCK_STREAM:
        s.listen(64)
    s.setblocking(False)
    return s


async def start(app: Pythia) -> list:
    loop = asyncio.get_running_loop()
    servers = []
    for host, port in app.s.listen:
        udp = _socket(host, port, socket.SOCK_DGRAM)
        transport, _ = await loop.create_datagram_endpoint(lambda: UdpServer(app), sock=udp)
        tcp = await asyncio.start_server(lambda r, w: _tcp_client(app, r, w), sock=_socket(host, port, socket.SOCK_STREAM))
        servers += [transport, tcp]
        app.listening.append(f"{host}:{port}")
    return servers


def custom_path(s: Settings) -> Path:
    return s.data_dir / "custom.json"


def load_custom(app: Pythia) -> None:
    try:
        data = json.loads(custom_path(app.s).read_text())
    except (OSError, ValueError):
        return
    app.lists.allow = set(data.get("allow", []))
    app.lists.custom_block = set(data.get("block", []))


def save_custom(app: Pythia) -> None:
    path = custom_path(app.s)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"allow": sorted(app.lists.allow), "block": sorted(app.lists.custom_block)}, indent=2))
    os.replace(tmp, path)
