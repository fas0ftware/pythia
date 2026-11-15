"""The DNS side: decide, answer or forward, over UDP and TCP (asyncio)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import secrets
import socket
import struct
import threading
import time
from pathlib import Path

from . import __version__, dns
from .blocklist import Lists
from .cache import Cache
from .config import Settings
from .stats import Stats

UPSTREAM_TIMEOUT = 2.0
TCP_IDLE = 10.0
MAX_TCP_MESSAGE = 65535
MAX_IN_FLIGHT = 256       # upstream queries at once; more means a flood, answered SERVFAIL
MAX_TCP_CONNECTIONS = 100
MAX_TCP_PER_CLIENT = 10
SAFE_UDP_SIZE = 1232      # the size every EDNS client accepts (DNS flag day 2020)
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


class Upstream:
    def __init__(self, servers: list[tuple[str, int]]):
        self.servers = servers
        self.preferred = 0
        self.failures = {f"{h}:{p}": 0 for h, p in servers}
        self.last_ok: dict[str, float] = {}

    async def _udp(self, server: tuple[str, int], packet: bytes) -> bytes:
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

        family = socket.AF_INET6 if ":" in server[0] else socket.AF_INET
        transport, _ = await loop.create_datagram_endpoint(Proto, remote_addr=server, family=family)
        try:
            transport.sendto(packet)
            return await asyncio.wait_for(fut, UPSTREAM_TIMEOUT)
        finally:
            transport.close()

    async def _tcp(self, server: tuple[str, int], packet: bytes) -> bytes:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(*server), UPSTREAM_TIMEOUT)
        try:
            writer.write(struct.pack("!H", len(packet)) + packet)
            await writer.drain()
            size = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), UPSTREAM_TIMEOUT))[0]
            return await asyncio.wait_for(reader.readexactly(size), UPSTREAM_TIMEOUT)
        finally:
            writer.close()

    async def ask(self, packet: bytes, tcp: bool) -> bytes:
        """Forward a query (with its own random id) to the servers in turn."""
        last_error: Exception | None = None
        n = len(self.servers)
        for i in range(n):
            idx = (self.preferred + i) % n
            server = self.servers[idx]
            key = f"{server[0]}:{server[1]}"
            try:
                answer = await (self._tcp(server, packet) if tcp else self._udp(server, packet))
                if dns.response_id(answer) != dns.response_id(packet):
                    raise OSError("answer with the wrong id")
                self.preferred = idx
                self.failures[key] = 0
                self.last_ok[key] = time.time()
                return answer
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, struct.error) as exc:
                self.failures[key] += 1
                last_error = exc
        raise OSError(f"no upstream answered ({last_error!r})")

    def health(self) -> list[dict]:
        return [{"server": k, "failures_in_a_row": v, "last_ok": self.last_ok.get(k)} for k, v in self.failures.items()]


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
        # Over UDP hand out only what the client surely accepts (512 without EDNS, else 1232);
        # a bigger cached answer is fetched again so the upstream can size or truncate it.
        limit = SAFE_UDP_SIZE if dns.has_additional(data) else 512
        if cached is not None and (tcp or len(cached) <= limit):
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
