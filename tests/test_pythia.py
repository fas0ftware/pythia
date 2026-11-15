import asyncio
import ipaddress
import json
import socket
import struct
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from pythia import blocklist, cache, config, dns, lists, server
from pythia.blocklist import Lists
from pythia.server import Pythia, RateLimiter, Upstream
from pythia.stats import Stats


# --- wire format -------------------------------------------------------------------------

def test_parse_and_blocked_answers():
    q = dns.parse_query(dns.build_query("Ads.Example.COM.", dns.A, qid=0xBEEF))
    assert (q.id, q.name, q.qtype, q.type_name) == (0xBEEF, "ads.example.com", dns.A, "A")
    a = dns.blocked_response(q, 300)
    assert dns.response_id(a) == 0xBEEF and dns.rcode(a) == dns.NOERROR
    assert a.endswith(struct.pack("!I", 300) + b"\x00\x04" + bytes(4))
    aaaa = dns.blocked_response(dns.parse_query(dns.build_query("x.com", dns.AAAA)), 60)
    assert aaaa.endswith(b"\x00\x10" + bytes(16))
    https = dns.blocked_response(dns.parse_query(dns.build_query("x.com", dns.HTTPS)), 60)
    assert dns.HEADER.unpack_from(https)[3] == 0, "no data for other types"


@pytest.mark.parametrize("packet", [
    b"", b"\x00" * 11,
    dns.HEADER.pack(1, dns.QR, 1, 0, 0, 0) + b"\x00\x00\x01\x00\x01",          # a response
    dns.HEADER.pack(1, 0, 2, 0, 0, 0) + b"\x00\x00\x01\x00\x01",               # two questions
    dns.HEADER.pack(1, 0, 1, 0, 0, 0) + b"\x05ab",                              # label past the end
    dns.HEADER.pack(1, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01",            # pointer to itself
    dns.HEADER.pack(1, 0, 1, 0, 0, 0) + b"\x01a" * 130 + b"\x00\x00\x01\x00\x01",  # too many labels
])
def test_malformed_queries(packet):
    with pytest.raises(dns.FormatError):
        dns.parse_query(packet)


def answer_for(query: bytes, ttl: int, ip: bytes = b"\x01\x02\x03\x04", rcode=0, extra_opt=False) -> bytes:
    q = dns.parse_query(query)
    flags = dns.QR | dns.RD | dns.RA | rcode
    ar = 1 if extra_opt else 0
    body = q.question + struct.pack("!HHHIH", 0xC00C, dns.A, 1, ttl, 4) + ip
    if extra_opt:
        body += b"\x00" + struct.pack("!HHIH", dns.OPT, 1232, 0, 0)
    return dns.HEADER.pack(q.id, flags, 1, 1, 0, ar) + body


def test_ttl_offsets_and_aging():
    data = answer_for(dns.build_query("a.com", dns.A), 120, extra_opt=True)
    offsets, smallest = dns.ttl_offsets(data)
    assert len(offsets) == 1 and smallest == 120, "OPT has no TTL to age"
    aged = dns.age_ttls(data, offsets, 30)
    assert dns.ttl_offsets(aged)[1] == 90
    assert dns.ttl_offsets(dns.age_ttls(data, offsets, 999))[1] == 0


# --- lists ---------------------------------------------------------------------------------

def test_parse_list_formats():
    text = """# comment
0.0.0.0 ads.example.com
127.0.0.1 localhost
0.0.0.0 tracker.example.net metrics.example.net  # two names
:: v6.example.org
plain.example.io
||adblock.example.com^
*.wild.example.com
not a domain
192.168.1.1
"""
    got = blocklist.parse_list(text)
    assert got == {"ads.example.com", "tracker.example.net", "metrics.example.net", "v6.example.org",
                   "plain.example.io", "adblock.example.com", "wild.example.com"}


def test_verdict_most_specific_wins():
    l = Lists(blocked={"ads.example.com", "tracker.net"}, allow={"cdn.ads.example.com", "example.com"})
    assert l.verdict("x.ads.example.com") == (True, "ads.example.com"), "allowing the parent does not unblock"
    assert l.verdict("cdn.ads.example.com") == (False, "cdn.ads.example.com")
    assert l.verdict("a.b.tracker.net") == (True, "tracker.net")
    assert l.verdict("example.com") == (False, "example.com")
    assert l.verdict("other.org") == (False, "")
    assert l.verdict("") == (False, "")


def test_refresh_keeps_old_copy_on_bad_download(tmp_path):
    l = Lists()
    good = "\n".join(f"0.0.0.0 d{i}.example.com" for i in range(1500))

    def fetch_good(name, url, directory):
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.txt").write_text(good)

    assert lists.refresh(l, [("main", "https://x")], tmp_path, fetch=fetch_good) == []
    assert l.total() == 1500

    def fetch_bad(name, url, directory):
        raise ValueError("only 3 domains, keeping the previous copy")

    errors = lists.refresh(l, [("main", "https://x")], tmp_path, fetch=fetch_bad)
    assert errors and l.total() == 1500, "the old list keeps working"
    lists.refresh(l, [], tmp_path, fetch=fetch_bad)
    assert l.total() == 0, "a list removed from the settings stops blocking"


def test_download_rejects_small_lists(tmp_path, monkeypatch):
    class Resp:
        def __init__(self, body):
            self.body = body

        def read(self, n):
            return self.body[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(lists.urllib.request, "urlopen", lambda req, timeout: Resp(b"<html>error page</html>"))
    with pytest.raises(ValueError):
        lists.download("x", "https://x", tmp_path)
    assert not (tmp_path / "x.txt").exists()


# --- cache, rate limit, config -------------------------------------------------------------

def test_cache_ttl_and_aging():
    now = [1000.0]
    c = cache.Cache(size=2, clock=lambda: now[0])
    q = dns.build_query("a.com", dns.A)
    c.put(("a.com", 1, 1), answer_for(q, 100))
    now[0] += 40
    hit = c.get(("a.com", 1, 1), 0x4242)
    assert dns.response_id(hit) == 0x4242 and dns.ttl_offsets(hit)[1] == 60
    now[0] += 61
    assert c.get(("a.com", 1, 1), 1) is None
    c.put(("b", 1, 1), answer_for(q, 100, rcode=dns.SERVFAIL))
    assert len(c) == 0, "failures are not cached"
    for name in "xyz":
        c.put((name, 1, 1), answer_for(q, 100))
    assert len(c) == 2, "size limit"


def test_rate_limiter():
    t = [0.0]
    r = RateLimiter(10, clock=lambda: t[0])
    assert sum(r.allow("a") for _ in range(30)) == 20     # burst = 2 x rate
    assert not r.allow("a") and r.allow("b")
    t[0] += 1
    assert sum(r.allow("a") for _ in range(30)) == 10


def test_config():
    s = config.parse({"listen": ["127.0.0.1:5354", "[::1]:53"], "upstreams": ["9.9.9.9"],
                      "allow_networks": ["192.168.1.0/24"]})
    assert s.listen == [("127.0.0.1", 5354), ("::1", 53)] and s.upstreams == [config.Server("9.9.9.9", 53)]
    for bad in ({"allow_networks": ["0.0.0.0/0"]}, {"upstreams": ["dns.google"]}, {"upstreams": []},
                {"lists": [{"name": "x", "url": "http://insecure"}]}, {"lists": [{"name": "../x", "url": "https://a"}]}):
        with pytest.raises(config.ConfigError):
            config.parse(bad)


# --- the server, end to end ----------------------------------------------------------------

class FakeUpstream(Upstream):
    def __init__(self, ttl=300, fail=False, wrong=False):
        super().__init__([config.Server("192.0.2.53", 53)])
        self.ttl, self.fail, self.wrong, self.calls = ttl, fail, wrong, 0

    async def ask(self, packet, tcp):
        self.calls += 1
        if self.fail:
            raise OSError("down")
        if self.wrong:
            return answer_for(dns.with_id(dns.build_query("evil.com", dns.A), dns.response_id(packet)), 60)
        return answer_for(packet, self.ttl)


def make(**kw):
    s = config.Settings(allow_networks=[ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("192.168.1.0/24")])
    up = kw.pop("upstream", FakeUpstream())
    p = Pythia(s, Lists(blocked={"ads.example.com"}), upstream=up, stats=Stats())
    return p, up


def run(coro):
    return asyncio.run(coro)


def test_handle_paths():
    p, up = make()
    q = dns.build_query("www.example.org", dns.A, qid=7)
    a = run(p.handle(q, "192.168.1.20"))
    assert dns.response_id(a) == 7 and dns.rcode(a) == dns.NOERROR and up.calls == 1
    run(p.handle(q, "192.168.1.20"))
    assert up.calls == 1 and p.stats.totals["cached"] == 1

    b = run(p.handle(dns.build_query("x.ads.example.com", dns.A), "127.0.0.1"))
    assert b.endswith(bytes(4)) and p.stats.top_blocked["x.ads.example.com"] == 1

    assert run(p.handle(q, "203.0.113.9")) is None, "not an open resolver"
    assert run(p.handle(q, "::ffff:192.168.1.20")) is not None, "IPv4-mapped clients are recognised"
    assert dns.rcode(run(p.handle(dns.build_query("example.org", dns.ANY), "127.0.0.1"))) == dns.REFUSED
    assert dns.rcode(run(p.handle(b"\x12\x34" + b"\x00" * 3, "127.0.0.1"))) == dns.FORMERR

    p.paused_until = 1e12
    unblocked = run(p.handle(dns.build_query("ads.example.com", dns.A), "127.0.0.1"))
    assert not unblocked.endswith(bytes(4)), "paused: forwarded"


def test_upstream_failures_and_spoofed_answers():
    p, _ = make(upstream=FakeUpstream(fail=True))
    assert dns.rcode(run(p.handle(dns.build_query("a.org", dns.A), "127.0.0.1"))) == dns.SERVFAIL
    p, _ = make(upstream=FakeUpstream(wrong=True))
    assert dns.rcode(run(p.handle(dns.build_query("a.org", dns.A), "127.0.0.1"))) == dns.SERVFAIL
    assert len(p.cache) == 0, "an answer to another question is never cached"


def test_udp_tcp_and_real_upstream_protocol(tmp_path):
    """A fake upstream DNS server on loopback, Pythia in front of it, real sockets both ways."""
    async def main():
        loop = asyncio.get_running_loop()

        class FakeDNS(asyncio.DatagramProtocol):
            def connection_made(self, t):
                self.t = t

            def datagram_received(self, data, addr):
                self.t.sendto(answer_for(data, 300), addr)

        up_t, _ = await loop.create_datagram_endpoint(FakeDNS, local_addr=("127.0.0.1", 0))
        up_port = up_t.get_extra_info("sockname")[1]

        async def tcp_upstream(r, w):
            size = struct.unpack("!H", await r.readexactly(2))[0]
            data = await r.readexactly(size)
            ans = answer_for(data, 300)
            w.write(struct.pack("!H", len(ans)) + ans)
            await w.drain()
            w.close()

        tcp_up = await asyncio.start_server(tcp_upstream, "127.0.0.1", up_port)

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        s = config.Settings(listen=[("127.0.0.1", port)], upstreams=[config.Server("127.0.0.1", up_port)], status_file=tmp_path / "s.json")
        p = Pythia(s, Lists(blocked={"ads.example.com"}))
        servers = await server.start(p)

        # UDP client
        reply = loop.create_future()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                reply.set_result(data)

        ct, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", port))
        ct.sendto(dns.build_query("site.example.org", dns.A, qid=99))
        udp_answer = await asyncio.wait_for(reply, 3)
        ct.close()

        # TCP client, two queries on one connection
        r, w = await asyncio.open_connection("127.0.0.1", port)
        tcp_answers = []
        for name in ("ads.example.com", "site2.example.org"):
            msg = dns.build_query(name, dns.A, qid=5)
            w.write(struct.pack("!H", len(msg)) + msg)
            await w.drain()
            size = struct.unpack("!H", await r.readexactly(2))[0]
            tcp_answers.append(await r.readexactly(size))
        w.close()

        p.write_status()
        for srv in servers:
            srv.close()
        tcp_up.close()
        up_t.close()
        return udp_answer, tcp_answers, json.loads((tmp_path / "s.json").read_text())

    udp_answer, tcp_answers, status = run(main())
    assert dns.response_id(udp_answer) == 99 and udp_answer.endswith(b"\x01\x02\x03\x04")
    assert tcp_answers[0].endswith(bytes(4)) and tcp_answers[1].endswith(b"\x01\x02\x03\x04")
    assert status["queries_24h"] == 3 and status["blocked_24h"] == 1 and "site.example.org" not in json.dumps(status)


# --- dashboard -------------------------------------------------------------------------------

@pytest.fixture
def web(tmp_path):
    from http.server import ThreadingHTTPServer
    from pythia.web import create_app
    p, _ = make()
    p.s.data_dir = tmp_path
    run(p.handle(dns.build_query("x.ads.example.com", dns.A), "127.0.0.1"))
    app = create_app(p)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.handler(0))
    port = srv.server_address[1]
    srv.RequestHandlerClass = app.handler(port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port, p, tmp_path
    srv.shutdown()


def call(port, path, body=None, origin=True, host=None):
    headers = {"Content-Type": "application/json"}
    if origin:
        headers["Origin"] = f"http://127.0.0.1:{port}"
    if host:
        headers["Host"] = host
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if body is None else json.dumps(body).encode(),
                                 headers=headers, method="GET" if body is None else "POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_dashboard_rules_pause_and_guards(web):
    port, p, data_dir = web
    status, state = call(port, "/api/state")
    assert status == 200 and state["top_blocked"] == [["x.ads.example.com", 1]]
    assert call(port, "/api/allow", {"domain": "X.Ads.Example.com"})[0] == 200
    assert p.lists.verdict("x.ads.example.com") == (False, "x.ads.example.com")
    assert json.loads((data_dir / "custom.json").read_text())["allow"] == ["x.ads.example.com"]
    assert call(port, "/api/allow", {"domain": "x.ads.example.com", "remove": True})[0] == 200
    assert call(port, "/api/block", {"domain": "not a domain"})[0] == 400
    assert call(port, "/api/pause", {"minutes": 5})[1]["blocking"] is False
    assert call(port, "/api/pause", {"minutes": 0})[1]["blocking"] is True
    assert call(port, "/api/pause", {"minutes": 99999})[0] == 400
    assert call(port, "/api/allow", {"domain": "a.com"}, origin=False)[0] == 403, "CSRF"
    assert call(port, "/api/state", host="evil.example")[0] == 403, "DNS rebinding"


def test_home_detection(tmp_path):
    from pythia import home
    (tmp_path / "route").write_text("Iface\tDestination\tGateway\tFlags\n"
                                    "wlo1\t0001A8C0\t00000000\t0001\n"
                                    "wlo1\t00000000\t0101A8C0\t0003\n")
    (tmp_path / "arp").write_text("IP address HW type Flags HW address Mask Device\n"
                                  "192.168.1.1 0x1 0x2 02:00:5E:00:53:01 * wlo1\n")
    assert home.default_gateway((tmp_path / "route").read_text()) == "192.168.1.1"
    assert home.at_home("02:00:5e:00:53:01", tmp_path)
    assert not home.at_home("00:11:22:33:44:55", tmp_path)
    assert home.at_home("", tmp_path), "not configured: always home"


def test_away_from_home_serves_only_this_machine():
    p, _ = make()
    p.at_home = False
    q = dns.build_query("www.example.org", dns.A)
    assert run(p.handle(q, "192.168.1.20")) is None
    assert run(p.handle(q, "127.0.0.1")) is not None


def test_flood_limits():
    p, up = make()

    class Slow(FakeUpstream):
        async def ask(self, packet, tcp):
            await asyncio.sleep(0.2)
            return answer_for(packet, 60)

    p.upstream = Slow()

    async def flood():
        qs = [p.handle(dns.build_query(f"n{i}.example.org", dns.A), f"192.168.1.{i % 250 + 1}") for i in range(400)]
        return await asyncio.gather(*qs)

    answers = run(flood())
    fails = sum(1 for a in answers if dns.rcode(a) == dns.SERVFAIL)
    assert fails == 400 - server.MAX_IN_FLIGHT and p.in_flight == 0


def test_answers_respect_the_clients_udp_size():
    p, up = make()
    plain = dns.build_query("big.example.org", dns.A)
    # the same question with an EDNS OPT record (UDP size 1232)
    edns = dns.HEADER.pack(0x1234, dns.RD, 1, 0, 0, 1) + plain[12:] + b"\x00" + struct.pack("!HHIH", dns.OPT, 1232, 0, 0)
    assert dns.udp_limit(plain) == 512 and dns.udp_limit(edns) == 1232
    key = ("big.example.org", dns.A, 1)
    stored = dns.HEADER.pack(0, dns.QR | dns.RA, 1, 0, 0, 0) + dns.parse_query(plain).question
    for size, query, truncated in ((600, plain, True), (1000, edns, False), (4000, edns, True)):
        p.cache._d[key] = (p.cache.clock(), p.cache.clock() + 300, stored + bytes(size), [])
        a = run(p.handle(query, "127.0.0.1"))
        assert dns.is_truncated(a) == truncated, (size, truncated)
        assert truncated or len(a) > 1000
        tcp = run(p.handle(query, "127.0.0.1", tcp=True))
        assert not dns.is_truncated(tcp) and len(tcp) >= size, "over TCP the full answer"
    assert up.calls == 0, "all from the cache"


def test_tcp_connection_cap():
    async def main():
        p, _ = make()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        p.s.listen = [("127.0.0.1", port)]
        servers = await server.start(p)
        conns = [await asyncio.open_connection("127.0.0.1", port) for _ in range(server.MAX_TCP_PER_CLIENT + 3)]
        await asyncio.sleep(0.2)
        open_now = sum(p.tcp_open.values())
        extra_r, extra_w = conns[-1]
        closed = await asyncio.wait_for(extra_r.read(1), 2) == b""
        for _, w in conns:
            w.close()
        await asyncio.sleep(0.2)
        for srv in servers:
            srv.close()
        return open_now, closed, sum(p.tcp_open.values())
    open_now, closed, after = run(main())
    assert open_now == server.MAX_TCP_PER_CLIENT and closed and after == 0


# --- DNS over TLS --------------------------------------------------------------------------

def make_cert(tmp_path, name="dns.test"):
    import shutil
    import subprocess
    if not shutil.which("openssl"):
        pytest.skip("openssl not installed")
    key, crt = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", f"/CN={name}",
                    "-addext", f"subjectAltName=DNS:{name}"], check=True, capture_output=True)
    return key, crt


def test_config_upstreams():
    s = config.parse({"upstreams": ["tls://1.1.1.1#cloudflare-dns.com", "9.9.9.9", "tls://[::1]:8853#dns.test"]})
    assert s.upstreams[0] == config.Server("1.1.1.1", 853, "cloudflare-dns.com") and s.upstreams[0].tls
    assert s.upstreams[1] == config.Server("9.9.9.9", 53) and not s.upstreams[1].tls
    assert s.upstreams[2] == config.Server("::1", 8853, "dns.test")
    assert all(u.tls for u in config.Settings().upstreams), "encrypted by default"
    for bad in ("tls://1.1.1.1", "https://1.1.1.1/dns-query", "tls://1.1.1.1#not a name"):
        with pytest.raises(config.ConfigError):
            config.parse_upstream(bad)


def test_dns_over_tls_pipelining_and_verification(tmp_path):
    import ssl
    key, crt = make_cert(tmp_path)

    async def main():
        sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sctx.load_cert_chain(crt, key)
        seen_conns = []

        async def dot_server(r, w):
            seen_conns.append(1)
            try:
                while True:
                    size = struct.unpack("!H", await r.readexactly(2))[0]
                    data = await r.readexactly(size)
                    await asyncio.sleep(0.05 if dns.parse_query(data).name.startswith("slow") else 0)
                    ans = answer_for(data, 300)
                    w.write(struct.pack("!H", len(ans)) + ans)
                    await w.drain()
            except (asyncio.IncompleteReadError, ConnectionError):
                pass

        srv = await asyncio.start_server(dot_server, "127.0.0.1", 0, ssl=sctx)
        port = srv.sockets[0].getsockname()[1]
        cctx = ssl.create_default_context(cafile=str(crt))
        up = Upstream([config.Server("127.0.0.1", port, "dns.test")], ssl_context=cctx)
        names = [("slow" if i % 3 == 0 else "fast") + f"{i}.example.org" for i in range(20)]
        packets = [dns.build_query(n, dns.A, qid=1000 + i) for i, n in enumerate(names)]
        answers = await asyncio.gather(*(up.ask(pk, tcp=False) for pk in packets))
        # wrong name: the certificate is for dns.test
        bad = Upstream([config.Server("127.0.0.1", port, "other.test")], ssl_context=cctx)
        with pytest.raises(OSError):
            await bad.ask(packets[0], tcp=False)
        # untrusted certificate (system CAs only)
        untrusted = Upstream([config.Server("127.0.0.1", port, "dns.test")])
        with pytest.raises(OSError):
            await untrusted.ask(packets[0], tcp=False)
        up.close()
        bad.close()
        untrusted.close()
        srv.close()
        return answers, len(seen_conns), up.health()

    answers, conns, health = run(main())
    for i, a in enumerate(answers):
        assert dns.response_id(a) == 1000 + i, "each answer back with the caller's id"
        assert dns.parse_query(a[:2] + b"\x00\x00" + a[4:]).name == (("slow" if i % 3 == 0 else "fast") + f"{i}.example.org")
    assert conns <= 3, "20 queries share one TLS connection (plus the two refused ones)"
    assert health[0]["encrypted"] is True and health[0]["failures_in_a_row"] == 0


def test_tls_upstream_never_falls_back_to_plain(tmp_path):
    async def main():
        # nothing listens on this port: the TLS server is down
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        up = Upstream([config.Server("127.0.0.1", dead, "dns.test")])
        with pytest.raises(OSError):
            await up.ask(dns.build_query("a.org", dns.A), tcp=False)
        return up.health()
    assert run(main())[0]["failures_in_a_row"] == 1


def test_serve_starts(tmp_path):
    """The real entry point: start, print the banner, write a status file."""
    import os
    import subprocess
    import sys
    import time
    with socket.socket() as a, socket.socket() as b:
        a.bind(("127.0.0.1", 0))
        b.bind(("127.0.0.1", 0))
        dns_port, web_port = a.getsockname()[1], b.getsockname()[1]
    conf = tmp_path / "p.toml"
    conf.write_text(f'listen = ["127.0.0.1:{dns_port}"]\nupstreams = ["tls://192.0.2.1#dns.test", "192.0.2.2"]\n'
                    f'web_port = {web_port}\nlist_refresh_hours = 100000\ndata_dir = "{tmp_path}/data"\n'
                    f'status_file = "{tmp_path}/status.json"\n')
    root = Path(__file__).resolve().parent.parent
    proc = subprocess.Popen([sys.executable, "-m", "pythia", "--config", str(conf), "serve"], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env={**os.environ, "PYTHONPATH": str(root)})
    try:
        line = proc.stdout.readline()
        deadline = time.time() + 5
        while not (tmp_path / "status.json").exists() and time.time() < deadline:
            time.sleep(0.1)
    finally:
        proc.terminate()
        proc.wait(5)
    assert line.startswith("Pythia ") and "tls://192.0.2.1:853#dns.test" in line, line
    assert (tmp_path / "status.json").exists()


def test_tls_reconnects_after_the_server_closes_an_idle_connection(tmp_path):
    import ssl
    key, crt = make_cert(tmp_path)

    async def main():
        sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        sctx.load_cert_chain(crt, key)
        conns = []

        async def one_answer_then_close(r, w):
            conns.append(1)
            size = struct.unpack("!H", await r.readexactly(2))[0]
            data = await r.readexactly(size)
            ans = answer_for(data, 300)
            w.write(struct.pack("!H", len(ans)) + ans)
            await w.drain()
            w.close()                      # like a server timing out an idle client

        srv = await asyncio.start_server(one_answer_then_close, "127.0.0.1", 0, ssl=sctx)
        port = srv.sockets[0].getsockname()[1]
        up = Upstream([config.Server("127.0.0.1", port, "dns.test")], ssl_context=ssl.create_default_context(cafile=str(crt)))
        first = await up.ask(dns.build_query("a.example.org", dns.A, qid=1), tcp=False)
        await asyncio.sleep(0.1)
        second = await up.ask(dns.build_query("b.example.org", dns.A, qid=2), tcp=False)
        up.close()
        srv.close()
        return first, second, len(conns), up.health()[0]["failures_in_a_row"]

    first, second, conns, failures = run(main())
    assert dns.response_id(first) == 1 and dns.response_id(second) == 2
    assert conns == 2 and failures == 0, "reconnected without counting a failure"
