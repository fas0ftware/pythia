import asyncio
import ipaddress
import json
import socket
import struct
import threading
import urllib.error
import urllib.request

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
    assert s.listen == [("127.0.0.1", 5354), ("::1", 53)] and s.upstreams == [("9.9.9.9", 53)]
    for bad in ({"allow_networks": ["0.0.0.0/0"]}, {"upstreams": ["dns.google"]}, {"upstreams": []},
                {"lists": [{"name": "x", "url": "http://insecure"}]}, {"lists": [{"name": "../x", "url": "https://a"}]}):
        with pytest.raises(config.ConfigError):
            config.parse(bad)


# --- the server, end to end ----------------------------------------------------------------

class FakeUpstream(Upstream):
    def __init__(self, ttl=300, fail=False, wrong=False):
        super().__init__([("192.0.2.53", 53)])
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
        s = config.Settings(listen=[("127.0.0.1", port)], upstreams=[("127.0.0.1", up_port)], status_file=tmp_path / "s.json")
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
