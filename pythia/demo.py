"""Fictional data for screenshots and trying the dashboard: python -m pythia demo

Only the dashboard runs (no DNS sockets). Devices, names and counts are made up; rule
changes stay in a temporary folder that is deleted on exit.
"""

from __future__ import annotations

import ipaddress
import random
import tempfile
import time
from collections import Counter
from pathlib import Path

from .blocklist import Lists
from .config import DEFAULT_UPSTREAMS, Settings
from .profiles import Profile
from .server import Pythia
from .stats import Entry, Stats
from .web import create_app

DEVICES = ["192.168.1.20", "192.168.1.21", "192.168.1.30", "192.168.1.31", "192.168.1.40", "192.168.1.50",
           "127.0.0.1"]
BLOCKED = ["ads.example-tracker.com", "metrics.example-analytics.net", "pixel.example-ads.com",
           "telemetry.example-tv.com", "beacon.example-cdn.net", "sdk.example-adnetwork.io"]
ALLOWED = ["news.example.org", "mail.example.com", "video.example.net", "maps.example.com", "docs.example.org",
           "weather.example.com", "music.example.net", "shop.example.com"]


class DemoLists(Lists):
    def total(self) -> int:
        return 77_309 + len(self.custom_block)


def build(now: float | None = None, seed: int = 7) -> Pythia:
    now = now or time.time()
    # made-up demo numbers, not security
    rnd = random.Random(seed)  # nosec B311
    data = Path(tempfile.mkdtemp(prefix="pythia-demo-"))
    s = Settings(data_dir=data, status_file=data / "status.json",
                 upstreams=list(DEFAULT_UPSTREAMS),
                 profiles=[Profile("tablet", [ipaddress.ip_network("192.168.1.40/32")],
                                   {"video.example.net"}, {"school.example.org"}, (21, 7))])
    lists = DemoLists()
    lists.replace_blocked(set(BLOCKED), {"stevenblack": 77_309})
    lists.allow.add("shop.example.com")
    stats = Stats(clock=lambda: now)
    stats.started = now - 6 * 86400

    # 30 days: more on weekends, a quieter week in the middle
    for i in range(29, -1, -1):
        t = now - i * 86400
        q = int(rnd.uniform(14_000, 19_000) * (1.2 if time.localtime(t).tm_wday >= 5 else 1) * (0.7 if 12 <= i <= 16 else 1))
        b = int(q * rnd.uniform(0.15, 0.21))
        c = int(q * 0.35)
        stats.daily[stats._date(t)] = Counter(queries=q, blocked=b, cached=c, forwarded=q - b - c, error=rnd.randint(0, 3))
    # 24 hours: quiet at night
    for i in range(24):
        hour = int(now // 3600) - i
        local = time.localtime(hour * 3600).tm_hour
        q = int(rnd.uniform(500, 1100) * (0.15 if 1 <= local <= 6 else 1))
        b = int(q * rnd.uniform(0.14, 0.22))
        stats.hourly[hour] = Counter(queries=q, blocked=b, cached=int(q * 0.35), forwarded=q - b - int(q * 0.35))
    for name in BLOCKED:
        stats.top_blocked[name] = rnd.randint(80, 900)
    for name in ALLOWED:
        stats.top_allowed[name] = rnd.randint(200, 2400)
    for d in DEVICES:
        stats.clients[d] = rnd.randint(300, 4000)
    stats.totals.update(stats.last_24h())
    for k in range(60):
        blocked = rnd.random() < 0.3
        name = rnd.choice(BLOCKED if blocked else ALLOWED)
        stats.recent.append(Entry(now - (60 - k) * 7, rnd.choice(DEVICES), name, rnd.choice(["A", "AAAA", "HTTPS"]),
                                  "blocked" if blocked else rnd.choice(["forwarded", "cached"]),
                                  "stevenblack" if blocked else "", 0.0 if blocked else round(rnd.uniform(0, 40), 1)))

    p = Pythia(s, lists, stats=stats)
    p.listening = ["127.0.0.1:53", "192.168.1.10:53"]
    p.lists_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 5 * 3600))
    for u in s.upstreams:
        p.upstream.last_ok[str(u)] = now - 2
    return p


def serve(port: int) -> None:
    p = build()
    try:
        create_app(p).serve(port, "Pythia demo")
    finally:
        import shutil
        shutil.rmtree(p.s.data_dir, ignore_errors=True)
