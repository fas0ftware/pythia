"""Counters for the dashboard and Olympos. Kept in memory; a summary is written to disk.

Privacy: which device asked for which name is personal. The recent-query list lives
only in memory, is shown only on the 127.0.0.1 dashboard and can be switched off
(log_queries = false); the status file holds counts only, never names or addresses.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass

HOURS = 24
TOP_LIMIT = 5000   # distinct names remembered for the "top" lists


@dataclass
class Entry:
    time: float
    client: str
    name: str
    qtype: str
    result: str        # blocked / cached / forwarded / refused / error
    rule: str = ""
    ms: float = 0.0


class Stats:
    def __init__(self, log_queries: bool = True, recent: int = 300, clock=time.time):
        self.clock = clock
        self.started = clock()
        self.log_queries = log_queries
        self.recent: deque[Entry] = deque(maxlen=recent)
        self.totals = Counter()
        self.hourly: dict[int, Counter] = {}
        self.top_blocked = Counter()
        self.top_allowed = Counter()
        self.clients = Counter()

    def record(self, client: str, name: str, qtype: str, result: str, rule: str = "", ms: float = 0.0) -> None:
        now = self.clock()
        self.totals["queries"] += 1
        self.totals[result] += 1
        hour = int(now // 3600)
        self.hourly.setdefault(hour, Counter())
        self.hourly[hour]["queries"] += 1
        self.hourly[hour][result] += 1
        for h in [h for h in self.hourly if h <= hour - HOURS]:
            del self.hourly[h]
        self.clients[client] += 1
        top = self.top_blocked if result == "blocked" else self.top_allowed if result in ("forwarded", "cached") else None
        if top is not None and name and (name in top or len(top) < TOP_LIMIT):
            top[name] += 1
        if self.log_queries:
            self.recent.append(Entry(now, client, name, qtype, result, rule, round(ms, 1)))

    def last_24h(self) -> Counter:
        total = Counter()
        for c in self.hourly.values():
            total += c
        return total

    def series(self) -> list[dict]:
        """Queries and blocks per hour for the last 24 hours, oldest first."""
        now_hour = int(self.clock() // 3600)
        return [{"hour": (now_hour - i) * 3600, "queries": self.hourly.get(now_hour - i, Counter())["queries"],
                 "blocked": self.hourly.get(now_hour - i, Counter())["blocked"]} for i in range(HOURS - 1, -1, -1)]

    def summary(self) -> dict:
        day = self.last_24h()
        q = day["queries"]
        return {
            "uptime_s": int(self.clock() - self.started),
            "queries_24h": q,
            "blocked_24h": day["blocked"],
            "blocked_percent_24h": round(100 * day["blocked"] / q, 1) if q else 0.0,
            "cached_24h": day["cached"],
            "errors_24h": day["error"],
            "refused_24h": day["refused"],
            "clients": len(self.clients),
            "total": dict(self.totals),
        }
