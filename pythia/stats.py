"""Counters for the dashboard and Olympos. Kept in memory; a summary is written to disk.

Privacy: which device asked for which name is personal. The recent-query list lives
only in memory, is shown only on the 127.0.0.1 dashboard and can be switched off
(log_queries = false); the status file and the history file (counts per hour and per day,
so the charts survive a restart) hold counts only, never names or addresses.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path

HOURS = 24
DAYS = 31          # daily counts kept on disk
TOP_LIMIT = 5000   # distinct names remembered for the "top" lists
KEPT = ("queries", "blocked", "cached", "forwarded", "refused", "error")


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
        self.daily: dict[str, Counter] = {}     # local date "YYYY-MM-DD" -> counts

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
        day = self.daily.setdefault(self._date(now), Counter())
        day["queries"] += 1
        day[result] += 1
        self.clients[client] += 1
        top = self.top_blocked if result == "blocked" else self.top_allowed if result in ("forwarded", "cached") else None
        if top is not None and name and (name in top or len(top) < TOP_LIMIT):
            top[name] += 1
        if self.log_queries:
            self.recent.append(Entry(now, client, name, qtype, result, rule, round(ms, 1)))

    @staticmethod
    def _date(t: float) -> str:
        return time.strftime("%Y-%m-%d", time.localtime(t))

    def days(self, n: int = 30) -> list[dict]:
        """Counts per local day for the last n days, oldest first (days with no data are zeros)."""
        now = self.clock()
        out = []
        for i in range(n - 1, -1, -1):
            date = self._date(now - i * 86400)
            c = self.daily.get(date, Counter())
            out.append({"date": date, **{k: c[k] for k in KEPT}})
        return out

    # --- on disk: counts only, never names or addresses ---------------------------------------

    def to_json(self) -> dict:
        cutoff = self._date(self.clock() - DAYS * 86400)
        self.daily = {d: c for d, c in self.daily.items() if d > cutoff}
        return {"version": 1,
                "days": {d: {k: c[k] for k in KEPT if c[k]} for d, c in sorted(self.daily.items())},
                "hours": {str(h): {k: c[k] for k in KEPT if c[k]} for h, c in sorted(self.hourly.items())}}

    def load_json(self, data: dict) -> None:
        """Merge saved counts (after a restart). Bad entries are skipped, never trusted blindly."""
        if not isinstance(data, dict):
            return
        now_hour = int(self.clock() // 3600)
        for d, c in (data.get("days") or {}).items():
            if isinstance(d, str) and len(d) == 10 and isinstance(c, dict):
                day = self.daily.setdefault(d, Counter())
                for k in KEPT:
                    v = c.get(k)
                    if isinstance(v, int) and 0 <= v < 10**12:
                        day[k] += v
        for h, c in (data.get("hours") or {}).items():
            try:
                hour = int(h)
            except ValueError:
                continue
            if now_hour - HOURS < hour <= now_hour and isinstance(c, dict):
                slot = self.hourly.setdefault(hour, Counter())
                for k in KEPT:
                    v = c.get(k)
                    if isinstance(v, int) and 0 <= v < 10**12:
                        slot[k] += v

    def save(self, path: Path) -> None:
        self.save_data(path, self.to_json())

    @staticmethod
    def save_data(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, path)

    def load(self, path: Path) -> bool:
        try:
            if path.stat().st_size > 2_000_000:
                return False
            self.load_json(json.loads(path.read_text()))
            return True
        except (OSError, ValueError):
            return False

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
        month = self.days(30)
        q30 = sum(d["queries"] for d in month)
        b30 = sum(d["blocked"] for d in month)
        return {
            "uptime_s": int(self.clock() - self.started),
            "queries_24h": q,
            "blocked_24h": day["blocked"],
            "blocked_percent_24h": round(100 * day["blocked"] / q, 1) if q else 0.0,
            "cached_24h": day["cached"],
            "errors_24h": day["error"],
            "refused_24h": day["refused"],
            "queries_30d": q30,
            "blocked_30d": b30,
            "blocked_percent_30d": round(100 * b30 / q30, 1) if q30 else 0.0,
            "clients": len(self.clients),
            "total": dict(self.totals),
        }
