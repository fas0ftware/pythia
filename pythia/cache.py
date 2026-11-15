"""Answer cache: upstream answers kept for their TTL (within limits), aged on the way out."""

from __future__ import annotations

import time
from collections import OrderedDict

from . import dns

MIN_TTL = 0
MAX_TTL = 24 * 3600
NEGATIVE_TTL = 300       # NXDOMAIN / empty answers without an SOA
MAX_ENTRY_BYTES = 4096


class Cache:
    def __init__(self, size: int = 10_000, clock=time.monotonic):
        self.size = size
        self.clock = clock
        self._d: OrderedDict[tuple, tuple[float, float, bytes, list[int]]] = OrderedDict()
        self.hits = self.misses = 0

    def get(self, key: tuple, qid: int) -> bytes | None:
        item = self._d.get(key)
        if item is None:
            self.misses += 1
            return None
        stored, expires, data, offsets = item
        now = self.clock()
        if now >= expires:
            del self._d[key]
            self.misses += 1
            return None
        self._d.move_to_end(key)
        self.hits += 1
        return dns.with_id(dns.age_ttls(data, offsets, int(now - stored)), qid)

    def put(self, key: tuple, data: bytes) -> None:
        if len(data) > MAX_ENTRY_BYTES or dns.is_truncated(data):
            return
        code = dns.rcode(data)
        if code not in (dns.NOERROR, dns.NXDOMAIN):
            return                                   # never cache SERVFAIL / REFUSED
        try:
            offsets, smallest = dns.ttl_offsets(data)
        except dns.FormatError:
            return
        ttl = NEGATIVE_TTL if smallest is None else smallest
        ttl = max(MIN_TTL, min(ttl, MAX_TTL))
        if ttl <= 0:
            return
        now = self.clock()
        self._d[key] = (now, now + ttl, data, offsets)
        self._d.move_to_end(key)
        while len(self._d) > self.size:
            self._d.popitem(last=False)

    def clear(self) -> None:
        self._d.clear()

    def __len__(self) -> int:
        return len(self._d)
