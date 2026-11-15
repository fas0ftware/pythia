"""Block and allow lists.

A domain is blocked when it or any parent is on a block list (ads.example.com blocks
x.ads.example.com) and neither it nor a parent is allowed. Lists are plain domain lists
or hosts files ("0.0.0.0 ads.example.com"); both are common formats for public lists.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

DOMAIN = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})+$")
NEVER_BLOCK = {"localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"}
MAX_DOMAINS = 3_000_000


def normalize(name: str) -> str | None:
    name = name.strip().strip(".").lower()
    if name.startswith("*."):
        name = name[2:]
    if not DOMAIN.match(name) or name in NEVER_BLOCK or name.replace(".", "").isdigit():
        return None   # a bare IP address is not a name to block
    return name


def parse_list(text: str) -> set[str]:
    """Domains from a hosts file or a domain list. Comments, IPs and junk are skipped."""
    out = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("!") or line.startswith("["):
            continue
        parts = line.split()
        if len(parts) >= 2 and (parts[0][0].isdigit() or ":" in parts[0]):
            candidates = parts[1:]          # hosts format: address then names
        else:
            candidates = parts[:1]
        for c in candidates:
            # Adblock style "||ads.example.com^" is common enough to accept the simple form.
            if c.startswith("||") and c.endswith("^"):
                c = c[2:-1]
            d = normalize(c)
            if d:
                out.add(d)
        if len(out) > MAX_DOMAINS:
            raise ValueError(f"more than {MAX_DOMAINS} domains")
    return out


def parents(name: str):
    """ads.example.com -> ads.example.com, example.com, com"""
    while True:
        yield name
        dot = name.find(".")
        if dot < 0:
            return
        name = name[dot + 1:]


@dataclass
class Lists:
    blocked: set[str] = field(default_factory=set)       # from downloaded lists
    custom_block: set[str] = field(default_factory=set)  # added by you
    allow: set[str] = field(default_factory=set)          # added by you; wins over everything
    sources: dict[str, int] = field(default_factory=dict)  # list name -> domains it had
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def verdict(self, name: str) -> tuple[bool, str]:
        """(blocked?, the entry that decided). The most specific entry wins, and at the same
        level an allow entry beats a block: allowing example.com does not unblock a listed
        ads.example.com, but allowing cdn.ads.example.com opens just that name."""
        if not name:
            return False, ""
        for p in parents(name):
            if p in self.allow:
                return False, p
            if p in self.custom_block or p in self.blocked:
                return True, p
        return False, ""

    def replace_blocked(self, domains: set[str], sources: dict[str, int]) -> None:
        with self._lock:
            self.blocked, self.sources = domains, sources   # one assignment: readers never see half a list

    def total(self) -> int:
        return len(self.blocked) + len(self.custom_block)


def load_dir(directory: Path) -> tuple[set[str], dict[str, int]]:
    """Every *.txt list in the directory, merged."""
    merged, sources = set(), {}
    if not directory.is_dir():
        return merged, sources
    for f in sorted(directory.glob("*.txt")):
        domains = parse_list(f.read_text(errors="replace"))
        sources[f.stem] = len(domains)
        merged |= domains
    return merged, sources
