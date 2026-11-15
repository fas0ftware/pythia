"""Per-device profiles: stricter rules for chosen devices (a child's tablet, a TV).

A profile names its devices by IP address or network (give them fixed addresses in the
router), blocks extra names, allows some, and can have a bedtime: during those hours
every name is blocked for its devices except the ones the profile allows.

A profile is checked before the global lists, so a name allowed for the whole house can
still be blocked on the tablet.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .blocklist import normalize, parents


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    name: str
    clients: list = field(default_factory=list)          # ip_network objects
    block: set[str] = field(default_factory=set)
    allow: set[str] = field(default_factory=set)
    bedtime: tuple[int, int] | None = None               # (start, end) local hours, may wrap midnight

    def covers(self, addr) -> bool:
        return any(addr in n for n in self.clients)

    def bedtime_now(self, hour: int) -> bool:
        if not self.bedtime:
            return False
        start, end = self.bedtime
        return start <= hour < end if start < end else hour >= start or hour < end

    def decide(self, name: str, hour: int) -> tuple[bool, str]:
        """(blocked?, why). Most specific entry wins; at the same level allow beats block."""
        for p in parents(name):
            if p in self.allow:
                return False, ""
            if p in self.block:
                return True, f"profile {self.name}: {p}"
        if self.bedtime_now(hour):
            return True, f"profile {self.name}: bedtime"
        return False, ""

    def summary(self, hour: int) -> dict:
        return {"name": self.name, "clients": [str(n) for n in self.clients], "blocked_names": len(self.block),
                "allowed_names": len(self.allow),
                "bedtime": f"{self.bedtime[0]:02d}-{self.bedtime[1]:02d}" if self.bedtime else "",
                "bedtime_now": self.bedtime_now(hour)}


def _domains(raw, what: str, profile: str) -> set[str]:
    if not isinstance(raw, list):
        raise ProfileError(f"profile {profile}: {what} must be a list of names")
    out = set()
    for item in raw:
        d = normalize(str(item))
        if not d:
            raise ProfileError(f"profile {profile}: {item!r} is not a domain name")
        out.add(d)
    return out


def parse(raw_list) -> list[Profile]:
    if not isinstance(raw_list, list):
        raise ProfileError("profiles must be a list of [[profiles]] tables")
    out = []
    for raw in raw_list:
        name = str(raw.get("name", "")).strip()
        if not name or len(name) > 40:
            raise ProfileError("every profile needs a name (at most 40 characters)")
        clients = []
        for c in raw.get("clients", []):
            try:
                net = ipaddress.ip_network(str(c), strict=False)
            except ValueError:
                raise ProfileError(f"profile {name}: {c!r} is not an IP address or network") from None
            if net.prefixlen == 0:
                raise ProfileError(f"profile {name}: a profile for every address is just the global list")
            clients.append(net)
        if not clients:
            raise ProfileError(f"profile {name}: list its devices in clients")
        bedtime = None
        if raw.get("bedtime"):
            try:
                a, b = (int(x) for x in str(raw["bedtime"]).split("-"))
            except ValueError:
                raise ProfileError(f"profile {name}: bedtime looks like 21-07 (hours)") from None
            if not (0 <= a <= 23 and 0 <= b <= 23) or a == b:
                raise ProfileError(f"profile {name}: bedtime hours 0-23, start and end different")
            bedtime = (a, b)
        out.append(Profile(name, clients, _domains(raw.get("block", []), "block", name),
                           _domains(raw.get("allow", []), "allow", name), bedtime))
    return out
