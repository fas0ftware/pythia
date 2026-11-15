"""Are we on the home network? (A laptop must not serve DNS to strangers elsewhere.)

The default gateway's MAC address identifies the home router; the IP range alone does
not, since half the world's routers hand out 192.168.1.x.
"""

from __future__ import annotations

from pathlib import Path


def default_gateway(route: str) -> str | None:
    """IPv4 default gateway from /proc/net/route text."""
    for line in route.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3 and f[1] == "00000000" and f[2] != "00000000":
            g = bytes.fromhex(f[2])[::-1]     # little-endian hex
            return ".".join(str(b) for b in g)
    return None


def mac_of(ip: str, arp: str) -> str | None:
    for line in arp.splitlines()[1:]:
        f = line.split()
        if len(f) >= 4 and f[0] == ip and f[3] != "00:00:00:00:00:00":
            return f[3].lower()
    return None


def gateway_mac(proc: Path = Path("/proc/net")) -> str | None:
    try:
        gw = default_gateway((proc / "route").read_text())
        return mac_of(gw, (proc / "arp").read_text()) if gw else None
    except OSError:
        return None


def at_home(wanted_mac: str, proc: Path = Path("/proc/net")) -> bool:
    if not wanted_mac:
        return True
    mac = gateway_mac(proc)
    return mac is not None and mac == wanted_mac.lower()
