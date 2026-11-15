"""Settings from pythia.toml (machine-specific, not in git; see pythia.example.toml)."""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_LISTS = [
    ("stevenblack", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
]


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Server:
    host: str
    port: int
    tls_name: str = ""      # set: DNS over TLS (RFC 7858), certificate checked against this name

    @property
    def tls(self) -> bool:
        return bool(self.tls_name)

    def __str__(self) -> str:
        return f"tls://{self.host}:{self.port}#{self.tls_name}" if self.tls else f"{self.host}:{self.port}"


# Encrypted by default: your provider sees that you use DNS over TLS, not which names.
DEFAULT_UPSTREAMS = [Server("1.1.1.1", 853, "cloudflare-dns.com"), Server("9.9.9.9", 853, "dns.quad9.net")]


@dataclass
class Settings:
    listen: list[tuple[str, int]] = field(default_factory=lambda: [("127.0.0.1", 53)])
    allow_networks: list = field(default_factory=lambda: [ipaddress.ip_network("127.0.0.0/8"),
                                                           ipaddress.ip_network("::1/128")])
    upstreams: list[Server] = field(default_factory=lambda: list(DEFAULT_UPSTREAMS))
    lists: list[tuple[str, str]] = field(default_factory=lambda: list(DEFAULT_LISTS))
    list_refresh_hours: float = 24
    blocked_ttl: int = 300
    cache_size: int = 10_000
    rate_limit: int = 100            # queries per second per client (burst: twice that)
    log_queries: bool = True
    web_port: int = 8748
    data_dir: Path = Path("~/.local/share/pythia").expanduser()
    status_file: Path = Path("~/.local/state/pythia/status.json").expanduser()
    # Answer network clients only while the default gateway has this MAC (empty: always).
    home_gateway_mac: str = ""


def default_path() -> Path:
    env = os.environ.get("PYTHIA_CONFIG")
    if env:
        return Path(env).expanduser()
    here = Path(__file__).resolve().parent.parent / "pythia.toml"
    if here.exists():
        return here
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "pythia" / "pythia.toml"


def parse_addr(text: str, default_port: int = 53) -> tuple[str, int]:
    """"1.1.1.1", "1.1.1.1:5353", "[2606:4700::1111]:53" or "::1"."""
    text = text.strip()
    host, port = text, default_port
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
    elif text.count(":") == 1:
        host, p = text.split(":")
        port = int(p)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ConfigError(f"{text!r}: give an IP address (names would need DNS to find DNS)") from None
    if not 0 < port < 65536:
        raise ConfigError(f"{text!r}: bad port")
    return host, port


NAME = __import__("re").compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


def parse_upstream(text: str) -> Server:
    """"9.9.9.9", "9.9.9.9:53", or "tls://1.1.1.1#cloudflare-dns.com" (port 853 unless given)."""
    text = text.strip()
    if text.startswith("tls://"):
        rest, _, name = text[6:].partition("#")
        if not NAME.match(name):
            raise ConfigError(f"{text!r}: DNS over TLS needs the server's name after #, "
                              "e.g. tls://1.1.1.1#cloudflare-dns.com (its certificate is checked against it)")
        host, port = parse_addr(rest, 853)
        return Server(host, port, name.lower())
    if "://" in text:
        raise ConfigError(f"{text!r}: only plain addresses and tls:// are supported")
    host, port = parse_addr(text)
    return Server(host, port)


def load(path: Path | None = None) -> Settings:
    path = path or default_path()
    if not path.exists():
        return Settings()
    try:
        raw = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: {exc}") from None
    return parse(raw)


def parse(raw: dict) -> Settings:
    s = Settings()
    if "listen" in raw:
        s.listen = [parse_addr(a) for a in raw["listen"]]
    if "allow_networks" in raw:
        try:
            s.allow_networks = [ipaddress.ip_network(n, strict=False) for n in raw["allow_networks"]]
        except ValueError as exc:
            raise ConfigError(f"allow_networks: {exc}") from None
        for n in s.allow_networks:
            if n.prefixlen == 0:
                # Answering the whole internet would make this an open resolver.
                raise ConfigError("allow_networks must not contain 0.0.0.0/0 or ::/0")
    if "upstreams" in raw:
        s.upstreams = [parse_upstream(a) for a in raw["upstreams"]]
        if not s.upstreams:
            raise ConfigError("upstreams must not be empty")
    if "lists" in raw:
        s.lists = []
        for item in raw["lists"]:
            url = str(item.get("url", ""))
            name = str(item.get("name", ""))
            if not url.startswith("https://"):
                raise ConfigError(f"list {name or url}: only https:// URLs")
            if not name.replace("-", "").replace("_", "").isalnum():
                raise ConfigError(f"list name {name!r}: letters, digits, - and _ only")
            s.lists.append((name, url))
    s.list_refresh_hours = float(raw.get("list_refresh_hours", s.list_refresh_hours))
    s.blocked_ttl = int(raw.get("blocked_ttl", s.blocked_ttl))
    s.cache_size = int(raw.get("cache_size", s.cache_size))
    s.rate_limit = int(raw.get("rate_limit", s.rate_limit))
    s.log_queries = bool(raw.get("log_queries", s.log_queries))
    s.web_port = int(raw.get("web_port", s.web_port))
    if "data_dir" in raw:
        s.data_dir = Path(raw["data_dir"]).expanduser()
    if "status_file" in raw:
        s.status_file = Path(raw["status_file"]).expanduser()
    s.home_gateway_mac = str(raw.get("home_gateway_mac", "")).strip().lower()
    if s.home_gateway_mac and len(s.home_gateway_mac.split(":")) != 6:
        raise ConfigError("home_gateway_mac must look like aa:bb:cc:dd:ee:ff")
    if not 1 <= s.rate_limit <= 100_000 or not 0 <= s.blocked_ttl <= 86400:
        raise ConfigError("rate_limit or blocked_ttl out of range")
    return s
