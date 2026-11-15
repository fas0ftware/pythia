"""python -m pythia [serve | check NAME | update-lists | status]"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
import time
from pathlib import Path

from . import __version__, config, home, lists
from .blocklist import Lists, normalize
from .server import Pythia, load_custom, start
from .web import serve_in_thread

STATUS_EVERY = 30


def build(settings: config.Settings) -> Pythia:
    p = Pythia(settings, Lists())
    load_custom(p)
    lists.reload(p.lists, settings.data_dir)
    return p


def refresher(p: Pythia):
    lock = threading.Lock()

    def run():
        if not lock.acquire(blocking=False):
            return     # one update at a time
        try:
            errors = lists.refresh(p.lists, p.s.lists, p.s.data_dir)
            p.cache.clear()
            p.lists_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for e in errors:
                print(f"pythia: list update: {e}", file=sys.stderr, flush=True)
            print(f"pythia: {p.lists.total()} domains on the block lists", flush=True)
        finally:
            lock.release()
    return run


async def serve(settings: config.Settings, web: bool = True) -> None:
    p = build(settings)
    refresh = refresher(p)
    age = lists.age_hours(settings.data_dir)
    if age is None or age > settings.list_refresh_hours:
        threading.Thread(target=refresh, daemon=True).start()
    p.at_home = home.at_home(settings.home_gateway_mac)
    await start(p)
    print(f"Pythia {__version__}: DNS on {', '.join(p.listening)}, {p.lists.total()} domains blocked, "
          f"upstream {', '.join(f'{h}:{port}' for h, port in settings.upstreams)}", flush=True)
    if web:
        serve_in_thread(p, settings.web_port, refresh)
    ticks = 0
    while True:
        p.at_home = home.at_home(settings.home_gateway_mac)
        try:
            p.write_status()
        except OSError as exc:
            print(f"pythia: cannot write {settings.status_file}: {exc}", file=sys.stderr, flush=True)
        await asyncio.sleep(STATUS_EVERY)
        ticks += 1
        if ticks * STATUS_EVERY >= settings.list_refresh_hours * 3600:
            ticks = 0
            threading.Thread(target=refresh, daemon=True).start()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pythia", description="DNS filter for the home network.")
    ap.add_argument("--version", action="version", version=f"pythia {__version__}")
    ap.add_argument("--config", type=Path, help="settings file (default: ./pythia.toml or ~/.config/pythia/pythia.toml)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve", help="run the DNS server and the dashboard")
    sv.add_argument("--no-web", action="store_true")
    ck = sub.add_parser("check", help="would this name be blocked?")
    ck.add_argument("name")
    sub.add_parser("update-lists", help="download the block lists now")
    sub.add_parser("status", help="print the status file the server writes")
    args = ap.parse_args(argv)
    try:
        settings = config.load(args.config)
    except config.ConfigError as exc:
        print(f"pythia: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "serve":
        try:
            asyncio.run(serve(settings, web=not args.no_web))
        except PermissionError:
            print("pythia: port 53 needs the CAP_NET_BIND_SERVICE capability (see the systemd unit in contrib/)",
                  file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            pass
        return 0
    if args.cmd == "check":
        p = build(settings)
        name = normalize(args.name)
        if not name:
            print(f"{args.name!r} is not a domain name", file=sys.stderr)
            return 2
        blocked, rule = p.lists.verdict(name)
        print(f"{name}: {'BLOCKED by ' + rule if blocked else 'allowed' + (' (allow entry ' + rule + ')' if rule else '')}")
        return 1 if blocked else 0
    if args.cmd == "update-lists":
        p = build(settings)
        errors = lists.refresh(p.lists, settings.lists, settings.data_dir)
        for name, count in p.lists.sources.items():
            print(f"{name}: {count} domains")
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"{p.lists.total()} domains in total")
        return 1 if errors else 0
    if args.cmd == "status":
        try:
            print(json.dumps(json.loads(settings.status_file.read_text()), indent=2))
        except (OSError, ValueError) as exc:
            print(f"pythia: no status yet ({exc})", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
