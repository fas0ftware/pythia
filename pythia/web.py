"""Dashboard on 127.0.0.1 (never on the network: it shows who asked for what)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from .blocklist import normalize
from .server import Pythia, save_custom
from .web_base import App, HttpError, field

STATIC = Path(__file__).resolve().parent / "static"


def create_app(p: Pythia, refresh_lists=None) -> App:
    app = App(STATIC)

    @app.get("/api/summary")
    def summary(query):
        return p.summary()

    @app.get("/api/state")
    def state(query):
        with p.stats_lock:
            st = p.stats
            data = {
                "series": st.series(),
                "days": st.days(30),
                "top_blocked": st.top_blocked.most_common(15),
                "top_allowed": st.top_allowed.most_common(15),
                "clients": st.clients.most_common(20),
                "recent": [e.__dict__ for e in reversed(st.recent)][:150],
                "log_queries": st.log_queries,
            }
        data["summary"] = p.summary()
        data["allow"] = sorted(p.lists.allow)
        data["block"] = sorted(p.lists.custom_block)
        return data

    @app.post("/api/pause")
    def pause(body):
        minutes = field(body, "minutes", int)
        if not 0 <= minutes <= 24 * 60:
            raise HttpError(400, "minutes must be 0 to 1440")
        p.paused_until = time.time() + minutes * 60 if minutes else 0.0
        return p.summary()

    def edit(target: set, body):
        domain = normalize(field(body, "domain", str, max_len=253))
        if not domain:
            raise HttpError(400, "not a domain name")
        if field(body, "remove", bool, required=False, default=False):
            target.discard(domain)
        else:
            target.add(domain)
        p.cache.clear()       # answers cached before the change must not linger
        save_custom(p)
        return {"allow": sorted(p.lists.allow), "block": sorted(p.lists.custom_block)}

    @app.post("/api/allow")
    def allow(body):
        return edit(p.lists.allow, body)

    @app.post("/api/block")
    def block(body):
        return edit(p.lists.custom_block, body)

    @app.post("/api/check")
    def check(body):
        domain = normalize(field(body, "domain", str, max_len=253)) or ""
        blocked, rule = p.lists.verdict(domain)
        return {"domain": domain, "blocked": blocked, "rule": rule}

    @app.post("/api/update-lists")
    def update(body):
        if refresh_lists is None:
            raise HttpError(400, "list updates are not available")
        threading.Thread(target=refresh_lists, daemon=True).start()
        return {"started": True}

    return app


def serve_in_thread(p: Pythia, port: int, refresh_lists=None) -> threading.Thread:
    app = create_app(p, refresh_lists)
    t = threading.Thread(target=app.serve, args=(port, "Pythia dashboard"), daemon=True)
    t.start()
    return t

