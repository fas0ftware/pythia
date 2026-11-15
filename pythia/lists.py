"""Download block lists (HTTPS only), check them, and swap them in atomically."""

from __future__ import annotations

import os
import time
import urllib.request
from pathlib import Path

from .blocklist import Lists, load_dir, parse_list

MAX_BYTES = 40 * 1024 * 1024
MIN_DOMAINS = 1000        # fewer means an error page, not a list: keep the old copy


def list_dir(data_dir: Path) -> Path:
    return data_dir / "lists"


def download(name: str, url: str, directory: Path, timeout: float = 60) -> int:
    """Fetch one list; replace the saved copy only if it looks like a real list."""
    req = urllib.request.Request(url, headers={"User-Agent": "pythia-dns-blocker"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"{name}: larger than {MAX_BYTES // 1024 // 1024} MB")
    text = body.decode("utf-8", errors="replace")
    count = len(parse_list(text))
    if count < MIN_DOMAINS:
        raise ValueError(f"{name}: only {count} domains, keeping the previous copy")
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / f".{name}.tmp"
    tmp.write_text(text)
    os.replace(tmp, directory / f"{name}.txt")
    return count


def refresh(lists: Lists, sources: list[tuple[str, str]], data_dir: Path, fetch=download) -> list[str]:
    """Download every list, then reload all saved copies. Returns error messages."""
    directory = list_dir(data_dir)
    errors = []
    for name, url in sources:
        try:
            fetch(name, url, directory)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
    wanted = {name for name, _ in sources}
    for f in directory.glob("*.txt") if directory.is_dir() else []:
        if f.stem not in wanted:
            f.unlink()      # a list removed from the settings stops blocking
    reload(lists, data_dir)
    return errors


def reload(lists: Lists, data_dir: Path) -> None:
    domains, counts = load_dir(list_dir(data_dir))
    lists.replace_blocked(domains, counts)


def age_hours(data_dir: Path) -> float | None:
    files = list(list_dir(data_dir).glob("*.txt")) if list_dir(data_dir).is_dir() else []
    if not files:
        return None
    return (time.time() - min(f.stat().st_mtime for f in files)) / 3600
