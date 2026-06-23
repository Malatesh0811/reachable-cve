"""On-disk JSON cache with TTL for OSV/EPSS/KEV responses.

Each cached response is a file at:
    $REACHABLE_CVE_CACHE_DIR/<prefix>_<sha256(args)[:16]>.json

Mtime is the cache timestamp. On read, if (now - mtime) > ttl, miss.

Designed for safety on Windows and POSIX: writes go through a temp file +
os.replace() so a half-written cache file can never be observed.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "reachable-cve"


def cache_dir() -> Path:
    return Path(os.environ.get("REACHABLE_CVE_CACHE_DIR", str(DEFAULT_CACHE_DIR)))


def _key_path(prefix: str, key_payload: Any) -> Path:
    blob = json.dumps(key_payload, default=str, sort_keys=True).encode()
    digest = hashlib.sha256(blob).hexdigest()[:16]
    return cache_dir() / f"{prefix}_{digest}.json"


def _read_if_fresh(path: Path, ttl_seconds: int) -> Any | None:
    try:
        st = path.stat()
    except FileNotFoundError:
        return None
    if time.time() - st.st_mtime > ttl_seconds:
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, default=str)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cached_json(prefix: str, ttl_seconds: int, key_from_args: Callable | None = None):
    """Decorate an *async* function whose return value is JSON-serializable.

    `key_from_args(*args, **kwargs)` returns the cache key payload. If omitted,
    we use (args[1:], kwargs) — args[0] is assumed to be a non-hashable client.
    """
    def deco(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            if key_from_args:
                key = key_from_args(*args, **kwargs)
            else:
                key = [args[1:], kwargs] if args else [args, kwargs]
            path = _key_path(prefix, key)
            hit = _read_if_fresh(path, ttl_seconds)
            if hit is not None:
                return hit
            result = await fn(*args, **kwargs)
            _atomic_write(path, result)
            return result
        wrapper.__cache_prefix__ = prefix  # type: ignore[attr-defined]
        wrapper.__cache_ttl__ = ttl_seconds  # type: ignore[attr-defined]
        return wrapper
    return deco


# TTL constants — single source of truth for the three feeds
TTL_OSV = 60 * 60                # 1 hour
TTL_EPSS = 24 * 60 * 60          # 24 hours (EPSS publishes daily)
TTL_KEV = 24 * 60 * 60           # 24 hours (CISA publishes daily)
