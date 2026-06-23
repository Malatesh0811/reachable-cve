"""TTL JSON cache invariants."""
import asyncio
import os
import time

import pytest

from reachable_cve.cache import cached_json, _key_path, cache_dir


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("REACHABLE_CVE_CACHE_DIR", str(tmp_path))
    yield tmp_path


def test_cache_returns_fresh_result_within_ttl():
    calls = {"n": 0}

    @cached_json("smoke", ttl_seconds=60, key_from_args=lambda *a, **kw: ["k"])
    async def fetch():
        calls["n"] += 1
        return {"value": calls["n"]}

    first = asyncio.run(fetch())
    second = asyncio.run(fetch())
    assert first == second == {"value": 1}
    assert calls["n"] == 1, "second call should hit cache, not invoke fetch()"


def test_cache_expires_after_ttl(monkeypatch):
    calls = {"n": 0}

    @cached_json("smoke_ttl", ttl_seconds=1, key_from_args=lambda *a, **kw: ["k"])
    async def fetch():
        calls["n"] += 1
        return {"value": calls["n"]}

    asyncio.run(fetch())
    # Backdate the cache file so it's older than the TTL
    p = _key_path("smoke_ttl", ["k"])
    os.utime(p, (time.time() - 10, time.time() - 10))
    asyncio.run(fetch())
    assert calls["n"] == 2


def test_cache_distinguishes_keys():
    calls = {"n": 0}

    @cached_json("byarg", ttl_seconds=60, key_from_args=lambda x: ["k", x])
    async def fetch(x):
        calls["n"] += 1
        return x * 2

    assert asyncio.run(fetch(3)) == 6
    assert asyncio.run(fetch(4)) == 8
    assert asyncio.run(fetch(3)) == 6  # cached
    assert calls["n"] == 2


def test_cache_file_is_json(isolated_cache):
    @cached_json("shape", ttl_seconds=60, key_from_args=lambda: ["x"])
    async def fetch():
        return [{"a": 1}, {"b": 2}]

    asyncio.run(fetch())
    p = _key_path("shape", ["x"])
    assert p.exists()
    import json
    assert json.loads(p.read_text()) == [{"a": 1}, {"b": 2}]
