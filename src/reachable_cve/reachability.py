"""BFS reachability + taint check.

Symbol match: a node `ext:<base>` matches symbol `<s>` if `base == s` or
`base.startswith(s + ".")`. Then, if `cve_ids` are provided, the taint module
gets the kwargs present at the sink call site and decides whether to suppress
the finding (Tier 2 false-positive reduction).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .call_graph import CallGraph
from .taint import check as taint_check


@dataclass
class ReachabilityResult:
    reachable: bool
    matched_symbol: str | None
    path: list[str]
    sink_locations: list[tuple[Path, int]]
    taint_reason: str | None = None  # populated when taint rules are consulted


# Framework bootstrap symbols — calling these is unavoidable in any Flask/FastAPI/
# Django project and they are not themselves vulnerability sinks. If a fallback
# (package-name) symbol-map entry would otherwise prefix-match one of these, we
# suppress the match to avoid the headline FP we hit on PyGoat
# (`pygoat.asgi.<module>` -> `ext:django.core.asgi.get_asgi_application` x 82).
BOOTSTRAP_EXCLUSIONS: set[str] = {
    # Django
    "django.core.asgi.get_asgi_application",
    "django.core.wsgi.get_wsgi_application",
    "django.core.management.execute_from_command_line",
    "django.urls.path",
    "django.urls.re_path",
    "django.urls.include",
    "django.urls.URLResolver",
    "django.conf.urls.url",
    "django.conf.settings",
    "django.setup",
    # FastAPI / Starlette
    "fastapi.FastAPI",
    "fastapi.APIRouter",
    "starlette.applications.Starlette",
    # Flask
    "flask.Flask",
    "flask.Blueprint",
    # Celery
    "celery.Celery",
}


def _match(node: str, symbols: list[str]) -> str | None:
    if not node.startswith("ext:"):
        return None
    bare = node[4:]
    if bare in BOOTSTRAP_EXCLUSIONS:
        return None
    for s in symbols:
        if bare == s or bare.startswith(s + "."):
            return s
    return None


def reachable_to(cg: CallGraph, symbols: list[str], cve_ids: list[str] | None = None) -> ReachabilityResult:
    g = cg.graph
    parents: dict[str, str | None] = {ep: None for ep in cg.entrypoints if ep in g}
    q: deque[str] = deque(parents.keys())

    # We may discover multiple candidate sinks during BFS; we want the first
    # one that PASSES the taint check, falling back to "reachable=False" if all
    # candidates are suppressed.
    suppressed_reason: str | None = None
    sink: str | None = None
    matched: str | None = None
    taint_reason: str | None = None

    while q:
        n = q.popleft()
        m = _match(n, symbols)
        if m is not None:
            if cve_ids:
                # Aggregate kwargs across all call sites that reach this sink.
                kwargs_seen: list[str] = []
                for kw in cg.sink_call_kwargs.get(n, []):
                    kwargs_seen.extend(kw)
                verdict = taint_check(cve_ids, kwargs_seen)
                if verdict.matched:
                    sink = n
                    matched = m
                    taint_reason = verdict.reason
                    break
                else:
                    suppressed_reason = verdict.reason
                    # don't break — keep searching for another sink that does match
            else:
                sink = n
                matched = m
                break
        for nxt in g.successors(n):
            if nxt not in parents:
                parents[nxt] = n
                q.append(nxt)

    if sink is None:
        return ReachabilityResult(
            reachable=False, matched_symbol=None, path=[], sink_locations=[],
            taint_reason=suppressed_reason,
        )

    path: list[str] = []
    cur: str | None = sink
    while cur is not None:
        path.append(cur)
        cur = parents.get(cur)
    path.reverse()

    locs: list[tuple[Path, int]] = []
    for a, b in zip(path, path[1:]):
        data = g.get_edge_data(a, b) or {}
        f = data.get("file")
        l = data.get("line")
        if f and l:
            locs.append((Path(f), int(l)))

    return ReachabilityResult(
        reachable=True, matched_symbol=matched, path=path, sink_locations=locs,
        taint_reason=taint_reason,
    )
