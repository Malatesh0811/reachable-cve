"""Framework entrypoint detection.

When a function is decorated with one of these patterns, treat it as a graph
entrypoint. Matching is suffix-based so import-as renames still work
(`from flask import Flask as Application; @Application.route(...)` still
matches `Flask.route`).
"""
from __future__ import annotations

# Decorator suffixes that mark a function as an HTTP/RPC entrypoint.
ENTRYPOINT_DECORATOR_SUFFIXES = {
    # Flask
    "app.route", "app.get", "app.post", "app.put", "app.delete", "app.patch",
    "blueprint.route", "bp.route",
    # FastAPI
    "app.get", "app.post", "app.put", "app.delete", "app.patch", "app.head", "app.options",
    "router.get", "router.post", "router.put", "router.delete", "router.patch",
    "router.head", "router.options", "router.websocket",
    # Celery
    "celery.task", "app.task", "shared_task",
    # AWS Lambda Powertools
    "tracer.capture_lambda_handler",
    # Pytest
    # (handled by function-name heuristic in call_graph, not here)
}


def is_entrypoint_decorator(deco_text: str) -> bool:
    """Suffix match — `something.route` matches `app.route`, `bp.route`, etc."""
    deco_text = deco_text.strip()
    if deco_text in ENTRYPOINT_DECORATOR_SUFFIXES:
        return True
    for suffix in ENTRYPOINT_DECORATOR_SUFFIXES:
        if deco_text.endswith("." + suffix):
            return True
        # Cover the case where the user wrote the suffix bare after an attribute path
        if "." in suffix and deco_text.endswith(suffix):
            return True
    return False


def is_test_function(name: str) -> bool:
    return name.startswith("test_") or name == "main"
