"""Structured JSON logging for production observability.

Every operational event becomes a single JSON object on stderr:

    {"ts": "...", "level": "INFO", "event": "finding", "osv_id": "...", "score": 94.1, ...}

Ingest with Loki, Splunk, or a CloudWatch Logs filter. The `event` key is the
stable name to filter on.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
        }
        # Anything passed via extra= lands on the record under those attribute names.
        extra = getattr(record, "_event_fields", None)
        if extra:
            payload.update(extra)
        else:
            payload["message"] = record.getMessage()
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_CONFIGURED = False


def setup_logging(level: str | int | None = None, json_output: bool | None = None) -> None:
    """Idempotent. Call once at process startup (CLI / FastAPI app factory)."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    if level is None:
        level = os.environ.get("RCVE_LOG_LEVEL", "INFO")
    if json_output is None:
        json_output = os.environ.get("RCVE_LOG_JSON", "1") != "0"

    handler = logging.StreamHandler(sys.stderr)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    _CONFIGURED = True


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a structured event. `event` becomes the stable filter key."""
    logger.info(event, extra={"_event_fields": {"event": event, **fields}})
