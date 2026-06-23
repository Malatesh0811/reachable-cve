"""JSON logging produces parseable, structured events."""
import io
import json
import logging

from reachable_cve.logging_config import JsonFormatter, log_event


def test_json_formatter_emits_valid_json():
    rec = logging.LogRecord("rcve", logging.INFO, __file__, 1, "hello", (), None)
    payload = json.loads(JsonFormatter().format(rec))
    assert payload["level"] == "INFO"
    assert payload["message"] == "hello"
    assert "ts" in payload


def test_log_event_includes_event_field_and_extras():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("rcve_test_logger")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_event(logger, "finding", osv_id="GHSA-x", score=94.1, reachable=True)

    line = buf.getvalue().strip()
    payload = json.loads(line)
    assert payload["event"] == "finding"
    assert payload["osv_id"] == "GHSA-x"
    assert payload["score"] == 94.1
    assert payload["reachable"] is True
