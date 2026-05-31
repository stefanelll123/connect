"""JSONFormatter for stdlib logging that serialises SentinelLogEvent objects."""
from __future__ import annotations

import logging
from typing import Any


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON string.

    If the record carries a ``sentinel_event`` attribute (a
    :class:`~common.sentinel_logging.schema.SentinelLogEvent` instance),
    it is serialised directly.  Otherwise, a minimal JSON envelope is produced.
    """

    def format(self, record: logging.LogRecord) -> str:
        sentinel_event = getattr(record, "sentinel_event", None)
        if sentinel_event is not None and hasattr(sentinel_event, "to_json"):
            return sentinel_event.to_json()

        # Fallback for non-sentinel log records passing through this handler
        import json
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
