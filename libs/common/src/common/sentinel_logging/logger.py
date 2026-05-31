"""SentinelLogger — structured logging for sentinel request decisions and lifecycle events.

Usage::

    logger = SentinelLogger(service_id="my-service", env="dev", role="producer")
    logger.setup_handlers()
    logger.log_request(
        event="request_decision",
        decision="permit",
        http_method="GET",
        http_path="/api/v1/data",
        http_status=200,
        latency_ms=12.3,
        jti="raw-jti-value",       # hashed internally
        consumer_did="did:key:z…", # hashed internally
    )
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.sentinel_logging.formatter import JSONFormatter
from common.sentinel_logging.redaction import hash_field, redact_dict
from common.sentinel_logging.ring_buffer import LogRingBuffer
from common.sentinel_logging.schema import SentinelLogEvent

# ---------------------------------------------------------------------------
# Environment-driven defaults
# ---------------------------------------------------------------------------
_DEFAULT_MAX_MB = int(os.getenv("SENTINEL_LOG_MAX_MB", "500"))
_DEFAULT_MAX_FILES = int(os.getenv("SENTINEL_LOG_MAX_FILES", "5"))
_DEFAULT_MAX_DAYS = int(os.getenv("SENTINEL_LOG_MAX_DAYS", "30"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SentinelLogger:
    """Structured JSON logger for sentinel nodes.

    Writes to stdout (container log collection) **and** a rotating file handler
    under ``$sentinel_home/.sentinel/logs/sentinel.log``.
    All events are also pushed to an in-process :class:`LogRingBuffer`.
    """

    def __init__(
        self,
        service_id: str,
        env: str,
        role: str,
        sentinel_home: str | None = None,
        ring_buffer: LogRingBuffer | None = None,
        max_log_mb: int = _DEFAULT_MAX_MB,
        max_log_files: int = _DEFAULT_MAX_FILES,
    ) -> None:
        self.service_id = service_id
        self.env = env
        self.role = role
        self.sentinel_home = sentinel_home or os.getenv("SENTINEL_HOME", str(Path.home()))
        self.max_log_mb = max_log_mb
        self.max_log_files = max_log_files
        self.ring_buffer: LogRingBuffer = ring_buffer if ring_buffer is not None else LogRingBuffer()
        self._logger = logging.getLogger(f"sentinel.{service_id}")
        self._logger.setLevel(logging.DEBUG)
        self._handlers_set_up = False

    # ------------------------------------------------------------------
    # Handler setup
    # ------------------------------------------------------------------

    def setup_handlers(self) -> None:
        """Install stdout and rotating-file handlers (idempotent)."""
        if self._handlers_set_up:
            return
        formatter = JSONFormatter()

        # 1. Stdout handler
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        self._logger.addHandler(stdout_handler)

        # 2. Rotating file handler
        log_dir = Path(self.sentinel_home) / ".sentinel" / "logs"
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "sentinel.log"
            file_handler = logging.handlers.RotatingFileHandler(
                str(log_path),
                maxBytes=self.max_log_mb * 1024 * 1024,
                backupCount=self.max_log_files,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)
        except OSError as exc:
            self._logger.warning("Could not set up file log handler: %s", exc)

        self._handlers_set_up = True

    # ------------------------------------------------------------------
    # Internal event emitter
    # ------------------------------------------------------------------

    def _emit(self, event: SentinelLogEvent) -> None:
        level_map = {
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
            "DEBUG": logging.DEBUG,
        }
        level = level_map.get(event.level.upper(), logging.INFO)
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=event.event,
            args=(),
            exc_info=None,
        )
        record.sentinel_event = event  # type: ignore[attr-defined]
        self._logger.handle(record)
        self.ring_buffer.append(event)

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log_request(
        self,
        event: str = "request_decision",
        *,
        decision: str | None = None,
        error_code: str | None = None,
        http_method: str | None = None,
        http_path: str | None = None,
        http_status: int | None = None,
        latency_ms: float | None = None,
        jti: str | None = None,
        consumer_did: str | None = None,
        trace_id: str | None = None,
        direction: str | None = None,
        request_id: str | None = None,
        level: str = "INFO",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Log a request decision event (inbound or outbound pipeline)."""
        jti_hash = hash_field(jti) if jti else None
        consumer_did_hash = hash_field(consumer_did) if consumer_did else None
        redacted_extra = redact_dict(extra) if extra else {}

        evt = SentinelLogEvent(
            ts=_now_iso(),
            level=level,
            event=event,
            service_id=self.service_id,
            env=self.env,
            role=self.role,
            direction=direction,
            request_id=request_id or str(uuid.uuid4()),
            decision=decision,
            error_code=error_code,
            http_method=http_method,
            http_path=http_path,
            http_status=http_status,
            latency_ms=latency_ms,
            jti_hash=jti_hash,
            consumer_did_hash=consumer_did_hash,
            trace_id=trace_id,
            extra=redacted_extra,
        )
        self._emit(evt)

    def log_lifecycle(
        self,
        event: str,
        *,
        level: str = "INFO",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Log a system lifecycle event (startup, shutdown, key rotation, etc.)."""
        redacted_extra = redact_dict(extra) if extra else {}
        evt = SentinelLogEvent(
            ts=_now_iso(),
            level=level,
            event=event,
            service_id=self.service_id,
            env=self.env,
            role=self.role,
            direction="internal",
            extra=redacted_extra,
        )
        self._emit(evt)

    def log_credential(
        self,
        event: str,
        *,
        credential_jti: str | None = None,
        action: str | None = None,
        level: str = "INFO",
    ) -> None:
        """Log a credential lifecycle event — only the JTI hash is stored."""
        jti_hash = hash_field(credential_jti) if credential_jti else None
        extra: dict[str, Any] = {}
        if action:
            extra["action"] = action
        evt = SentinelLogEvent(
            ts=_now_iso(),
            level=level,
            event=event,
            service_id=self.service_id,
            env=self.env,
            role=self.role,
            direction="internal",
            jti_hash=jti_hash,
            extra=extra,
        )
        self._emit(evt)


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_default_logger: SentinelLogger | None = None


def get_logger() -> SentinelLogger:
    """Return the module-level singleton, or a no-op fallback if not configured."""
    global _default_logger  # noqa: PLW0603
    if _default_logger is None:
        _default_logger = SentinelLogger(
            service_id="unknown",
            env="dev",
            role="unknown",
        )
    return _default_logger


def configure_logger(
    service_id: str,
    env: str,
    role: str,
    sentinel_home: str | None = None,
    ring_buffer: LogRingBuffer | None = None,
) -> SentinelLogger:
    """Create, configure, and register the module-level singleton."""
    global _default_logger  # noqa: PLW0603
    _default_logger = SentinelLogger(
        service_id=service_id,
        env=env,
        role=role,
        sentinel_home=sentinel_home,
        ring_buffer=ring_buffer,
    )
    _default_logger.setup_handlers()
    return _default_logger
