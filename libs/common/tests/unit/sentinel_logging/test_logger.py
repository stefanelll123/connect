"""Unit tests for TASK-051: Structured Request/Activity Logging.

Covers:
1. JWT in extra dict is redacted
2. Raw DID in extra is masked
3. jti_hash is only first 16 chars of SHA-256
4. consumer_did_hash is only first 16 chars of SHA-256
5. Authorization header value never appears in serialised log
6. Ring buffer evicts oldest on 10001th insert
7. Subscriber queue receives events pushed after subscription
8. Log event schema passes JSON serialisation
9. Log levels map correctly (INFO/WARNING/ERROR)
10. Retention cleanup deletes files older than max_days
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from common.sentinel_logging.redaction import hash_field, redact_dict
from common.sentinel_logging.retention import cleanup_old_log_files
from common.sentinel_logging.ring_buffer import LogRingBuffer
from common.sentinel_logging.schema import SentinelLogEvent
from common.sentinel_logging.logger import SentinelLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_logger(ring_buffer: LogRingBuffer | None = None) -> SentinelLogger:
    return SentinelLogger(
        service_id="test-svc",
        env="dev",
        role="producer",
        ring_buffer=ring_buffer,
    )


def _make_event(**kwargs) -> SentinelLogEvent:
    defaults = dict(
        ts="2026-03-15T10:00:00Z",
        level="INFO",
        event="request_decision",
        service_id="test-svc",
        env="dev",
        role="producer",
    )
    defaults.update(kwargs)
    return SentinelLogEvent(**defaults)


# ---------------------------------------------------------------------------
# Test 1: JWT in extra dict is redacted
# ---------------------------------------------------------------------------

class TestJWTRedaction:
    def test_jwt_in_extra_is_redacted(self):
        raw_jwt = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.abc123def456ghi789jkl"
        result = redact_dict({"token": raw_jwt})
        assert result["token"] == "<jwt_redacted>"
        assert "eyJ" not in result["token"]

    def test_nested_jwt_redacted(self):
        raw_jwt = "header.payload.signature"
        result = redact_dict({"outer": {"inner": raw_jwt}})
        assert result["outer"]["inner"] == "<jwt_redacted>"

    def test_non_jwt_string_unchanged(self):
        result = redact_dict({"key": "plain-value"})
        assert result["key"] == "plain-value"


# ---------------------------------------------------------------------------
# Test 2: Raw DID in extra is masked
# ---------------------------------------------------------------------------

class TestDIDRedaction:
    def test_did_in_extra_is_masked(self):
        raw_did = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y34ySteMObwk4BMqm"
        result = redact_dict({"consumer": raw_did})
        assert result["consumer"].startswith("did:*:")
        assert raw_did not in result["consumer"]

    def test_did_mask_is_sha256_8chars(self):
        raw_did = "did:key:z6Mknhash"
        result = redact_dict({"d": raw_did})
        # Extract the hash portion
        masked = result["d"]
        assert masked.startswith("did:*:")
        suffix = masked[len("did:*:"):]
        assert len(suffix) == 8

    def test_did_in_list_redacted(self):
        raw_did = "did:web:example.com"
        result = redact_dict({"dids": [raw_did, "plain"]})
        assert result["dids"][0].startswith("did:*:")
        assert result["dids"][1] == "plain"


# ---------------------------------------------------------------------------
# Test 3: jti_hash is first 16 chars of SHA-256
# ---------------------------------------------------------------------------

class TestJtiHash:
    def test_jti_hash_is_16_hex_chars(self):
        jti = "my-unique-jti-value"
        h = hash_field(jti, 16)
        expected = hashlib.sha256(jti.encode()).hexdigest()[:16]
        assert h == expected
        assert len(h) == 16

    def test_logger_records_jti_hash(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        jti = "test-jti-abc"
        logger.log_request(event="req", jti=jti)
        events = buf.get_recent(1)
        assert len(events) == 1
        expected_hash = hashlib.sha256(jti.encode()).hexdigest()[:16]
        assert events[0].jti_hash == expected_hash


# ---------------------------------------------------------------------------
# Test 4: consumer_did_hash is first 16 chars of SHA-256
# ---------------------------------------------------------------------------

class TestConsumerDidHash:
    def test_did_hash_is_16_hex_chars(self):
        did = "did:key:z6Mkfull"
        h = hash_field(did, 16)
        assert len(h) == 16
        assert h == hashlib.sha256(did.encode()).hexdigest()[:16]

    def test_logger_records_consumer_did_hash(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        did = "did:key:z6MkMyDid"
        logger.log_request(event="req", consumer_did=did)
        events = buf.get_recent(1)
        expected = hashlib.sha256(did.encode()).hexdigest()[:16]
        assert events[0].consumer_did_hash == expected


# ---------------------------------------------------------------------------
# Test 5: Authorization header value never appears in serialised log
# ---------------------------------------------------------------------------

class TestAuthHeaderRedaction:
    def test_auth_header_value_not_in_log(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        auth_value = "Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.SIG"
        logger.log_request(
            event="req",
            extra={"Authorization": auth_value},
        )
        events = buf.get_recent(1)
        serialised = events[0].to_json()
        # The entire Authorization value must be replaced with <redacted>
        assert "Bearer" not in serialised
        assert "eyJhbGciOiJFZERTQSJ9" not in serialised
        assert "<redacted>" in serialised

    def test_bytes_in_extra_are_redacted(self):
        result = redact_dict({"key_bytes": b"\x01\x02\x03"})
        assert result["key_bytes"] == "<bytes_redacted>"


# ---------------------------------------------------------------------------
# Test 6: Ring buffer evicts oldest on 10001th insert
# ---------------------------------------------------------------------------

class TestRingBufferEviction:
    def test_evicts_oldest_at_capacity(self):
        buf = LogRingBuffer(maxlen=10)

        for i in range(10):
            buf.append(_make_event(event=f"evt_{i}", service_id="svc"))

        assert len(buf) == 10
        events = buf.get_recent(10)
        assert events[0].event == "evt_0"

        # Insert one more — evicts evt_0
        buf.append(_make_event(event="evt_10", service_id="svc"))
        assert len(buf) == 10
        events = buf.get_recent(10)
        assert events[0].event == "evt_1"
        assert events[-1].event == "evt_10"

    def test_large_ringbuffer_caps_at_10000(self):
        buf = LogRingBuffer(maxlen=10_000)
        for i in range(10_001):
            buf.append(_make_event(event=f"e{i}"))
        assert len(buf) == 10_000


# ---------------------------------------------------------------------------
# Test 7: Subscriber queue receives events
# ---------------------------------------------------------------------------

class TestSubscriber:
    @pytest.mark.asyncio
    async def test_subscriber_receives_event(self):
        buf = LogRingBuffer()
        q = buf.subscribe()
        evt = _make_event(event="live_event")
        buf.append(evt)
        received = await asyncio.wait_for(q.get(), timeout=1.0)
        assert received.event == "live_event"

    @pytest.mark.asyncio
    async def test_subscriber_limit_enforced(self):
        buf = LogRingBuffer()
        queues = [buf.subscribe() for _ in range(10)]
        assert buf.subscriber_count() == 10
        with pytest.raises(RuntimeError, match="Maximum number"):
            buf.subscribe()
        for q in queues:
            buf.unsubscribe(q)

    def test_unsubscribe_removes_queue(self):
        buf = LogRingBuffer()
        q = buf.subscribe()
        assert buf.subscriber_count() == 1
        buf.unsubscribe(q)
        assert buf.subscriber_count() == 0


# ---------------------------------------------------------------------------
# Test 8: Log event schema passes JSON serialisation
# ---------------------------------------------------------------------------

class TestSchemaSerialisation:
    def test_to_json_is_valid_json(self):
        evt = _make_event(decision="permit", jti_hash="abcd1234abcd1234")
        serialised = evt.to_json()
        parsed = json.loads(serialised)
        assert parsed["event"] == "request_decision"
        assert parsed["decision"] == "permit"
        assert parsed["jti_hash"] == "abcd1234abcd1234"

    def test_none_fields_omitted(self):
        evt = _make_event()
        d = evt.to_dict()
        assert "decision" not in d  # None → omitted
        assert "jti_hash" not in d


# ---------------------------------------------------------------------------
# Test 9: Log levels map correctly
# ---------------------------------------------------------------------------

class TestLogLevels:
    def test_info_level_recorded(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        logger.log_lifecycle("startup", level="INFO")
        events = buf.get_recent(1)
        assert events[0].level == "INFO"

    def test_warning_level_recorded(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        logger.log_lifecycle("stale_revocation", level="WARNING")
        events = buf.get_recent(1)
        assert events[0].level == "WARNING"

    def test_error_level_recorded(self):
        buf = LogRingBuffer()
        logger = _make_logger(buf)
        logger.log_lifecycle("chain_error", level="ERROR")
        events = buf.get_recent(1)
        assert events[0].level == "ERROR"


# ---------------------------------------------------------------------------
# Test 10: Retention cleanup deletes files older than max_days
# ---------------------------------------------------------------------------

class TestRetentionCleanup:
    def test_deletes_files_older_than_max_days(self, tmp_path: Path):
        log_file = tmp_path / "sentinel.log"
        log_file.write_text("old log")
        # Back-date the mtime to 31 days ago
        old_time = time.time() - 31 * 86_400
        os.utime(log_file, (old_time, old_time))

        removed = cleanup_old_log_files(tmp_path, max_days=30)
        assert removed == 1
        assert not log_file.exists()

    def test_keeps_recent_files(self, tmp_path: Path):
        log_file = tmp_path / "sentinel.log"
        log_file.write_text("recent log")
        # Recent mtime — 1 day ago
        recent = time.time() - 1 * 86_400
        os.utime(log_file, (recent, recent))

        removed = cleanup_old_log_files(tmp_path, max_days=30)
        assert removed == 0
        assert log_file.exists()

    def test_nonexistent_dir_returns_zero(self, tmp_path: Path):
        removed = cleanup_old_log_files(tmp_path / "nonexistent", max_days=30)
        assert removed == 0
