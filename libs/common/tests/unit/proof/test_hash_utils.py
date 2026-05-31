"""Unit tests for common.proof.hash_utils."""

from __future__ import annotations

import base64
import hashlib

import pytest

from common.proof.hash_utils import (
    EMPTY_HASH,
    MAX_BODY_BYTES,
    body_hash_for_method,
    hash_body,
    hash_bytes,
    hash_query,
    normalize_content_type,
)


class TestEmptyHash:
    def test_empty_hash_is_sha256_of_empty_bytes(self) -> None:
        expected = base64.urlsafe_b64encode(hashlib.sha256(b"").digest()).rstrip(b"=").decode()
        assert EMPTY_HASH == expected

    def test_empty_hash_known_value(self) -> None:
        assert EMPTY_HASH == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    def test_hash_bytes_empty_equals_empty_hash(self) -> None:
        assert hash_bytes(b"") == EMPTY_HASH


class TestHashBytes:
    def test_known_single_byte(self) -> None:
        # SHA-256 of b'\x00' is a known value
        expected = base64.urlsafe_b64encode(hashlib.sha256(b"\x00").digest()).rstrip(b"=").decode()
        assert hash_bytes(b"\x00") == expected

    def test_deterministic(self) -> None:
        data = b"hello world"
        assert hash_bytes(data) == hash_bytes(data)

    def test_different_inputs_produce_different_hashes(self) -> None:
        assert hash_bytes(b"abc") != hash_bytes(b"def")

    def test_no_padding_characters(self) -> None:
        result = hash_bytes(b"some data here")
        assert "=" not in result

    def test_returns_base64url_not_standard(self) -> None:
        # Standard base64 uses + and / — base64url uses - and _
        result = hash_bytes(b"\xfb\xff")
        assert "+" not in result
        assert "/" not in result

    def test_length_is_43_chars(self) -> None:
        # SHA-256 = 32 bytes → 256 bits → 43 base64url chars (no padding)
        assert len(hash_bytes(b"anything here")) == 43


class TestHashQuery:
    def test_empty_query_gives_empty_hash(self) -> None:
        assert hash_query("") == EMPTY_HASH

    def test_non_empty_query(self) -> None:
        result = hash_query("foo=bar&baz=1")
        expected = hash_bytes("foo=bar&baz=1".encode("utf-8"))
        assert result == expected

    def test_different_queries_differ(self) -> None:
        assert hash_query("a=1") != hash_query("a=2")

    def test_encoding_is_utf8(self) -> None:
        raw = "q=ăîșțâ"
        assert hash_query(raw) == hash_bytes(raw.encode("utf-8"))


class TestHashBody:
    def test_empty_body_gives_empty_hash(self) -> None:
        assert hash_body(b"") == EMPTY_HASH

    def test_known_body(self) -> None:
        body = b'{"key": "value"}'
        assert hash_body(body) == hash_bytes(body)

    def test_exceeds_max_raises(self) -> None:
        oversized = b"x" * (MAX_BODY_BYTES + 1)
        with pytest.raises(ValueError, match="maximum"):
            hash_body(oversized)

    def test_exactly_max_size_is_allowed(self) -> None:
        at_limit = b"x" * MAX_BODY_BYTES
        result = hash_body(at_limit)
        assert len(result) == 43


class TestBodyHashForMethod:
    def test_get_always_empty_hash(self) -> None:
        assert body_hash_for_method("GET", b"some body") == EMPTY_HASH

    def test_head_always_empty_hash(self) -> None:
        assert body_hash_for_method("HEAD", b"data") == EMPTY_HASH

    def test_options_always_empty_hash(self) -> None:
        assert body_hash_for_method("OPTIONS", b"data") == EMPTY_HASH

    def test_trace_always_empty_hash(self) -> None:
        assert body_hash_for_method("TRACE", b"data") == EMPTY_HASH

    def test_post_hashes_body(self) -> None:
        body = b"request payload"
        assert body_hash_for_method("POST", body) == hash_bytes(body)

    def test_put_hashes_body(self) -> None:
        body = b"update data"
        assert body_hash_for_method("PUT", body) == hash_bytes(body)

    def test_delete_with_body_hashes_body(self) -> None:
        body = b"delete payload"
        assert body_hash_for_method("DELETE", body) == hash_bytes(body)

    def test_case_insensitive_method(self) -> None:
        # lowercase "get" should still give EMPTY_HASH
        assert body_hash_for_method("get", b"data") == EMPTY_HASH


class TestNormalizeContentType:
    def test_strips_parameters(self) -> None:
        assert normalize_content_type("application/json; charset=utf-8") == "application/json"

    def test_lowercases(self) -> None:
        assert normalize_content_type("Application/JSON") == "application/json"

    def test_no_parameters_unchanged(self) -> None:
        assert normalize_content_type("application/json") == "application/json"

    def test_strips_whitespace(self) -> None:
        assert normalize_content_type("  text/plain  ; charset=ascii") == "text/plain"

    def test_multipart_with_boundary(self) -> None:
        result = normalize_content_type("multipart/form-data; boundary=----abc123")
        assert result == "multipart/form-data"
