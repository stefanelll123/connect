"""Unit tests for common.crypto.hashing.

Verifies:
* EMPTY_BODY_HASH equals the base64url-encoded SHA-256 of b"".
* sha256_b64url produces correct digests for known inputs.
* body_hash returns EMPTY_BODY_HASH for None / empty bytes.
* query_hash returns EMPTY_BODY_HASH for None / empty string.
* Both functions produce standard base64url encoding (no padding, URL-safe chars).
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from common.crypto.hashing import (
    EMPTY_BODY_HASH,
    body_hash,
    query_hash,
    sha256_b64url,
)


def _expected_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


class TestEmptyBodyHash:
    def test_matches_sha256_of_empty_bytes(self) -> None:
        assert EMPTY_BODY_HASH == _expected_b64url(b"")

    def test_has_no_padding(self) -> None:
        assert "=" not in EMPTY_BODY_HASH

    def test_is_43_characters(self) -> None:
        # SHA-256 → 32 bytes → ceil(32*8/6) = 43 base64url chars
        assert len(EMPTY_BODY_HASH) == 43

    def test_contains_only_url_safe_chars(self) -> None:
        safe = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in safe for c in EMPTY_BODY_HASH)


class TestSha256B64url:
    def test_known_value_hello(self) -> None:
        result = sha256_b64url(b"hello")
        assert result == _expected_b64url(b"hello")

    def test_known_value_empty(self) -> None:
        assert sha256_b64url(b"") == EMPTY_BODY_HASH

    def test_no_padding(self) -> None:
        assert "=" not in sha256_b64url(b"test data")

    def test_url_safe_alphabet(self) -> None:
        # Standard base64 uses + and / but urlsafe uses - and _
        result = sha256_b64url(b"\xff\xfe")
        assert "+" not in result
        assert "/" not in result

    def test_different_inputs_produce_different_hashes(self) -> None:
        assert sha256_b64url(b"abc") != sha256_b64url(b"abd")

    def test_output_length_is_43(self) -> None:
        assert len(sha256_b64url(b"anything")) == 43


class TestBodyHash:
    def test_none_returns_empty_hash(self) -> None:
        assert body_hash(None) == EMPTY_BODY_HASH

    def test_empty_bytes_returns_empty_hash(self) -> None:
        assert body_hash(b"") == EMPTY_BODY_HASH

    def test_non_empty_body_hashed(self) -> None:
        data = b'{"key":"value"}'
        assert body_hash(data) == _expected_b64url(data)

    def test_body_hash_differs_from_empty(self) -> None:
        assert body_hash(b"non-empty") != EMPTY_BODY_HASH

    def test_binary_body(self) -> None:
        binary = bytes(range(256))
        assert body_hash(binary) == _expected_b64url(binary)


class TestQueryHash:
    def test_none_returns_empty_hash(self) -> None:
        assert query_hash(None) == EMPTY_BODY_HASH

    def test_empty_string_returns_empty_hash(self) -> None:
        assert query_hash("") == EMPTY_BODY_HASH

    def test_empty_bytes_returns_empty_hash(self) -> None:
        assert query_hash(b"") == EMPTY_BODY_HASH

    def test_string_input(self) -> None:
        qs = "foo=bar&baz=qux"
        expected = _expected_b64url(qs.encode())
        assert query_hash(qs) == expected

    def test_bytes_input(self) -> None:
        qs_bytes = b"page=1&size=10"
        assert query_hash(qs_bytes) == _expected_b64url(qs_bytes)

    def test_string_and_bytes_equivalent(self) -> None:
        qs = "search=hello%20world"
        assert query_hash(qs) == query_hash(qs.encode())

    def test_different_queries_differ(self) -> None:
        assert query_hash("a=1") != query_hash("a=2")

    def test_percent_encoded_differs_from_decoded(self) -> None:
        # Query hash is over the raw (percent-encoded) query string
        assert query_hash("q=hello%20world") != query_hash("q=hello world")
