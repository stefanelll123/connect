"""Unit tests for common.revocation.bitstring."""

from __future__ import annotations

import base64
import gzip

import pytest

from common.revocation.bitstring import (
    MAX_BITSTRING_SIZE,
    MIN_BITSTRING_SIZE,
    check_bit,
    create_status_list,
    decode_bitstring,
    encode_bitstring,
    revoke_credential,
    set_bit,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SMALL_SIZE = 8  # 1 byte — used for concise bit-level tests


def _raw_bytes(hex_str: str, total_bytes: int) -> bytes:
    """Return *total_bytes* of bytes whose first bytes are from *hex_str*."""
    raw = bytes.fromhex(hex_str)
    assert len(raw) <= total_bytes
    return raw + b"\x00" * (total_bytes - len(raw))


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_min_and_max_equal(self) -> None:
        assert MIN_BITSTRING_SIZE == MAX_BITSTRING_SIZE

    def test_size_is_2_pow_17(self) -> None:
        assert MIN_BITSTRING_SIZE == 2**17


# ---------------------------------------------------------------------------
# TestEncodeBitstring
# ---------------------------------------------------------------------------


class TestEncodeBitstring:
    def test_returns_string(self) -> None:
        raw = b"\x00" * 16
        result = encode_bitstring(raw)
        assert isinstance(result, str)

    def test_no_padding_chars(self) -> None:
        raw = b"\xAB\xCD"
        result = encode_bitstring(raw)
        assert "=" not in result

    def test_deterministic(self) -> None:
        raw = b"\x01\x02\x03"
        assert encode_bitstring(raw) == encode_bitstring(raw)

    def test_known_roundtrip(self) -> None:
        # Encode, then decode — must get back the original bytes
        original = b"\xFF\x00\xAA\x55"
        assert decode_bitstring(encode_bitstring(original)) == original


# ---------------------------------------------------------------------------
# TestDecodeBitstring
# ---------------------------------------------------------------------------


class TestDecodeBitstring:
    def test_decode_all_zeros(self) -> None:
        packed = b"\x00" * 8
        encoded = encode_bitstring(packed)
        assert decode_bitstring(encoded) == packed

    def test_decode_handles_missing_padding(self) -> None:
        packed = b"\xDE\xAD\xBE\xEF"
        encoded = encode_bitstring(packed)
        # Remove any padding that may be present in an intermediate form
        encoded_no_pad = encoded.rstrip("=")
        assert decode_bitstring(encoded_no_pad) == packed

    def test_decode_invalid_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            decode_bitstring("not-valid-gzip-data!!!")


# ---------------------------------------------------------------------------
# TestCheckBit
# ---------------------------------------------------------------------------


class TestCheckBit:
    """Bit ordering: index 0 is MSB of byte 0 (big-endian / MSB-first)."""

    def test_index_0_set(self) -> None:
        # Byte 0 = 0b10000000 — bit 0 is MSB → True
        data = bytes([0b10000000])
        assert check_bit(data, 0) is True

    def test_index_0_clear(self) -> None:
        data = bytes([0b01111111])
        assert check_bit(data, 0) is False

    def test_index_1_set(self) -> None:
        data = bytes([0b01000000])
        assert check_bit(data, 1) is True

    def test_index_7_set(self) -> None:
        # Bit 7 is LSB of byte 0
        data = bytes([0b00000001])
        assert check_bit(data, 7) is True

    def test_index_8_set(self) -> None:
        # Bit 8 is MSB of byte 1
        data = bytes([0b00000000, 0b10000000])
        assert check_bit(data, 8) is True

    def test_index_8_clear(self) -> None:
        data = bytes([0b11111111, 0b01111111])
        assert check_bit(data, 8) is False

    def test_out_of_range_raises_index_error(self) -> None:
        data = bytes([0b11111111])  # 8 bits total, valid range 0–7
        with pytest.raises(IndexError):
            check_bit(data, 8)

    def test_negative_index_raises_index_error(self) -> None:
        data = bytes([0b11111111])
        with pytest.raises(IndexError):
            check_bit(data, -1)


# ---------------------------------------------------------------------------
# TestSetBit
# ---------------------------------------------------------------------------


class TestSetBit:
    def test_set_bit_revokes(self) -> None:
        data = bytearray([0b00000000])
        set_bit(data, 0, True)
        assert data[0] == 0b10000000

    def test_set_bit_clears(self) -> None:
        data = bytearray([0b11111111])
        set_bit(data, 0, False)
        assert data[0] == 0b01111111

    def test_set_bit_index_7(self) -> None:
        data = bytearray([0b00000000])
        set_bit(data, 7, True)
        assert data[0] == 0b00000001

    def test_set_bit_idempotent_set(self) -> None:
        data = bytearray([0b10000000])
        set_bit(data, 0, True)
        assert data[0] == 0b10000000  # unchanged

    def test_set_bit_idempotent_clear(self) -> None:
        data = bytearray([0b00000000])
        set_bit(data, 0, False)
        assert data[0] == 0b00000000  # unchanged

    def test_set_bit_out_of_range_raises(self) -> None:
        data = bytearray(1)  # 8 bits
        with pytest.raises(IndexError):
            set_bit(data, 8, True)


# ---------------------------------------------------------------------------
# TestCreateStatusList
# ---------------------------------------------------------------------------


class TestCreateStatusList:
    def test_returns_string(self) -> None:
        result = create_status_list()
        assert isinstance(result, str)

    def test_all_bits_clear_by_default(self) -> None:
        encoded = create_status_list()
        raw = decode_bitstring(encoded)
        assert all(b == 0 for b in raw)

    def test_size_is_min_bitstring_size_bytes(self) -> None:
        encoded = create_status_list()
        raw = decode_bitstring(encoded)
        assert len(raw) * 8 == MIN_BITSTRING_SIZE

    def test_revoked_indices_are_set(self) -> None:
        indices = [0, 7, 100, 1023]
        encoded = create_status_list(revoked_indices=indices)
        raw = decode_bitstring(encoded)
        for idx in indices:
            assert check_bit(raw, idx), f"Expected bit {idx} to be set"

    def test_non_revoked_indices_are_clear(self) -> None:
        encoded = create_status_list(revoked_indices=[0])
        raw = decode_bitstring(encoded)
        assert check_bit(raw, 0) is True
        assert check_bit(raw, 1) is False


# ---------------------------------------------------------------------------
# TestRevokeCredential
# ---------------------------------------------------------------------------


class TestRevokeCredential:
    def test_revoke_clears_bit_is_false_before(self) -> None:
        original = create_status_list()
        raw_before = decode_bitstring(original)
        assert check_bit(raw_before, 42) is False

    def test_revoke_sets_bit(self) -> None:
        original = create_status_list()
        updated = revoke_credential(original, 42)
        raw = decode_bitstring(updated)
        assert check_bit(raw, 42) is True

    def test_revoke_does_not_mutate_other_bits(self) -> None:
        original = create_status_list()
        updated = revoke_credential(original, 0)
        raw = decode_bitstring(updated)
        # All bits except 0 are still clear
        assert check_bit(raw, 1) is False
        assert check_bit(raw, MIN_BITSTRING_SIZE - 1) is False

    def test_revoke_idempotent(self) -> None:
        original = create_status_list()
        updated_once = revoke_credential(original, 5)
        updated_twice = revoke_credential(updated_once, 5)
        assert decode_bitstring(updated_once) == decode_bitstring(updated_twice)

    def test_revoke_multiple_sequential(self) -> None:
        encoded = create_status_list()
        for idx in [10, 20, 30]:
            encoded = revoke_credential(encoded, idx)
        raw = decode_bitstring(encoded)
        for idx in [10, 20, 30]:
            assert check_bit(raw, idx) is True
