"""Bitstring encode/decode/check utilities (W3C Bitstring Status List v1.0).

Reference: https://www.w3.org/TR/bitstring-status-list/

Encoding
--------
The status list bitstring is a *packed* sequence of bits, one per entry.
The bit at index ``N`` occupies:

* byte position: ``N // 8``
* bit position within that byte: bit ``(7 - (N % 8))`` (MSB first)

This means that credential index 0 is the most-significant bit of byte 0,
index 1 is the second-most-significant bit of byte 0, etc.

The packed bytes are then gzip-compressed and base64url-encoded to produce
the ``encodedList`` value stored in the ``BitstringStatusList`` credential.

Bit value semantics (``statusPurpose: revocation``):
* 0 → credential is valid (not revoked)
* 1 → credential is revoked
"""

from __future__ import annotations

import base64
import gzip

__all__ = [
    "MIN_BITSTRING_SIZE",
    "MAX_BITSTRING_SIZE",
    "encode_bitstring",
    "decode_bitstring",
    "check_bit",
    "set_bit",
    "create_status_list",
    "revoke_credential",
]

# Minimum and maximum entries in a single status list per spec §2.1
MIN_BITSTRING_SIZE = 131_072   # 2^17 bits = 16 KB minimum (spec mandates ≥ 16 KB)
MAX_BITSTRING_SIZE = 131_072   # upper cap kept at spec minimum for simplicity

# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def encode_bitstring(packed_bytes: bytes) -> str:
    """Gzip-compress *packed_bytes* and base64url-encode the result.

    Args:
        packed_bytes: Raw bitstring bytes (MSB-first packed).

    Returns:
        ``base64url(gzip(packed_bytes))`` — the ``encodedList`` value.
    """
    compressed = gzip.compress(packed_bytes, mtime=0)
    return base64.urlsafe_b64encode(compressed).rstrip(b"=").decode()


def decode_bitstring(encoded_list: str) -> bytes:
    """Reverse of :func:`encode_bitstring`.

    Args:
        encoded_list: base64url-encoded, gzip-compressed bitstring.

    Returns:
        Decompressed raw bitstring bytes.

    Raises:
        ValueError: If decoding or decompression fails.
    """
    try:
        padding = 4 - len(encoded_list) % 4
        if padding != 4:
            encoded_list += "=" * padding
        compressed = base64.urlsafe_b64decode(encoded_list)
        return gzip.decompress(compressed)
    except Exception as exc:
        raise ValueError(f"Failed to decode bitstring: {exc}") from exc


# ---------------------------------------------------------------------------
# Bit operations
# ---------------------------------------------------------------------------


def check_bit(bitstring_bytes: bytes, index: int) -> bool:
    """Return ``True`` if the bit at *index* is set (credential revoked).

    Args:
        bitstring_bytes: Decompressed bitstring bytes from the status list.
        index: Zero-based credential index.

    Returns:
        ``True`` if the corresponding bit equals 1 (revoked / suspended).

    Raises:
        IndexError: If *index* is outside the bitstring.
    """
    if index < 0:
        raise IndexError(f"Credential index {index} must be non-negative.")
    byte_pos = index // 8
    if byte_pos >= len(bitstring_bytes):
        raise IndexError(
            f"Credential index {index} is outside the bitstring "
            f"(bitstring size: {len(bitstring_bytes) * 8} bits)."
        )
    bit_pos = 7 - (index % 8)  # MSB first
    return bool((bitstring_bytes[byte_pos] >> bit_pos) & 1)


def set_bit(bitstring_bytes: bytearray, index: int, value: bool) -> None:
    """Set or clear the bit at *index* in-place within *bitstring_bytes*.

    Args:
        bitstring_bytes: Mutable bytearray; modified in-place.
        index: Zero-based credential index.
        value: ``True`` to set (revoke); ``False`` to clear (reinstate).

    Raises:
        IndexError: If *index* is outside the bytearray.
    """
    byte_pos = index // 8
    if byte_pos >= len(bitstring_bytes):
        raise IndexError(
            f"Credential index {index} is outside the bytearray "
            f"(size: {len(bitstring_bytes) * 8} bits)."
        )
    bit_pos = 7 - (index % 8)
    if value:
        bitstring_bytes[byte_pos] |= (1 << bit_pos)
    else:
        bitstring_bytes[byte_pos] &= ~(1 << bit_pos)


# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------


def create_status_list(
    size: int = MIN_BITSTRING_SIZE,
    revoked_indices: list[int] | None = None,
) -> str:
    """Create a new ``encodedList`` for a status list credential.

    Args:
        size: Number of credential slots in the status list.  Must be a
            positive multiple of 8.  Minimum :data:`MIN_BITSTRING_SIZE`.
        revoked_indices: Optional list of indices to pre-mark as revoked.

    Returns:
        ``encodedList`` string suitable for a ``BitstringStatusList``
        credential.

    Raises:
        ValueError: If *size* is not a positive multiple of 8.
    """
    if size <= 0 or size % 8 != 0:
        raise ValueError(f"size must be a positive multiple of 8, got {size}.")
    num_bytes = size // 8
    bits = bytearray(num_bytes)
    if revoked_indices:
        for idx in revoked_indices:
            set_bit(bits, idx, True)
    return encode_bitstring(bytes(bits))


def revoke_credential(encoded_list: str, index: int) -> str:
    """Return a new ``encodedList`` with the bit at *index* set to 1.

    Does not mutate *encoded_list* — returns a new encoded string.

    Args:
        encoded_list: Current ``encodedList`` value from the credential.
        index: Zero-based credential index to revoke.

    Returns:
        Updated ``encodedList`` with the credential at *index* revoked.
    """
    bits = bytearray(decode_bitstring(encoded_list))
    set_bit(bits, index, True)
    return encode_bitstring(bytes(bits))
