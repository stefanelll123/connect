"""SecretBytes — zero-on-del memory container (TASK-038).

Stores sensitive bytes in a ``ctypes`` mutable buffer so that:
- The memory can be explicitly zeroed when the object is garbage-collected.
- repr/str never expose the value.
- JSON serialisation raises ``TypeError`` to prevent accidental logging.

Usage::

    key = SecretBytes(raw_key_bytes)
    # ... use key.reveal() only inside a tight scope ...
    key.reveal()       # → bytes
    del key            # zeroes underlying buffer
"""
from __future__ import annotations

import ctypes


class SecretBytes:
    """Immutable wrapper for sensitive byte data with zero-on-del semantics."""

    __slots__ = ("_buf", "_length")

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecretBytes requires bytes or bytearray")
        self._length = len(data)
        self._buf = ctypes.create_string_buffer(data, self._length)

    # ── Public interface ────────────────────────────────────────────────

    def reveal(self) -> bytes:
        """Return the raw bytes.  Use this only in a tight, controlled scope."""
        return bytes(self._buf.raw)

    def __len__(self) -> int:
        return self._length

    # ── Safety: block accidental disclosure ────────────────────────────

    def __repr__(self) -> str:
        return "<secret>"

    def __str__(self) -> str:
        return "<secret>"

    def __eq__(self, other: object) -> bool:
        """Constant-time comparison to avoid timing oracles."""
        if isinstance(other, SecretBytes):
            import hmac
            return hmac.compare_digest(self.reveal(), other.reveal())
        return NotImplemented

    def __hash__(self):  # type: ignore[override]
        # Intentionally unsupported — secrets must not be dict keys.
        raise TypeError("SecretBytes is not hashable")

    # Prevent JSON serialisation (json.JSONEncoder calls __str__ / __repr__,
    # but custom encoders may call other dunder methods)
    def __reduce__(self):
        raise TypeError("SecretBytes cannot be pickled")

    # ── Lifecycle ───────────────────────────────────────────────────────

    def __del__(self) -> None:
        """Zero the buffer when the object is collected."""
        try:
            ctypes.memset(self._buf, 0, self._length)
        except Exception:  # pragma: no cover — best-effort
            pass
