"""DID resolver with did:key local derivation and LRU cache (TASK-041)."""
from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from common.vc_engine.errors import VCError, VCErrorCode

# Multicodec prefix for Ed25519 (varint 0xed01)
_ED25519_CODEC = bytes([0xed, 0x01])
_LRU_MAX = 512
_LRU_TTL = 300.0  # seconds


# ---------------------------------------------------------------------------
# DID Document dataclass
# ---------------------------------------------------------------------------

@dataclass
class VerificationMethod:
    id: str
    type: str
    controller: str
    public_key_bytes: bytes  # raw 32-byte Ed25519 public key

    def public_key_jwk(self) -> dict:
        x_b64 = base64.urlsafe_b64encode(self.public_key_bytes).rstrip(b"=").decode()
        return {"kty": "OKP", "crv": "Ed25519", "x": x_b64}


@dataclass
class DIDDocument:
    id: str
    verification_method: list[VerificationMethod] = field(default_factory=list)

    @property
    def first_verification_method(self) -> Optional[VerificationMethod]:
        return self.verification_method[0] if self.verification_method else None


# ---------------------------------------------------------------------------
# Base58btc helpers (shared with key_manager — duplicated to avoid coupling)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        if ch not in _B58_ALPHABET:
            raise ValueError(f"Invalid base58btc character: {ch!r}")
        n = n * 58 + _B58_ALPHABET.index(ch)
    # convert to bytes
    result = n.to_bytes(max((n.bit_length() + 7) // 8, 1), "big")
    # leading '1' chars represent leading zero bytes (count LEADING only)
    pad = 0
    for c in s:
        if c == _B58_ALPHABET[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + result


# ---------------------------------------------------------------------------
# LRU cache
# ---------------------------------------------------------------------------

class _LRUCache:
    def __init__(self, max_size: int = _LRU_MAX, ttl: float = _LRU_TTL) -> None:
        self._store: dict[str, tuple[DIDDocument, float]] = {}
        self._max = max_size
        self._ttl = ttl

    def get(self, key: str) -> Optional[DIDDocument]:
        entry = self._store.get(key)
        if entry is None:
            return None
        doc, ts = entry
        if time.time() - ts > self._ttl:
            del self._store[key]
            return None
        # Move to end (LRU update)
        self._store.pop(key)
        self._store[key] = (doc, ts)
        return doc

    def put(self, key: str, doc: DIDDocument) -> None:
        if key in self._store:
            self._store.pop(key)
        elif len(self._store) >= self._max:
            # Evict oldest
            oldest = next(iter(self._store))
            del self._store[oldest]
        self._store[key] = (doc, time.time())


# ---------------------------------------------------------------------------
# DIDResolver
# ---------------------------------------------------------------------------

class DIDResolver:
    """Resolves DIDs to DIDDocuments.

    Supports:
    - ``did:key`` — local derivation, no network required.
    - ``did:ethr`` — optional, via injected chain_client.
    """

    def __init__(self, chain_client: Any = None) -> None:
        self._chain_client = chain_client
        self._cache = _LRUCache()

    async def resolve(self, did: str) -> DIDDocument:
        """Resolve a DID to a DIDDocument.

        Raises:
            VCError(DID_UNRESOLVABLE): if the DID cannot be resolved.
        """
        cached = self._cache.get(did)
        if cached is not None:
            return cached

        try:
            if did.startswith("did:key:"):
                doc = self._resolve_did_key(did)
            elif did.startswith("did:ethr:"):
                doc = await self._resolve_did_ethr(did)
            else:
                raise VCError(VCErrorCode.DID_UNRESOLVABLE, f"Unsupported DID method: {did!r}")
        except VCError:
            raise
        except Exception as exc:
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, str(exc)) from exc

        self._cache.put(did, doc)
        return doc

    def _resolve_did_key(self, did: str) -> DIDDocument:
        if not did.startswith("did:key:z"):
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, f"Invalid did:key format: {did!r}")
        encoded = did[len("did:key:z"):]
        try:
            decoded = _b58_decode(encoded)
        except ValueError as exc:
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, f"Base58 decode error: {exc}") from exc

        if decoded[:2] != _ED25519_CODEC:
            raise VCError(
                VCErrorCode.DID_UNRESOLVABLE,
                f"Unsupported key type prefix {decoded[:2].hex()!r}; expected 'ed01'",
            )
        pub_key_bytes = decoded[2:]
        if len(pub_key_bytes) != 32:
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, "Ed25519 public key must be 32 bytes")

        vm = VerificationMethod(
            id=f"{did}#{did[8:]}",
            type="Ed25519VerificationKey2020",
            controller=did,
            public_key_bytes=pub_key_bytes,
        )
        return DIDDocument(id=did, verification_method=[vm])

    async def _resolve_did_ethr(self, did: str) -> DIDDocument:
        if self._chain_client is None:
            raise VCError(VCErrorCode.DID_UNRESOLVABLE, "did:ethr requires chain client")
        # Delegate to injected chain client
        doc_data = await self._chain_client.get_did_document(did)
        pub_key_bytes = bytes.fromhex(doc_data.get("publicKeyHex", ""))
        vm = VerificationMethod(
            id=f"{did}#controller",
            type="EcdsaSecp256k1VerificationKey2019",
            controller=did,
            public_key_bytes=pub_key_bytes,
        )
        return DIDDocument(id=did, verification_method=[vm])
