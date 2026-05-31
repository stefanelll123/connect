"""did:key DID method implementation for Ed25519 keys.

Implements:
* Generation of a new Ed25519 key pair and derivation of the corresponding
  ``did:key`` DID.
* Resolution of a ``did:key`` DID string back to a minimal DID Document.

Format
------
A did:key identifier is constructed as follows::

    did:key:z<base58btc(multicodec_prefix || raw_public_key_bytes)>

For Ed25519 the multicodec prefix is ``0xed01`` (varint-encoded).  The
``z`` prefix character indicates the ``base58btc`` multibase encoding.

Example::

    did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK

References
----------
* W3C DID Core v1.0 — https://www.w3.org/TR/did-core/
* did:key method v0.7 — https://w3c-ccg.github.io/did-method-key/
* Multicodec — https://github.com/multiformats/multicodec
* Multibase — https://github.com/multiformats/multibase
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

__all__ = [
    "DidKeyPair",
    "DIDDocument",
    "did_key_to_public_key",
    "did_key_to_raw_public_bytes",
    "generate_did_key",
    "resolve_did_key",
]

# ---------------------------------------------------------------------------
# Multicodec / multibase constants
# ---------------------------------------------------------------------------

# Multicodec varint prefix for Ed25519 public key: 0xed 0x01
_ED25519_MULTICODEC_PREFIX: bytes = b"\xed\x01"

# Multibase prefix character for base58btc
_MULTIBASE_BASE58BTC_PREFIX: str = "z"

# ---------------------------------------------------------------------------
# Base-58 alphabet (Bitcoin / IPFS convention)
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode *data* using the Bitcoin/IPFS Base58Check alphabet (no check)."""
    # Count leading zero bytes
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break

    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(_BASE58_ALPHABET[remainder])

    return ("1" * count) + "".join(reversed(result))


def _base58_decode(text: str) -> bytes:
    """Decode a Base58 string back to bytes."""
    count = 0
    for ch in text:
        if ch == "1":
            count += 1
        else:
            break

    n = 0
    for ch in text:
        n = n * 58 + _BASE58_ALPHABET.index(ch)

    result = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return (b"\x00" * count) + result


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DidKeyPair:
    """An Ed25519 key pair with the derived did:key DID.

    Attributes
    ----------
    did:
        The ``did:key`` DID string.
    public_key_multibase:
        The multibase-encoded public key (the fragment after ``did:key:``).
    private_key_bytes:
        Raw 32-byte Ed25519 private (seed) bytes.  Store securely — never log.
    public_key_bytes:
        Raw 32-byte Ed25519 public key bytes.
    """

    did: str
    public_key_multibase: str
    private_key_bytes: bytes
    public_key_bytes: bytes

    @property
    def verification_method_id(self) -> str:
        """Full verification method identifier (DID + fragment)."""
        return f"{self.did}#{self.public_key_multibase}"

    def private_key(self) -> Ed25519PrivateKey:
        """Return the :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`."""
        return Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)

    def public_key(self) -> Ed25519PublicKey:
        """Return the :class:`~cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey`."""
        return self.private_key().public_key()

    def private_key_jwk(self) -> dict[str, str]:
        """Serialize the key pair as an Ed25519 JWK (``"kty": "OKP"``)."""
        raw_private = self.private_key_bytes
        raw_public = self.public_key_bytes
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode(),
            "d": base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode(),
            "kid": self.verification_method_id,
        }

    def public_key_jwk(self) -> dict[str, str]:
        """Serialize only the public portion as a JWK."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(self.public_key_bytes).rstrip(b"=").decode(),
            "kid": self.verification_method_id,
        }


@dataclass
class DIDDocument:
    """Minimal W3C DID Document for a did:key DID.

    Attributes
    ----------
    id:
        The DID string.
    verification_method:
        List with the single :class:`VerificationMethod` entry.
    authentication:
        Reference list (verification method IDs for authentication).
    assertion_method:
        Reference list (verification method IDs for assertion).
    """

    id: str
    verification_method: list[dict[str, str]] = field(default_factory=list)
    authentication: list[str] = field(default_factory=list)
    assertion_method: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:  # type: ignore[type-arg]
        """Return a JSON-serialisable representation."""
        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/ed25519-2020/v1",
            ],
            "id": self.id,
            "verificationMethod": self.verification_method,
            "authentication": self.authentication,
            "assertionMethod": self.assertion_method,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_did_key() -> DidKeyPair:
    """Generate a new Ed25519 key pair and derive its ``did:key`` DID.

    Returns
    -------
    DidKeyPair
        A frozen dataclass carrying the DID, multibase-encoded public key,
        and both raw key byte strings.  The private key bytes are sensitive
        and must be stored securely (see TASK-008 secret storage).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    multicodec_bytes = _ED25519_MULTICODEC_PREFIX + public_bytes
    multibase_key = _MULTIBASE_BASE58BTC_PREFIX + _base58_encode(multicodec_bytes)
    did = f"did:key:{multibase_key}"

    return DidKeyPair(
        did=did,
        public_key_multibase=multibase_key,
        private_key_bytes=private_bytes,
        public_key_bytes=public_bytes,
    )


def resolve_did_key(did: str) -> DIDDocument:
    """Resolve a ``did:key`` DID string to a minimal DID Document.

    Parameters
    ----------
    did:
        A ``did:key:z<base58btc>`` string.

    Returns
    -------
    DIDDocument
        The resolved DID document with a single Ed25519VerificationKey2020
        verification method.

    Raises
    ------
    ValueError
        If *did* does not start with ``did:key:z`` or the encoded public key
        does not carry the Ed25519 multicodec prefix.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID — expected did:key:z..., got: {did!r}")

    multibase_key = did.removeprefix("did:key:")
    if not multibase_key.startswith(_MULTIBASE_BASE58BTC_PREFIX):
        raise ValueError(
            f"Unsupported multibase encoding in {did!r}. "
            "Only base58btc ('z' prefix) is supported."
        )

    encoded = multibase_key[1:]  # strip 'z'
    multicodec_bytes = _base58_decode(encoded)

    if not multicodec_bytes.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError(
            f"DID {did!r} does not encode an Ed25519 key "
            f"(expected multicodec prefix {_ED25519_MULTICODEC_PREFIX.hex()})."
        )

    # Strip 2-byte multicodec prefix to get raw 32-byte public key
    raw_public = multicodec_bytes[len(_ED25519_MULTICODEC_PREFIX):]
    if len(raw_public) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(raw_public)}."
        )

    vm_id = f"{did}#{multibase_key}"
    vm = {
        "id": vm_id,
        "type": "Ed25519VerificationKey2020",
        "controller": did,
        "publicKeyMultibase": multibase_key,
    }

    return DIDDocument(
        id=did,
        verification_method=[vm],
        authentication=[vm_id],
        assertion_method=[vm_id],
    )


def did_key_to_public_key(did: str) -> Ed25519PublicKey:
    """Decode a ``did:key`` DID string and return its :class:`Ed25519PublicKey`.

    Parameters
    ----------
    did:
        A ``did:key:z<base58btc>`` string encoding an Ed25519 public key.

    Returns
    -------
    Ed25519PublicKey
        The raw Ed25519 public key embedded in the DID.

    Raises
    ------
    ValueError
        If *did* is not a valid Ed25519 ``did:key`` DID.
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Unsupported DID — expected did:key:z..., got: {did!r}")

    multibase_key = did.removeprefix("did:key:")
    encoded = multibase_key[1:]  # strip 'z' multibase prefix
    multicodec_bytes = _base58_decode(encoded)

    if not multicodec_bytes.startswith(_ED25519_MULTICODEC_PREFIX):
        raise ValueError(
            f"DID {did!r} does not encode an Ed25519 key "
            f"(expected multicodec prefix {_ED25519_MULTICODEC_PREFIX.hex()})."
        )

    raw_public = multicodec_bytes[len(_ED25519_MULTICODEC_PREFIX):]
    if len(raw_public) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(raw_public)}."
        )
    return Ed25519PublicKey.from_public_bytes(raw_public)


def did_key_to_raw_public_bytes(did: str) -> bytes:
    """Decode a ``did:key`` DID and return the raw 32-byte Ed25519 public key.

    Unlike :func:`did_key_to_public_key` this returns plain bytes suitable
    for embedding in a ``cnf.jwk`` or other byte-level operations.

    Parameters
    ----------
    did:
        A ``did:key:z<base58btc>`` string encoding an Ed25519 public key.

    Returns
    -------
    bytes
        Raw 32-byte Ed25519 public key.

    Raises
    ------
    ValueError
        If *did* is not a valid Ed25519 ``did:key`` DID.
    """
    pub_key = did_key_to_public_key(did)
    return pub_key.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
