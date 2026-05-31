"""DID and Key Lifecycle Management for the Sentinel (TASK-039).

Supports:
- Ed25519 key generation
- did:key DID derivation (multibase base58btc, multicodec 0xed01)
- Loading and integrity validation (manifest DID must match re-derived DID)
- Proof-of-Possession signing (sign_pop) and verification (verify_pop)
- Manifest read/write (sentinel.json)
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Optional

from sentinel.wallet.secret_bytes import SecretBytes

logger = logging.getLogger(__name__)

# Multicodec prefix for Ed25519 public key (varint-encoded 0xed01)
_ED25519_MULTICODEC = bytes([0xed, 0x01])
_MANIFEST_FILENAME = "sentinel.json"
_KEY_FILENAME = "did_private_key_v{version}.enc"


# ---------------------------------------------------------------------------
# DID derivation helpers
# ---------------------------------------------------------------------------

def _base58btc_encode(data: bytes) -> str:
    """Minimal base58 encoding (Bitcoin alphabet)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(alphabet[r])
    # leading zero bytes → leading '1'
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    return "".join(reversed(result))


def _base58btc_decode(s: str) -> bytes:
    """Minimal base58 decoding (Bitcoin alphabet)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for char in s:
        n = n * 58 + alphabet.index(char)
    result = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    # re-add leading zeros
    pad = 0
    for char in s:
        if char == alphabet[0]:
            pad += 1
        else:
            break
    return b"\x00" * pad + result


def derive_did_key(public_key_bytes: bytes) -> str:
    """Derive a did:key DID from raw 32-byte Ed25519 public key bytes."""
    prefixed = _ED25519_MULTICODEC + public_key_bytes
    encoded = _base58btc_encode(prefixed)
    return f"did:key:z{encoded}"


def resolve_did_key_public_key(did: str) -> bytes:
    """Extract raw 32-byte Ed25519 public key bytes from a did:key DID."""
    if not did.startswith("did:key:z"):
        raise ValueError(f"Not a did:key DID: {did!r}")
    encoded = did[len("did:key:z"):]
    decoded = _base58btc_decode(encoded)
    if decoded[:2] != _ED25519_MULTICODEC:
        raise ValueError(f"Not an Ed25519 did:key (expected prefix 0xed01): {did!r}")
    return decoded[2:]


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair.

    Returns:
        (private_key_bytes_32, public_key_bytes_32)
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    privkey = Ed25519PrivateKey.generate()
    private_bytes = privkey.private_bytes_raw()
    public_bytes = privkey.public_key().public_bytes_raw()
    return private_bytes, public_bytes


# ---------------------------------------------------------------------------
# Proof-of-Possession
# ---------------------------------------------------------------------------

def _pop_payload_bytes(did: str, challenge_nonce: str, token_jti: str, iat: int | None = None) -> bytes:
    """Canonical JSON (sorted keys) for PoP signing.

    Must match the serialisation used by Discovery's verify_pop:
    json.dumps(..., sort_keys=True) — no custom separators.
    """
    payload = {
        "challenge_nonce": challenge_nonce,
        "did": did,
        "iat": iat if iat is not None else int(time.time()),
        "jti": token_jti,
    }
    return json.dumps(payload, sort_keys=True).encode()


def sign_pop(
    private_key_bytes: bytes,
    did: str,
    challenge_nonce: str,
    token_jti: str,
    iat: int | None = None,
) -> str:
    """Sign a Proof-of-Possession over the onboarding challenge payload.

    Returns:
        base64url-encoded 64-byte Ed25519 signature.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    privkey = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    payload = _pop_payload_bytes(did, challenge_nonce, token_jti, iat=iat)
    signature = privkey.sign(payload)
    return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()


def verify_pop(
    did: str,
    challenge_nonce: str,
    token_jti: str,
    signature_b64url: str,
) -> bool:
    """Verify an Ed25519 PoP signature.  Resolves the public key from the DID.

    Returns:
        True if the signature is valid, False otherwise.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pub_bytes = resolve_did_key_public_key(did)
        pubkey = Ed25519PublicKey.from_public_bytes(pub_bytes)
        padded = signature_b64url + "=" * (4 - len(signature_b64url) % 4)
        signature = base64.urlsafe_b64decode(padded)
        payload = _pop_payload_bytes(did, challenge_nonce, token_jti)
        pubkey.verify(signature, payload)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------

class SentinelManifest:
    """Parsed sentinel.json manifest."""

    def __init__(self, data: dict) -> None:
        self.sentinel_id: str = data["sentinel_id"]
        self.did: str = data["did"]
        self.service_id: str = data.get("service_id", "")
        self.role: str = data.get("role", "producer")
        self.env: str = data.get("env", "dev")
        self.key_version: int = int(data.get("key_version", 1))
        self.generated_at: float = float(data.get("generated_at", 0.0))
        self.previous_did: Optional[str] = data.get("previous_did")
        self.grace_until: Optional[float] = data.get("grace_until")
        self.rotation_started_at: Optional[float] = data.get("rotation_started_at")
        self._raw = data

    def to_dict(self) -> dict:
        d = {
            "sentinel_id": self.sentinel_id,
            "did": self.did,
            "service_id": self.service_id,
            "role": self.role,
            "env": self.env,
            "key_version": self.key_version,
            "generated_at": self.generated_at,
        }
        if self.previous_did is not None:
            d["previous_did"] = self.previous_did
        if self.grace_until is not None:
            d["grace_until"] = self.grace_until
        if self.rotation_started_at is not None:
            d["rotation_started_at"] = self.rotation_started_at
        return d


def _manifest_path(store_dir: Path) -> Path:
    return store_dir / _MANIFEST_FILENAME


def load_manifest(store_dir: Path) -> SentinelManifest:
    path = _manifest_path(store_dir)
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")
    return SentinelManifest(json.loads(path.read_text()))


def save_manifest(store_dir: Path, manifest: SentinelManifest) -> None:
    path = _manifest_path(store_dir)
    path.write_text(json.dumps(manifest.to_dict(), indent=2))
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


# ---------------------------------------------------------------------------
# Encrypted key storage helpers
# ---------------------------------------------------------------------------

def _key_path(store_dir: Path, version: int) -> Path:
    return store_dir / _KEY_FILENAME.format(version=version)


def _encrypt_key(private_key_bytes: bytes, passphrase: bytes) -> bytes:
    """Encrypt private key bytes with AES-256-GCM using scrypt-derived key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    aes_key = kdf.derive(passphrase)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
    # Format: 16-byte salt | 12-byte nonce | ciphertext+tag
    return salt + nonce + ciphertext


def _decrypt_key(blob: bytes, passphrase: bytes) -> bytes:
    """Decrypt private key blob produced by ``_encrypt_key``."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    salt = blob[:16]
    nonce = blob[16:28]
    ciphertext = blob[28:]
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    aes_key = kdf.derive(passphrase)
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Wallet: high-level key lifecycle
# ---------------------------------------------------------------------------

class Wallet:
    """Manages the sentinel's Ed25519 key and DID identity.

    Usage::

        wallet = Wallet(store_dir=Path("/var/sentinel/store"))
        wallet.load(passphrase=b"secret")
        sig = wallet.sign_pop(challenge_nonce="abc", token_jti="xyz")
    """

    def __init__(self, store_dir: Path) -> None:
        self._store_dir = store_dir
        self._private_key: Optional[SecretBytes] = None
        self._manifest: Optional[SentinelManifest] = None

    @property
    def did(self) -> str:
        if self._manifest is None:
            raise RuntimeError("Wallet not loaded — call load() first")
        return self._manifest.did

    @property
    def manifest(self) -> SentinelManifest:
        if self._manifest is None:
            raise RuntimeError("Wallet not loaded — call load() first")
        return self._manifest

    @property
    def is_loaded(self) -> bool:
        return self._private_key is not None and self._manifest is not None

    def init(
        self,
        service_id: str,
        role: str,
        env: str,
        passphrase: bytes,
    ) -> SentinelManifest:
        """Generate a new keypair, derive DID, encrypt and store.

        Raises:
            FileExistsError: if a key already exists (idempotent protection).
        """
        key_path = _key_path(self._store_dir, 1)
        if key_path.exists():
            raise FileExistsError(
                f"Key already exists at {key_path}. Use rotate-key to rotate."
            )

        self._store_dir.mkdir(parents=True, exist_ok=True)
        private_bytes, public_bytes = generate_ed25519_keypair()
        did = derive_did_key(public_bytes)

        blob = _encrypt_key(private_bytes, passphrase)
        key_path.write_bytes(blob)
        try:
            os.chmod(key_path, 0o600)
        except (OSError, NotImplementedError):
            pass

        manifest = SentinelManifest({
            "sentinel_id": str(uuid.uuid4()),
            "did": did,
            "service_id": service_id,
            "role": role,
            "env": env,
            "key_version": 1,
            "generated_at": time.time(),
        })
        save_manifest(self._store_dir, manifest)
        logger.info("Wallet initialised DID=%s...", did[:20])
        return manifest

    def load(self, passphrase: bytes) -> None:
        """Load and validate the wallet from disk.

        Raises:
            FileNotFoundError: if manifest or key not found.
            ValueError: if key → DID mismatch (corruption).
        """
        manifest = load_manifest(self._store_dir)
        key_path = _key_path(self._store_dir, manifest.key_version)
        if not key_path.exists():
            raise FileNotFoundError(f"Key file not found: {key_path}")

        blob = key_path.read_bytes()
        private_bytes = _decrypt_key(blob, passphrase)

        # Integrity check: re-derive DID from loaded key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        privkey = Ed25519PrivateKey.from_private_bytes(private_bytes)
        derived_did = derive_did_key(privkey.public_key().public_bytes_raw())
        if derived_did != manifest.did:
            raise ValueError(
                f"DID mismatch: manifest has {manifest.did[:20]}..., "
                f"key derives {derived_did[:20]}... — key or manifest is corrupted"
            )

        self._private_key = SecretBytes(private_bytes)
        self._manifest = manifest
        logger.info("DID loaded: %s...", manifest.did[:20])

    def sign_pop(self, challenge_nonce: str, token_jti: str, iat: int | None = None) -> str:
        """Sign a Proof-of-Possession.  Returns base64url-encoded signature."""
        if self._private_key is None:
            raise RuntimeError("Wallet not loaded")
        return sign_pop(self._private_key.reveal(), self.did, challenge_nonce, token_jti, iat=iat)

    def sign_renewal_assertion(self, sentinel_id: str, iat: int) -> str:
        """Sign a time-bound renewal assertion (no challenge nonce needed).

        Payload: {action, did, iat, sentinel_id} — sorted keys canonical JSON.
        Returns base58btc multibase-encoded signature (z-prefix).
        """
        if self._private_key is None:
            raise RuntimeError("Wallet not loaded")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        payload = json.dumps({
            "action": "sentinel_auth_renew",
            "did": self.did,
            "iat": iat,
            "sentinel_id": sentinel_id,
        }, sort_keys=True).encode()
        privkey = Ed25519PrivateKey.from_private_bytes(self._private_key.reveal())
        signature_bytes = privkey.sign(payload)
        return "z" + _base58btc_encode(signature_bytes)

    def verify_pop(
        self,
        pop_payload_did: str,
        challenge_nonce: str,
        token_jti: str,
        signature_b64url: str,
    ) -> bool:
        """Verify a PoP signature against the DID's public key."""
        return verify_pop(pop_payload_did, challenge_nonce, token_jti, signature_b64url)

    def accept_did_for_verification(self, did: str) -> bool:
        """Return True if *did* should be accepted during grace window after rotation."""
        if self._manifest is None:
            return False
        if did == self._manifest.did:
            return True
        # During grace window, also accept the previous DID
        if (
            self._manifest.previous_did == did
            and self._manifest.grace_until is not None
            and time.time() < self._manifest.grace_until
        ):
            return True
        return False
