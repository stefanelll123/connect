"""Unit tests for common.crypto.did_key.

Tests cover:
* generate_did_key() produces valid did:key DIDs for Ed25519 keys.
* resolve_did_key() round-trips correctly with generated keys.
* DID Document structure matches the did:key v0.7 spec.
* Error handling for malformed or unsupported DID strings.
* DidKeyPair helper methods (JWK serialisation, verification method ID).
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common.crypto.did_key import (
    DIDDocument,
    DidKeyPair,
    generate_did_key,
    resolve_did_key,
)


class TestGenerateDidKey:
    def test_returns_did_key_pair(self) -> None:
        pair = generate_did_key()
        assert isinstance(pair, DidKeyPair)

    def test_did_starts_with_expected_prefix(self) -> None:
        pair = generate_did_key()
        assert pair.did.startswith("did:key:z6Mk"), (
            f"Ed25519 did:key DIDs should start with 'did:key:z6Mk', got: {pair.did}"
        )

    def test_did_contains_multibase_key(self) -> None:
        pair = generate_did_key()
        assert pair.public_key_multibase in pair.did

    def test_private_key_bytes_length(self) -> None:
        pair = generate_did_key()
        assert len(pair.private_key_bytes) == 32

    def test_public_key_bytes_length(self) -> None:
        pair = generate_did_key()
        assert len(pair.public_key_bytes) == 32

    def test_each_call_produces_unique_did(self) -> None:
        dids = {generate_did_key().did for _ in range(10)}
        assert len(dids) == 10, "DIDs must be unique across generations"

    def test_private_key_method_returns_correct_type(self) -> None:
        pair = generate_did_key()
        assert isinstance(pair.private_key(), Ed25519PrivateKey)

    def test_public_key_method_returns_correct_type(self) -> None:
        pair = generate_did_key()
        assert isinstance(pair.public_key(), Ed25519PublicKey)

    def test_verification_method_id_format(self) -> None:
        pair = generate_did_key()
        expected = f"{pair.did}#{pair.public_key_multibase}"
        assert pair.verification_method_id == expected

    def test_public_key_bytes_derivable_from_private(self) -> None:
        pair = generate_did_key()
        derived_pub = pair.private_key().public_key()
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        raw = derived_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
        assert raw == pair.public_key_bytes


class TestDidKeyPairJwk:
    def test_private_jwk_has_required_fields(self) -> None:
        pair = generate_did_key()
        jwk = pair.private_key_jwk()
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk
        assert "d" in jwk
        assert "kid" in jwk

    def test_public_jwk_omits_private_component(self) -> None:
        pair = generate_did_key()
        pub_jwk = pair.public_key_jwk()
        assert "d" not in pub_jwk
        assert pub_jwk["kty"] == "OKP"

    def test_jwk_x_matches_public_key_bytes(self) -> None:
        pair = generate_did_key()
        jwk = pair.public_key_jwk()
        # Decode base64url with padding
        x_decoded = base64.urlsafe_b64decode(jwk["x"] + "==")
        assert x_decoded == pair.public_key_bytes

    def test_jwk_kid_is_verification_method_id(self) -> None:
        pair = generate_did_key()
        assert pair.private_key_jwk()["kid"] == pair.verification_method_id
        assert pair.public_key_jwk()["kid"] == pair.verification_method_id

    def test_jwk_no_padding_in_b64url_fields(self) -> None:
        pair = generate_did_key()
        jwk = pair.private_key_jwk()
        assert "=" not in jwk["x"]
        assert "=" not in jwk["d"]


class TestResolveDidKey:
    def test_round_trip(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        assert isinstance(doc, DIDDocument)
        assert doc.id == pair.did

    def test_verification_method_present(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        assert len(doc.verification_method) == 1
        vm = doc.verification_method[0]
        assert vm["type"] == "Ed25519VerificationKey2020"
        assert vm["controller"] == pair.did
        assert vm["publicKeyMultibase"] == pair.public_key_multibase

    def test_authentication_references_vm(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        assert pair.verification_method_id in doc.authentication

    def test_assertion_method_references_vm(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        assert pair.verification_method_id in doc.assertion_method

    def test_as_dict_has_context(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        d = doc.as_dict()
        assert "@context" in d
        contexts = d["@context"]
        assert any("did/v1" in c for c in contexts)

    def test_as_dict_round_trips_id(self) -> None:
        pair = generate_did_key()
        doc = resolve_did_key(pair.did)
        assert doc.as_dict()["id"] == pair.did


class TestResolveDidKeyErrors:
    def test_raises_for_non_did_key(self) -> None:
        with pytest.raises(ValueError, match="did:key"):
            resolve_did_key("did:ethr:0x1234")

    def test_raises_for_missing_multibase_prefix(self) -> None:
        with pytest.raises(ValueError):
            resolve_did_key("did:key:6MksomethingWithoutZ")

    def test_raises_for_wrong_multicodec_prefix(self) -> None:
        # Craft a did:key with a different multicodec (e.g. secp256k1 = 0xe701)
        # by directly encoding wrong bytes
        from common.crypto.did_key import _base58_encode  # type: ignore[attr-defined]
        wrong_prefix = b"\xe7\x01" + b"\x02" * 33  # secp256k1 compressed pubkey
        encoded = "z" + _base58_encode(wrong_prefix)
        bad_did = f"did:key:{encoded}"
        with pytest.raises(ValueError, match="Ed25519"):
            resolve_did_key(bad_did)

    def test_raises_for_empty_string(self) -> None:
        with pytest.raises(ValueError):
            resolve_did_key("")

    def test_raises_for_wrong_public_key_length(self) -> None:
        from common.crypto.did_key import _base58_encode  # type: ignore[attr-defined]
        # Ed25519 multicodec prefix + only 16 bytes (too short)
        bad_bytes = b"\xed\x01" + b"\x00" * 16
        encoded = "z" + _base58_encode(bad_bytes)
        bad_did = f"did:key:{encoded}"
        with pytest.raises(ValueError, match="32 bytes"):
            resolve_did_key(bad_did)
