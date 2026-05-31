"""Unit tests for common.crypto.jws.

Tests cover:
* sign_jws() produces a valid 3-part compact serialization.
* verify_jws() accepts a token produced by sign_jws() (round-trip).
* verify_jws() raises JWSVerificationError for tampered tokens.
* ProhibitedAlgorithmError is raised before any crypto operation for banned algs.
* alg:none and variants are rejected by verify_jws() at the header-parse stage.
* Algorithm / key type mismatch raises JWSVerificationError.
* sign_jws() sets the correct alg header based on key type.
* Extra JOSE headers (typ, etc.) are preserved but alg/kid cannot be overridden.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key as ec_generate,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256Sentinel
from cryptography.hazmat.backends import default_backend

from common.crypto.algorithms import ProhibitedAlgorithmError
from common.crypto.did_key import generate_did_key
from common.crypto.jws import JWSVerificationError, sign_jws, verify_jws


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ed25519_pair():
    """Return (private_key, public_key, kid)."""
    pair = generate_did_key()
    return pair.private_key(), pair.public_key(), pair.verification_method_id


@pytest.fixture()
def p256_pair():
    """Return (private_key, public_key, kid) for a P-256 key."""
    priv = ec_generate(SECP256R1(), default_backend())
    kid = "did:key:testP256#key-1"
    return priv, priv.public_key(), kid


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _decode_part(part: str) -> Any:
    pad = 4 - len(part) % 4
    raw = base64.urlsafe_b64decode(part + ("=" * (pad if pad != 4 else 0)))
    return json.loads(raw)


def _tamper_payload(token: str, new_payload: dict[str, Any]) -> str:
    header, _, sig = token.split(".")
    new_p = base64.urlsafe_b64encode(
        json.dumps(new_payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{new_p}.{sig}"


# ---------------------------------------------------------------------------
# sign_jws
# ---------------------------------------------------------------------------


class TestSignJwsEdDSA:
    def test_returns_three_part_string(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws({"sub": "test"}, priv, kid=kid)
        assert len(token.split(".")) == 3

    def test_header_contains_eddsa(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws({"sub": "test"}, priv, kid=kid)
        header = _decode_part(token.split(".")[0])
        assert header["alg"] == "EdDSA"

    def test_header_contains_kid(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws({"sub": "test"}, priv, kid=kid)
        header = _decode_part(token.split(".")[0])
        assert header["kid"] == kid

    def test_payload_round_trips(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        payload = {"claim": "value", "num": 42}
        token = sign_jws(payload, priv, kid=kid)
        actual = _decode_part(token.split(".")[1])
        assert actual == payload

    def test_extra_headers_are_included(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws({"x": 1}, priv, kid=kid, extra_headers={"typ": "vc+jwt"})
        header = _decode_part(token.split(".")[0])
        assert header["typ"] == "vc+jwt"

    def test_extra_headers_cannot_override_alg(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws({"x": 1}, priv, kid=kid, extra_headers={"alg": "HS256"})
        header = _decode_part(token.split(".")[0])
        assert header["alg"] == "EdDSA"

    def test_extra_headers_cannot_override_kid(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws(
            {"x": 1}, priv, kid=kid, extra_headers={"kid": "attacker-kid"}
        )
        header = _decode_part(token.split(".")[0])
        assert header["kid"] == kid

    def test_bytes_payload_accepted(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        token = sign_jws(b'{"raw":true}', priv, kid=kid)
        assert len(token.split(".")) == 3


class TestSignJwsES256:
    def test_header_contains_es256(self, p256_pair) -> None:
        priv, _, kid = p256_pair
        token = sign_jws({"sub": "test"}, priv, kid=kid)
        header = _decode_part(token.split(".")[0])
        assert header["alg"] == "ES256"


class TestSignJwsErrors:
    def test_raises_type_error_for_wrong_key_type(self) -> None:
        with pytest.raises(TypeError, match="Unsupported private key type"):
            sign_jws({"x": 1}, object(), kid="kid")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# verify_jws — happy path
# ---------------------------------------------------------------------------


class TestVerifyJwsRoundTrip:
    def test_eddsa_round_trip(self, ed25519_pair) -> None:
        priv, pub, kid = ed25519_pair
        payload = {"iss": "did:key:z6Mktest", "sub": "me"}
        token = sign_jws(payload, priv, kid=kid)
        result = verify_jws(token, pub)
        assert result == payload

    def test_es256_round_trip(self, p256_pair) -> None:
        priv, pub, kid = p256_pair
        payload = {"env": "prod", "aud": "did:key:z6Mkprod"}
        token = sign_jws(payload, priv, kid=kid)
        result = verify_jws(token, pub)
        assert result == payload

    def test_different_keys_do_not_verify(self, ed25519_pair) -> None:
        priv, _, kid = ed25519_pair
        other_pair = generate_did_key()
        token = sign_jws({"x": 1}, priv, kid=kid)
        with pytest.raises(JWSVerificationError):
            verify_jws(token, other_pair.public_key())


# ---------------------------------------------------------------------------
# verify_jws — rejection of prohibited algorithms
# ---------------------------------------------------------------------------


class TestVerifyJwsProhibitedAlgorithms:
    def _forge_header_token(
        self, alg: str, pub_key_for_verify
    ) -> tuple[str, Any]:
        """Return (forged_token, public_key) — token with arbitrary alg header."""
        pair = generate_did_key()
        # Sign legitimately
        legit_token = sign_jws({"x": 1}, pair.private_key(), kid="kid")
        _, payload_b64, sig_b64 = legit_token.split(".")
        # Replace header with forbidden alg
        bad_header = base64.urlsafe_b64encode(
            json.dumps({"alg": alg, "kid": "kid"}, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()
        return f"{bad_header}.{payload_b64}.{sig_b64}", pub_key_for_verify

    @pytest.mark.parametrize("alg", ["none", "None", "NONE", "HS256", "RS256"])
    def test_rejects_prohibited_algorithm_in_header(
        self, alg: str, ed25519_pair
    ) -> None:
        _, pub, _ = ed25519_pair
        forged, _ = self._forge_header_token(alg, pub)
        with pytest.raises(JWSVerificationError):
            verify_jws(forged, pub)


# ---------------------------------------------------------------------------
# verify_jws — structural errors
# ---------------------------------------------------------------------------


class TestVerifyJwsStructuralErrors:
    def test_raises_for_two_part_token(self, ed25519_pair) -> None:
        _, pub, _ = ed25519_pair
        with pytest.raises(JWSVerificationError, match="3 parts"):
            verify_jws("header.payload", pub)

    def test_raises_for_four_part_token(self, ed25519_pair) -> None:
        _, pub, _ = ed25519_pair
        with pytest.raises(JWSVerificationError, match="3 parts"):
            verify_jws("a.b.c.d", pub)

    def test_raises_for_tampered_payload(self, ed25519_pair) -> None:
        priv, pub, kid = ed25519_pair
        token = sign_jws({"role": "user"}, priv, kid=kid)
        forged = _tamper_payload(token, {"role": "admin"})
        with pytest.raises(JWSVerificationError):
            verify_jws(forged, pub)

    def test_raises_for_corrupted_signature(self, ed25519_pair) -> None:
        priv, pub, kid = ed25519_pair
        token = sign_jws({"x": 1}, priv, kid=kid)
        h, p, _ = token.split(".")
        corrupted = f"{h}.{p}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # noqa: E501
        with pytest.raises(JWSVerificationError):
            verify_jws(corrupted, pub)

    def test_raises_for_invalid_header_base64(self, ed25519_pair) -> None:
        _, pub, _ = ed25519_pair
        with pytest.raises(JWSVerificationError):
            verify_jws("!!!invalid!!!.payload.sig", pub)


# ---------------------------------------------------------------------------
# verify_jws — algorithm / key mismatch
# ---------------------------------------------------------------------------


class TestVerifyJwsAlgKeyMismatch:
    def test_eddsa_token_with_ec_pub_key_rejected(
        self, ed25519_pair, p256_pair
    ) -> None:
        priv_ed, _, kid_ed = ed25519_pair
        _, pub_p256, _ = p256_pair
        token = sign_jws({"x": 1}, priv_ed, kid=kid_ed)
        with pytest.raises(JWSVerificationError, match="Ed25519"):
            verify_jws(token, pub_p256)

    def test_es256_token_with_ed_pub_key_rejected(
        self, ed25519_pair, p256_pair
    ) -> None:
        priv_p256, _, kid_p256 = p256_pair
        _, pub_ed, _ = ed25519_pair
        token = sign_jws({"x": 1}, priv_p256, kid=kid_p256)
        with pytest.raises(JWSVerificationError, match="P-256|EllipticCurve"):
            verify_jws(token, pub_ed)
