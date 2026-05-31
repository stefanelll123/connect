"""Unit tests for common.onboarding.token.

Covers:
* Enrollment token creation — structure, unique JTI, nonce length, hash.
* Enrollment token validation — success, wrong key, expired, malformed.
* Migration ticket creation and validation.
* hash_token — determinism and SHA-256 correctness.
* Error codes on every failure path.
"""

from __future__ import annotations

import base64
import hashlib
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from common.crypto.did_key import generate_did_key
from common.onboarding.token import (
    DEFAULT_TOKEN_TTL,
    EnrollmentTokenClaims,
    EnrollmentTokenError,
    MigrationTicketClaims,
    create_enrollment_token,
    create_migration_ticket,
    hash_token,
    validate_enrollment_token,
    validate_migration_ticket,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SENTINEL_ID = "11111111-2222-3333-4444-555555555555"
_SERVICE_ID = "citizen-data-service"


@pytest.fixture(scope="module")
def discovery_keypair():
    return generate_did_key()


@pytest.fixture(scope="module")
def sentinel_keypair():
    return generate_did_key()


# ---------------------------------------------------------------------------
# hash_token
# ---------------------------------------------------------------------------

class TestHashToken:
    def test_deterministic(self) -> None:
        token = "some.jwt.token"
        assert hash_token(token) == hash_token(token)

    def test_correct_sha256(self) -> None:
        token = "test"
        expected = hashlib.sha256(b"test").hexdigest()
        assert hash_token(token) == expected

    def test_hex_encoded(self) -> None:
        result = hash_token("anything")
        assert all(c in "0123456789abcdef" for c in result)
        assert len(result) == 64  # SHA-256 = 32 bytes = 64 hex chars

    def test_different_tokens_different_hashes(self) -> None:
        assert hash_token("token-a") != hash_token("token-b")


# ---------------------------------------------------------------------------
# create_enrollment_token
# ---------------------------------------------------------------------------

class TestCreateEnrollmentToken:
    def test_returns_three_part_jwt(self, discovery_keypair) -> None:
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="prod",
        )
        assert token.count(".") == 2

    def test_unique_jti_each_call(self, discovery_keypair) -> None:
        jtis = set()
        for _ in range(10):
            token = create_enrollment_token(
                discovery_keypair.private_key(),
                issuer_did=discovery_keypair.did,
                kid=discovery_keypair.verification_method_id,
                service_id=_SERVICE_ID,
                role="CONSUMER",
                env="dev",
            )
            claims = validate_enrollment_token(token, discovery_keypair.public_key())
            jtis.add(claims.jti)
        assert len(jtis) == 10, "Each enrollment token must have a unique JTI"

    def test_nonce_is_32_bytes(self, discovery_keypair) -> None:
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="test",
        )
        claims = validate_enrollment_token(token, discovery_keypair.public_key())
        # base64url decode the nonce — must be 32 bytes
        nonce_bytes = base64.urlsafe_b64decode(claims.nonce + "==")
        assert len(nonce_bytes) == 32

    def test_claims_match_inputs(self, discovery_keypair) -> None:
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id="my-service",
            role="CONSUMER",
            env="test",
            required_approval=False,
        )
        claims = validate_enrollment_token(token, discovery_keypair.public_key())
        assert claims.iss == discovery_keypair.did
        assert claims.service_id == "my-service"
        assert claims.role == "CONSUMER"
        assert claims.env == "test"
        assert claims.required_approval is False

    def test_exp_is_approximately_ttl_from_now(self, discovery_keypair) -> None:
        before = int(time.time())
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="dev",
            ttl=300,
        )
        claims = validate_enrollment_token(token, discovery_keypair.public_key())
        after = int(time.time())
        assert before + 300 <= claims.exp <= after + 300

    def test_zero_ttl_raises(self, discovery_keypair) -> None:
        with pytest.raises(ValueError):
            create_enrollment_token(
                discovery_keypair.private_key(),
                issuer_did=discovery_keypair.did,
                kid=discovery_keypair.verification_method_id,
                service_id=_SERVICE_ID,
                role="PRODUCER",
                env="dev",
                ttl=0,
            )

    def test_typ_header_is_enrollment_plus_jwt(self, discovery_keypair) -> None:
        import base64, json
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="dev",
        )
        header_b64 = token.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header.get("typ") == "enrollment+jwt"


# ---------------------------------------------------------------------------
# validate_enrollment_token
# ---------------------------------------------------------------------------

class TestValidateEnrollmentToken:
    def test_valid_token_returns_claims(self, discovery_keypair) -> None:
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="prod",
        )
        claims = validate_enrollment_token(token, discovery_keypair.public_key())
        assert isinstance(claims, EnrollmentTokenClaims)

    def test_wrong_key_raises_invalid(self, discovery_keypair, sentinel_keypair) -> None:
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="prod",
        )
        with pytest.raises(EnrollmentTokenError) as exc_info:
            validate_enrollment_token(token, sentinel_keypair.public_key())
        assert exc_info.value.code == "ENROLLMENT_TOKEN_INVALID"

    def test_expired_token_raises(self, discovery_keypair) -> None:
        # Minimal ttl is 1; we then sleep past it — instead manipulate the payload.
        import base64, json, struct
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="dev",
            ttl=1,
        )
        # The token was just created with exp = now + 1; to test expiry
        # without sleeping we create with a very-past exp via a patched approach:
        # Instead, create with ttl=1 and subtract 5 from iat/exp.
        # Easiest: patch time by creating claims manually with past exp.
        import freezegun
        with freezegun.freeze_time("2020-01-01"):
            past_token = create_enrollment_token(
                discovery_keypair.private_key(),
                issuer_did=discovery_keypair.did,
                kid=discovery_keypair.verification_method_id,
                service_id=_SERVICE_ID,
                role="PRODUCER",
                env="dev",
            )
        with pytest.raises(EnrollmentTokenError) as exc_info:
            validate_enrollment_token(past_token, discovery_keypair.public_key())
        assert exc_info.value.code == "ENROLLMENT_TOKEN_EXPIRED"

    def test_tampered_payload_raises(self, discovery_keypair) -> None:
        import base64, json
        token = create_enrollment_token(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            service_id=_SERVICE_ID,
            role="PRODUCER",
            env="dev",
        )
        header, payload, sig = token.split(".")
        # Tamper with the payload
        decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
        decoded["role"] = "ADMIN"
        tampered = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
        bad_token = f"{header}.{tampered}.{sig}"
        with pytest.raises(EnrollmentTokenError) as exc_info:
            validate_enrollment_token(bad_token, discovery_keypair.public_key())
        assert exc_info.value.code == "ENROLLMENT_TOKEN_INVALID"


# ---------------------------------------------------------------------------
# Migration ticket
# ---------------------------------------------------------------------------

class TestCreateMigrationTicket:
    def test_returns_valid_jwt(self, discovery_keypair) -> None:
        ticket = create_migration_ticket(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            sentinel_id=_SENTINEL_ID,
            sentinel_did="did:key:z6MkSentinelDID",
            reason="VM migration to new data centre",
        )
        assert ticket.count(".") == 2

    def test_claims_match_inputs(self, discovery_keypair) -> None:
        ticket = create_migration_ticket(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            sentinel_id=_SENTINEL_ID,
            sentinel_did="did:key:z6MkSentinelDID",
            reason="Test migration",
        )
        claims = validate_migration_ticket(ticket, discovery_keypair.public_key())
        assert claims.sentinel_id == _SENTINEL_ID
        assert claims.sentinel_did == "did:key:z6MkSentinelDID"
        assert claims.reason == "Test migration"

    def test_validate_wrong_key_raises(self, discovery_keypair, sentinel_keypair) -> None:
        ticket = create_migration_ticket(
            discovery_keypair.private_key(),
            issuer_did=discovery_keypair.did,
            kid=discovery_keypair.verification_method_id,
            sentinel_id=_SENTINEL_ID,
            sentinel_did="did:key:z6MkSentinelDID",
            reason="Test",
        )
        with pytest.raises(EnrollmentTokenError) as exc_info:
            validate_migration_ticket(ticket, sentinel_keypair.public_key())
        assert exc_info.value.code == "ENROLLMENT_TOKEN_INVALID"

    def test_expired_migration_ticket_raises(self, discovery_keypair) -> None:
        import freezegun
        with freezegun.freeze_time("2020-01-01"):
            ticket = create_migration_ticket(
                discovery_keypair.private_key(),
                issuer_did=discovery_keypair.did,
                kid=discovery_keypair.verification_method_id,
                sentinel_id=_SENTINEL_ID,
                sentinel_did="did:key:z6MkSentinelDID",
                reason="Test",
            )
        with pytest.raises(EnrollmentTokenError) as exc_info:
            validate_migration_ticket(ticket, discovery_keypair.public_key())
        assert exc_info.value.code == "ENROLLMENT_TOKEN_EXPIRED"
