"""Unit tests for common.proof.verifier."""

from __future__ import annotations

import pytest

from common.crypto.did_key import generate_did_key
from common.proof.builder import build_proof, build_req_binding
from common.proof.hash_utils import hash_bytes
from common.proof.models import ProofClaims
from common.proof.replay_cache import InMemoryReplayCache
from common.proof.verifier import ProofVerificationError, VerificationConfig, verify_proof


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def consumer_kp():
    return generate_did_key()


@pytest.fixture(scope="module")
def producer_kp():
    return generate_did_key()


@pytest.fixture(scope="module")
def simple_req():
    return build_req_binding(method="GET", path="/api/v1/resource")


def _make_proof(consumer_kp, producer_kp, req=None, env="test", ttl=30, nonce=None):
    """Helper: build a fresh proof (unique jti each call)."""
    if req is None:
        req = build_req_binding(method="GET", path="/api/v1/resource")
    return build_proof(
        consumer_kp.private_key(),
        consumer_did=consumer_kp.did,
        kid=consumer_kp.verification_method_id,
        producer_did=producer_kp.did,
        env=env,
        req=req,
        ttl=ttl,
        nonce=nonce,
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestVerifyProofSuccess:
    def test_valid_proof_returns_claims(
        self, consumer_kp, producer_kp, simple_req
    ) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
        claims = verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            body=b"",
            replay_cache=InMemoryReplayCache(),
        )
        assert isinstance(claims, ProofClaims)
        assert claims.iss == consumer_kp.did
        assert claims.aud == producer_kp.did
        assert claims.env == "test"

    def test_post_proof_with_body(self, consumer_kp, producer_kp) -> None:
        body = b'{"key": "value"}'
        req = build_req_binding(
            method="POST",
            path="/api/v1/data",
            body=body,
            content_type="application/json",
        )
        proof = _make_proof(consumer_kp, producer_kp, req=req)
        claims = verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            body=body,
            replay_cache=InMemoryReplayCache(),
        )
        assert claims.req.method == "POST"

    def test_returns_frozen_claims(self, consumer_kp, producer_kp) -> None:
        proof = _make_proof(consumer_kp, producer_kp)
        claims = verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            replay_cache=InMemoryReplayCache(),
        )
        with pytest.raises(Exception):
            claims.iss = "did:key:z6Mkother"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Signature errors
# ---------------------------------------------------------------------------


class TestSignatureErrors:
    def test_wrong_public_key_rejected(self, consumer_kp, producer_kp, simple_req) -> None:
        other_kp = generate_did_key()
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                other_kp.public_key(),  # wrong key
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code == "PROOF_SIGNATURE_INVALID"

    def test_garbled_token_rejected(self, consumer_kp, producer_kp) -> None:
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                "not.a.valid.jwt",
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code in ("PROOF_ALG_PROHIBITED", "PROOF_SIGNATURE_INVALID")


# ---------------------------------------------------------------------------
# Time checks
# ---------------------------------------------------------------------------


class TestTimeChecks:
    def test_expired_proof_rejected(self, consumer_kp, producer_kp) -> None:
        import freezegun
        with freezegun.freeze_time("2020-01-01"):
            proof = _make_proof(consumer_kp, producer_kp)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code == "PROOF_EXPIRED"

    def test_future_iat_rejected(self, consumer_kp, producer_kp) -> None:
        import freezegun, time as _time
        # Build a proof 1 hour in the future
        with freezegun.freeze_time("2099-01-01"):
            proof = _make_proof(consumer_kp, producer_kp)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        # Could be PROOF_NOT_YET_VALID (iat in future) or PROOF_EXPIRED (exp in future but iat check fails differently)
        assert exc_info.value.code in ("PROOF_NOT_YET_VALID", "PROOF_EXPIRED")


# ---------------------------------------------------------------------------
# Binding checks
# ---------------------------------------------------------------------------


class TestBindingChecks:
    def test_wrong_audience_rejected(self, consumer_kp, producer_kp, simple_req) -> None:
        other = generate_did_key()
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=other.did,  # wrong producer DID
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code == "AUD_MISMATCH"

    def test_wrong_env_rejected(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req, env="test")
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="prod",  # proof says "test", producer expects "prod"
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code == "ENV_MISMATCH"

    def test_body_hash_mismatch_rejected(self, consumer_kp, producer_kp) -> None:
        body = b'{"original": true}'
        req = build_req_binding(method="POST", path="/data", body=body)
        proof = _make_proof(consumer_kp, producer_kp, req=req)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                body=b'{"tampered": true}',  # different body
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.code == "BODY_HASH_MISMATCH"


# ---------------------------------------------------------------------------
# Replay detection
# ---------------------------------------------------------------------------


class TestReplayDetection:
    def test_second_use_of_same_proof_rejected(
        self, consumer_kp, producer_kp, simple_req
    ) -> None:
        cache = InMemoryReplayCache()
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)

        # First use passes
        verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            replay_cache=cache,
        )
        # Second use with the same proof → replay
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=cache,
            )
        assert exc_info.value.code == "REPLAY_DETECTED"

    def test_different_proofs_both_pass(
        self, consumer_kp, producer_kp, simple_req
    ) -> None:
        cache = InMemoryReplayCache()
        for _ in range(5):
            proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=cache,
            )


# ---------------------------------------------------------------------------
# Nonce validation
# ---------------------------------------------------------------------------


class TestNonceValidation:
    def test_correct_nonce_passes(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req, nonce="abc-nonce")
        claims = verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            replay_cache=InMemoryReplayCache(),
            expected_nonce="abc-nonce",
        )
        assert claims.nonce == "abc-nonce"

    def test_wrong_nonce_rejected(self, consumer_kp, producer_kp, simple_req) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req, nonce="correct-nonce")
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
                expected_nonce="wrong-nonce",
            )
        assert exc_info.value.code == "NONCE_INVALID"

    def test_missing_nonce_when_required_rejected(
        self, consumer_kp, producer_kp, simple_req
    ) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)  # no nonce
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
                expected_nonce="required-nonce",
            )
        assert exc_info.value.code == "NONCE_INVALID"

    def test_no_expected_nonce_skips_check(
        self, consumer_kp, producer_kp, simple_req
    ) -> None:
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)  # no nonce
        # Should not raise even though there's no nonce claim
        verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            replay_cache=InMemoryReplayCache(),
            expected_nonce=None,
        )


# ---------------------------------------------------------------------------
# Error code HTTP status
# ---------------------------------------------------------------------------


class TestErrorHttpStatus:
    def test_aud_mismatch_is_403(self, consumer_kp, producer_kp, simple_req) -> None:
        other = generate_did_key()
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=other.did,
                producer_env="test",
                replay_cache=InMemoryReplayCache(),
            )
        assert exc_info.value.http_status == 403

    def test_replay_detected_is_401(self, consumer_kp, producer_kp, simple_req) -> None:
        cache = InMemoryReplayCache()
        proof = _make_proof(consumer_kp, producer_kp, req=simple_req)
        verify_proof(
            proof,
            consumer_kp.public_key(),
            producer_did=producer_kp.did,
            producer_env="test",
            replay_cache=cache,
        )
        with pytest.raises(ProofVerificationError) as exc_info:
            verify_proof(
                proof,
                consumer_kp.public_key(),
                producer_did=producer_kp.did,
                producer_env="test",
                replay_cache=cache,
            )
        assert exc_info.value.http_status == 401
